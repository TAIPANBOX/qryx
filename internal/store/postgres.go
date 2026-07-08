package store

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/TAIPANBOX/qryx/internal/graph"
	"github.com/TAIPANBOX/qryx/internal/model"
)

//go:embed schema.sql
var schemaSQL string

// PostgresStore persists the asset graph in normalized relational tables. It
// implements Store, so the diff/drift logic above is reused unchanged. Each
// operation opens and closes its own connection — the CLI is one-shot.
type PostgresStore struct {
	ConnString string
}

func (s PostgresStore) connect(ctx context.Context) (*pgx.Conn, error) {
	return pgConnect(ctx, s.ConnString)
}

// pgConnect opens a connection and applies the schema idempotently. Shared by
// the snapshot store and the evidence trail.
func pgConnect(ctx context.Context, connString string) (*pgx.Conn, error) {
	conn, err := pgx.Connect(ctx, connString)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Exec(ctx, schemaSQL); err != nil {
		_ = conn.Close(ctx)
		return nil, fmt.Errorf("ensure schema: %w", err)
	}
	return conn, nil
}

// Save writes the snapshot as one scan with its assets and occurrences, in a
// single transaction.
func (s PostgresStore) Save(snap Snapshot) error {
	ctx := context.Background()
	conn, err := s.connect(ctx)
	if err != nil {
		return err
	}
	defer conn.Close(ctx)

	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op once committed

	var scanID int64
	if err := tx.QueryRow(ctx,
		`INSERT INTO scans (root, schema_version, created_at) VALUES ($1, $2, $3) RETURNING id`,
		snap.Root, snap.SchemaVersion, snap.CreatedAt,
	).Scan(&scanID); err != nil {
		return err
	}

	for _, a := range snap.Assets {
		var assetID int64
		if err := tx.QueryRow(ctx,
			`INSERT INTO assets (scan_id, type, algorithm, key_size, primitive, risk_class, severity, reason)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`,
			scanID, a.Asset.Type, a.Asset.Algorithm, a.Asset.KeySize, a.Asset.Primitive,
			a.Risk.Class, int(a.Risk.Severity), a.Risk.Reason,
		).Scan(&assetID); err != nil {
			return err
		}
		for _, o := range a.Occurrences {
			tagsJSON, err := json.Marshal(o.Tags)
			if err != nil {
				return fmt.Errorf("marshal tags: %w", err)
			}
			if _, err := tx.Exec(ctx,
				`INSERT INTO occurrences (asset_id, location_file, location_line, source, evidence, tags)
				 VALUES ($1,$2,$3,$4,$5,$6)`,
				assetID, o.Location.File, o.Location.Line, o.Source, o.Evidence, tagsJSON,
			); err != nil {
				return err
			}
		}
	}
	return tx.Commit(ctx)
}

// Load reconstructs the most recent snapshot. Returns ErrNotFound when no scan
// has been saved.
func (s PostgresStore) Load() (Snapshot, error) {
	ctx := context.Background()
	conn, err := s.connect(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	defer conn.Close(ctx)

	var snap Snapshot
	var scanID int64
	err = conn.QueryRow(ctx,
		`SELECT id, root, schema_version, created_at FROM scans ORDER BY created_at DESC, id DESC LIMIT 1`,
	).Scan(&scanID, &snap.Root, &snap.SchemaVersion, &snap.CreatedAt)
	if err == pgx.ErrNoRows {
		return Snapshot{}, ErrNotFound
	}
	if err != nil {
		return Snapshot{}, err
	}

	assets, byID, err := loadAssets(ctx, conn, scanID)
	if err != nil {
		return Snapshot{}, err
	}
	if err := loadOccurrences(ctx, conn, scanID, assets, byID); err != nil {
		return Snapshot{}, err
	}
	snap.Assets = assets
	return snap, nil
}

// PostgresTrail is the Postgres-backed evidence trail. It implements Trail,
// reusing the same connect/ensure-schema bootstrap as PostgresStore.
type PostgresTrail struct {
	ConnString string
}

// Append inserts one evidence record, preserving its CreatedAt.
func (t PostgresTrail) Append(r EvidenceRecord) error {
	ctx := context.Background()
	conn, err := pgConnect(ctx, t.ConnString)
	if err != nil {
		return err
	}
	defer conn.Close(ctx)

	_, err = conn.Exec(ctx,
		`INSERT INTO evidence (created_at, root, version, score_pct, compliant, non_compliant, issues, total, digest)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		r.CreatedAt, r.Root, r.Version, r.ScorePct, r.Compliant, r.NonCompliant, r.Issues, r.Total, r.Digest,
	)
	return err
}

// History returns all evidence records in append order. An empty table yields
// an empty slice, matching the file backend.
func (t PostgresTrail) History() ([]EvidenceRecord, error) {
	ctx := context.Background()
	conn, err := pgConnect(ctx, t.ConnString)
	if err != nil {
		return nil, err
	}
	defer conn.Close(ctx)

	rows, err := conn.Query(ctx,
		`SELECT created_at, root, version, score_pct, compliant, non_compliant, issues, total, digest
		 FROM evidence ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []EvidenceRecord
	for rows.Next() {
		var r EvidenceRecord
		if err := rows.Scan(&r.CreatedAt, &r.Root, &r.Version, &r.ScorePct,
			&r.Compliant, &r.NonCompliant, &r.Issues, &r.Total, &r.Digest); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// loadAssets returns the scan's asset nodes (without occurrences) and a map from
// the DB asset id to its index in the returned slice.
func loadAssets(ctx context.Context, conn *pgx.Conn, scanID int64) ([]graph.AssetNode, map[int64]int, error) {
	rows, err := conn.Query(ctx,
		`SELECT id, type, algorithm, key_size, primitive, risk_class, severity, reason
		 FROM assets WHERE scan_id=$1 ORDER BY id`, scanID)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	var assets []graph.AssetNode
	byID := map[int64]int{}
	for rows.Next() {
		var id int64
		var n graph.AssetNode
		var sev int
		if err := rows.Scan(&id, &n.Asset.Type, &n.Asset.Algorithm, &n.Asset.KeySize,
			&n.Asset.Primitive, &n.Risk.Class, &sev, &n.Risk.Reason); err != nil {
			return nil, nil, err
		}
		n.Risk.Severity = model.Severity(sev)
		byID[id] = len(assets)
		assets = append(assets, n)
	}
	return assets, byID, rows.Err()
}

// loadOccurrences attaches occurrences to their asset nodes.
func loadOccurrences(ctx context.Context, conn *pgx.Conn, scanID int64, assets []graph.AssetNode, byID map[int64]int) error {
	rows, err := conn.Query(ctx,
		`SELECT o.asset_id, o.location_file, o.location_line, o.source, o.evidence, o.tags
		 FROM occurrences o JOIN assets a ON a.id=o.asset_id
		 WHERE a.scan_id=$1 ORDER BY o.id`, scanID)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var assetID int64
		var o graph.Occurrence
		var tagsJSON []byte
		if err := rows.Scan(&assetID, &o.Location.File, &o.Location.Line, &o.Source, &o.Evidence, &tagsJSON); err != nil {
			return err
		}
		if len(tagsJSON) > 0 && string(tagsJSON) != "null" {
			if err := json.Unmarshal(tagsJSON, &o.Tags); err != nil {
				return fmt.Errorf("unmarshal tags: %w", err)
			}
		}
		if idx, ok := byID[assetID]; ok {
			o.Primitive = assets[idx].Asset.Primitive
			assets[idx].Occurrences = append(assets[idx].Occurrences, o)
		}
	}
	return rows.Err()
}
