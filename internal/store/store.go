// Package store persists the cryptographic asset graph and diffs snapshots to
// detect drift between runs. The JSON backend is dependency-free; the Store
// interface lets a Postgres backend drop in later without touching diff logic.
package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/TAIPANBOX/qryx/internal/graph"
	"github.com/TAIPANBOX/qryx/internal/scan"
)

// schemaVersion is bumped when the snapshot format changes incompatibly.
const schemaVersion = 1

// ErrNotFound is returned by Load when no snapshot exists at the path.
var ErrNotFound = errors.New("snapshot not found")

// Snapshot is a point-in-time capture of the asset graph.
type Snapshot struct {
	SchemaVersion int               `json:"schemaVersion"`
	CreatedAt     time.Time         `json:"createdAt"`
	Root          string            `json:"root"`
	Assets        []graph.AssetNode `json:"assets"`
}

// Snap builds a snapshot from a scan result.
func Snap(res *scan.Result) Snapshot {
	return Snapshot{
		SchemaVersion: schemaVersion,
		CreatedAt:     time.Now().UTC(),
		Root:          res.Root,
		Assets:        graph.Build(res.Findings),
	}
}

// Store persists and retrieves a single snapshot.
type Store interface {
	Save(Snapshot) error
	Load() (Snapshot, error)
}

// JSONStore persists a snapshot as indented JSON at Path.
type JSONStore struct {
	Path string
}

// Save writes the snapshot atomically (temp file + rename).
func (s JSONStore) Save(snap Snapshot) error {
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.Path), ".qryx-snap-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, s.Path)
}

// Load reads the snapshot, returning ErrNotFound if the file is absent.
func (s JSONStore) Load() (Snapshot, error) {
	data, err := os.ReadFile(s.Path)
	if errors.Is(err, os.ErrNotExist) {
		return Snapshot{}, ErrNotFound
	}
	if err != nil {
		return Snapshot{}, err
	}
	var snap Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return Snapshot{}, err
	}
	return snap, nil
}

// Delta is the difference between a baseline and a current snapshot.
type Delta struct {
	Added   []graph.AssetNode
	Removed []graph.AssetNode
}

// Empty reports whether there is no drift.
func (d Delta) Empty() bool { return len(d.Added) == 0 && len(d.Removed) == 0 }

// Diff compares two snapshots by canonical asset key: Added are assets present
// in cur but not base, Removed are present in base but not cur.
func Diff(base, cur Snapshot) Delta {
	baseKeys := keySet(base.Assets)
	curKeys := keySet(cur.Assets)

	var d Delta
	for _, a := range cur.Assets {
		if !baseKeys[graph.AssetKey(a.Asset)] {
			d.Added = append(d.Added, a)
		}
	}
	for _, a := range base.Assets {
		if !curKeys[graph.AssetKey(a.Asset)] {
			d.Removed = append(d.Removed, a)
		}
	}
	return d
}

func keySet(assets []graph.AssetNode) map[string]bool {
	m := make(map[string]bool, len(assets))
	for _, a := range assets {
		m[graph.AssetKey(a.Asset)] = true
	}
	return m
}
