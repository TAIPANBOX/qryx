-- qryx cryptographic asset graph. Applied idempotently on each operation.

CREATE TABLE IF NOT EXISTS scans (
    id             BIGSERIAL PRIMARY KEY,
    root           TEXT        NOT NULL,
    schema_version INT         NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS assets (
    id         BIGSERIAL PRIMARY KEY,
    scan_id    BIGINT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    type       TEXT   NOT NULL,
    algorithm  TEXT   NOT NULL,
    key_size   INT    NOT NULL,
    primitive  TEXT   NOT NULL,
    risk_class TEXT   NOT NULL,
    severity   INT    NOT NULL,
    reason     TEXT   NOT NULL
);

CREATE TABLE IF NOT EXISTS occurrences (
    id            BIGSERIAL PRIMARY KEY,
    asset_id      BIGINT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    location_file TEXT   NOT NULL,
    location_line INT    NOT NULL,
    source        TEXT   NOT NULL,
    evidence      TEXT   NOT NULL,
    tags          JSONB  NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS scans_created_at_idx ON scans (created_at DESC);
CREATE INDEX IF NOT EXISTS assets_scan_id_idx   ON assets (scan_id);
CREATE INDEX IF NOT EXISTS occurrences_asset_id_idx ON occurrences (asset_id);
