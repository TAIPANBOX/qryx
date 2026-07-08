package store

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// EvidenceRecord is one compact, digest-stamped compliance data point, appended
// to a trail per run so posture can be tracked over time.
type EvidenceRecord struct {
	CreatedAt    time.Time `json:"createdAt"`
	Root         string    `json:"root"`
	Version      string    `json:"version"`
	ScorePct     int       `json:"scorePct"`
	Compliant    int       `json:"compliant"`
	NonCompliant int       `json:"nonCompliant"`
	Issues       int       `json:"issues"`
	Total        int       `json:"total"`
	Digest       string    `json:"digest"`
}

// Trail is an append-only log of evidence records. Unlike Store (single
// overwrite), it accumulates history.
type Trail interface {
	Append(EvidenceRecord) error
	History() ([]EvidenceRecord, error)
}

// JSONLTrail stores records as JSON Lines (one object per line) at Path.
type JSONLTrail struct {
	Path string
}

// Append writes one record as a JSON line. The file is created if absent.
func (t JSONLTrail) Append(r EvidenceRecord) error {
	line, err := json.Marshal(r)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(t.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return err
	}
	return nil
}

// History returns all records in append order. A missing trail is an empty
// history, not an error; a malformed line is an error to protect trail integrity.
func (t JSONLTrail) History() ([]EvidenceRecord, error) {
	data, err := os.ReadFile(t.Path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []EvidenceRecord
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for line := 1; sc.Scan(); line++ {
		b := bytes.TrimSpace(sc.Bytes())
		if len(b) == 0 {
			continue
		}
		var r EvidenceRecord
		if err := json.Unmarshal(b, &r); err != nil {
			return nil, fmt.Errorf("evidence trail %s line %d: %w", t.Path, line, err)
		}
		out = append(out, r)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
