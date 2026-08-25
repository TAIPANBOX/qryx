package report

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/TAIPANBOX/qryx/internal/model"
	"github.com/TAIPANBOX/qryx/internal/scan"
)

var regexpTimestamp = regexp.MustCompile(`"generatedAt": "[^"]*"`)

func aiFinding(label, provider, role, file string, line int) model.Finding {
	return model.Finding{
		Asset:    model.Asset{Type: model.TypeAIModel, Algorithm: label, Primitive: model.PrimitiveUnknown},
		Location: model.Location{File: file, Line: line},
		Evidence: "import " + label,
		Source:   "aiusage",
		Risk:     model.Risk{Class: model.RiskNone, Severity: model.SeverityInfo},
		Tags:     map[string]string{"qryx.ai.provider": provider, "qryx.ai.role": role},
	}
}

func decodeInventory(t *testing.T, res *scan.Result) map[string]any {
	t.Helper()
	var buf bytes.Buffer
	if err := AIInventory(&buf, res, "v0-test"); err != nil {
		t.Fatalf("AIInventory: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, buf.String())
	}
	return doc
}

func TestAIInventoryCarriesProviderAndRole(t *testing.T) {
	res := &scan.Result{Root: "/tree", FilesWalked: 3, Findings: []model.Finding{
		aiFinding("Anthropic SDK (python)", "anthropic", "provider", "a.py", 2),
	}}
	doc := decodeInventory(t, res)

	entries, _ := doc["entries"].([]any)
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}
	row, _ := entries[0].(map[string]any)
	if row["provider"] != "anthropic" {
		t.Errorf("provider = %v, want anthropic", row["provider"])
	}
	if row["role"] != "provider" {
		t.Errorf("role = %v, want provider", row["role"])
	}
	if row["label"] != "Anthropic SDK (python)" {
		t.Errorf("label = %v", row["label"])
	}
	if doc["schema"] != AIInventorySchema {
		t.Errorf("schema = %v, want %s", doc["schema"], AIInventorySchema)
	}
}

// TestAIInventoryExcludesCryptographicAssets is the mirror of the CBOM's own
// exclusion, and it matters in this direction too: a cryptographic asset
// appearing in an AI inventory would tell a reader the tree talks to a model
// it has no evidence for.
func TestAIInventoryExcludesCryptographicAssets(t *testing.T) {
	res := &scan.Result{Root: "/tree", Findings: []model.Finding{
		aiFinding("OpenAI SDK (python)", "openai", "provider", "a.py", 1),
		{
			Asset:    model.Asset{Type: model.TypeAlgorithm, Algorithm: "RSA", KeySize: 2048, Primitive: model.PrimitiveSignature},
			Location: model.Location{File: "b.go", Line: 9},
			Source:   "goast",
			Risk:     model.Risk{Class: model.RiskQuantumVulnerable, Severity: model.SeverityHigh},
		},
	}}
	doc := decodeInventory(t, res)

	entries, _ := doc["entries"].([]any)
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1 (the crypto asset must not ride along)", len(entries))
	}
	if row, _ := entries[0].(map[string]any); row["label"] == "RSA" {
		t.Error("a cryptographic asset reached the AI inventory")
	}
}

// TestAIInventoryAlwaysStatesItsLimits holds the half of invariant 6 that a
// consumer can actually act on. An empty inventory is the dangerous case: it
// looks exactly like a tree that uses no AI, and only the limits in the
// document say otherwise.
func TestAIInventoryAlwaysStatesItsLimits(t *testing.T) {
	for _, tc := range []struct {
		name string
		res  *scan.Result
	}{
		{"with findings", &scan.Result{Root: "/tree", Findings: []model.Finding{
			aiFinding("OpenAI SDK (python)", "openai", "provider", "a.py", 1),
		}}},
		{"empty scan", &scan.Result{Root: "/tree"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := decodeInventory(t, tc.res)
			limits, _ := doc["limits"].([]any)
			if len(limits) == 0 {
				t.Fatal("the document states no limits, so an empty result reads as proof of absence")
			}
			var joined string
			for _, l := range limits {
				s, _ := l.(string)
				joined += " " + s
			}
			if !strings.Contains(joined, "proof") {
				t.Errorf("limits never say an empty result is not proof of absence: %q", joined)
			}
		})
	}
}

// TestAIInventoryIsDeterministic pins invariant 8 where it bites: the rows
// come out of a graph built from a map, so an unsorted document would differ
// between two scans of one tree and every diff downstream would be noise.
func TestAIInventoryIsDeterministic(t *testing.T) {
	res := &scan.Result{Root: "/tree", Findings: []model.Finding{
		aiFinding("OpenAI SDK (python)", "openai", "provider", "z.py", 3),
		aiFinding("Anthropic SDK (python)", "anthropic", "provider", "a.py", 1),
		aiFinding("LangChain (python)", "", "framework", "m.py", 7),
		aiFinding("OpenAI SDK (python)", "openai", "provider", "b.py", 4),
	}}

	var first string
	for i := 0; i < 8; i++ {
		var buf bytes.Buffer
		if err := AIInventory(&buf, res, "v0-test"); err != nil {
			t.Fatalf("AIInventory: %v", err)
		}
		// generatedAt is a clock reading and is expected to move.
		got := regexpTimestamp.ReplaceAllString(buf.String(), `"generatedAt": "-"`)
		if i == 0 {
			first = got
			continue
		}
		if got != first {
			t.Fatalf("run %d differs from run 0:\n%s\n---\n%s", i, first, got)
		}
	}

	doc := decodeInventory(t, res)
	entries, _ := doc["entries"].([]any)
	if len(entries) != 3 {
		t.Fatalf("entries = %d, want 3 (two OpenAI findings are one asset)", len(entries))
	}
	var order []string
	for _, e := range entries {
		row, _ := e.(map[string]any)
		order = append(order, row["provider"].(string))
	}
	// Empty provider sorts first: the framework row, whose provider is open.
	if order[0] != "" || order[1] != "anthropic" || order[2] != "openai" {
		t.Errorf("provider order = %v", order)
	}
}

// TestAIInventoryOrderIsTotal reaches the tie-breaks the determinism test
// above never touches. Its rows all have distinct providers, so it proved
// ordering by provider and nothing else, and the two comparisons underneath
// were carried by no assertion that could go red.
//
// They are the ones that matter, because a provider legitimately produces
// several rows: OpenAI as an SDK import and again as a bare endpoint literal
// is one provider and two labels, which is the shape every real scan on this
// machine produced.
func TestAIInventoryOrderIsTotal(t *testing.T) {
	res := &scan.Result{Root: "/tree", Findings: []model.Finding{
		aiFinding("OpenAI SDK (python)", "openai", "provider", "b.py", 9),
		aiFinding("OpenAI SDK (python)", "openai", "provider", "b.py", 2),
		aiFinding("OpenAI API endpoint", "openai", "provider", "a.py", 1),
		// Same provider, different role: the second comparison.
		aiFinding("Ollama client (python)", "openai", "local-runtime", "c.py", 1),
	}}

	doc := decodeInventory(t, res)
	entries, _ := doc["entries"].([]any)
	if len(entries) != 3 {
		t.Fatalf("entries = %d, want 3", len(entries))
	}

	var got []string
	for _, e := range entries {
		row, _ := e.(map[string]any)
		got = append(got, row["role"].(string)+"/"+row["label"].(string))
	}
	want := []string{
		"local-runtime/Ollama client (python)", // role sorts before "provider"
		"provider/OpenAI API endpoint",         // same role, label decides
		"provider/OpenAI SDK (python)",
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("row %d = %q, want %q", i, got[i], want[i])
		}
	}

	// And within one row, two occurrences in one file are ordered by line.
	last, _ := entries[2].(map[string]any)
	occs, _ := last["occurrences"].([]any)
	if len(occs) != 2 {
		t.Fatalf("occurrences = %d, want 2", len(occs))
	}
	first, _ := occs[0].(map[string]any)
	if first["line"].(float64) != 2 {
		t.Errorf("first occurrence line = %v, want 2", first["line"])
	}
}
