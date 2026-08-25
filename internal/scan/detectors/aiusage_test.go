package detectors

import (
	"testing"

	"github.com/TAIPANBOX/qryx/internal/model"
	"github.com/TAIPANBOX/qryx/internal/risk"
	"github.com/TAIPANBOX/qryx/internal/scan"
)

// assertAIFinding checks the invariants every AIUsage finding must hold:
// TypeAIModel, PrimitiveUnknown, and an explicit RiskNone/SeverityInfo risk
// that can never trip --fail-on (cmd/qryx/main.go gates on
// `Severity >= threshold && Class != RiskNone`; RiskNone alone already makes
// that false regardless of threshold, so this checks both halves).
func assertAIFinding(t *testing.T, f model.Finding, wantAlgorithm string) {
	t.Helper()
	if f.Asset.Type != model.TypeAIModel {
		t.Errorf("Asset.Type = %q, want %q", f.Asset.Type, model.TypeAIModel)
	}
	if f.Asset.Algorithm != wantAlgorithm {
		t.Errorf("Asset.Algorithm = %q, want %q", f.Asset.Algorithm, wantAlgorithm)
	}
	if f.Asset.Primitive != model.PrimitiveUnknown {
		t.Errorf("Asset.Primitive = %q, want %q", f.Asset.Primitive, model.PrimitiveUnknown)
	}
	if f.Risk.Class != model.RiskNone {
		t.Errorf("Risk.Class = %q, want %q (must never read as a crypto risk)", f.Risk.Class, model.RiskNone)
	}
	if f.Risk.Severity != model.SeverityInfo {
		t.Errorf("Risk.Severity = %v, want %v", f.Risk.Severity, model.SeverityInfo)
	}
	for _, threshold := range []model.Severity{model.SeverityLow, model.SeverityMedium, model.SeverityHigh, model.SeverityCritical} {
		if f.Risk.Severity >= threshold && f.Risk.Class != model.RiskNone {
			t.Errorf("finding would trip --fail-on at threshold %v", threshold)
		}
	}
}

func TestAIUsageWants(t *testing.T) {
	d := NewAIUsage()
	for path, want := range map[string]bool{
		"go.mod": true, "requirements.txt": true, "package.json": true,
		"Cargo.toml": true, "pom.xml": true,
		"main.go": true, "app.py": true, "index.ts": true, "index.tsx": true,
		"config.yaml": true, ".env": true, "settings.toml": true, "app.conf": true,
		"notes.md": false, "image.png": false, "data.bin": false,
	} {
		if got := d.Wants(path); got != want {
			t.Errorf("Wants(%q) = %v, want %v", path, got, want)
		}
	}
}

// --- (a) dependency manifests ---

func TestAIUsageDetectsManifestDependency(t *testing.T) {
	content := []byte("flask==3.0\nanthropic==0.34.0\nrequests==2.32\n")
	got := NewAIUsage().Detect(scan.File{Path: "requirements.txt", Content: content})
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(got), got)
	}
	assertAIFinding(t, got[0], "Anthropic SDK (python)")
	if got[0].Location.Line != 2 {
		t.Errorf("line = %d, want 2", got[0].Location.Line)
	}
	if got[0].Source != "aiusage" {
		t.Errorf("Source = %q, want aiusage", got[0].Source)
	}
}

// TestAIUsageBoto3AloneNotFlagged pins the explicit non-goal: boto3 is AWS's
// general-purpose SDK, not an LLM SDK, and must not be flagged by itself.
// Only a Bedrock-specific signal (the bedrock-runtime endpoint literal)
// should ever produce an AI-usage finding for AWS SDK code.
func TestAIUsageBoto3AloneNotFlagged(t *testing.T) {
	content := []byte("boto3==1.34.0\nbotocore==1.34.0\n")
	got := NewAIUsage().Detect(scan.File{Path: "requirements.txt", Content: content})
	if len(got) != 0 {
		t.Fatalf("expected 0 findings for boto3 alone, got %d: %+v", len(got), got)
	}
}

func TestAIUsageManifestEcosystemLabel(t *testing.T) {
	tests := []struct {
		path    string
		content string
		want    string
	}{
		{"requirements.txt", "openai==1.30\n", "OpenAI SDK (python)"},
		{"package.json", `{"dependencies": {"openai": "^4.50.0"}}`, "OpenAI SDK (JS/TS)"},
		{"go.mod", "require github.com/sashabaranov/go-openai v1.26.2\n", "OpenAI SDK (Go)"},
		{"Cargo.toml", "async-openai = \"0.20\"\n", "OpenAI SDK (Rust)"},
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			got := NewAIUsage().Detect(scan.File{Path: tc.path, Content: []byte(tc.content)})
			var found bool
			for _, f := range got {
				if f.Asset.Algorithm == tc.want {
					found = true
				}
			}
			if !found {
				t.Fatalf("expected a %q finding, got %+v", tc.want, got)
			}
		})
	}
}

// --- (b) source imports/calls ---

func TestAIUsageDetectsPythonImport(t *testing.T) {
	// Only the import line matches: this detector recognizes declared
	// imports, not bare attribute access like openai.OpenAI() with no import
	// in sight (see the package doc comment's regex-limits note).
	src := []byte("import os\nimport openai\n\nclient = openai.OpenAI()\n")
	got := NewAIUsage().Detect(scan.File{Path: "agent.py", Content: src})
	if len(got) != 1 {
		t.Fatalf("expected 1 finding (the import line only), got %d: %+v", len(got), got)
	}
	assertAIFinding(t, got[0], "OpenAI SDK (python)")
	if got[0].Location.Line != 2 {
		t.Errorf("line = %d, want 2", got[0].Location.Line)
	}
}

func TestAIUsageDetectsPythonFromImport(t *testing.T) {
	src := []byte("from anthropic import Anthropic\n")
	got := NewAIUsage().Detect(scan.File{Path: "agent.py", Content: src})
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(got), got)
	}
	assertAIFinding(t, got[0], "Anthropic SDK (python)")
}

// TestAIUsageLangchainUnderscoreSplitPackages pins a real regex-boundary
// gotcha: the modern LangChain ecosystem splits into underscore-suffixed
// packages (langchain_openai, langchain_community, ...). A naive \b
// word-boundary after "langchain" would never match, because "_" is itself a
// word character and so creates no boundary right after "langchain".
func TestAIUsageLangchainUnderscoreSplitPackages(t *testing.T) {
	for _, src := range []string{
		"from langchain_community.llms import Ollama\n",
		"import langchain_openai\n",
		"from langchain.chains import LLMChain\n",
	} {
		got := NewAIUsage().Detect(scan.File{Path: "chain.py", Content: []byte(src)})
		if len(got) != 1 || got[0].Asset.Algorithm != "LangChain (python)" {
			t.Errorf("src %q: expected 1 LangChain (python) finding, got %+v", src, got)
		}
	}
}

func TestAIUsageTransformersLabeledAsLocalRuntime(t *testing.T) {
	src := []byte("from transformers import AutoModelForCausalLM\n")
	got := NewAIUsage().Detect(scan.File{Path: "infer.py", Content: src})
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(got), got)
	}
	assertAIFinding(t, got[0], "local model runtime (transformers, python)")
}

func TestAIUsageJSImportVariants(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{"CommonJS require", "const OpenAI = require('openai');\n", "OpenAI SDK (JS/TS)"},
		{"ES default import", "import Anthropic from '@anthropic-ai/sdk';\n", "Anthropic SDK (JS/TS)"},
		{"Vercel AI SDK subpath", "import { generateText } from '@ai-sdk/openai';\n", "Vercel AI SDK (JS/TS)"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := NewAIUsage().Detect(scan.File{Path: "route.ts", Content: []byte(tc.src)})
			var found bool
			for _, f := range got {
				if f.Asset.Algorithm == tc.want {
					found = true
					assertAIFinding(t, f, tc.want)
				}
			}
			if !found {
				t.Fatalf("expected a %q finding, got %+v", tc.want, got)
			}
		})
	}
}

func TestAIUsageGoImportPaths(t *testing.T) {
	src := []byte(`package main

import (
	"github.com/anthropics/anthropic-sdk-go"
)
`)
	got := NewAIUsage().Detect(scan.File{Path: "client.go", Content: src})
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(got), got)
	}
	assertAIFinding(t, got[0], "Anthropic SDK (Go)")
}

// --- (c) endpoint literals ---

func TestAIUsageDetectsBedrockEndpointLiteral(t *testing.T) {
	src := []byte(`ENDPOINT = "bedrock-runtime.us-east-1.amazonaws.com"` + "\n")
	got := NewAIUsage().Detect(scan.File{Path: "config.py", Content: src})
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(got), got)
	}
	assertAIFinding(t, got[0], "AWS Bedrock")
}

func TestAIUsageDetectsEndpointLiterals(t *testing.T) {
	tests := []struct {
		src  string
		want string
	}{
		{`base := "https://api.openai.com/v1"`, "OpenAI API endpoint"},
		{`url = "https://api.anthropic.com/v1/messages"`, "Anthropic API endpoint"},
		{`endpoint: "generativelanguage.googleapis.com"`, "Google Generative Language API endpoint (Gemini)"},
		{`API_BASE = "https://api.mistral.ai/v1"`, "Mistral AI API endpoint"},
		{`base = "https://api.cohere.ai/v1"`, "Cohere API endpoint"},
		{`base = "https://api.cohere.com/v1"`, "Cohere API endpoint"},
		{`base = "https://api.groq.com/openai/v1"`, "Groq API endpoint"},
		{`base = "https://api.together.xyz/v1"`, "Together AI API endpoint"},
		{`base = "https://openrouter.ai/api/v1"`, "OpenRouter API endpoint"},
		{`base = "https://api.perplexity.ai"`, "Perplexity API endpoint"},
		{`base = "https://api.replicate.com/v1"`, "Replicate API endpoint"},
	}
	for _, tc := range tests {
		got := NewAIUsage().Detect(scan.File{Path: "conf.txt", Content: []byte(tc.src)})
		var found bool
		for _, f := range got {
			if f.Asset.Algorithm == tc.want {
				found = true
			}
		}
		if !found {
			t.Errorf("src %q: expected a %q finding, got %+v", tc.src, tc.want, got)
		}
	}
}

// --- de-duplication ---

// TestAIUsageDedupSameLine pins the required de-dup behavior against the
// detector's actual Detect path (not just the helper in isolation, see
// TestAIUsageDedupSameLineHelper): FindAllIndex reports every match on a
// line, so a line naming the same provider twice (here, two require()
// calls for "openai" on one line, as generated or copy-pasted code might)
// would otherwise produce two findings for what is really one occurrence.
func TestAIUsageDedupSameLine(t *testing.T) {
	src := []byte("const a = require('openai'); const b = require('openai');\n")
	got := NewAIUsage().Detect(scan.File{Path: "client.js", Content: src})
	var openaiCount int
	for _, f := range got {
		if f.Asset.Algorithm == "OpenAI SDK (JS/TS)" {
			openaiCount++
		}
	}
	if openaiCount != 1 {
		t.Fatalf("expected exactly 1 OpenAI SDK (JS/TS) finding after dedup, got %d: %+v", openaiCount, got)
	}
}

func TestAIUsageDedupSameLineHelper(t *testing.T) {
	in := []model.Finding{
		{Asset: model.Asset{Algorithm: "OpenAI SDK"}, Location: model.Location{Line: 1}},
		{Asset: model.Asset{Algorithm: "OpenAI SDK"}, Location: model.Location{Line: 1}},
		{Asset: model.Asset{Algorithm: "OpenAI SDK"}, Location: model.Location{Line: 2}},
		{Asset: model.Asset{Algorithm: "Anthropic SDK"}, Location: model.Location{Line: 1}},
	}
	out := dedupeSameLine(in)
	if len(out) != 3 {
		t.Fatalf("expected 3 deduped findings, got %d: %+v", len(out), out)
	}
}

// --- no false positives ---

func TestAIUsageNoFalsePositiveOnUnrelatedCode(t *testing.T) {
	tests := []struct {
		path    string
		content string
	}{
		{"main.go", "package main\n\nimport \"fmt\"\n\nfunc main() { fmt.Println(\"hello\") }\n"},
		{"app.py", "import os\nimport json\n\ndef main():\n    print(os.getcwd())\n"},
		{"requirements.txt", "flask==3.0\nrequests==2.32\nnumpy==1.26\n"},
		{"index.ts", "import express from 'express';\nconst app = express();\n"},
	}
	for _, tc := range tests {
		got := NewAIUsage().Detect(scan.File{Path: tc.path, Content: []byte(tc.content)})
		if len(got) != 0 {
			t.Errorf("%s: expected 0 findings, got %d: %+v", tc.path, len(got), got)
		}
	}
}

// --- integration with the central risk classifier ---

// TestAIUsageRiskSurvivesCentralClassification confirms the explicit Risk
// asserted by this detector is not overwritten by risk.Apply (the walker
// calls risk.Apply on every batch of findings; it only fills in Risk when
// Class is still the empty zero value, see internal/risk/apply.go), the same
// way hardcoded.go's and tlsconfig.go's own asserted Risk survives.
func TestAIUsageRiskSurvivesCentralClassification(t *testing.T) {
	got := NewAIUsage().Detect(scan.File{Path: "requirements.txt", Content: []byte("openai==1.30\n")})
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	applied := risk.Apply(got)
	assertAIFinding(t, applied[0], "OpenAI SDK (python)")
}

// A manifest is matched by substring, which is right for a dependency name and
// wrong for prose. The needle list is full of ordinary English words, and a real
// Cargo.toml whose comment ended "...pins the two independent token readers
// together" was reported as depending on the Together AI SDK, in a repository with
// no network dependencies at all.
func TestAIUsageIgnoresManifestComments(t *testing.T) {
	manifest := []byte("[dev-dependencies]\n" +
		"trailryx-verify = { path = \"../trailryx-verify\" }\n" +
		"# pins the two independent token readers together, and is cohere-nt about it\n")
	got := NewAIUsage().Detect(scan.File{Path: "Cargo.toml", Content: manifest})
	if len(got) != 0 {
		t.Fatalf("a comment was read as a dependency: %+v", got)
	}
}

// The other half: stripping comments must not stop a real dependency being seen.
func TestAIUsageStillSeesARealManifestDependency(t *testing.T) {
	manifest := []byte("# an ordinary comment\n[dependencies]\nasync-openai = \"0.20\"\n")
	got := NewAIUsage().Detect(scan.File{Path: "Cargo.toml", Content: manifest})
	if len(got) != 1 {
		t.Fatalf("expected the OpenAI dependency, got %+v", got)
	}
	if got[0].Location.Line != 3 {
		t.Errorf("line %d, want 3: blanking must keep positions", got[0].Location.Line)
	}
}

// TestAIUsageCarriesACanonicalProvider pins the field that makes this
// detector's output joinable with the rest of the estate. The human label is
// prose ("Anthropic SDK (python)"), and a consumer correlating it against a
// Passport's declared provider or against an observed egress host would be
// left mangling that string. The canonical id is the join key, and it is
// carried on the finding rather than derived downstream, so there is one row
// per provider instead of a second copy of the vocabulary in every consumer.
func TestAIUsageCarriesACanonicalProvider(t *testing.T) {
	cases := []struct {
		name     string
		path     string
		content  string
		provider string
		role     string
	}{
		{"manifest", "requirements.txt", "anthropic==0.34.0\n", "anthropic", "provider"},
		{"python import", "a.py", "import openai\n", "openai", "provider"},
		{"endpoint literal", "cfg.yaml", "url: https://api.mistral.ai/v1\n", "mistral", "provider"},
		{"bedrock endpoint", "cfg.yaml", "host: bedrock-runtime.eu-west-1.amazonaws.com\n", "aws-bedrock", "provider"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := NewAIUsage().Detect(scan.File{Path: tc.path, Content: []byte(tc.content)})
			if len(got) != 1 {
				t.Fatalf("expected 1 finding, got %d: %+v", len(got), got)
			}
			if p := got[0].Tags["qryx.ai.provider"]; p != tc.provider {
				t.Errorf("provider = %q, want %q", p, tc.provider)
			}
			if r := got[0].Tags["qryx.ai.role"]; r != tc.role {
				t.Errorf("role = %q, want %q", r, tc.role)
			}
		})
	}
}

// TestAIUsageFrameworkNamesNoProvider is the other half, and it is a fact
// rather than missing data: a tree that reaches an LLM through LangChain or
// LiteLLM tells you it reaches one and not which. An empty provider is what
// an inventory consumer must show as "reaches a model through an indirection
// this scan cannot resolve", and filling it in with a guess would be worse
// than leaving it open.
func TestAIUsageFrameworkNamesNoProvider(t *testing.T) {
	for _, tc := range []struct {
		content string
		role    string
	}{
		{"import langchain\n", "framework"},
		{"import litellm\n", "framework"},
		{"import transformers\n", "local-runtime"},
	} {
		got := NewAIUsage().Detect(scan.File{Path: "a.py", Content: []byte(tc.content)})
		if len(got) != 1 {
			t.Fatalf("%q: expected 1 finding, got %d", tc.content, len(got))
		}
		if p := got[0].Tags["qryx.ai.provider"]; p != "" {
			t.Errorf("%q: provider = %q, want empty", tc.content, p)
		}
		if r := got[0].Tags["qryx.ai.role"]; r != tc.role {
			t.Errorf("%q: role = %q, want %q", tc.content, r, tc.role)
		}
	}
}

// TestEveryAIUsageLabelHasACanonicalRow walks every row of all three tables
// and requires a role on each, so a provider added later cannot ship without
// one. It fails loudly on an empty walk rather than passing on nothing.
func TestEveryAIUsageLabelHasACanonicalRow(t *testing.T) {
	rows := 0
	check := func(where, label, role string) {
		rows++
		if role == "" {
			t.Errorf("%s: %q has no role", where, label)
		}
	}
	for _, n := range aiManifestNeedles {
		check("aiManifestNeedles", n.label, n.role)
	}
	for ext, pats := range aiImportPatterns {
		for _, p := range pats {
			check("aiImportPatterns"+ext, p.label, p.role)
		}
	}
	for _, e := range aiEndpoints {
		check("aiEndpoints", e.label, e.role)
	}
	if rows == 0 {
		t.Fatal("walked no rows: this test measured nothing, which is a failure of the test")
	}
}

// TestAIUsageManifestNeedleIsAWholeToken is a real false positive, from
// tokenfuse/crates/cluster/Cargo.toml, caught the first time this detector's
// output was read by another program rather than by a person.
//
// The needle "replicate" matched inside the word "raft-replicated", in a
// description field, and the row that came out named Replicate as a provider
// the code has never heard of. A person reading a table might squint at it;
// a consumer joining on the provider id reports AI usage that does not exist,
// which is the one failure an inventory must not have.
func TestAIUsageManifestNeedleIsAWholeToken(t *testing.T) {
	content := []byte("[package]\nname = \"tokenfuse-cluster\"\ndescription = \"HA budget counters for TokenFuse: a raft-replicated ledger (openraft)\"\n")
	got := NewAIUsage().Detect(scan.File{Path: "Cargo.toml", Content: content})
	if len(got) != 0 {
		t.Fatalf("expected 0 findings, got %d: %+v", len(got), got)
	}
}

// TestAIUsageManifestStillMatchesRealPackageNames is the other direction, and
// it is the one that stops the fix above from being a silent recall cut. Every
// case here is a real dependency line from a real ecosystem.
func TestAIUsageManifestStillMatchesRealPackageNames(t *testing.T) {
	for _, tc := range []struct {
		path, line, provider string
	}{
		{"requirements.txt", "openai==1.50.0", "openai"},
		{"requirements.txt", "anthropic==0.40.0", "anthropic"},
		{"requirements.txt", "langchain-openai==0.2.0", "openai"},
		{"go.mod", "\tgithub.com/sashabaranov/go-openai v1.32.0", "openai"},
		{"go.mod", "\tgithub.com/anthropics/anthropic-sdk-go v0.2.0", "anthropic"},
		{"package.json", "    \"@anthropic-ai/sdk\": \"^0.30.0\"", "anthropic"},
		{"requirements.txt", "huggingface_hub==0.26.0", "huggingface"},
		{"requirements.txt", "mistralai==1.2.0", "mistral"},
	} {
		got := NewAIUsage().Detect(scan.File{Path: tc.path, Content: []byte(tc.line + "\n")})
		if len(got) == 0 {
			t.Errorf("%s: %q produced no finding, want provider %q", tc.path, tc.line, tc.provider)
			continue
		}
		found := false
		for _, f := range got {
			if f.Tags["qryx.ai.provider"] == tc.provider {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: %q named no %q provider, got %+v", tc.path, tc.line, tc.provider, got)
		}
	}
}

// TestAIUsageMavenManifest covers the pom.xml path, which was reachable by
// any Java operator and exercised by nothing: pom.xml is in aiManifestBases,
// so a scan walks it, and three separate branches were carried by no test at
// all. Its comment syntax spans lines, so comments are deliberately left in
// place rather than half-stripped, and the ecosystem tag it produces is the
// one a reader sees in the label.
func TestAIUsageMavenManifest(t *testing.T) {
	content := []byte("<project>\n  <dependency>\n    <artifactId>openai-java</artifactId>\n  </dependency>\n</project>\n")
	got := NewAIUsage().Detect(scan.File{Path: "pom.xml", Content: content})
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(got), got)
	}
	if got[0].Asset.Algorithm != "OpenAI SDK (Java)" {
		t.Errorf("label = %q, want \"OpenAI SDK (Java)\"", got[0].Asset.Algorithm)
	}
	if p := got[0].Tags["qryx.ai.provider"]; p != "openai" {
		t.Errorf("provider = %q, want openai", p)
	}
}

// TestAIUsageLabelWithItsOwnParentheticalKeepsIt pins withEcosystem's early
// return. A label that already names something more specific than the
// language must not collect a second, clashing bracket.
func TestAIUsageLabelWithItsOwnParentheticalKeepsIt(t *testing.T) {
	got := NewAIUsage().Detect(scan.File{
		Path:    "requirements.txt",
		Content: []byte("google-generativeai==0.8.0\n"),
	})
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	if want := "Google Generative AI SDK (Gemini)"; got[0].Asset.Algorithm != want {
		t.Errorf("label = %q, want %q", got[0].Asset.Algorithm, want)
	}
}

// TestIndexAsTokenGuards holds the boundary rule directly, including the
// empty needle, which no table row can produce and which would loop forever
// on strings.Index if the guard were dropped.
func TestIndexAsTokenGuards(t *testing.T) {
	for _, tc := range []struct {
		hay, needle string
		want        int
	}{
		{"anything at all", "", -1},
		{"a raft-replicated ledger", "replicate", -1},
		{"replicated then replicate", "replicate", 16},
		{"go-openai v1.32.0", "openai", 3},
		{"openai==1.50.0", "openai", 0},
		{"langchain_openai", "langchain", 0},
		{"myopenaiclient", "openai", -1},
	} {
		if got := indexAsToken(tc.hay, tc.needle); got != tc.want {
			t.Errorf("indexAsToken(%q, %q) = %d, want %d", tc.hay, tc.needle, got, tc.want)
		}
	}
}
