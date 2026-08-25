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
		{"bedrock endpoint", "cfg.yaml", "host: bedrock-runtime.eu-west-1.amazonaws.com\n", "bedrock", "provider"},
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

// providersFound collects the distinct provider id -> label pairs one file
// produced. Most of the Azure and Vertex cases below assert on this shape
// rather than on a finding count, because the question they ask is never "is
// there a row" but "is there a row naming a provider the bytes never leave
// for".
func providersFound(t *testing.T, path, content string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, f := range NewAIUsage().Detect(scan.File{Path: path, Content: []byte(content)}) {
		out[f.Tags["qryx.ai.provider"]] = f.Asset.Algorithm
	}
	return out
}

// TestAIUsageAzureOpenAIIsNotOpenAI is the false attribution this change was
// written for, and it was live: a package.json depending on "@azure/openai"
// was reported as provider "openai", because the "openai" needle matches
// inside "@azure/openai" ("/" is a legal token boundary, and it has to be, it
// is how scoped packages are spelled).
//
// It is the worst shape an inventory can produce. The row is not empty and it
// is not obviously wrong: it names a real provider, with a real file and line,
// for a tree that has never sent a byte to OpenAI. A consumer joining on the
// id reports the passport as declaring a provider it does not use, and a
// reader has no way to tell that from real drift. Where the bytes go is the
// whole question: through Azure they go to Microsoft (agent-passport SPEC
// 4.7).
func TestAIUsageAzureOpenAIIsNotOpenAI(t *testing.T) {
	got := providersFound(t, "package.json", `{"dependencies":{"@azure/openai":"^2.0.0"}}`)
	if _, wrong := got["openai"]; wrong {
		t.Errorf("named openai for a dependency whose bytes go to Microsoft: %+v", got)
	}
	if label, ok := got["azure-openai"]; !ok {
		t.Errorf("no azure-openai row, got %+v", got)
	} else if label != "Azure OpenAI SDK (JS/TS)" {
		t.Errorf("label = %q, want %q", label, "Azure OpenAI SDK (JS/TS)")
	}
	if len(got) != 1 {
		t.Errorf("expected exactly one provider, got %+v", got)
	}
}

// TestAIUsageManifestSpecificityKeepsBothRealDependencies is the other
// direction of the specificity rule, and it is the one that stops the fix
// above from being a silent recall cut. A tree really can depend on both, and
// then both rows are true. Both orderings are here on purpose: the shorter
// needle's FIRST occurrence is the one inside the longer package name when
// "@azure/openai" is listed first, so a rule that looked only at the first
// match would drop a dependency that is really there.
func TestAIUsageManifestSpecificityKeepsBothRealDependencies(t *testing.T) {
	for _, content := range []string{
		`{"dependencies":{"openai":"^4.50.0","@azure/openai":"^2.0.0"}}`,
		`{"dependencies":{"@azure/openai":"^2.0.0","openai":"^4.50.0"}}`,
	} {
		got := providersFound(t, "package.json", content)
		if _, ok := got["openai"]; !ok {
			t.Errorf("%s: lost the real openai dependency: %+v", content, got)
		}
		if _, ok := got["azure-openai"]; !ok {
			t.Errorf("%s: no azure-openai row: %+v", content, got)
		}
	}
}

// TestAIUsageAzureAndVertexManifestNeedles pins the manifest half of the two
// new ids. Every line here is how the ecosystem actually spells the
// dependency.
func TestAIUsageAzureAndVertexManifestNeedles(t *testing.T) {
	for _, tc := range []struct {
		path, line, provider, label string
	}{
		{"package.json", `    "@azure/openai": "^2.0.0"`, "azure-openai", "Azure OpenAI SDK (JS/TS)"},
		{"requirements.txt", "azure-ai-inference==1.0.0b9", "azure-openai", "Azure AI Inference SDK (python)"},
		{"requirements.txt", "azure-ai-projects==1.0.0b5", "azure-openai", "Azure AI Projects SDK (python)"},
		{"requirements.txt", "google-cloud-aiplatform==1.60.0", "vertex", "Google Vertex AI SDK (python)"},
		{"requirements.txt", "vertexai==1.60.0", "vertex", "Google Vertex AI SDK (python)"},
		{"package.json", `    "@google-cloud/vertexai": "^1.9.0"`, "vertex", "Google Vertex AI SDK (JS/TS)"},
		{"go.mod", "\tcloud.google.com/go/vertexai v0.12.0", "vertex", "Google Vertex AI SDK (Go)"},
	} {
		got := providersFound(t, tc.path, tc.line+"\n")
		label, ok := got[tc.provider]
		if !ok {
			t.Errorf("%s: %q named no %q provider, got %+v", tc.path, tc.line, tc.provider, got)
			continue
		}
		if label != tc.label {
			t.Errorf("%s: %q label = %q, want %q", tc.path, tc.line, label, tc.label)
		}
		if len(got) != 1 {
			t.Errorf("%s: %q named more than one provider: %+v", tc.path, tc.line, got)
		}
	}
}

// TestAIUsagePythonAzureOpenAIImportNamesAzureOnly covers how Azure users
// actually write it: the class comes from the openai package, so the only
// text naming Azure on the line is the class name. Without the specificity
// rule the same line produces an openai row too, which is the same false
// attribution as the manifest case and just as live.
//
// The second case is the boundary: a tree that imports the module and then
// builds an Azure client is reaching both spellings, and both rows are true.
func TestAIUsagePythonAzureOpenAIImportNamesAzureOnly(t *testing.T) {
	got := providersFound(t, "agent.py", "from openai import AzureOpenAI\n")
	if _, wrong := got["openai"]; wrong {
		t.Errorf("named openai for a client that talks to Microsoft: %+v", got)
	}
	if label := got["azure-openai"]; label != "Azure OpenAI SDK (python)" {
		t.Errorf("azure-openai label = %q, want %q (got %+v)", label, "Azure OpenAI SDK (python)", got)
	}

	both := providersFound(t, "agent.py", "import openai\n\nclient = openai.AzureOpenAI()\n")
	if _, ok := both["openai"]; !ok {
		t.Errorf("the plain module import is real evidence and must stay: %+v", both)
	}
	if _, ok := both["azure-openai"]; !ok {
		t.Errorf("openai.AzureOpenAI names Azure and must be reported: %+v", both)
	}
}

// TestAIUsageJSAzureImportNamesAzureOnly is the same question asked of the
// JS/TS table, and the answer there is different: jsImportPattern anchors the
// package name to immediately after the opening quote, so "openai" never
// matches inside `from "@azure/openai"` in the first place. This test is here
// to hold that property rather than to fix it, because it is held today by one
// line of jsImportPattern that a later edit could relax without noticing.
func TestAIUsageJSAzureImportNamesAzureOnly(t *testing.T) {
	for _, src := range []string{
		"import { AzureOpenAI } from \"@azure/openai\";\n",
		"const { AzureOpenAI } = require('@azure/openai');\n",
	} {
		got := providersFound(t, "route.ts", src)
		if _, wrong := got["openai"]; wrong {
			t.Errorf("%q: named openai, got %+v", src, got)
		}
		if _, ok := got["azure-openai"]; !ok {
			t.Errorf("%q: no azure-openai row, got %+v", src, got)
		}
	}
}

// TestAIUsageAzureAndVertexSourceImports pins the import half of the two new
// ids across the three languages the detector reads.
func TestAIUsageAzureAndVertexSourceImports(t *testing.T) {
	for _, tc := range []struct {
		path, src, provider string
	}{
		{"a.py", "from azure.ai.inference import ChatCompletionsClient\n", "azure-openai"},
		{"a.py", "from azure.ai.projects import AIProjectClient\n", "azure-openai"},
		{"a.py", "import vertexai\n", "vertex"},
		{"a.py", "from vertexai.generative_models import GenerativeModel\n", "vertex"},
		{"a.py", "import google.cloud.aiplatform\n", "vertex"},
		// The spelling Vertex code actually uses, which a module-name
		// pattern alone would miss.
		{"a.py", "from google.cloud import aiplatform\n", "vertex"},
		{"route.ts", "import { AzureOpenAI } from \"@azure/openai\";\n", "azure-openai"},
		{"route.ts", "import ModelClient from \"@azure-rest/ai-inference\";\n", "azure-openai"},
		{"route.ts", "import { VertexAI } from \"@google-cloud/vertexai\";\n", "vertex"},
		{"client.go", "\t\"cloud.google.com/go/vertexai/genai\"\n", "vertex"},
		{"client.go", "\taiplatform \"cloud.google.com/go/aiplatform/apiv1\"\n", "vertex"},
	} {
		got := providersFound(t, tc.path, tc.src)
		if _, ok := got[tc.provider]; !ok {
			t.Errorf("%s: %q named no %q provider, got %+v", tc.path, tc.src, tc.provider, got)
		}
	}
}

// TestAIUsageEndpointLiteralNamesExactlyOneProvider asks the containment
// question of the endpoint table, for every row in it rather than only the new
// ones. An endpoint literal is a full hostname anchored by dots on both sides
// of each label, so one host matching two rows would take a deliberate
// coincidence: this is the test that says so instead of assuming it.
func TestAIUsageEndpointLiteralNamesExactlyOneProvider(t *testing.T) {
	for _, tc := range []struct{ host, provider string }{
		{"https://api.openai.com/v1", "openai"},
		{"https://api.anthropic.com/v1/messages", "anthropic"},
		{"https://generativelanguage.googleapis.com/v1beta", "google"},
		{"bedrock-runtime.us-east-1.amazonaws.com", "bedrock"},
		{"https://api.mistral.ai/v1", "mistral"},
		{"https://api.cohere.com/v1", "cohere"},
		{"https://api.groq.com/openai/v1", "groq"},
		{"https://api.together.xyz/v1", "together"},
		{"https://openrouter.ai/api/v1", "openrouter"},
		{"https://api.perplexity.ai", "perplexity"},
		{"https://api.replicate.com/v1", "replicate"},
		// The four new ones, in the shapes Azure and Google Cloud hand an
		// operator. The Azure OpenAI one carries "/openai/" in its path,
		// which is exactly the kind of coincidence this test exists to catch.
		{"https://my-res.openai.azure.com/openai/deployments/gpt-4o/chat/completions", "azure-openai"},
		{"https://my-res.cognitiveservices.azure.com/", "azure-openai"},
		{"https://my-proj.services.ai.azure.com/models", "azure-openai"},
		{"https://us-central1-aiplatform.googleapis.com/v1/projects/p/locations/l", "vertex"},
	} {
		got := providersFound(t, "conf.txt", "url = \""+tc.host+"\"\n")
		if _, ok := got[tc.provider]; !ok {
			t.Errorf("%q named no %q provider, got %+v", tc.host, tc.provider, got)
			continue
		}
		if len(got) != 1 {
			t.Errorf("%q named more than one provider: %+v", tc.host, got)
		}
	}
}

// TestAIUsagePythonDottedModuleImports covers a defect that predates the
// Azure and Vertex rows and would have been copied straight into them: the
// google rows passed pyImport a module name with the dots ALREADY escaped, and
// pyImport quotes what it is given, so the backslash was quoted too. The
// compiled pattern demanded a literal backslash in the source and matched
// nothing any Python file has ever contained. Two rows of the table were dead
// and every gate was green, because nothing scanned a file that imported them.
func TestAIUsagePythonDottedModuleImports(t *testing.T) {
	for _, tc := range []struct{ src, label string }{
		{"import google.generativeai as genai\n", "Google Generative AI SDK (python, Gemini)"},
		{"from google.generativeai import GenerativeModel\n", "Google Generative AI SDK (python, Gemini)"},
		{"from google.genai import types\n", "Google GenAI SDK (python, Gemini)"},
	} {
		got := providersFound(t, "a.py", tc.src)
		if label := got["google"]; label != tc.label {
			t.Errorf("%q: google label = %q, want %q (got %+v)", tc.src, label, tc.label, got)
		}
	}
	// And the boundary the escaping was there to hold in the first place: a
	// dot is a dot, not "any character".
	if got := providersFound(t, "a.py", "import googleXgenerativeai\n"); len(got) != 0 {
		t.Errorf("a dot matched a letter: %+v", got)
	}
}

// TestAISpanContainment holds the rule directly, including the case the
// length comparison exists for: two rows that match exactly the same bytes are
// not a specificity question, and neither may silence the other.
func TestAISpanContainment(t *testing.T) {
	for _, tc := range []struct {
		name  string
		outer aiSpan
		inner aiSpan
		want  bool
	}{
		{"strictly inside", aiSpan{0, 13}, aiSpan{7, 13}, true},
		{"same start, longer", aiSpan{0, 13}, aiSpan{0, 6}, true},
		{"identical spans", aiSpan{0, 6}, aiSpan{0, 6}, false},
		{"disjoint", aiSpan{0, 6}, aiSpan{10, 16}, false},
		{"overlapping but not contained", aiSpan{0, 10}, aiSpan{5, 15}, false},
		{"inner is the longer one", aiSpan{7, 13}, aiSpan{0, 13}, false},
	} {
		if got := tc.outer.contains(tc.inner); got != tc.want {
			t.Errorf("%s: %+v.contains(%+v) = %v, want %v", tc.name, tc.outer, tc.inner, got, tc.want)
		}
	}
}

// TestProviderIdsAreTheRegisteredOnes pins the whole vocabulary this detector
// emits, rather than only the row that was wrong.
//
// The ids are a join key: another product correlates them against a Passport's
// declared provider and against an observed egress host, and agent-passport
// SPEC 4.7 is where the agreed spelling lives. A misspelling here is not a
// cosmetic defect. It reports a provider as undeclared on a passport that
// declares it, and the reader has no way to tell that from real drift.
//
// This test cannot read that SPEC: it is another repository, and the sentence
// this comment is in is the only thing tying the two together. What it does
// instead is make the vocabulary visible in one place, so adding a provider is
// a deliberate edit to a list somebody has to look at, rather than one more
// row appended to a table of forty.
func TestProviderIdsAreTheRegisteredOnes(t *testing.T) {
	// agent-passport SPEC 4.7, as of 2026-08-25. Ids are appended there, never
	// renamed, so a value dropping off this list means a row was renamed here
	// and not there.
	//
	// azure-openai and vertex arrived with SPEC 4.7's PR #39, and they are the
	// clearest statement of what the rule means: an id names the API surface
	// the bytes leave for, so the same model is azure-openai through Azure and
	// vertex through Vertex, never openai and never google.
	registered := map[string]bool{
		"anthropic": true, "openai": true, "azure-openai": true,
		"google": true, "vertex": true, "bedrock": true,
		"mistral": true, "cohere": true, "groq": true, "together": true,
		"perplexity": true, "replicate": true, "openrouter": true,
		"huggingface": true, "ollama": true,
	}

	seen := map[string]bool{}
	check := func(where, provider, role string) {
		if provider == "" {
			// A framework or a local runtime names no provider, and that is
			// the design: see roleFramework.
			return
		}
		seen[provider] = true
		if !registered[provider] {
			t.Errorf("%s: provider %q is not registered in agent-passport SPEC 4.7", where, provider)
		}
	}
	for _, n := range aiManifestNeedles {
		check("aiManifestNeedles", n.provider, n.role)
	}
	for ext, pats := range aiImportPatterns {
		for _, p := range pats {
			check("aiImportPatterns"+ext, p.provider, p.role)
		}
	}
	for _, e := range aiEndpoints {
		check("aiEndpoints", e.provider, e.role)
	}
	if len(seen) == 0 {
		t.Fatal("walked no provider at all: this test measured nothing")
	}
}
