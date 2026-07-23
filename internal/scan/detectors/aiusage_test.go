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
