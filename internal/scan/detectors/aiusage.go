package detectors

import (
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/TAIPANBOX/qryx/internal/model"
	"github.com/TAIPANBOX/qryx/internal/scan"
)

// AIUsage inventories an operator's OWN use of LLM/AI provider SDKs and
// endpoints across their OWN source tree: dependency-manifest entries,
// source-level imports/calls, and API endpoint literals. It is a defensive,
// self-inventory tool, the same posture as the rest of qryx's detectors
// applied to a new kind of asset, built so an operator can see and govern
// their own LLM usage (the EU AI Act code-inventory angle: knowing where your
// own systems talk to a model is a precondition for governing it). It is not,
// and must never become, a scanner of someone else's code or systems.
//
// Every finding here carries model.TypeAIModel, not a crypto AssetType, and
// an explicit informational Risk (see aiRisk below): this is an inventory
// fact, not a cryptographic weakness, and it must never masquerade as one:
// it does not trip --fail-on, --policy, or a CNSA/NCSC verdict. See
// model.AssetType.IsCryptographic and the reports that key on it
// (internal/report/cbom.go, cnsa.go, ncsc.go).
//
// Detection is regex-over-content across languages, mirroring cryptocall.go
// rather than goast.go's AST resolution. That is an honest v1 trade-off, not
// an oversight: it catches declared/imported usage and literal endpoint
// strings, but it cannot see a dynamically constructed import name, a
// runtime-built endpoint URL, or a call made through an indirection the text
// doesn't name. It also cannot prove an LLM call actually happens at runtime,
// only that the code mentions one. Runtime confirmation is a different
// source (idryx's eBPF network view) and a different, later correlation step;
// this detector's job is the static, code-side half of the inventory.
type AIUsage struct{}

func NewAIUsage() *AIUsage { return &AIUsage{} }

func (a *AIUsage) Name() string { return "aiusage" }

// aiRisk is asserted explicitly on every finding this detector produces,
// rather than left for risk.Apply/risk.Classify to fill in. Leaving it empty
// would happen to land on the same RiskNone/SeverityNone as any other
// algorithm string risk.Classify doesn't recognize, but that would be true by
// coincidence, not by design: a future baseline entry could theoretically
// collide with a real algorithm name. Asserting it here, with SeverityInfo
// specifically (not SeverityNone), documents the intent unambiguously: this
// is a governance/inventory fact, always informational, never a graded
// severity, and it reads that way in `human`/`html` output (SEVERITY column
// shows "info") without depending on what the risk baseline does or doesn't
// contain. RiskNone also means it is structurally exempt from --fail-on,
// --fail-on-new, and every --policy maxSeverity/forbid* rule, all of which
// gate on `Risk.Class != model.RiskNone` (see cmd/qryx/main.go and
// internal/policy/policy.go); this is not a coincidence either. RiskNone was
// chosen specifically because that gate already exists and is exercised by
// the rest of the codebase, rather than inventing a new RiskClass that every
// one of those call sites would have to be individually taught to exempt.
var aiRisk = model.Risk{
	Class:    model.RiskNone,
	Severity: model.SeverityInfo,
	Reason:   "AI/LLM usage inventory (EU AI Act code-inventory mapping): informational, not a cryptographic risk",
}

// aiManifestBases are dependency-manifest filenames scanned for LLM/AI SDK
// entries, the same set deps.go already scans for crypto libraries.
var aiManifestBases = map[string]bool{
	"go.mod": true, "requirements.txt": true, "package.json": true,
	"Cargo.toml": true, "pom.xml": true,
}

// aiSourceExts are extensions scanned for LLM SDK imports/calls and endpoint
// literals: common application source plus the config/text formats an
// operator might hardcode a provider endpoint into. Mirrors hardcoded.go's
// sourceExts, extended with a few plain config formats endpoints tend to live
// in (.toml/.cfg/.ini/.conf/.txt) that hardcoded.go has no reason to cover.
var aiSourceExts = map[string]bool{
	".go": true, ".py": true, ".js": true, ".ts": true, ".mjs": true,
	".jsx": true, ".tsx": true, ".rb": true, ".java": true, ".rs": true,
	".yaml": true, ".yml": true, ".json": true, ".env": true, ".toml": true,
	".cfg": true, ".ini": true, ".conf": true, ".txt": true,
}

func (a *AIUsage) Wants(path string) bool {
	if aiManifestBases[filepath.Base(path)] {
		return true
	}
	return aiSourceExts[filepath.Ext(path)]
}

// aiNeedle binds a dependency-manifest substring to the provider/SDK label it
// implies, mirroring deps.go's cryptoLibs.
type aiNeedle struct {
	needle string
	label  string
}

// aiManifestNeedles maps a manifest substring to a bare provider/SDK label
// (no ecosystem qualifier: see withEcosystem, which appends one based on
// which manifest file matched). One flat table covers every manifest type,
// like deps.go's cryptoLibs: a bare package name such as "openai" or
// "anthropic" is exactly as meaningful in requirements.txt, package.json, or a
// go.mod require line (e.g. github.com/sashabaranov/go-openai contains
// "openai"; github.com/anthropics/anthropic-sdk-go contains "anthropic"), so
// one needle per provider is enough; withEcosystem then labels which
// language it was found in.
//
// boto3 is deliberately NOT here: it is AWS's general-purpose SDK, not an LLM
// SDK, and flagging it alone would falsely imply every boto3 user calls an
// LLM. AWS Bedrock usage is instead detected via the "bedrock-runtime"
// endpoint literal (see aiEndpoints), which only fires for code that actually
// names the Bedrock runtime endpoint/client.
var aiManifestNeedles = []aiNeedle{
	{"anthropic", "Anthropic SDK"},
	{"openai", "OpenAI SDK"},
	{"@ai-sdk/", "Vercel AI SDK"},
	{"langgraph", "LangGraph"},
	{"langchain", "LangChain"},
	{"google-generativeai", "Google Generative AI SDK (Gemini)"},
	{"google-genai", "Google GenAI SDK (Gemini)"},
	{"cohere", "Cohere SDK"},
	{"mistralai", "Mistral AI SDK"},
	{"litellm", "LiteLLM"},
	{"ollama", "Ollama client"},
	{"groq", "Groq SDK"},
	{"together", "Together AI SDK"},
	{"replicate", "Replicate SDK"},
	{"huggingface_hub", "Hugging Face Hub client"},
	// transformers is flagged cautiously: it is HuggingFace's local
	// model-runtime library (loads and runs weights in-process) as much as it
	// is an LLM-API client, so it is labeled as local inference rather than a
	// hosted LLM call.
	{"transformers", "local model runtime (transformers)"},
}

// manifestEcosystem names the language/ecosystem a manifest basename implies,
// for labels like "OpenAI SDK (python)".
func manifestEcosystem(base string) string {
	switch base {
	case "requirements.txt":
		return "python"
	case "package.json":
		return "JS/TS"
	case "go.mod":
		return "Go"
	case "Cargo.toml":
		return "Rust"
	case "pom.xml":
		return "Java"
	default:
		return ""
	}
}

// withEcosystem appends the ecosystem implied by a manifest's basename to a
// bare label, e.g. "OpenAI SDK" + go.mod -> "OpenAI SDK (Go)". Labels that
// already carry their own parenthetical (e.g. "... (Gemini)",
// "... (transformers)") are left alone rather than getting a second, clashing
// one; the specific provider name they carry is more useful there than a
// generic ecosystem tag.
func withEcosystem(label, base string) string {
	eco := manifestEcosystem(base)
	if eco == "" || strings.HasSuffix(label, ")") {
		return label
	}
	return label + " (" + eco + ")"
}

// detectManifest scans a dependency manifest for LLM/AI SDK entries, mirroring
// deps.go's Detect: lowercase the whole file and look for each needle as a
// substring.
func (a *AIUsage) detectManifest(f scan.File) []model.Finding {
	base := filepath.Base(f.Path)
	if !aiManifestBases[base] {
		return nil
	}
	lower := strings.ToLower(string(f.Content))
	var out []model.Finding
	for _, n := range aiManifestNeedles {
		idx := strings.Index(lower, n.needle)
		if idx < 0 {
			continue
		}
		out = append(out, model.Finding{
			Asset: model.Asset{
				Type:      model.TypeAIModel,
				Algorithm: withEcosystem(n.label, base),
				Primitive: model.PrimitiveUnknown,
			},
			Location: model.Location{File: f.Path, Line: lineNumber(f.Content, idx)},
			Evidence: "depends on " + n.needle,
			Source:   a.Name(),
			Risk:     aiRisk,
		})
	}
	return out
}

// aiPattern binds a regex to the label it implies, mirroring cryptocall.go's
// pattern.
type aiPattern struct {
	re    *regexp.Regexp
	label string
}

// jsImportPattern builds a regex matching an ES module or CommonJS import of
// pkgPrefix, e.g. `import Anthropic from '@anthropic-ai/sdk'` or
// `require('openai')`. Anchoring the package name to right after the opening
// quote (rather than just searching for the bare string anywhere) keeps a
// scoped package like "@langchain/langgraph" from also matching a plainer
// "langchain" pattern registered alongside it.
func jsImportPattern(pkgPrefix string) *regexp.Regexp {
	q := regexp.QuoteMeta(pkgPrefix)
	return regexp.MustCompile(`(?:from\s+['"]` + q + `|require\(\s*['"]` + q + `)`)
}

// pyImport builds a regex matching a Python `import x` or `from x import y`
// for module x, requiring a word boundary after the module name so e.g.
// "openai" doesn't also match an unrelated "openaiwrapper".
func pyImport(module string) *regexp.Regexp {
	return regexp.MustCompile(`\b(?:import|from)\s+` + regexp.QuoteMeta(module) + `\b`)
}

var jsAIPatterns = []aiPattern{
	{jsImportPattern("openai"), "OpenAI SDK (JS/TS)"},
	{jsImportPattern("@anthropic-ai/sdk"), "Anthropic SDK (JS/TS)"},
	{jsImportPattern("@ai-sdk/"), "Vercel AI SDK (JS/TS)"},
	{jsImportPattern("@langchain/langgraph"), "LangGraph (JS/TS)"},
	{jsImportPattern("langchain"), "LangChain (JS/TS)"},
	{jsImportPattern("@google/generative-ai"), "Google Generative AI SDK (JS/TS, Gemini)"},
	{jsImportPattern("cohere-ai"), "Cohere SDK (JS/TS)"},
	{jsImportPattern("ollama"), "Ollama client (JS/TS)"},
	{jsImportPattern("groq-sdk"), "Groq SDK (JS/TS)"},
	{jsImportPattern("together-ai"), "Together AI SDK (JS/TS)"},
	{jsImportPattern("replicate"), "Replicate SDK (JS/TS)"},
}

// aiImportPatterns maps a file extension to the LLM SDK import/call patterns
// checked for it. Go is included here (regex, not AST): this detector's own
// concern (an AI-SDK import path) is orthogonal to goast.go's crypto-package
// resolution, so it does not belong in that detector, and a full second
// import resolver is not justified for v1 (see the package doc comment).
var aiImportPatterns = map[string][]aiPattern{
	".py": {
		{pyImport("openai"), "OpenAI SDK (python)"},
		{pyImport("anthropic"), "Anthropic SDK (python)"},
		{pyImport("langgraph"), "LangGraph (python)"},
		// No trailing \b: the modern LangChain ecosystem splits into
		// underscore-suffixed packages (langchain_openai, langchain_community,
		// langchain_core, ...) that a \b word-boundary would miss, since "_"
		// is itself a word character and so never creates a boundary right
		// after "langchain".
		{regexp.MustCompile(`\b(?:import|from)\s+langchain`), "LangChain (python)"},
		{pyImport(`google\.generativeai`), "Google Generative AI SDK (python, Gemini)"},
		{pyImport(`google\.genai`), "Google GenAI SDK (python, Gemini)"},
		{pyImport("cohere"), "Cohere SDK (python)"},
		{pyImport("mistralai"), "Mistral AI SDK (python)"},
		{pyImport("litellm"), "LiteLLM (python)"},
		{pyImport("ollama"), "Ollama client (python)"},
		{pyImport("groq"), "Groq SDK (python)"},
		{pyImport("replicate"), "Replicate SDK (python)"},
		{pyImport("huggingface_hub"), "Hugging Face Hub client (python)"},
		{pyImport("transformers"), "local model runtime (transformers, python)"},
	},
	".js":  jsAIPatterns,
	".ts":  jsAIPatterns,
	".jsx": jsAIPatterns,
	".tsx": jsAIPatterns,
	".mjs": jsAIPatterns,
	".go": {
		{regexp.MustCompile(`github\.com/sashabaranov/go-openai`), "OpenAI SDK (Go)"},
		{regexp.MustCompile(`github\.com/anthropics/anthropic-sdk-go`), "Anthropic SDK (Go)"},
		{regexp.MustCompile(`github\.com/tmc/langchaingo`), "LangChain (Go)"},
	},
}

// detectPatterns scans source for LLM SDK imports/calls via the per-extension
// regex table, mirroring cryptocall.go's Detect.
func (a *AIUsage) detectPatterns(f scan.File) []model.Finding {
	pats, ok := aiImportPatterns[filepath.Ext(f.Path)]
	if !ok {
		return nil
	}
	var out []model.Finding
	for _, p := range pats {
		for _, loc := range p.re.FindAllIndex(f.Content, -1) {
			out = append(out, model.Finding{
				Asset: model.Asset{
					Type:      model.TypeAIModel,
					Algorithm: p.label,
					Primitive: model.PrimitiveUnknown,
				},
				Location: model.Location{File: f.Path, Line: lineNumber(f.Content, loc[0])},
				Evidence: string(f.Content[loc[0]:loc[1]]),
				Source:   a.Name(),
				Risk:     aiRisk,
			})
		}
	}
	return out
}

// aiEndpoints are LLM provider API endpoint literals checked across any
// source this detector wants, regardless of extension: an operator can name
// an endpoint directly (a base-URL constant, an env default, a config file)
// without ever importing the matching SDK, e.g. calling a provider's
// OpenAI-compatible REST API straight from an http client.
var aiEndpoints = []aiPattern{
	{regexp.MustCompile(`api\.openai\.com`), "OpenAI API endpoint"},
	{regexp.MustCompile(`api\.anthropic\.com`), "Anthropic API endpoint"},
	{regexp.MustCompile(`generativelanguage\.googleapis\.com`), "Google Generative Language API endpoint (Gemini)"},
	// Matches both the bare literal and the fuller
	// *.bedrock-runtime.*.amazonaws.com hostname, since the substring is
	// contained in both. This is the only Bedrock signal this detector uses;
	// boto3 alone is never flagged (see aiManifestNeedles).
	{regexp.MustCompile(`bedrock-runtime`), "AWS Bedrock"},
	{regexp.MustCompile(`api\.mistral\.ai`), "Mistral AI API endpoint"},
	{regexp.MustCompile(`api\.cohere\.(?:ai|com)`), "Cohere API endpoint"},
	{regexp.MustCompile(`api\.groq\.com`), "Groq API endpoint"},
	{regexp.MustCompile(`api\.together\.xyz`), "Together AI API endpoint"},
	{regexp.MustCompile(`openrouter\.ai`), "OpenRouter API endpoint"},
	{regexp.MustCompile(`api\.perplexity\.ai`), "Perplexity API endpoint"},
	{regexp.MustCompile(`api\.replicate\.com`), "Replicate API endpoint"},
}

// detectEndpoints scans for LLM provider endpoint literals.
func (a *AIUsage) detectEndpoints(f scan.File) []model.Finding {
	var out []model.Finding
	for _, e := range aiEndpoints {
		for _, loc := range e.re.FindAllIndex(f.Content, -1) {
			out = append(out, model.Finding{
				Asset: model.Asset{
					Type:      model.TypeAIModel,
					Algorithm: e.label,
					Primitive: model.PrimitiveUnknown,
				},
				Location: model.Location{File: f.Path, Line: lineNumber(f.Content, loc[0])},
				Evidence: string(f.Content[loc[0]:loc[1]]),
				Source:   a.Name(),
				Risk:     aiRisk,
			})
		}
	}
	return out
}

func (a *AIUsage) Detect(f scan.File) []model.Finding {
	var out []model.Finding
	out = append(out, a.detectManifest(f)...)
	out = append(out, a.detectPatterns(f)...)
	out = append(out, a.detectEndpoints(f)...)
	return dedupeSameLine(out)
}

// dedupeSameLine collapses findings that share both algorithm label and line
// within the one file just scanned. The regex passes above use
// FindAllIndex, which reports every match on a line, not just the first: a
// line that names the same provider twice (`require('openai');
// require('openai');` in generated or copy-pasted code, or a config line
// listing an endpoint twice) otherwise produces two findings for one real
// occurrence. This is deliberately narrow: it only merges an exact
// (algorithm, line) repeat, so two distinct providers named on the same line,
// or the same provider named twice on different lines, are both still
// reported as separate findings/occurrences.
func dedupeSameLine(findings []model.Finding) []model.Finding {
	if len(findings) < 2 {
		return findings
	}
	seen := make(map[string]bool, len(findings))
	out := make([]model.Finding, 0, len(findings))
	for _, f := range findings {
		key := f.Asset.Algorithm + "@" + strconv.Itoa(f.Location.Line)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
	}
	return out
}
