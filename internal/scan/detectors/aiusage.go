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
	needle   string
	label    string
	provider string
	role     string
}

// The role a matched row plays, which is orthogonal to where it was found.
// A row is matched in a manifest, in an import, or as an endpoint literal,
// and that is evidence; the role is what the matched thing IS, and only the
// role decides whether a provider can be named at all.
//
// roleFramework is the one worth understanding, because its provider is
// deliberately empty and that emptiness is a fact rather than missing data.
// Code reaching a model through LangChain or LiteLLM tells an inventory that
// the tree reaches one and refuses to tell it which: the provider is chosen
// at runtime, by configuration this detector cannot read. Filling it in with
// a guess would put a name into an inventory that no evidence supports, and
// leaving the row out entirely would hide the reach. So it is reported with
// the provider open, which is the only honest answer and is exactly the
// indirection limit the package comment already declares.
//
// roleLocalRuntime is the other case where a hosted provider is the wrong
// answer: weights loaded in-process, or a model server on the operator's own
// machine. It matters to an inventory because nothing leaves.
const (
	roleProvider     = "provider"
	roleFramework    = "framework"
	roleLocalRuntime = "local-runtime"
)

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
	{"anthropic", "Anthropic SDK", "anthropic", roleProvider},
	{"openai", "OpenAI SDK", "openai", roleProvider},
	{"@ai-sdk/", "Vercel AI SDK", "", roleFramework},
	{"langgraph", "LangGraph", "", roleFramework},
	{"langchain", "LangChain", "", roleFramework},
	{"google-generativeai", "Google Generative AI SDK (Gemini)", "google", roleProvider},
	{"google-genai", "Google GenAI SDK (Gemini)", "google", roleProvider},
	{"cohere", "Cohere SDK", "cohere", roleProvider},
	{"mistralai", "Mistral AI SDK", "mistral", roleProvider},
	{"litellm", "LiteLLM", "", roleFramework},
	{"ollama", "Ollama client", "ollama", roleLocalRuntime},
	{"groq", "Groq SDK", "groq", roleProvider},
	{"together", "Together AI SDK", "together", roleProvider},
	{"replicate", "Replicate SDK", "replicate", roleProvider},
	{"huggingface_hub", "Hugging Face Hub client", "huggingface", roleProvider},
	// transformers is flagged cautiously: it is HuggingFace's local
	// model-runtime library (loads and runs weights in-process) as much as it
	// is an LLM-API client, so it is labeled as local inference rather than a
	// hosted LLM call.
	{"transformers", "local model runtime (transformers)", "", roleLocalRuntime},
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
	lower := strings.ToLower(string(stripManifestComments(base, f.Content)))
	var out []model.Finding
	for _, n := range aiManifestNeedles {
		idx := indexAsToken(lower, n.needle)
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
			Tags:     aiTags(n.provider, n.role),
		})
	}
	return out
}

// aiPattern binds a regex to the label it implies, mirroring cryptocall.go's
// pattern.
type aiPattern struct {
	re       *regexp.Regexp
	label    string
	provider string
	role     string
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
	{jsImportPattern("openai"), "OpenAI SDK (JS/TS)", "openai", roleProvider},
	{jsImportPattern("@anthropic-ai/sdk"), "Anthropic SDK (JS/TS)", "anthropic", roleProvider},
	{jsImportPattern("@ai-sdk/"), "Vercel AI SDK (JS/TS)", "", roleFramework},
	{jsImportPattern("@langchain/langgraph"), "LangGraph (JS/TS)", "", roleFramework},
	{jsImportPattern("langchain"), "LangChain (JS/TS)", "", roleFramework},
	{jsImportPattern("@google/generative-ai"), "Google Generative AI SDK (JS/TS, Gemini)", "google", roleProvider},
	{jsImportPattern("cohere-ai"), "Cohere SDK (JS/TS)", "cohere", roleProvider},
	{jsImportPattern("ollama"), "Ollama client (JS/TS)", "ollama", roleLocalRuntime},
	{jsImportPattern("groq-sdk"), "Groq SDK (JS/TS)", "groq", roleProvider},
	{jsImportPattern("together-ai"), "Together AI SDK (JS/TS)", "together", roleProvider},
	{jsImportPattern("replicate"), "Replicate SDK (JS/TS)", "replicate", roleProvider},
}

// aiImportPatterns maps a file extension to the LLM SDK import/call patterns
// checked for it. Go is included here (regex, not AST): this detector's own
// concern (an AI-SDK import path) is orthogonal to goast.go's crypto-package
// resolution, so it does not belong in that detector, and a full second
// import resolver is not justified for v1 (see the package doc comment).
var aiImportPatterns = map[string][]aiPattern{
	".py": {
		{pyImport("openai"), "OpenAI SDK (python)", "openai", roleProvider},
		{pyImport("anthropic"), "Anthropic SDK (python)", "anthropic", roleProvider},
		{pyImport("langgraph"), "LangGraph (python)", "", roleFramework},
		// No trailing \b: the modern LangChain ecosystem splits into
		// underscore-suffixed packages (langchain_openai, langchain_community,
		// langchain_core, ...) that a \b word-boundary would miss, since "_"
		// is itself a word character and so never creates a boundary right
		// after "langchain".
		{regexp.MustCompile(`\b(?:import|from)\s+langchain`), "LangChain (python)", "", roleFramework},
		{pyImport(`google\.generativeai`), "Google Generative AI SDK (python, Gemini)", "google", roleProvider},
		{pyImport(`google\.genai`), "Google GenAI SDK (python, Gemini)", "google", roleProvider},
		{pyImport("cohere"), "Cohere SDK (python)", "cohere", roleProvider},
		{pyImport("mistralai"), "Mistral AI SDK (python)", "mistral", roleProvider},
		{pyImport("litellm"), "LiteLLM (python)", "", roleFramework},
		{pyImport("ollama"), "Ollama client (python)", "ollama", roleLocalRuntime},
		{pyImport("groq"), "Groq SDK (python)", "groq", roleProvider},
		{pyImport("replicate"), "Replicate SDK (python)", "replicate", roleProvider},
		{pyImport("huggingface_hub"), "Hugging Face Hub client (python)", "huggingface", roleProvider},
		{pyImport("transformers"), "local model runtime (transformers, python)", "", roleLocalRuntime},
	},
	".js":  jsAIPatterns,
	".ts":  jsAIPatterns,
	".jsx": jsAIPatterns,
	".tsx": jsAIPatterns,
	".mjs": jsAIPatterns,
	".go": {
		{regexp.MustCompile(`github\.com/sashabaranov/go-openai`), "OpenAI SDK (Go)", "openai", roleProvider},
		{regexp.MustCompile(`github\.com/anthropics/anthropic-sdk-go`), "Anthropic SDK (Go)", "anthropic", roleProvider},
		{regexp.MustCompile(`github\.com/tmc/langchaingo`), "LangChain (Go)", "", roleFramework},
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
				Tags:     aiTags(p.provider, p.role),
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
	{regexp.MustCompile(`api\.openai\.com`), "OpenAI API endpoint", "openai", roleProvider},
	{regexp.MustCompile(`api\.anthropic\.com`), "Anthropic API endpoint", "anthropic", roleProvider},
	{regexp.MustCompile(`generativelanguage\.googleapis\.com`), "Google Generative Language API endpoint (Gemini)", "google", roleProvider},
	// Matches both the bare literal and the fuller
	// *.bedrock-runtime.*.amazonaws.com hostname, since the substring is
	// contained in both. This is the only Bedrock signal this detector uses;
	// boto3 alone is never flagged (see aiManifestNeedles).
	{regexp.MustCompile(`bedrock-runtime`), "AWS Bedrock", "bedrock", roleProvider},
	{regexp.MustCompile(`api\.mistral\.ai`), "Mistral AI API endpoint", "mistral", roleProvider},
	{regexp.MustCompile(`api\.cohere\.(?:ai|com)`), "Cohere API endpoint", "cohere", roleProvider},
	{regexp.MustCompile(`api\.groq\.com`), "Groq API endpoint", "groq", roleProvider},
	{regexp.MustCompile(`api\.together\.xyz`), "Together AI API endpoint", "together", roleProvider},
	// A router: the operator's data goes to OpenRouter, and which model
	// finally runs the prompt is chosen there rather than here. The provider
	// is the address the bytes leave for, which is the question an inventory
	// is asking.
	{regexp.MustCompile(`openrouter\.ai`), "OpenRouter API endpoint", "openrouter", roleProvider},
	{regexp.MustCompile(`api\.perplexity\.ai`), "Perplexity API endpoint", "perplexity", roleProvider},
	{regexp.MustCompile(`api\.replicate\.com`), "Replicate API endpoint", "replicate", roleProvider},
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
				Tags:     aiTags(e.provider, e.role),
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

// stripManifestComments blanks comment text in a dependency manifest, keeping
// every byte's position so a reported line number still points at the right line.
//
// A manifest is matched by substring, which is right for a dependency name and
// wrong for prose. A real `Cargo.toml` carrying the comment "pins the two
// independent token readers together" was reported as depending on the Together AI
// SDK, in a repository with no network dependencies at all. The needle list is full
// of ordinary English: `together`, `cohere`, `groq`, `replicate`, `transformers`.
func stripManifestComments(base string, content []byte) []byte {
	var marker string
	switch base {
	case "Cargo.toml", "requirements.txt", "go.mod":
		marker = "#"
	case "package.json":
		// Not valid JSON, but common enough in hand-edited manifests, and a
		// comment is never a dependency wherever it appears.
		marker = "//"
	default:
		// pom.xml uses <!-- --> which can span lines; left alone rather than
		// half-handled, since a wrong strip hides real dependencies.
		return content
	}

	out := make([]byte, len(content))
	copy(out, content)
	inComment := false
	for i := 0; i < len(out); i++ {
		switch {
		case out[i] == '\n':
			inComment = false
		case inComment:
			out[i] = ' '
		case !inComment && i+len(marker) <= len(out) && string(out[i:i+len(marker)]) == marker:
			inComment = true
			for k := i; k < i+len(marker); k++ {
				out[k] = ' '
			}
			i += len(marker) - 1
		}
	}
	return out
}

// aiTags carries the canonical provider and role onto the finding, so a
// consumer joining this inventory against a declaration or an observed
// egress has a key instead of a prose label to mangle. The keys are
// namespaced because Tags is shared with cloud connectors, where the map
// holds a resource's own tags: a provider's tag named "role" is not
// impossible, and a collision here would be silent.
//
// A framework's provider is empty and the key is still written, because a
// consumer must be able to tell "reaches a model through an indirection this
// scan cannot resolve" from "this row predates the vocabulary".
func aiTags(provider, role string) map[string]string {
	return map[string]string{
		"qryx.ai.provider": provider,
		"qryx.ai.role":     role,
	}
}

// AIUsageLimits is what this detector cannot see, in the words a reader of a
// report needs rather than a reader of this file. It is exported because the
// machine-readable inventory carries it in the document itself: an inventory
// read as proof of absence is the one way this detector's output can do harm,
// and a limit that lives only in a doc comment reaches nobody downstream.
//
// One owner, deliberately. The same sentences in the package comment above and
// again in a reporter would be two copies that drift, and the copy that leaves
// the building is the one that would rot.
var AIUsageLimits = []string{
	"Detection is text matching over source, so an import name built at runtime, an endpoint assembled from parts, or a call reached through an indirection the text does not name produces nothing here.",
	"A mention in code is not a call at runtime. This says the code can reach a provider, never that it did.",
	"A row whose role is framework names no provider on purpose: the choice is made by configuration this scan cannot read.",
	"Only files this scan walked are represented. A dependency vendored as a binary, or code outside the scanned path, is not.",
	"An empty result is not proof that a tree uses no AI.",
}

// indexAsToken finds needle in hay where it is not part of a longer word:
// no letter immediately before it, none immediately after. It returns -1
// when there is no such occurrence.
//
// A bare substring is the right shape for a manifest, because one needle has
// to cover "openai==1.50.0", a go.mod line reading
// "github.com/sashabaranov/go-openai" and a package.json key
// "@anthropic-ai/sdk", and demanding a package-name grammar per ecosystem
// would be five parsers for one question. What it must not do is match inside
// an English word, and manifests carry prose: "replicate" was found inside
// "raft-replicated", in a Cargo.toml description, and the row that came out
// named a provider the code has never called.
//
// Only letters bound it. A hyphen, an underscore, a slash, a quote, a digit
// and a line start all stay legal neighbours, because every one of them is
// how real package names are actually spelled.
func indexAsToken(hay, needle string) int {
	if needle == "" {
		return -1
	}
	for off := 0; ; {
		i := strings.Index(hay[off:], needle)
		if i < 0 {
			return -1
		}
		i += off
		beforeOK := i == 0 || !isASCIILetter(hay[i-1])
		end := i + len(needle)
		afterOK := end == len(hay) || !isASCIILetter(hay[end])
		if beforeOK && afterOK {
			return i
		}
		off = i + 1
	}
}

func isASCIILetter(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}
