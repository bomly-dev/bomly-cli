package sdk

import "strings"

// Language identifies the programming language used by a package or analyzed
// by a code analyzer. Languages are coarse-grained and ecosystem-agnostic;
// one PackageManager can carry multiple languages (e.g. Maven covers Java,
// Kotlin, Scala, and Groovy).
type Language string

const (
	LanguageUnknown    Language = ""
	LanguageGo         Language = "go"
	LanguageJavaScript Language = "javascript"
	LanguageTypeScript Language = "typescript"
	LanguagePython     Language = "python"
	LanguageJava       Language = "java"
	LanguageKotlin     Language = "kotlin"
	LanguageScala      Language = "scala"
	LanguageGroovy     Language = "groovy"
	LanguageRuby       Language = "ruby"
	LanguagePHP        Language = "php"
	LanguageRust       Language = "rust"
	LanguageCSharp     Language = "csharp"
	LanguageFSharp     Language = "fsharp"
	LanguageVB         Language = "vb"
	LanguageSwift      Language = "swift"
	LanguageObjC       Language = "objective-c"
	LanguageDart       Language = "dart"
	LanguageElixir     Language = "elixir"
	LanguageErlang     Language = "erlang"
	LanguageHaskell    Language = "haskell"
	LanguageOCaml      Language = "ocaml"
	LanguageLua        Language = "lua"
	LanguageR          Language = "r"
	LanguageC          Language = "c"
	LanguageCPP        Language = "cpp"
)

var languageAliases = map[string]Language{
	"":            LanguageUnknown,
	"go":          LanguageGo,
	"golang":      LanguageGo,
	"js":          LanguageJavaScript,
	"javascript":  LanguageJavaScript,
	"node":        LanguageJavaScript,
	"nodejs":      LanguageJavaScript,
	"ts":          LanguageTypeScript,
	"typescript":  LanguageTypeScript,
	"py":          LanguagePython,
	"python":      LanguagePython,
	"python3":     LanguagePython,
	"java":        LanguageJava,
	"kotlin":      LanguageKotlin,
	"kt":          LanguageKotlin,
	"scala":       LanguageScala,
	"groovy":      LanguageGroovy,
	"ruby":        LanguageRuby,
	"rb":          LanguageRuby,
	"php":         LanguagePHP,
	"rust":        LanguageRust,
	"rs":          LanguageRust,
	"csharp":      LanguageCSharp,
	"c#":          LanguageCSharp,
	"cs":          LanguageCSharp,
	"fsharp":      LanguageFSharp,
	"f#":          LanguageFSharp,
	"vb":          LanguageVB,
	"vbnet":       LanguageVB,
	"vb.net":      LanguageVB,
	"swift":       LanguageSwift,
	"objective-c": LanguageObjC,
	"objectivec":  LanguageObjC,
	"objc":        LanguageObjC,
	"dart":        LanguageDart,
	"elixir":      LanguageElixir,
	"erlang":      LanguageErlang,
	"haskell":     LanguageHaskell,
	"hs":          LanguageHaskell,
	"ocaml":       LanguageOCaml,
	"lua":         LanguageLua,
	"r":           LanguageR,
	"c":           LanguageC,
	"cpp":         LanguageCPP,
	"c++":         LanguageCPP,
}

// ParseLanguage normalizes a string into a Language. Returns LanguageUnknown
// for unrecognized values; callers that need strict validation should compare
// the result against LanguageUnknown for non-empty input.
func ParseLanguage(value string) Language {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if l, ok := languageAliases[normalized]; ok {
		return l
	}
	return LanguageUnknown
}

// LanguageFromPackage returns the most specific language for a package. It
// prefers the package's own Language field, then falls back to the primary
// language declared by the package's PackageManager (if recognizable), and
// finally returns LanguageUnknown.
func LanguageFromPackage(p Package) Language {
	if p.Language != LanguageUnknown {
		return p.Language
	}
	if p.PackageManager != PackageManagerUnknown {
		langs := p.PackageManager.Languages()
		if len(langs) > 0 {
			return langs[0]
		}
	}
	return LanguageUnknown
}
