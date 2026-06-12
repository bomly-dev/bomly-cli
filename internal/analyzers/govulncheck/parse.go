package govulncheck

import (
	"bufio"
	"encoding/json"
	"strings"

	model "github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

// govulncheck -json emits a stream of single-key envelopes. Each line is
// one JSON object; we only consume the keys we need.
//
//	{"config":   {...}}
//	{"progress": {...}}
//	{"osv":      {"id": "GO-...", "aliases": [...], ...}}
//	{"finding":  {"osv": "GO-...", "fixed_version": "v...", "trace": [...]}}
//
// The parser deliberately tolerates unknown keys for forward-compat with
// future govulncheck output extensions.
type envelope struct {
	OSV     *osvEntry     `json:"osv,omitempty"`
	Finding *findingEntry `json:"finding,omitempty"`
}

type osvEntry struct {
	ID      string   `json:"id"`
	Aliases []string `json:"aliases,omitempty"`
	Summary string   `json:"summary,omitempty"`
}

type findingEntry struct {
	OSV          string       `json:"osv"`
	FixedVersion string       `json:"fixed_version,omitempty"`
	Trace        []traceEntry `json:"trace,omitempty"`
}

type traceEntry struct {
	Module   string    `json:"module,omitempty"`
	Version  string    `json:"version,omitempty"`
	Package  string    `json:"package,omitempty"`
	Function string    `json:"function,omitempty"`
	Receiver string    `json:"receiver,omitempty"`
	Position *position `json:"position,omitempty"`
}

type position struct {
	Filename string `json:"filename,omitempty"`
	Line     int    `json:"line,omitempty"`
	Column   int    `json:"column,omitempty"`
}

// parseGovulncheckJSON consumes a stream of govulncheck JSON envelopes
// and returns a RunnerResult. Each Finding is keyed on its OSV id; the
// CallPaths slice carries one path per "trace" entry so consumers can
// reason about distinct evidence chains.
func parseGovulncheckJSON(data []byte) (RunnerResult, error) {
	result := RunnerResult{
		Findings:        make(map[string]Finding),
		ImportedModules: make(map[string]struct{}),
	}
	osvAliases := make(map[string][]string)
	osvSummaries := make(map[string]string)

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(make([]byte, 0, 64*1024), 10<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var env envelope
		if err := json.Unmarshal([]byte(line), &env); err != nil {
			// Skip malformed records rather than aborting the whole
			// parse — govulncheck occasionally emits records the
			// schema doesn't model and we don't want one bad envelope
			// to lose the rest.
			continue
		}
		if env.OSV != nil && env.OSV.ID != "" {
			osvAliases[env.OSV.ID] = append([]string(nil), env.OSV.Aliases...)
			if env.OSV.Summary != "" {
				osvSummaries[env.OSV.ID] = env.OSV.Summary
			}
		}
		if env.Finding == nil || env.Finding.OSV == "" {
			continue
		}
		mergeFinding(result.Findings, result.ImportedModules, *env.Finding)
	}
	if err := scanner.Err(); err != nil {
		return RunnerResult{}, err
	}

	for id, f := range result.Findings {
		f.Aliases = osvAliases[id]
		result.Findings[id] = f
	}
	return result, nil
}

func mergeFinding(into map[string]Finding, modules map[string]struct{}, src findingEntry) {
	current := into[src.OSV]
	current.OSV = src.OSV
	if src.FixedVersion != "" && current.FixedIn == "" {
		current.FixedIn = src.FixedVersion
	}

	if len(src.Trace) == 0 {
		// "Imported but not called" findings still record the module.
		current.ImportedBy = true
		into[src.OSV] = current
		return
	}

	// govulncheck trace order: index 0 is the entry frame (e.g. main.main);
	// the last frame is the call site of the vulnerable symbol.
	frames := make([]model.CallFrame, 0, len(src.Trace))
	for _, t := range src.Trace {
		if t.Module != "" {
			modules[t.Module] = struct{}{}
		}
		frames = append(frames, model.CallFrame{
			Function: t.Function,
			Package:  t.Package,
			Receiver: t.Receiver,
			Position: positionToSDK(t.Position),
		})
	}
	last := src.Trace[len(src.Trace)-1]
	current.CalledBy = true
	current.ImportedBy = true
	if last.Module != "" {
		current.Modules = appendUnique(current.Modules, last.Module)
	}
	sym := model.AffectedSymbol{
		Symbol:  last.Function,
		Kind:    symbolKind(last),
		Package: last.Package,
		Module:  last.Module,
	}
	current.Symbols = appendUniqueSymbol(current.Symbols, sym)
	current.CallPaths = append(current.CallPaths, model.CallPath{Sink: sym, Frames: frames})
	into[src.OSV] = current
}

func positionToSDK(p *position) model.SourcePosition {
	if p == nil {
		return model.SourcePosition{}
	}
	return model.SourcePosition{File: p.Filename, Line: p.Line, Column: p.Column}
}

func symbolKind(t traceEntry) model.SymbolKind {
	if t.Receiver != "" {
		return model.SymbolKindMethod
	}
	if t.Function != "" {
		return model.SymbolKindFunction
	}
	return ""
}

func appendUnique(values []string, candidate string) []string {
	for _, v := range values {
		if v == candidate {
			return values
		}
	}
	return append(values, candidate)
}

func appendUniqueSymbol(symbols []model.AffectedSymbol, candidate model.AffectedSymbol) []model.AffectedSymbol {
	for _, s := range symbols {
		if s.Symbol == candidate.Symbol && s.Package == candidate.Package && s.Kind == candidate.Kind {
			return symbols
		}
	}
	return append(symbols, candidate)
}

func ensureLogger(l *zap.Logger) *zap.Logger {
	if l != nil {
		return l
	}
	return zap.NewNop()
}
