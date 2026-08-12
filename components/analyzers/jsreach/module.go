package jsreach

import (
	"context"

	sdk "github.com/bomly-dev/bomly-sdk"
)

// Module returns the jsreach analyzer as an execution-neutral sdk.Module.
// The Bomly CLI composition embeds it directly; the same value could back a
// managed plugin binary via sdk.ServeModule.
func Module() sdk.Module {
	return sdk.Module{Kind: sdk.PluginKindAnalyzer, Analyzer: &sdk.AnalyzerModule{
		Descriptor: Analyzer{}.Descriptor(),
		New: func(_ context.Context, host sdk.HostContext) (sdk.Analyzer, error) {
			return Analyzer{Logger: host.Logger()}, nil
		},
	}}
}
