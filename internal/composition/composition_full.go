//go:build !bomly_external_syft && !bomly_external_grype

package composition

import (
	"context"

	grype "github.com/bomly-dev/bomly-plugin-grype-matcher/plugin"
	"github.com/bomly-dev/bomly-sdk"
)

// grypeEntry composes the grype matcher for the full build: the matcher runs
// against the builtin (vendored) Grype libraries.
func grypeEntry() Entry {
	return Entry{
		Name:           "grype",
		Kind:           sdk.PluginKindMatcher,
		Implementation: ImplementationNative,
		DefaultEnabled: true,
		Module: func(deps Deps) sdk.Module {
			return sdk.Module{Kind: sdk.PluginKindMatcher, Matcher: &sdk.MatcherModule{
				Descriptor: sdk.MatcherDescriptor{Name: "grype", DisplayName: "Grype"},
				New: func(_ context.Context, _ sdk.HostContext) (sdk.Matcher, error) {
					return grype.Matcher{Logger: deps.logger()}, nil
				},
			}}
		},
	}
}
