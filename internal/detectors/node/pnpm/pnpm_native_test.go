package pnpm

import (
	"reflect"
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestPNPMListArgsScopeFilter(t *testing.T) {
	tests := []struct {
		name  string
		scope sdk.Scope
		want  []string
	}{
		{
			name:  "unknown resolves full graph",
			scope: sdk.ScopeUnknown,
			want:  []string{"list", "--json", "--depth", "Infinity"},
		},
		{
			name:  "runtime uses production graph",
			scope: sdk.ScopeRuntime,
			want:  []string{"list", "--json", "--depth", "Infinity", "--prod"},
		},
		{
			name:  "development uses development graph",
			scope: sdk.ScopeDevelopment,
			want:  []string{"list", "--json", "--depth", "Infinity", "--dev"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := pnpmListArgs(tt.scope); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("pnpmListArgs() = %#v, want %#v", got, tt.want)
			}
		})
	}
}
