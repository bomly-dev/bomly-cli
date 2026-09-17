package npm

import (
	"reflect"
	"testing"

	"github.com/bomly-dev/bomly-sdk/model"
)

func TestNPMListArgsScopeFilter(t *testing.T) {
	tests := []struct {
		name  string
		scope model.Scope
		want  []string
	}{
		{
			name:  "unknown resolves full graph",
			scope: model.ScopeUnknown,
			want:  []string{"ls", "--all", "--json", "--package-lock-only"},
		},
		{
			name:  "runtime omits dev dependencies",
			scope: model.ScopeRuntime,
			want:  []string{"ls", "--all", "--json", "--package-lock-only", "--omit=dev"},
		},
		{
			name:  "development resolves full graph for shared filtering",
			scope: model.ScopeDevelopment,
			want:  []string{"ls", "--all", "--json", "--package-lock-only"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := npmListArgs(tt.scope); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("npmListArgs() = %#v, want %#v", got, tt.want)
			}
		})
	}
}
