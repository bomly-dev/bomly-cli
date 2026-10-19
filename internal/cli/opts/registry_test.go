package opts

import (
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/config"
)

// TestRegistryConfigsGrypeDBUpdateSwitch pins that every spelling Validate
// accepts for matchers.grype.db_auto_update reaches the matcher with the same
// meaning: the switch is read once, here, with config.ParseBool.
func TestRegistryConfigsGrypeDBUpdateSwitch(t *testing.T) {
	cases := map[string]bool{
		"":      false,
		"true":  false,
		"yes":   false,
		"1":     false,
		"false": true,
		"off":   true,
		"no":    true,
		"0":     true,
		" OFF ": true,
	}
	for value, wantDisabled := range cases {
		got := RegistryConfigsFromResolved(config.Resolved{GrypeDBAutoUpdate: value})
		if got.GrypeDBUpdateDisabled != wantDisabled {
			t.Errorf("db_auto_update=%q: GrypeDBUpdateDisabled = %v, want %v", value, got.GrypeDBUpdateDisabled, wantDisabled)
		}
	}
}
