package cli

import (
	"reflect"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/engine"
)

// A matcher that returned no data must leave a line in the text report. The
// progress stream carries the same warning only on a terminal, so a CI log of
// a scan with a missing vulnerability database read as a clean scan.
func TestPipelineWarningNoticesNameTheSourceAndDeduplicate(t *testing.T) {
	warnings := []engine.PipelineWarning{
		{Source: "grype", Message: "grype vulnerability DB unavailable: database does not exist"},
		{Source: "grype", Message: "grype vulnerability DB unavailable: database does not exist"},
		{Source: "osv", Message: "osv batch query:\nconnection refused\x1b[31m"},
		{Source: "", Message: "   "},
	}
	got := pipelineWarningNotices(warnings)
	want := []string{
		"grype: grype vulnerability DB unavailable: database does not exist",
		"osv: osv batch query: connection refused",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("notices = %#v, want %#v", got, want)
	}
	if got := pipelineWarningNotices(nil); got != nil {
		t.Fatalf("expected nil for no warnings, got %#v", got)
	}
}
