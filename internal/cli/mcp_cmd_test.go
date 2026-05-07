package cli

import "testing"

func TestApplyStringOverride(t *testing.T) {
	value := "original"
	applyStringOverride(&value, "")
	if value != "original" {
		t.Fatalf("empty override changed value to %q", value)
	}

	applyStringOverride(&value, "updated")
	if value != "updated" {
		t.Fatalf("expected updated value, got %q", value)
	}
}
