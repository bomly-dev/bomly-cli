package sdk

import "testing"

func TestParseFailOn(t *testing.T) {
	cases := []struct {
		in       string
		wantKind FailOnKind
		wantVal  string
		wantErr  bool
	}{
		{"low", SeverityConstraint, "low", false},
		{"HIGH", SeverityConstraint, "high", false},
		{" critical ", SeverityConstraint, "critical", false},
		{"any", SeverityConstraint, "any", false},
		{"reachable", ReachabilityConstraint, "reachable", false},
		{"REACHABLE", ReachabilityConstraint, "reachable", false},
		{"", "", "", false},
		{"bogus", "", "", true},
	}
	for _, tc := range cases {
		c, err := ParseFailOn(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ParseFailOn(%q): expected error, got nil", tc.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseFailOn(%q): unexpected error: %v", tc.in, err)
			continue
		}
		if c.Kind != tc.wantKind || c.Value != tc.wantVal {
			t.Errorf("ParseFailOn(%q) = {%q,%q}, want {%q,%q}", tc.in, c.Kind, c.Value, tc.wantKind, tc.wantVal)
		}
	}
}

func TestParseFailOnListSkipsEmptyAggregatesErrors(t *testing.T) {
	raw := []string{"low", "", "reachable", "bogus"}
	out, err := ParseFailOnList(raw)
	if err == nil {
		t.Fatal("expected error for bogus entry")
	}
	if len(out) != 2 {
		t.Fatalf("got %d valid constraints, want 2: %+v", len(out), out)
	}
	if out[0].Kind != SeverityConstraint || out[0].Value != "low" {
		t.Errorf("first constraint = %+v", out[0])
	}
	if out[1].Kind != ReachabilityConstraint || out[1].Value != "reachable" {
		t.Errorf("second constraint = %+v", out[1])
	}
}

func TestSeverityMeets(t *testing.T) {
	cases := []struct {
		candidate, threshold string
		want                 bool
	}{
		{"critical", "low", true},
		{"low", "critical", false},
		{"medium", "medium", true},
		{"high", "any", true},
		{"", "any", true},
		{"", "low", false},
		{"unknown", "low", false},
	}
	for _, tc := range cases {
		if got := SeverityMeets(tc.candidate, tc.threshold); got != tc.want {
			t.Errorf("SeverityMeets(%q, %q) = %v, want %v", tc.candidate, tc.threshold, got, tc.want)
		}
	}
}

func TestMatchesConstraints(t *testing.T) {
	highReachable := PackageVulnerability{
		Severity:     "high",
		Reachability: &Reachability{Status: ReachabilityReachable},
	}
	highUnreachable := PackageVulnerability{
		Severity:     "high",
		Reachability: &Reachability{Status: ReachabilityUnreachable},
	}
	highNoReach := PackageVulnerability{Severity: "high"}
	lowReachable := PackageVulnerability{
		Severity:     "low",
		Reachability: &Reachability{Status: ReachabilityReachable},
	}

	sevHigh := FailOnConstraint{Kind: SeverityConstraint, Value: "high"}
	reach := FailOnConstraint{Kind: ReachabilityConstraint, Value: "reachable"}

	cases := []struct {
		name string
		v    PackageVulnerability
		c    []FailOnConstraint
		want bool
	}{
		{"empty constraints match anything", highReachable, nil, true},
		{"severity satisfied", highReachable, []FailOnConstraint{sevHigh}, true},
		{"severity not satisfied", lowReachable, []FailOnConstraint{sevHigh}, false},
		{"both satisfied", highReachable, []FailOnConstraint{sevHigh, reach}, true},
		{"severity ok but unreachable", highUnreachable, []FailOnConstraint{sevHigh, reach}, false},
		{"severity ok but no analyzer ran", highNoReach, []FailOnConstraint{sevHigh, reach}, false},
		{"reach-only matches reachable", highReachable, []FailOnConstraint{reach}, true},
		{"reach-only excludes nil", highNoReach, []FailOnConstraint{reach}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.v.MatchesConstraints(tc.c); got != tc.want {
				t.Errorf("MatchesConstraints = %v, want %v", got, tc.want)
			}
		})
	}
}
