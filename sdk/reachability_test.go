package sdk

import "testing"

func TestDeriveConfidence(t *testing.T) {
	cases := []struct {
		name           string
		hops           *int
		dynamicImports bool
		want           ReachabilityConfidence
	}{
		{"nil hops -> unknown", nil, false, ConfidenceUnknown},
		{"nil hops with dynamic still unknown", nil, true, ConfidenceUnknown},
		{"hops=0 -> high", new(0), false, ConfidenceHigh},
		{"hops=1 -> medium", new(1), false, ConfidenceMedium},
		{"hops=3 -> medium", new(3), false, ConfidenceMedium},
		{"hops=4 -> low", new(4), false, ConfidenceLow},
		{"hops=10 -> low", new(10), false, ConfidenceLow},
		{"dynamic forces low for direct", new(0), true, ConfidenceLow},
		{"dynamic forces low for medium chain", new(2), true, ConfidenceLow},
		{"dynamic forces low for long chain", new(8), true, ConfidenceLow},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := DeriveConfidence(tc.hops, tc.dynamicImports); got != tc.want {
				t.Errorf("DeriveConfidence(hops=%v, dyn=%v) = %q, want %q", tc.hops, tc.dynamicImports, got, tc.want)
			}
		})
	}
}

func TestReachabilityCloneDeepCopiesHops(t *testing.T) {
	src := &Reachability{
		Status:                 ReachabilityReachable,
		Hops:                   new(5),
		Confidence:             ConfidenceMedium,
		DynamicImportsDetected: true,
	}
	clone := src.Clone()
	if clone == nil {
		t.Fatal("clone is nil")
	}
	if clone.Hops == src.Hops {
		t.Error("Hops pointer not deep-copied")
	}
	if clone.Hops == nil || *clone.Hops != 5 {
		t.Errorf("Hops value = %v, want 5", clone.Hops)
	}
	// Mutating the original must not affect the clone.
	*src.Hops = 99
	if *clone.Hops != 5 {
		t.Errorf("mutation to src.Hops leaked into clone: %v", *clone.Hops)
	}
	if clone.Confidence != ConfidenceMedium {
		t.Errorf("Confidence not preserved: %v", clone.Confidence)
	}
	if !clone.DynamicImportsDetected {
		t.Error("DynamicImportsDetected not preserved")
	}
}
