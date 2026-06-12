package sdk

import "testing"

func TestParseLanguage(t *testing.T) {
	cases := []struct {
		in   string
		want Language
	}{
		{"go", LanguageGo},
		{"GO", LanguageGo},
		{" Golang ", LanguageGo},
		{"js", LanguageJavaScript},
		{"javascript", LanguageJavaScript},
		{"NodeJS", LanguageJavaScript},
		{"ts", LanguageTypeScript},
		{"py", LanguagePython},
		{"c#", LanguageCSharp},
		{"c++", LanguageCPP},
		{"unknown-lang", LanguageUnknown},
		{"", LanguageUnknown},
	}
	for _, tc := range cases {
		if got := ParseLanguage(tc.in); got != tc.want {
			t.Errorf("ParseLanguage(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestPackageManagerLanguages(t *testing.T) {
	cases := []struct {
		pm   PackageManager
		want []Language
	}{
		{PackageManagerGoMod, []Language{LanguageGo}},
		{PackageManagerNPM, []Language{LanguageJavaScript, LanguageTypeScript}},
		{PackageManagerPNPM, []Language{LanguageJavaScript, LanguageTypeScript}},
		{PackageManagerMaven, []Language{LanguageJava, LanguageKotlin, LanguageScala, LanguageGroovy}},
		{PackageManagerCargo, []Language{LanguageRust}},
		{PackageManagerAPK, nil},  // OS package manager
		{PackageManagerDPKG, nil}, // OS package manager
		{PackageManagerUnknown, nil},
	}
	for _, tc := range cases {
		got := tc.pm.Languages()
		if len(got) != len(tc.want) {
			t.Errorf("%s.Languages() length = %d, want %d (got %v)", tc.pm.Name(), len(got), len(tc.want), got)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("%s.Languages()[%d] = %q, want %q", tc.pm.Name(), i, got[i], tc.want[i])
			}
		}
	}
}

func TestLanguageFromPackage(t *testing.T) {
	cases := []struct {
		name string
		pkg  Package
		want Language
	}{
		{
			name: "explicit Language wins",
			pkg:  Package{Language: LanguageKotlin, PackageManager: PackageManagerMaven},
			want: LanguageKotlin,
		},
		{
			name: "fallback to PackageManager primary",
			pkg:  Package{PackageManager: PackageManagerMaven},
			want: LanguageJava,
		},
		{
			name: "fallback for npm",
			pkg:  Package{PackageManager: PackageManagerNPM},
			want: LanguageJavaScript,
		},
		{
			name: "no info",
			pkg:  Package{},
			want: LanguageUnknown,
		},
		{
			name: "OS-level pm has no language",
			pkg:  Package{PackageManager: PackageManagerAPK},
			want: LanguageUnknown,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := LanguageFromPackage(tc.pkg); got != tc.want {
				t.Errorf("LanguageFromPackage(%+v) = %q, want %q", tc.pkg, got, tc.want)
			}
		})
	}
}

func TestReachabilityClone(t *testing.T) {
	original := &Reachability{
		Status:   ReachabilityReachable,
		Tier:     TierSymbol,
		Analyzer: "govulncheck",
		Symbols: []AffectedSymbol{
			{Symbol: "Decoder.Decode", Package: "encoding/json"},
		},
		CallPaths: []CallPath{
			{
				Sink: AffectedSymbol{Symbol: "Decoder.Decode"},
				Frames: []CallFrame{
					{Function: "main.main", Position: SourcePosition{File: "main.go", Line: 10}},
				},
			},
		},
	}
	clone := original.Clone()
	if clone == original {
		t.Fatal("Clone returned same pointer")
	}
	clone.Symbols[0].Symbol = "mutated"
	if original.Symbols[0].Symbol != "Decoder.Decode" {
		t.Error("mutating clone leaked into original (Symbols)")
	}
	clone.CallPaths[0].Frames[0].Function = "mutated"
	if original.CallPaths[0].Frames[0].Function != "main.main" {
		t.Error("mutating clone leaked into original (CallPaths)")
	}
	if (*Reachability)(nil).Clone() != nil {
		t.Error("nil receiver Clone should return nil")
	}
}

func TestVulnerabilityCloneCarriesNewFields(t *testing.T) {
	v := Vulnerability{
		ID:            "CVE-2024-1234",
		Source:        "osv",
		FixedVersions: []string{"1.2.3"},
		FixAvailable:  []FixAvailable{{Version: "1.2.3", Date: "2024-01-02"}},
		KnownExploited: []KnownExploited{{
			CVE:  "CVE-2024-1234",
			URLs: []string{"https://kev.example"},
			CWEs: []string{"CWE-79"},
		}},
		EPSS: []EPSSScore{{CVE: "CVE-2024-1234", EPSS: 0.5}},
		CWEs: []CWE{{CVE: "CVE-2024-1234", ID: "CWE-79"}},
		CPEs: []string{"cpe:2.3:a:example:pkg:1.0:*:*:*:*:*:*:*"},
		AffectedSymbols: []AffectedSymbol{
			{Symbol: "ParseURL", Package: "net/url"},
		},
		Reachability: &Reachability{Status: ReachabilityReachable, Analyzer: "govulncheck"},
	}
	clone := v.Clone()
	clone.AffectedSymbols[0].Symbol = "Mutated"
	if v.AffectedSymbols[0].Symbol != "ParseURL" {
		t.Error("Clone did not deep-copy AffectedSymbols")
	}
	if clone.Reachability == v.Reachability {
		t.Error("Clone did not deep-copy Reachability pointer")
	}
	clone.FixedVersions[0] = "mutated"
	if v.FixedVersions[0] != "1.2.3" {
		t.Error("Clone did not deep-copy FixedVersions")
	}
	clone.KnownExploited[0].URLs[0] = "mutated"
	if v.KnownExploited[0].URLs[0] != "https://kev.example" {
		t.Error("Clone did not deep-copy KnownExploited URLs")
	}
	clone.CPEs[0] = "mutated"
	if v.CPEs[0] == "mutated" {
		t.Error("Clone did not deep-copy CPEs")
	}
}

func TestDependencyCloneCarriesLocationPosition(t *testing.T) {
	pos := SourcePosition{File: "package.json", Line: 12, Column: 5}
	dep := Dependency{
		Name:    "lodash",
		Version: "4.17.21",
		Locations: []PackageLocation{
			{RealPath: "/abs/package.json", Position: &pos},
		},
	}
	clone := dep.Clone()
	if clone.Locations[0].Position == dep.Locations[0].Position {
		t.Error("Clone did not deep-copy PackageLocation.Position pointer")
	}
	clone.Locations[0].Position.Line = 99
	if dep.Locations[0].Position.Line != 12 {
		t.Error("mutating cloned Position leaked into original")
	}
}
