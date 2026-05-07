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
			pkg:  Package{Language: "kotlin", BuildSystem: "maven"},
			want: LanguageKotlin,
		},
		{
			name: "fallback to BuildSystem primary",
			pkg:  Package{BuildSystem: "maven"},
			want: LanguageJava,
		},
		{
			name: "fallback for npm",
			pkg:  Package{BuildSystem: "npm"},
			want: LanguageJavaScript,
		},
		{
			name: "no info",
			pkg:  Package{},
			want: LanguageUnknown,
		},
		{
			name: "OS-level pm has no language",
			pkg:  Package{BuildSystem: "apk"},
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

func TestPackageVulnerabilityCloneCarriesNewFields(t *testing.T) {
	v := PackageVulnerability{
		ID:     "CVE-2024-1234",
		Source: "osv",
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
}

func TestPackageCloneCarriesLocationPosition(t *testing.T) {
	pos := SourcePosition{File: "package.json", Line: 12, Column: 5}
	pkg := Package{
		Name:    "lodash",
		Version: "4.17.21",
		Locations: []PackageLocation{
			{RealPath: "/abs/package.json", Position: &pos},
		},
	}
	clone := pkg.Clone()
	if clone.Locations[0].Position == pkg.Locations[0].Position {
		t.Error("Clone did not deep-copy PackageLocation.Position pointer")
	}
	clone.Locations[0].Position.Line = 99
	if pkg.Locations[0].Position.Line != 12 {
		t.Error("mutating cloned Position leaked into original")
	}
}
