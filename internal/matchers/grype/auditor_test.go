//go:build !bomly_external_grype

package grype

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	v6dist "github.com/anchore/grype/grype/db/v6/distribution"
	"github.com/bomly/bomly-cli/internal/model"
	"github.com/bomly/bomly-cli/internal/scan"
)

func TestDescriptor_Name(t *testing.T) {
	a := Matcher{Priority: 90}
	d := a.Descriptor()
	if d.Name != "grype" {
		t.Errorf("Descriptor.Name = %q, want %q", d.Name, "grype")
	}
	if d.Priority != 90 {
		t.Errorf("Descriptor.Priority = %d, want 90", d.Priority)
	}
	if d.SupportedEcosystems != nil {
		t.Error("SupportedEcosystems should be nil (all ecosystems)")
	}
}

func TestMatch_NilGraph_ReturnsEmpty(t *testing.T) {
	a := Matcher{Priority: 90}
	result, err := a.Match(context.Background(), scan.MatchRequest{Graph: nil, Mode: scan.TargetModeFullGraph})
	if err != nil {
		t.Fatalf("Match with nil graph: %v", err)
	}
	if result.Graph != nil {
		t.Errorf("expected nil graph result for nil input graph")
	}
}

func TestReady_FalseWhenDBDirAbsent(t *testing.T) {
	a := Matcher{Priority: 90, DBDir: filepath.Join(t.TempDir(), "nonexistent-db")}
	if a.Ready() {
		t.Error("Ready() = true, want false when DB dir does not exist")
	}
}

func TestReady_TrueWhenDBDirExists(t *testing.T) {
	dir := t.TempDir()
	a := Matcher{Priority: 90, DBDir: dir}
	if !a.Ready() {
		t.Error("Ready() = false, want true when DB dir exists")
	}
}

func TestMatch_DBNotPresent_AttemptsDownloadAndReturnsEmpty(t *testing.T) {
	// Inject a bad LatestURL so the download fails fast without network access.
	// Match should warn and return an empty result rather than hard-failing.
	badDist := v6dist.DefaultConfig()
	badDist.LatestURL = "http://127.0.0.1:0/no-such-db" // immediately refused
	badDist.CheckTimeout = 2 * time.Second

	a := Matcher{
		Priority:           90,
		DBDir:              filepath.Join(t.TempDir(), "no-db"),
		DistConfigOverride: &badDist,
	}

	pkg := &model.Package{ID: "npm:lodash:4.17.15", Name: "lodash", Version: "4.17.15", PURL: "pkg:npm/lodash@4.17.15"}
	g := model.New()
	if err := g.AddPackage(pkg); err != nil {
		t.Fatalf("AddPackage: %v", err)
	}

	result, err := a.Match(context.Background(), scan.MatchRequest{Graph: g, Mode: scan.TargetModeFullGraph})
	if err == nil {
		t.Fatal("expected non-nil error when DB download fails")
	}
	if result.Graph != g {
		t.Fatalf("expected original graph to be returned when DB download fails")
	}
}

func TestDBDir_DefaultUsesOSCacheDir(t *testing.T) {
	a := Matcher{Priority: 90}
	dir := a.dbDir()
	if dir == "" {
		t.Error("dbDir() = empty string, want non-empty path")
	}
	// Should end in grype/db.
	cacheDir, err := os.UserCacheDir()
	if err == nil {
		want := filepath.Join(cacheDir, "grype", "db")
		if dir != want {
			t.Errorf("dbDir() = %q, want %q", dir, want)
		}
	}
}

func TestGraphPkgToGrypePkg_FieldMapping(t *testing.T) {
	p := &model.Package{
		ID:        "npm:lodash:4.17.15",
		Name:      "lodash",
		Version:   "4.17.15",
		PURL:      "pkg:npm/lodash@4.17.15",
		Ecosystem: "npm",
	}
	gp := graphPkgToGrypePkg(p)
	if gp.Name != "lodash" {
		t.Errorf("Name = %q, want lodash", gp.Name)
	}
	if gp.Version != "4.17.15" {
		t.Errorf("Version = %q, want 4.17.15", gp.Version)
	}
	if gp.PURL != "pkg:npm/lodash@4.17.15" {
		t.Errorf("PURL = %q, want pkg:npm/lodash@4.17.15", gp.PURL)
	}
}
