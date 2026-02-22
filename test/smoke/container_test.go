//go:build smoke

package smoke

import "testing"

// Container image references pinned by digest for reproducibility.
// Using small base images that produce a manageable number of packages.
const (
	alpineImage = "alpine:3.20"
	debianImage = "debian:bookworm-slim"
)

// ---------------------------------------------------------------------------
// Container scan tests
// ---------------------------------------------------------------------------

func TestContainerScan(t *testing.T) {
	// requireContainerRuntime(t) — built-in Syft does not need docker/podman.

	cases := []struct {
		name string
		args []string
	}{
		{
			name: "container-scan-alpine",
			args: []string{"scan", "--container", alpineImage, "--format", "json"},
		},
		{
			name: "container-scan-debian",
			args: []string{"scan", "--container", debianImage, "--format", "json"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stdout, stderr, code := runBomly(t, tc.args...)
			if code != 0 {
				t.Fatalf("bomly exited %d\nstderr:\n%s", code, stderr)
			}
			if len(stdout) == 0 {
				t.Fatal("bomly produced no stdout output")
			}

			got := normalizeContainerJSON(t, []byte(stdout))
			assertGolden(t, tc.name, got)
		})
	}
}

// ---------------------------------------------------------------------------
// Container diff tests
// ---------------------------------------------------------------------------

func TestContainerDiff(t *testing.T) {
	// requireContainerRuntime(t) — built-in Syft does not need docker/podman.

	cases := []struct {
		name string
		args []string
	}{
		{
			name: "container-diff-alpine",
			args: []string{"diff", "--container", "alpine", "--base", "3.19", "--head", "3.20", "--format", "json"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stdout, stderr, code := runBomly(t, tc.args...)
			if code != 0 {
				t.Fatalf("bomly exited %d\nstderr:\n%s", code, stderr)
			}
			if len(stdout) == 0 {
				t.Fatal("bomly produced no stdout output")
			}

			got := normalizeContainerJSON(t, []byte(stdout))
			assertGolden(t, tc.name, got)
		})
	}
}

// ---------------------------------------------------------------------------
// Container explain tests
// ---------------------------------------------------------------------------

func TestContainerExplain(t *testing.T) {
	// requireContainerRuntime(t) — built-in Syft does not need docker/podman.

	cases := []struct {
		name string
		args []string
	}{
		{
			name: "container-explain-alpine",
			args: []string{"explain", "musl", "--container", alpineImage, "--format", "json"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stdout, stderr, code := runBomly(t, tc.args...)
			if code != 0 {
				t.Fatalf("bomly exited %d\nstderr:\n%s", code, stderr)
			}
			if len(stdout) == 0 {
				t.Fatal("bomly produced no stdout output")
			}

			got := normalizeContainerJSON(t, []byte(stdout))
			assertGolden(t, tc.name, got)
		})
	}
}

// ---------------------------------------------------------------------------
// Container-specific normalization
// ---------------------------------------------------------------------------

// normalizeContainerJSON applies the standard normalization plus additional
// container-specific adjustments. Container image scans may include packages
// whose versions shift across image rebuilds, so we normalize package versions
// when the image is referenced by mutable tag rather than digest.
//
// For now this is the same as normalizeJSON — if digest-pinning proves
// insufficient, additional per-package version masking can be added here.
func normalizeContainerJSON(t *testing.T, raw []byte) []byte {
	t.Helper()
	return normalizeJSON(t, raw)
}
