package sbt

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/internal/logging"
	"github.com/bomly-dev/bomly-cli/internal/system"
	"github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

// NativeDetector resolves Scala sbt dependency graphs by running
// `sbt --no-colors --batch dependencyTree`. This produces a proper transitive
// tree with parent-child edges, unlike the manifest-only Detector.
type NativeDetector struct {
	Logger     *zap.Logger
	WorkingDir string
	Fallback   sdk.Detector
}

// PackageManagerSupport returns sbt package-manager discovery metadata.
func (d NativeDetector) PackageManagerSupport() []sdk.PackageManagerSupport {
	return []sdk.PackageManagerSupport{sdk.Support(sdk.PackageManagerSBT, evidencePatterns...)}
}

// Ready reports whether the sbt binary is available.
func (d NativeDetector) Ready() bool {
	_, err := system.LookPath("sbt")
	return err == nil
}

// Applicable reports whether sbt build files are present.
func (d NativeDetector) Applicable(ctx context.Context, req sdk.DetectionRequest) (bool, error) {
	workingDir := d.workingDir(req.ProjectPath)
	applicable, err := (Detector{WorkingDir: workingDir}).Applicable(ctx, req)
	if err != nil || !applicable {
		return applicable, err
	}
	if requiresDependencyGraphPlugin(workingDir) && !hasDependencyGraphPlugin(workingDir) {
		d.logger().Debug("sbt native detector skipped: dependencyTree task is unavailable for this sbt version",
			zap.String("working_dir", workingDir),
			zap.String("sbt_version", sbtVersion(workingDir)),
		)
		return false, nil
	}
	return true, nil
}

// Descriptor describes the sbt native detector.
func (d NativeDetector) Descriptor() sdk.DetectorDescriptor {
	return sdk.DetectorDescriptor{
		Name:                detectors.NameSBTNative,
		Technique:           sdk.BuildToolTechnique,
		SupportedEcosystems: []sdk.Ecosystem{sdk.EcosystemScala, sdk.EcosystemMaven},
		SupportedManagers:   []sdk.PackageManager{sdk.PackageManagerSBT},
		Tags:                []string{"graph-resolution", "component-targeting", "scope-annotation"},
	}
}

// ResolveGraph resolves an sbt dependency graph via sbt dependencyTree.
func (d NativeDetector) ResolveGraph(_ context.Context, req sdk.DetectionRequest) (sdk.DetectionResult, error) {
	logger := d.logger()
	workingDir := d.workingDir(req.ProjectPath)

	cmd := system.Command("sbt", "--no-colors", "--batch", "dependencyTree")
	cmd.Dir = workingDir
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = logging.NewCommandStderr(req.Stderr, req.Verbose)

	started := time.Now()
	logger.Debug("running sbt native detector", zap.String("working_dir", workingDir))
	if err := cmd.Run(); err != nil {
		logger.Debug("sbt dependencyTree failed", zap.Error(err))
		return sdk.DetectionResult{}, fmt.Errorf("sbt dependencyTree: %w", err)
	}

	g, err := depGraphFromSBTDependencyTree(out.Bytes())
	if err != nil {
		return sdk.DetectionResult{}, fmt.Errorf("parse sbt dependencyTree output: %w", err)
	}
	logger.Info(fmt.Sprintf("sbt native detector found %d dependencies in %s", g.Size(), logging.FormatDuration(time.Since(started))))
	AttachSBTPositions(g, workingDir)
	return sdk.DetectionResult{
		Graphs: sdk.SingleGraphContainer(g, detectors.InferManifestMetadata(req, evidencePatterns)),
	}, nil
}

// FallbackDetector returns the configured fallback detector.
func (d NativeDetector) FallbackDetector() sdk.Detector {
	return d.Fallback
}

func (d NativeDetector) workingDir(projectPath string) string {
	if d.WorkingDir != "" {
		return d.WorkingDir
	}
	return projectPath
}

func (d NativeDetector) logger() *zap.Logger {
	if d.Logger != nil {
		return d.Logger
	}
	return zap.NewNop()
}

func requiresDependencyGraphPlugin(workingDir string) bool {
	version := sbtVersion(workingDir)
	if version == "" {
		return false
	}
	major, minor, ok := parseSBTMajorMinor(version)
	if !ok {
		return false
	}
	return major == 0 || (major == 1 && minor < 4)
}

func sbtVersion(workingDir string) string {
	raw, err := os.ReadFile(filepath.Join(workingDir, "project", "build.properties"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(raw), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if strings.TrimSpace(key) == "sbt.version" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func parseSBTMajorMinor(version string) (int, int, bool) {
	parts := strings.Split(strings.TrimSpace(version), ".")
	if len(parts) < 2 {
		return 0, 0, false
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, false
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, false
	}
	return major, minor, true
}

func hasDependencyGraphPlugin(workingDir string) bool {
	for _, name := range []string{
		filepath.Join("project", "plugins.sbt"),
		filepath.Join("project", "build.sbt"),
		"build.sbt",
	} {
		raw, err := os.ReadFile(filepath.Join(workingDir, name))
		if err != nil {
			continue
		}
		if strings.Contains(string(raw), "sbt-dependency-graph") {
			return true
		}
	}
	return false
}

// sbtDepTreeLinePattern matches a dependency line from sbt dependencyTree.
// Examples:
//
//	[info] com.typesafe:config:1.4.3 [S]
//	[info]   +-org.scalatest:scalatest_3:3.2.18 [S]
//	[info]   | +-...
//	[info]   +-...
var sbtDepTreeLinePattern = regexp.MustCompile(`^\[info\]([ |]*)\+?-?\s*([^:]+:[^:\s]+:[^\s\[]+)`)

// sbtPackageCoordPattern matches `org:name:version`.
// The artifact suffix (for example `_2.13`) is part of the Maven artifact ID
// and must be preserved for matching/enrichment.
var sbtPackageCoordPattern = regexp.MustCompile(`^([^:]+):([^:]+):([^\s\[]+)`)

// depGraphFromSBTDependencyTree parses the text output of `sbt dependencyTree`
// and builds a proper transitive dependency graph.
//
// sbt's dependencyTree uses indentation (pairs of spaces) to indicate depth.
// Each `[info]   +-org:name:version` line is a dependency at a given nesting level.
// The root package is the first `[info]` line without `+-`.
//
// Scope: sbt does not embed scope in dependencyTree output by default.
// We fall back to parsing build.sbt for scope annotation via parseSBTDependencies.
func depGraphFromSBTDependencyTree(raw []byte) (*sdk.Graph, error) {
	lines := strings.Split(string(raw), "\n")

	g := sdk.New()
	root := rootNode()
	if err := g.AddNode(root); err != nil {
		return nil, fmt.Errorf("add root node: %w", err)
	}

	// parentStack[depth] = nodeID of the package at that depth.
	// Depth 0 = root.
	parentStack := []string{root.ID}
	seen := make(map[string]bool)

	for _, line := range lines {
		m := sbtDepTreeLinePattern.FindStringSubmatch(line)
		if m == nil {
			continue
		}

		// Compute depth from leading whitespace ("|" and " " characters before "+-").
		// Each "  " (2 chars) or "| " represents one level of nesting.
		indent := m[1]
		// Count groups of 2 chars; each group is one level.
		depth := len([]rune(indent)) / 2
		if depth < 0 {
			depth = 0
		}

		coord := strings.TrimSpace(m[2])
		cm := sbtPackageCoordPattern.FindStringSubmatch(coord)
		if cm == nil {
			continue
		}

		org := strings.TrimSpace(cm[1])
		name := strings.TrimSpace(cm[2])
		version := strings.TrimSpace(cm[3])
		if name == "" {
			continue
		}
		// Skip evicted marker.
		if strings.Contains(line, "[E]") {
			continue
		}

		pkg := sbtPackage{
			Org:     org,
			Name:    name,
			Version: version,
			Scope:   sdk.ScopeRuntime,
		}
		node := packageNode(pkg)

		if !seen[node.ID] {
			seen[node.ID] = true
			if err := addNodeIfMissing(g, node); err != nil {
				return nil, err
			}
		}

		existing, ok := g.Node(node.ID)
		if !ok {
			continue
		}

		// The parent is the item one level up in the stack.
		if depth >= len(parentStack) {
			// Extend the stack.
			for len(parentStack) <= depth {
				parentStack = append(parentStack, root.ID)
			}
		} else {
			// Trim the stack back.
			parentStack = parentStack[:depth+1]
		}

		parentID := parentStack[depth]
		if err := g.AddEdge(parentID, existing.ID); err != nil {
			// Duplicate edges are silently ignored.
			_ = err
		}

		// Push this node as the parent for the next (deeper) level.
		if depth+1 < len(parentStack) {
			parentStack[depth+1] = existing.ID
		} else {
			parentStack = append(parentStack, existing.ID)
		}
	}

	if len(seen) == 0 {
		return nil, fmt.Errorf("sbt dependencyTree output contained no parseable packages")
	}
	return g, nil
}
