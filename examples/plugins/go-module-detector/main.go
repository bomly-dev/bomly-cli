package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/bomly-dev/bomly-cli/sdk"
)

const (
	pluginID      = "bomly.example.gomod-detector"
	pluginVersion = "0.1.0"
)

type detector struct{}

func (d *detector) Metadata(context.Context) (*sdk.PluginMetadata, error) {
	return &sdk.PluginMetadata{
		ID:               pluginID,
		Name:             "Bomly Example Go Module Detector",
		Version:          pluginVersion,
		Kind:             sdk.PluginKindDetector,
		PluginAPIVersion: sdk.PluginAPIVersion,
		Description:      "Example managed detector plugin that reads a local go.mod and returns the module itself as a single package.",
		Homepage:         "https://github.com/bomly-dev/bomly-cli/tree/main/examples/plugins/go-module-detector",
		License:          "Apache-2.0",
	}, nil
}

func (d *detector) Descriptor(context.Context) (*sdk.DetectorDescriptor, error) {
	return &sdk.DetectorDescriptor{
		Name:           pluginID,
		Enabled:        true,
		Origin:         sdk.ExternalOrigin,
		SupportedModes: []sdk.TargetMode{sdk.TargetModeFullGraph, sdk.TargetModeComponent},
		Capabilities:   []string{"dependency-detection"},
	}, nil
}

func (d *detector) PackageManagerSupport(context.Context) ([]sdk.PackageManagerSupport, error) {
	return []sdk.PackageManagerSupport{sdk.Support(sdk.PackageManagerGoMod, "go.mod")}, nil
}

func (d *detector) Ready(context.Context, *sdk.DetectRequest) (*sdk.ReadyResponse, error) {
	return &sdk.ReadyResponse{Ready: true}, nil
}

func (d *detector) Applicable(context.Context, *sdk.DetectRequest) (*sdk.ApplicableResponse, error) {
	return &sdk.ApplicableResponse{Applicable: true}, nil
}

func (d *detector) Detect(ctx context.Context, req *sdk.DetectRequest) (*sdk.DetectResponse, error) {
	moduleName, err := readModuleName(filepath.Join(req.ProjectPath, "go.mod"))
	if err != nil {
		return nil, err
	}
	pkg := &sdk.Package{
		ID:        moduleName + "@v0.0.0",
		Ecosystem: string(sdk.EcosystemGo),
		Name:      moduleName,
		Version:   "v0.0.0",
		PURL:      "pkg:golang/" + moduleName + "@v0.0.0",
		FoundBy:   pluginID,
	}
	graph := sdk.New()
	if err := graph.AddPackage(pkg); err != nil {
		return nil, err
	}
	return &sdk.DetectResponse{
		SubprojectInfo:      req.Subproject,
		RootExecutionTarget: req.ExecutionTarget,
		DetectorName:        pluginID,
		Origin:              sdk.ExternalOrigin,
		Graphs: &sdk.GraphContainer{
			Entries: []sdk.GraphEntry{{
				Manifest: sdk.ManifestMetadata{
					Path: filepath.Join(req.ProjectPath, "go.mod"),
					Kind: sdk.ManifestKind("go.mod"),
				},
				Graph: graph,
			}},
		},
	}, nil
}

func readModuleName(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open go.mod: %w", err)
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "module ") {
			continue
		}
		name := strings.TrimSpace(strings.TrimPrefix(line, "module"))
		if name == "" {
			return "", fmt.Errorf("go.mod module directive is empty")
		}
		return name, nil
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("scan go.mod: %w", err)
	}
	return "", fmt.Errorf("go.mod does not contain a module directive")
}

func main() {
	sdk.ServeDetector(&detector{})
}
