package plugin

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/bomly/bomly-cli/pkg/system"
)

const protocolV1 = "v1"

// Command describes a plugin subcommand.
type Command struct {
	Name             string   `json:"name"`
	Summary          string   `json:"summary"`
	Stage            string   `json:"stage,omitempty"`
	Ecosystems       []string `json:"ecosystems,omitempty"`
	PackageManagers  []string `json:"package_managers,omitempty"`
	EvidencePatterns []string `json:"evidence_patterns,omitempty"`
	TargetKinds      []string `json:"target_kinds,omitempty"`
}

// EffectiveStage returns the stage this command participates in.
// Commands without an explicit stage default to "detect" for backward compatibility.
func (c Command) EffectiveStage() string {
	if c.Stage == "" {
		return StageDetect
	}
	return c.Stage
}

// Metadata is the plugin handshake payload.
type Metadata struct {
	Name     string    `json:"name"`
	Version  string    `json:"version"`
	Protocol string    `json:"protocol"`
	Commands []Command `json:"commands"`
}

// Plugin is a discovered plugin executable with validated metadata.
type Plugin struct {
	Path     string
	Metadata Metadata
}

// CommandForStage returns the command registered for the given pipeline stage, if any.
func (p Plugin) CommandForStage(stage string) (Command, bool) {
	for _, c := range p.Metadata.Commands {
		if c.EffectiveStage() == stage {
			return c, true
		}
	}
	return Command{}, false
}

// SupportsStage reports whether the plugin has a command for the given stage.
func (p Plugin) SupportsStage(stage string) bool {
	_, ok := p.CommandForStage(stage)
	return ok
}

// DiscoverOptions configures discovery behavior.
type DiscoverOptions struct {
	HomeDir        string
	PathEnv        string
	MetadataLoader func(path string) (Metadata, error)
}

// Discover finds plugins from ~/.bomly/plugins and PATH.
func Discover(opts DiscoverOptions) ([]Plugin, error) {
	homeDir := opts.HomeDir
	if homeDir == "" {
		resolvedHome, err := system.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("resolve home dir: %w", err)
		}
		homeDir = resolvedHome
	}

	pathEnv := opts.PathEnv
	if pathEnv == "" {
		pathEnv = system.PathEnv()
	}

	loader := opts.MetadataLoader
	if loader == nil {
		loader = LoadMetadata
	}

	orderedCandidates, err := collectCandidates(homeDir, pathEnv)
	if err != nil {
		return nil, err
	}

	seen := map[string]struct{}{}
	resolved := map[string]Plugin{}

	for _, path := range orderedCandidates {
		cleanPath := filepath.Clean(path)
		if _, ok := seen[cleanPath]; ok {
			continue
		}
		seen[cleanPath] = struct{}{}

		md, loadErr := loader(cleanPath)
		if loadErr != nil {
			continue
		}
		if _, exists := resolved[md.Name]; exists {
			continue
		}
		resolved[md.Name] = Plugin{Path: cleanPath, Metadata: md}
	}

	plugins := make([]Plugin, 0, len(resolved))
	for _, p := range resolved {
		plugins = append(plugins, p)
	}
	sort.Slice(plugins, func(i, j int) bool {
		return plugins[i].Metadata.Name < plugins[j].Metadata.Name
	})

	return plugins, nil
}

func collectCandidates(homeDir, pathEnv string) ([]string, error) {
	var candidates []string

	userDir := filepath.Join(homeDir, ".bomly", "plugins")
	entries, err := os.ReadDir(userDir)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("read user plugin dir: %w", err)
	}
	if err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			if strings.HasPrefix(entry.Name(), "bomly-") {
				candidates = append(candidates, filepath.Join(userDir, entry.Name()))
			}
		}
	}

	for _, dir := range filepath.SplitList(pathEnv) {
		if dir == "" {
			continue
		}
		pathEntries, readErr := os.ReadDir(dir)
		if readErr != nil {
			continue
		}
		for _, entry := range pathEntries {
			if entry.IsDir() {
				continue
			}
			if strings.HasPrefix(entry.Name(), "bomly-") {
				candidates = append(candidates, filepath.Join(dir, entry.Name()))
			}
		}
	}
	return candidates, nil
}

// LoadMetadata executes plugin handshake and validates the response.
func LoadMetadata(path string) (Metadata, error) {
	cmd := system.Command(path, "--bomly-plugin-info")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return Metadata{}, fmt.Errorf("run handshake for %s: %w", path, err)
	}

	md, err := ParseMetadata(stdout.Bytes())
	if err != nil {
		return Metadata{}, fmt.Errorf("parse handshake for %s: %w", path, err)
	}

	return md, nil
}

// ParseMetadata parses and validates handshake JSON.
func ParseMetadata(data []byte) (Metadata, error) {
	var md Metadata
	if err := json.Unmarshal(data, &md); err != nil {
		return Metadata{}, fmt.Errorf("decode metadata json: %w", err)
	}

	if strings.TrimSpace(md.Name) == "" {
		return Metadata{}, fmt.Errorf("metadata.name is required")
	}
	if strings.TrimSpace(md.Version) == "" {
		return Metadata{}, fmt.Errorf("metadata.version is required")
	}
	if md.Protocol != protocolV1 {
		return Metadata{}, fmt.Errorf("unsupported protocol %q", md.Protocol)
	}
	for i, c := range md.Commands {
		if strings.TrimSpace(c.Name) == "" {
			return Metadata{}, fmt.Errorf("metadata.commands[%d].name is required", i)
		}
	}

	return md, nil
}
