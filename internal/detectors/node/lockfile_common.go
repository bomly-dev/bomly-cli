package node

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"path/filepath"
	"strings"

	"github.com/bomly-dev/bomly-sdk/system"

	"github.com/bomly-dev/bomly-sdk/model"
)

// ParseIntegrityDigests parses a space-separated integrity string (for example "sha512-abc sha1-xyz")
// into Digest values. Returns nil when the string is empty.
func ParseIntegrityDigests(integrity string) []model.Digest {
	if integrity == "" {
		return nil
	}
	tokens := strings.Fields(integrity)
	digests := make([]model.Digest, 0, len(tokens))
	for _, token := range tokens {
		if idx := strings.Index(token, "-"); idx > 0 {
			digests = append(digests, model.Digest{Algorithm: model.DigestAlgorithm(token[:idx]), Value: token[idx+1:]})
		}
	}
	return digests
}

// ReadPackageJSONManifest reads the package.json manifest used by Node lockfile parsers.
func ReadPackageJSONManifest(projectPath string) (PackageJSONManifest, error) {
	data, err := system.ReadRepositoryFile(filepath.Join(projectPath, "package.json"))
	if err != nil {
		return PackageJSONManifest{}, fmt.Errorf("read package.json: %w", err)
	}
	var manifest PackageJSONManifest
	if err := json.Unmarshal(StripUTF8BOM(data), &manifest); err != nil {
		return PackageJSONManifest{}, fmt.Errorf("parse package.json: %w", err)
	}
	return manifest, nil
}

// StripUTF8BOM removes an optional UTF-8 byte-order mark from input.
func StripUTF8BOM(data []byte) []byte {
	return bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf})
}

// DependencySourceFromSpecifier classifies a Node dependency specifier by
// where its resolved artifact originates.
func DependencySourceFromSpecifier(value string) model.DependencySource {
	normalized := strings.ToLower(strings.TrimSpace(value))
	switch {
	case strings.HasPrefix(normalized, "workspace:"), strings.HasPrefix(normalized, "link:"):
		return model.DependencySourceWorkspace
	case strings.HasPrefix(normalized, "file:"):
		return model.DependencySourceFile
	case strings.HasPrefix(normalized, "git:"), strings.HasPrefix(normalized, "git+"),
		strings.HasPrefix(normalized, "github:"), strings.HasPrefix(normalized, "gitlab:"),
		strings.HasPrefix(normalized, "bitbucket:"):
		return model.DependencySourceGit
	case strings.HasPrefix(normalized, "http:"), strings.HasPrefix(normalized, "https:"):
		return model.DependencySourceURL
	default:
		return model.DependencySourceRegistry
	}
}

// NormalizeVersionToken removes common package-manager range and protocol markers from a version token.
func NormalizeVersionToken(value string) string {
	trimmed := strings.Trim(strings.TrimSpace(value), "\"")
	for _, prefix := range []string{"npm:", "workspace:", "link:", "file:"} {
		trimmed = strings.TrimPrefix(trimmed, prefix)
	}
	if idx := strings.Index(trimmed, "("); idx >= 0 {
		trimmed = trimmed[:idx]
	}
	trimmed = strings.TrimSpace(trimmed)
	trimmed = strings.TrimPrefix(trimmed, "=")
	trimmed = strings.TrimPrefix(trimmed, "~")
	trimmed = strings.TrimPrefix(trimmed, "^")
	trimmed = strings.TrimPrefix(trimmed, ">")
	trimmed = strings.TrimPrefix(trimmed, "<")
	return strings.TrimSpace(trimmed)
}

// MergeStringMaps returns a shallow merge of two string maps.
func MergeStringMaps(left map[string]string, right map[string]string) map[string]string {
	out := make(map[string]string, len(left)+len(right))
	maps.Copy(out, left)
	maps.Copy(out, right)
	return out
}
