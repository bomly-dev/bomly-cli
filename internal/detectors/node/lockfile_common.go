package node

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/bomly-dev/bomly-cli/sdk"
)

// ParseIntegrityDigests parses a space-separated integrity string (for example "sha512-abc sha1-xyz")
// into Digest values. Returns nil when the string is empty.
func ParseIntegrityDigests(integrity string) []sdk.Digest {
	if integrity == "" {
		return nil
	}
	tokens := strings.Fields(integrity)
	digests := make([]sdk.Digest, 0, len(tokens))
	for _, token := range tokens {
		if idx := strings.Index(token, "-"); idx > 0 {
			digests = append(digests, sdk.Digest{Algorithm: token[:idx], Value: token[idx+1:]})
		}
	}
	return digests
}

// ReadPackageJSONManifest reads the package.json manifest used by Node lockfile parsers.
func ReadPackageJSONManifest(projectPath string) (PackageJSONManifest, error) {
	data, err := os.ReadFile(filepath.Join(projectPath, "package.json"))
	if err != nil {
		return PackageJSONManifest{}, err
	}
	var manifest PackageJSONManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return PackageJSONManifest{}, fmt.Errorf("parse package.json: %w", err)
	}
	return manifest, nil
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
	for key, value := range left {
		out[key] = value
	}
	for key, value := range right {
		out[key] = value
	}
	return out
}
