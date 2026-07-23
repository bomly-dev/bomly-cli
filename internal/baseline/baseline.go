// Package baseline implements portable, package-specific finding suppression.
package baseline

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

const (
	// SchemaVersion is the current baseline document schema.
	SchemaVersion = "bomly.finding-baseline/v1"
	// DefaultRelativePath is the conventional project baseline location.
	DefaultRelativePath = ".bomly/baseline.json"
)

// Document is a portable collection of package-specific finding entries.
type Document struct {
	SchemaVersion string  `json:"schema_version"`
	Entries       []Entry `json:"entries"`
}

// Entry identifies one package finding that may be suppressed.
type Entry struct {
	PackageRef   string                 `json:"package_ref"`
	Kind         sdk.FindingKind        `json:"kind"`
	Auditor      string                 `json:"auditor"`
	RuleID       string                 `json:"rule_id,omitempty"`
	AdvisoryIDs  []string               `json:"advisory_ids,omitempty"`
	Severity     sdk.SeverityLevel      `json:"severity,omitempty"`
	PolicyStatus sdk.FindingDisposition `json:"policy_status,omitempty"`
	Reachability sdk.ReachabilityStatus `json:"reachability,omitempty"`
}

// Resolver applies a validated baseline during the audit stage.
type Resolver struct{ document Document }

// NewResolver validates document and constructs a disposition resolver.
func NewResolver(document Document) (*Resolver, error) {
	if err := document.Validate(); err != nil {
		return nil, err
	}
	return &Resolver{document: document}, nil
}

// ResolveFindingPolicy accepts a finding when a compatible package entry exists.
func (r *Resolver) ResolveFindingPolicy(_ context.Context, finding sdk.Finding, registry *sdk.PackageRegistry) (sdk.FindingPolicyDecision, bool) {
	candidate := EntryFromFinding(finding, registry)
	for _, entry := range r.document.Entries {
		if entriesMatch(entry, candidate) && stateCompatible(entry, candidate) {
			return sdk.FindingPolicyDecision{Status: sdk.FindingDispositionSuppressed, Source: "baseline", Reason: "matched package finding baseline"}, true
		}
	}
	return sdk.FindingPolicyDecision{}, false
}

// EntryFromFinding constructs a portable entry from a finding and registry.
func EntryFromFinding(finding sdk.Finding, registry *sdk.PackageRegistry) Entry {
	entry := Entry{
		PackageRef:   strings.TrimSpace(finding.PackageRef),
		Kind:         finding.Kind,
		Auditor:      strings.TrimSpace(finding.Auditor),
		RuleID:       stableRuleID(finding),
		Severity:     finding.Severity,
		PolicyStatus: finding.Disposition,
	}
	if finding.Kind == sdk.FindingKindVulnerability {
		entry.AdvisoryIDs = advisoryIDs(finding, registry)
		entry.Reachability = sdk.ReachabilityUnknown
		if vulnerability := referencedVulnerability(finding, registry); vulnerability != nil && vulnerability.Reachability != nil {
			entry.Reachability = vulnerability.Reachability.Status
		}
	}
	return entry
}

// NewDocument constructs a deterministic document from findings.
func NewDocument(findings []sdk.Finding, registry *sdk.PackageRegistry) Document {
	entries := make([]Entry, 0, len(findings))
	seen := map[string]struct{}{}
	for _, finding := range findings {
		entry := EntryFromFinding(finding, registry)
		if entry.PackageRef == "" {
			continue
		}
		key := entryKey(entry)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool { return entryKey(entries[i]) < entryKey(entries[j]) })
	return Document{SchemaVersion: SchemaVersion, Entries: entries}
}

// Validate checks the document schema and entry uniqueness.
func (d Document) Validate() error {
	if d.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported baseline schema %q", d.SchemaVersion)
	}
	seen := map[string]struct{}{}
	for idx, entry := range d.Entries {
		if !strings.HasPrefix(strings.TrimSpace(entry.PackageRef), "pkg:") || entry.Kind == "" || strings.TrimSpace(entry.Auditor) == "" {
			return fmt.Errorf("baseline entry %d is missing package_ref, kind, or auditor", idx)
		}
		switch entry.PolicyStatus {
		case "", sdk.FindingDispositionFail, sdk.FindingDispositionWarn, sdk.FindingDispositionSuppressed:
		default:
			return fmt.Errorf("baseline entry %d has unsupported policy_status %q", idx, entry.PolicyStatus)
		}
		if entry.Severity != "" && sdk.ParseSeverityLevel(string(entry.Severity)) != entry.Severity {
			return fmt.Errorf("baseline entry %d has unsupported severity %q", idx, entry.Severity)
		}
		switch entry.Reachability {
		case "", sdk.ReachabilityUnknown, sdk.ReachabilityReachable, sdk.ReachabilityUnreachable:
		default:
			return fmt.Errorf("baseline entry %d has unsupported reachability %q", idx, entry.Reachability)
		}
		if entry.Kind == sdk.FindingKindVulnerability && len(entry.AdvisoryIDs) == 0 {
			return fmt.Errorf("baseline entry %d is missing advisory_ids", idx)
		}
		if entry.Kind != sdk.FindingKindVulnerability && strings.TrimSpace(entry.RuleID) == "" {
			return fmt.Errorf("baseline entry %d is missing rule_id", idx)
		}
		key := entryKey(entry)
		if _, ok := seen[key]; ok {
			return fmt.Errorf("baseline contains duplicate entry %q", key)
		}
		for prior := 0; prior < idx; prior++ {
			if entriesMatch(d.Entries[prior], entry) {
				return fmt.Errorf("baseline entries %d and %d identify the same package finding", prior, idx)
			}
		}
		seen[key] = struct{}{}
	}
	return nil
}

// Load reads and validates a baseline document.
func Load(path string) (Document, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Document{}, fmt.Errorf("read baseline %q: %w", path, err)
	}
	var document Document
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return Document{}, fmt.Errorf("parse baseline %q: %w", path, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Document{}, fmt.Errorf("parse baseline %q: trailing JSON content", path)
	}
	if err := document.Validate(); err != nil {
		return Document{}, fmt.Errorf("validate baseline %q: %w", path, err)
	}
	return document, nil
}

// ResolversForTarget discovers or loads the selected baseline for target.
func ResolversForTarget(selection string, target sdk.ExecutionTarget, logger *zap.Logger) ([]sdk.FindingPolicyResolver, error) {
	if logger == nil {
		logger = zap.NewNop()
	}
	if (strings.TrimSpace(selection) == "" || strings.EqualFold(strings.TrimSpace(selection), "auto")) &&
		target.Kind == sdk.ExecutionTargetGitRepository && strings.TrimSpace(target.RepositoryURL) != "" {
		logger.Debug("baseline: automatic project policy ignored for URL target")
		return nil, nil
	}
	path, required, ok, err := ResolvePath(selection, target)
	if err != nil || !ok {
		return nil, err
	}
	document, err := Load(path)
	if err != nil {
		if !required && errors.Is(err, os.ErrNotExist) {
			logger.Debug("baseline: no project policy found", zap.String("path", path))
			return nil, nil
		}
		return nil, err
	}
	resolver, err := NewResolver(document)
	if err != nil {
		return nil, err
	}
	logger.Info("baseline: project policy loaded",
		zap.String("path", path),
		zap.Int("entries", len(document.Entries)))
	return []sdk.FindingPolicyResolver{resolver}, nil
}

// Update returns a document that accepts all current entries while retaining
// historical entries that were not observed by the current scan.
func Update(existing Document, current []sdk.Finding, registry *sdk.PackageRegistry) Document {
	updated := NewDocument(current, registry)
	byKey := make(map[string]Entry, len(existing.Entries)+len(updated.Entries))
	for _, entry := range existing.Entries {
		byKey[entryKey(entry)] = entry
	}
	for _, entry := range updated.Entries {
		for key, accepted := range byKey {
			if entriesMatch(accepted, entry) {
				delete(byKey, key)
			}
		}
		byKey[entryKey(entry)] = entry
	}
	return documentFromMap(byKey)
}

// Prune removes entries that are not present in a complete current scan and
// never adds findings that have not already been accepted.
func Prune(existing Document, current []sdk.Finding, registry *sdk.PackageRegistry) Document {
	observed := NewDocument(current, registry)
	result := make(map[string]Entry)
	for _, accepted := range existing.Entries {
		for _, candidate := range observed.Entries {
			if entriesMatch(accepted, candidate) {
				result[entryKey(accepted)] = accepted
				break
			}
		}
	}
	return documentFromMap(result)
}

func documentFromMap(entries map[string]Entry) Document {
	document := Document{SchemaVersion: SchemaVersion, Entries: make([]Entry, 0, len(entries))}
	for _, entry := range entries {
		document.Entries = append(document.Entries, entry)
	}
	sort.Slice(document.Entries, func(i, j int) bool { return entryKey(document.Entries[i]) < entryKey(document.Entries[j]) })
	return document
}

// ResolvePath resolves a baseline selection for an execution target. The
// required result distinguishes explicit paths from optional auto-discovery.
func ResolvePath(selection string, target sdk.ExecutionTarget) (path string, required, ok bool, err error) {
	selection = strings.TrimSpace(selection)
	if selection == "" || strings.EqualFold(selection, "auto") {
		if target.Kind != sdk.ExecutionTargetFilesystem && target.Kind != sdk.ExecutionTargetGitRepository {
			return "", false, false, nil
		}
		root := target.Location
		if info, statErr := os.Stat(root); statErr == nil && !info.IsDir() {
			root = filepath.Dir(root)
		}
		return filepath.Join(root, filepath.FromSlash(DefaultRelativePath)), false, true, nil
	}
	if strings.EqualFold(selection, "none") {
		return "", false, false, nil
	}
	if filepath.IsAbs(selection) {
		return filepath.Clean(selection), true, true, nil
	}
	root := target.Location
	if info, statErr := os.Stat(root); statErr == nil && !info.IsDir() {
		root = filepath.Dir(root)
	}
	if strings.TrimSpace(root) == "" || target.Kind == sdk.ExecutionTargetContainerImage {
		return "", false, false, fmt.Errorf("relative baseline path requires a filesystem or git project target")
	}
	return filepath.Join(root, filepath.Clean(selection)), true, true, nil
}

// WriteAtomic writes a validated baseline without exposing a partial file.
func WriteAtomic(path string, document Document, replace bool) error {
	if err := document.Validate(); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("baseline destination %q is a symbolic link", path)
		}
		if !replace {
			return fmt.Errorf("baseline %q already exists", path)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect baseline destination %q: %w", path, err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create baseline directory: %w", err)
	}
	data, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal baseline: %w", err)
	}
	data = append(data, '\n')
	tmp, err := os.CreateTemp(filepath.Dir(path), ".baseline-*")
	if err != nil {
		return fmt.Errorf("create temporary baseline: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("set baseline permissions: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temporary baseline: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temporary baseline: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary baseline: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("replace baseline %q: %w", path, err)
	}
	return nil
}

func entriesMatch(expected, actual Entry) bool {
	if expected.PackageRef != actual.PackageRef || expected.Kind != actual.Kind || expected.Auditor != actual.Auditor {
		return false
	}
	if expected.Kind != sdk.FindingKindVulnerability {
		return expected.RuleID == actual.RuleID
	}
	for _, left := range expected.AdvisoryIDs {
		for _, right := range actual.AdvisoryIDs {
			if strings.EqualFold(left, right) {
				return true
			}
		}
	}
	return false
}

func stateCompatible(expected, actual Entry) bool {
	if expected.Severity != "" && sdk.SeverityRank(actual.Severity) > sdk.SeverityRank(expected.Severity) {
		return false
	}
	if expected.PolicyStatus != "" && expected.PolicyStatus != sdk.FindingDispositionSuppressed {
		actualRank, actualKnown := sdk.FindingPolicyStatusRank(actual.PolicyStatus)
		expectedRank, expectedKnown := sdk.FindingPolicyStatusRank(expected.PolicyStatus)
		if !actualKnown || !expectedKnown || actualRank > expectedRank {
			return false
		}
	}
	return expected.Reachability == "" || reachabilityRisk(actual.Reachability) <= reachabilityRisk(expected.Reachability)
}

func reachabilityRisk(status sdk.ReachabilityStatus) int {
	switch status {
	case sdk.ReachabilityUnreachable:
		return 1
	case "", sdk.ReachabilityUnknown:
		return 2
	case sdk.ReachabilityReachable:
		return 3
	default:
		return 4
	}
}

func stableRuleID(finding sdk.Finding) string {
	if value := strings.TrimSpace(finding.RuleID); value != "" {
		return value
	}
	if finding.Kind != sdk.FindingKindVulnerability {
		return strings.TrimSpace(finding.ID)
	}
	return ""
}

func advisoryIDs(finding sdk.Finding, registry *sdk.PackageRegistry) []string {
	values := []string{finding.VulnerabilityID, finding.ID}
	if vulnerability := referencedVulnerability(finding, registry); vulnerability != nil {
		values = append(values, vulnerability.ID)
		values = append(values, vulnerability.Aliases...)
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		key := strings.ToLower(value)
		if value == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i]) < strings.ToLower(out[j]) })
	return out
}

func referencedVulnerability(finding sdk.Finding, registry *sdk.PackageRegistry) *sdk.Vulnerability {
	if registry == nil {
		return nil
	}
	pkg, ok := registry.Get(finding.PackageRef)
	if !ok || pkg == nil {
		return nil
	}
	for idx := range pkg.Vulnerabilities {
		vulnerability := &pkg.Vulnerabilities[idx]
		if vulnerability.ID == finding.VulnerabilityID || vulnerability.ID == finding.ID {
			return vulnerability
		}
		for _, alias := range vulnerability.Aliases {
			if strings.EqualFold(alias, finding.VulnerabilityID) || strings.EqualFold(alias, finding.ID) {
				return vulnerability
			}
		}
	}
	return nil
}

func entryKey(entry Entry) string {
	ids := append([]string(nil), entry.AdvisoryIDs...)
	sort.Slice(ids, func(i, j int) bool { return strings.ToLower(ids[i]) < strings.ToLower(ids[j]) })
	return strings.Join([]string{entry.PackageRef, string(entry.Kind), entry.Auditor, entry.RuleID, strings.ToLower(strings.Join(ids, ","))}, "|")
}
