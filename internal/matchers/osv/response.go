// Package osv implements an engine.Auditor backed by the OSV (Open Source Vulnerabilities) API.
package osv

import "encoding/json"

// PurlPackage is the wire shape for PURL-based OSV queries.
type PurlPackage struct {
	Purl string `json:"purl"`
}

// NamePackage is the wire shape for name+ecosystem OSV queries.
type NamePackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

// BatchQuery is one entry in the OSV batch request wire format.
// Exactly one of PurlPkg or NamePkg will be set inside the Package field.
type BatchQuery struct {
	Package json.RawMessage `json:"package"`
	Version string          `json:"version,omitempty"`
}

// BatchRequest is the wire body for POST /v1/querybatch.
type BatchRequest struct {
	Queries []BatchQuery `json:"queries"`
}

// BatchResponse is the top-level response from POST /v1/querybatch.
type BatchResponse struct {
	Results []BatchResult `json:"results"`
}

// BatchResult is the result for one query in the batch.
// The /v1/querybatch endpoint returns only the ID and modified timestamp;
// use Client.GetVuln to retrieve the full vulnerability detail.
type BatchResult struct {
	Vulns []VulnRef `json:"vulns"`
}

// VulnRef is the minimal vulnerability entry returned by POST /v1/querybatch.
type VulnRef struct {
	ID       string `json:"id"`
	Modified string `json:"modified"`
}

// Vulnerability is the full vulnerability as returned by GET /v1/vulns/{id}.
type Vulnerability struct {
	ID               string            `json:"id"`
	Summary          string            `json:"summary"`
	Details          string            `json:"details"`
	Aliases          []string          `json:"aliases"`
	Severity         []Severity        `json:"severity"`
	Affected         []Affected        `json:"affected"`
	Published        string            `json:"published"`
	Modified         string            `json:"modified"`
	DatabaseSpecific *DatabaseSpecific `json:"database_specific,omitempty"`
}

// Severity holds a CVSS vector and type.
type Severity struct {
	Type  string `json:"type"`  // e.g. "CVSS_V3", "CVSS_V4"
	Score string `json:"score"` // vector string or numeric score
}

// Affected holds version ranges and specific affected versions.
type Affected struct {
	Versions []string `json:"versions"`
	Ranges   []Range  `json:"ranges"`
}

// Range holds a single range entry.
type Range struct {
	Events []Event `json:"events"`
}

// Event holds introduced/fixed/last_affected markers.
type Event struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
}

// DatabaseSpecific holds ecosystem-specific metadata (e.g., CWE IDs from GitHub).
type DatabaseSpecific struct {
	CweIDs []string `json:"cwe_ids,omitempty"`
	// Severity is GitHub Security Advisory's textual rating (LOW / MODERATE /
	// HIGH / CRITICAL). GHSA-sourced OSV entries frequently omit a CVSS vector
	// in the top-level `severity` array, so this is the only severity signal
	// available for them.
	Severity string `json:"severity,omitempty"`
}
