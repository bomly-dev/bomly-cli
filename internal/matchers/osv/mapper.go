package osv

import (
	"fmt"
	"strconv"
	"strings"

	gocvss20 "github.com/pandatix/go-cvss/20"
	gocvss30 "github.com/pandatix/go-cvss/30"
	gocvss31 "github.com/pandatix/go-cvss/31"
	gocvss40 "github.com/pandatix/go-cvss/40"

	model "github.com/bomly-dev/bomly-cli/sdk"
)

// MapVulnerability converts one OsvVulnerability into package vulnerability enrichment.
func MapVulnerability(v OsvVulnerability) model.PackageVulnerability {
	return model.PackageVulnerability{
		ID:           v.ID,
		Title:        firstNonEmpty(v.Summary, v.ID),
		Severity:     extractSeverity(v.Severity),
		Aliases:      append([]string(nil), v.Aliases...),
		Description:  strings.TrimSpace(v.Details),
		Reasons:      buildReasons(v),
		Source:       "osv",
		CVSS:         buildCVSS(v.Severity),
		FixedIn:      extractFixedVersion(v.Affected),
		References:   []model.Reference{},
		KEVExploited: false,
	}
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// extractSeverity derives a normalized severity string from OSV severity entries.
// Prefers CVSS v4 > v3.1 > v3 > v2 > unknown.
func extractSeverity(severities []OsvSeverity) string {
	scores := map[string]float64{}
	for _, s := range severities {
		if score := parseCVSSScore(s.Type, s.Score); score > 0 {
			scores[s.Type] = score
		}
	}
	// Priority order
	for _, t := range []string{"CVSS_V4", "CVSS_V31", "CVSS_V3", "CVSS_V2"} {
		if score, ok := scores[t]; ok {
			return cvssScoreToBand(score)
		}
	}
	return "unknown"
}

func parseCVSSScore(kind, raw string) float64 {
	f, err := strconv.ParseFloat(raw, 64)
	if err == nil {
		return f
	}
	if f, ok := parseCVSSVectorScore(kind, raw); ok {
		return f
	}
	// Try the last segment after all slashes.
	parts := strings.Split(raw, "/")
	if len(parts) > 0 {
		if f, err := strconv.ParseFloat(parts[len(parts)-1], 64); err == nil {
			return f
		}
	}
	return 0
}

func parseCVSSVectorScore(kind, raw string) (float64, bool) {
	version, vector := normalizeCVSSVector(kind, raw)
	switch version {
	case "CVSS:4.0", "CVSS_V4":
		cvss, err := gocvss40.ParseVector(vector)
		if err != nil {
			return 0, false
		}
		return cvss.Score(), true
	case "CVSS:3.1", "CVSS_V31":
		cvss, err := gocvss31.ParseVector(vector)
		if err != nil {
			return 0, false
		}
		return cvss.BaseScore(), true
	case "CVSS:3.0", "CVSS_V3":
		cvss, err := gocvss30.ParseVector(vector)
		if err != nil {
			return 0, false
		}
		return cvss.BaseScore(), true
	case "CVSS_V2":
		cvss, err := gocvss20.ParseVector(vector)
		if err != nil {
			return 0, false
		}
		return cvss.BaseScore(), true
	default:
		return 0, false
	}
}

func normalizeCVSSVector(kind, raw string) (string, string) {
	raw = strings.TrimSpace(raw)
	switch {
	case strings.HasPrefix(raw, "CVSS:4.0/"):
		return "CVSS:4.0", raw
	case strings.HasPrefix(raw, "CVSS:3.1/"):
		return "CVSS:3.1", raw
	case strings.HasPrefix(raw, "CVSS:3.0/"):
		return "CVSS:3.0", raw
	}

	switch kind {
	case "CVSS_V4":
		return kind, "CVSS:4.0/" + strings.TrimPrefix(raw, "/")
	case "CVSS_V31":
		return kind, "CVSS:3.1/" + strings.TrimPrefix(raw, "/")
	case "CVSS_V3":
		return kind, "CVSS:3.0/" + strings.TrimPrefix(raw, "/")
	case "CVSS_V2":
		return kind, raw
	default:
		return kind, raw
	}
}

func cvssScoreToBand(score float64) string {
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	default:
		return "low"
	}
}

func buildReasons(v OsvVulnerability) []string {
	var reasons []string
	if fixed := extractFixedVersion(v.Affected); fixed != "" {
		reasons = append(reasons, fmt.Sprintf("Fix available: upgrade to %s", fixed))
	}
	if len(v.Aliases) > 0 {
		reasons = append(reasons, fmt.Sprintf("Also known as: %s", strings.Join(v.Aliases, ", ")))
	}
	if cwes := extractCWEs(v.DatabaseSpecific); len(cwes) > 0 {
		reasons = append(reasons, fmt.Sprintf("CWEs: %s", strings.Join(cwes, ", ")))
	}
	return reasons
}

func buildCVSS(severities []OsvSeverity) []model.CVSSScore {
	if len(severities) == 0 {
		return nil
	}
	scores := make([]model.CVSSScore, 0, len(severities))
	for _, severity := range severities {
		score := parseCVSSScore(severity.Type, severity.Score)
		if score <= 0 {
			continue
		}
		scores = append(scores, model.CVSSScore{
			Vector:  strings.TrimSpace(severity.Score),
			Score:   score,
			Version: strings.TrimSpace(severity.Type),
			Source:  "osv",
		})
	}
	return scores
}

func extractFixedVersion(affected []OsvAffected) string {
	for _, a := range affected {
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if e.Fixed != "" {
					return e.Fixed
				}
			}
		}
	}
	return ""
}

func extractCWEs(ds *DatabaseSpecific) []string {
	if ds == nil {
		return nil
	}
	return ds.CweIDs
}
