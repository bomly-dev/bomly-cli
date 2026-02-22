package plugin

import "encoding/json"

const envelopeProtocol = "bomly-plugin-v1"

// Stage constants identify the pipeline stage a plugin participates in.
const (
	StagePreResolve  = "pre-resolve"
	StageDetect      = "detect"
	StageAudit       = "audit"
	StagePostResolve = "post-resolve"
)

// Envelope is the top-level JSON wire format for plugin communication.
type Envelope struct {
	Protocol string          `json:"protocol"`
	Stage    string          `json:"stage"`
	Payload  json.RawMessage `json:"payload"`
}

// ExecutionTargetInfo describes the scan target sent to plugins.
type ExecutionTargetInfo struct {
	Kind     string `json:"kind"`
	Location string `json:"location"`
}

// SubprojectInfo describes a subproject sent to plugins.
type SubprojectInfo struct {
	Path           string `json:"path"`
	RelativePath   string `json:"relative_path"`
	PackageManager string `json:"package_manager"`
	Ecosystem      string `json:"ecosystem"`
}

// PreResolveInput is sent to a plugin pre-resolve stage.
type PreResolveInput struct {
	ExecutionTarget ExecutionTargetInfo `json:"execution_target"`
	Subprojects     []SubprojectInfo    `json:"subprojects"`
	Config          map[string]any      `json:"config,omitempty"`
}

// PreResolveOutput is returned by a plugin pre-resolve stage.
type PreResolveOutput struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}

// DetectInput is sent to a plugin detect stage.
type DetectInput struct {
	Subproject      SubprojectInfo      `json:"subproject"`
	ExecutionTarget ExecutionTargetInfo `json:"execution_target"`
	Config          map[string]any      `json:"config,omitempty"`
}

// DetectOutput is returned by a plugin detect stage (graph as SBOM JSON).
type DetectOutput struct {
	Format string          `json:"format"`
	Graph  json.RawMessage `json:"graph"`
}

// PackageInfo is the wire format for a package sent to audit/post-resolve plugins.
type PackageInfo struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	PURL      string `json:"purl,omitempty"`
	Ecosystem string `json:"ecosystem,omitempty"`
	Scope     string `json:"scope,omitempty"`
}

// AuditInput is sent to a plugin audit stage.
type AuditInput struct {
	Packages []PackageInfo `json:"packages"`
}

// FindingInfo is the wire format for a vulnerability finding.
type FindingInfo struct {
	ID          string   `json:"id"`
	Source      string   `json:"source"`
	Severity    string   `json:"severity,omitempty"`
	Summary     string   `json:"summary,omitempty"`
	PackageName string   `json:"package_name"`
	Version     string   `json:"version"`
	FixVersions []string `json:"fix_versions,omitempty"`
	References  []string `json:"references,omitempty"`
}

// AuditOutput is returned by a plugin audit stage.
type AuditOutput struct {
	Findings []FindingInfo `json:"findings"`
}

// PostResolveInput is sent to a plugin post-resolve stage.
type PostResolveInput struct {
	Packages []PackageInfo  `json:"packages"`
	Findings []FindingInfo  `json:"findings,omitempty"`
	Config   map[string]any `json:"config,omitempty"`
}

// PostResolveOutput is returned by a plugin post-resolve stage.
type PostResolveOutput struct {
	Success   bool     `json:"success"`
	Message   string   `json:"message,omitempty"`
	Artifacts []string `json:"artifacts,omitempty"`
}

// NewEnvelope creates a typed envelope with the given stage and payload.
func NewEnvelope(stage string, payload any) ([]byte, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return json.Marshal(Envelope{
		Protocol: envelopeProtocol,
		Stage:    stage,
		Payload:  raw,
	})
}

// ParseEnvelope decodes an envelope and validates the protocol version.
func ParseEnvelope(data []byte) (Envelope, error) {
	var env Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return Envelope{}, err
	}
	if env.Protocol != envelopeProtocol {
		return Envelope{}, &UnsupportedProtocolError{Protocol: env.Protocol}
	}
	return env, nil
}

// UnsupportedProtocolError indicates an envelope with an unknown protocol version.
type UnsupportedProtocolError struct {
	Protocol string
}

func (e *UnsupportedProtocolError) Error() string {
	return "unsupported plugin protocol: " + e.Protocol
}
