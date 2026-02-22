package plugin

import (
	"encoding/json"
	"testing"
)

func TestNewEnvelope_Roundtrip(t *testing.T) {
	input := PreResolveInput{
		ExecutionTarget: ExecutionTargetInfo{Kind: "filesystem", Location: "/repo"},
		Subprojects: []SubprojectInfo{
			{Path: "/repo", RelativePath: ".", PackageManager: "npm", Ecosystem: "npm"},
		},
	}
	data, err := NewEnvelope(StagePreResolve, input)
	if err != nil {
		t.Fatalf("NewEnvelope() error = %v", err)
	}

	env, err := ParseEnvelope(data)
	if err != nil {
		t.Fatalf("ParseEnvelope() error = %v", err)
	}
	if env.Protocol != envelopeProtocol {
		t.Fatalf("expected protocol %q, got %q", envelopeProtocol, env.Protocol)
	}
	if env.Stage != StagePreResolve {
		t.Fatalf("expected stage %q, got %q", StagePreResolve, env.Stage)
	}

	var decoded PreResolveInput
	if err := json.Unmarshal(env.Payload, &decoded); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if decoded.ExecutionTarget.Location != "/repo" {
		t.Fatalf("expected location /repo, got %q", decoded.ExecutionTarget.Location)
	}
}

func TestParseEnvelope_RejectsUnknownProtocol(t *testing.T) {
	data := []byte(`{"protocol":"unknown","stage":"detect","payload":{}}`)
	_, err := ParseEnvelope(data)
	if err == nil {
		t.Fatal("expected error for unknown protocol")
	}
	var upe *UnsupportedProtocolError
	if !isUnsupportedProtocol(err) {
		t.Fatalf("expected UnsupportedProtocolError, got %T: %v", err, err)
	}
	_ = upe
}

func isUnsupportedProtocol(err error) bool {
	_, ok := err.(*UnsupportedProtocolError)
	return ok
}

func TestParseEnvelope_RejectsInvalidJSON(t *testing.T) {
	_, err := ParseEnvelope([]byte(`not json`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestDecodePayload_DetectOutput(t *testing.T) {
	payload := DetectOutput{Format: "spdx-json", Graph: json.RawMessage(`{}`)}
	data, _ := json.Marshal(payload)
	env := Envelope{Protocol: envelopeProtocol, Stage: StageDetect, Payload: data}

	decoded, err := DecodePayload[DetectOutput](env)
	if err != nil {
		t.Fatalf("DecodePayload() error = %v", err)
	}
	if decoded.Format != "spdx-json" {
		t.Fatalf("expected format spdx-json, got %q", decoded.Format)
	}
}

func TestCommand_EffectiveStage_DefaultsToDetect(t *testing.T) {
	cmd := Command{Name: "deps"}
	if got := cmd.EffectiveStage(); got != StageDetect {
		t.Fatalf("expected %q, got %q", StageDetect, got)
	}
}

func TestCommand_EffectiveStage_RespectsExplicitStage(t *testing.T) {
	cmd := Command{Name: "audit-hook", Stage: StageAudit}
	if got := cmd.EffectiveStage(); got != StageAudit {
		t.Fatalf("expected %q, got %q", StageAudit, got)
	}
}

func TestPlugin_SupportsStage(t *testing.T) {
	p := Plugin{
		Metadata: Metadata{
			Name:     "test-plugin",
			Version:  "1.0.0",
			Protocol: protocolV1,
			Commands: []Command{
				{Name: "deps", Stage: StageDetect},
				{Name: "pre-check", Stage: StagePreResolve},
			},
		},
	}
	if !p.SupportsStage(StageDetect) {
		t.Fatal("expected detect stage support")
	}
	if !p.SupportsStage(StagePreResolve) {
		t.Fatal("expected pre-resolve stage support")
	}
	if p.SupportsStage(StageAudit) {
		t.Fatal("expected no audit stage support")
	}
}

func TestPlugin_CommandForStage_LegacyDefault(t *testing.T) {
	p := Plugin{
		Metadata: Metadata{
			Commands: []Command{
				{Name: "deps"},
			},
		},
	}
	cmd, ok := p.CommandForStage(StageDetect)
	if !ok {
		t.Fatal("expected detect command for legacy plugin")
	}
	if cmd.Name != "deps" {
		t.Fatalf("expected command name deps, got %q", cmd.Name)
	}
}

func TestParseMetadata_WithStage(t *testing.T) {
	data := []byte(`{
		"name":"reporter",
		"version":"1.0.0",
		"protocol":"v1",
		"commands":[
			{"name":"report","summary":"Generate report","stage":"post-resolve"}
		]
	}`)
	md, err := ParseMetadata(data)
	if err != nil {
		t.Fatalf("ParseMetadata() error = %v", err)
	}
	if len(md.Commands) != 1 {
		t.Fatalf("expected 1 command, got %d", len(md.Commands))
	}
	if md.Commands[0].Stage != StagePostResolve {
		t.Fatalf("expected stage %q, got %q", StagePostResolve, md.Commands[0].Stage)
	}
}
