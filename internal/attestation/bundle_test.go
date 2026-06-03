package attestation

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/protobuf/types/known/structpb"
)

func TestBuildStatementEmbedsSupportedSBOM(t *testing.T) {
	subject := Subject{
		Kind:   SubjectKindFile,
		Name:   "file:artifact.tar",
		Digest: map[string]string{"sha256": strings.Repeat("a", 64)},
	}
	statement, err := BuildStatement(subject, []byte(minimalSPDXDocument()))
	if err != nil {
		t.Fatalf("BuildStatement() error = %v", err)
	}
	if statement.PredicateType != PredicateTypeSBOM {
		t.Fatalf("PredicateType = %q, want %q", statement.PredicateType, PredicateTypeSBOM)
	}
	if len(statement.Subject) != 1 || statement.Subject[0].Name != subject.Name {
		t.Fatalf("unexpected subject: %#v", statement.Subject)
	}
	if got := statement.Predicate.Fields["sbomFormat"].GetStringValue(); got != "spdx-2.3+json" {
		t.Fatalf("sbomFormat = %q", got)
	}
	if raw := statement.Predicate.Fields[sbomRawBase64Field].GetStringValue(); raw == "" {
		t.Fatal("expected byte-preserving SBOM payload")
	}
	if statement.Predicate.Fields["sbom"] != nil {
		t.Fatal("new predicates should not duplicate the SBOM as a parsed JSON object")
	}
}

func TestBuildStatementRejectsUnsupportedSBOM(t *testing.T) {
	subject := Subject{Name: "file:artifact", Digest: map[string]string{"sha256": strings.Repeat("a", 64)}}
	if _, err := BuildStatement(subject, []byte(`{"not":"an sbom"}`)); err == nil {
		t.Fatal("expected unsupported SBOM error")
	}
}

func TestSBOMFromPredicateRequiresRawSBOMBytes(t *testing.T) {
	predicate, err := structpb.NewStruct(map[string]any{
		"schemaVersion": "experimental/v1",
		"sbomFormat":    "spdx-2.3+json",
		"sbomDigest": map[string]any{
			"sha256": strings.Repeat("a", 64),
		},
	})
	if err != nil {
		t.Fatalf("build predicate: %v", err)
	}
	if _, _, err := sbomFromPredicate(predicate); err == nil || !strings.Contains(err.Error(), "missing required fields") {
		t.Fatalf("expected missing raw SBOM error, got %v", err)
	}
}

func TestAttestAndVerifyKeylessRoundTrip(t *testing.T) {
	dir := t.TempDir()
	sbomPath := filepath.Join(dir, "bomly.spdx.json")
	if err := os.WriteFile(sbomPath, []byte(minimalSPDXDocument()), 0o644); err != nil {
		t.Fatalf("write sbom: %v", err)
	}
	subjectPath := filepath.Join(dir, "artifact.txt")
	if err := os.WriteFile(subjectPath, []byte("artifact"), 0o644); err != nil {
		t.Fatalf("write subject: %v", err)
	}
	subject, err := ResolveSubject("file:"+subjectPath, SubjectOptions{})
	if err != nil {
		t.Fatalf("ResolveSubject() error = %v", err)
	}

	bundle, err := Attest(context.Background(), AttestRequest{
		SBOMPath: sbomPath,
		Subject:  subject,
		Keyless:  true,
	})
	if err != nil {
		t.Fatalf("Attest() error = %v", err)
	}
	if !json.Valid(bundle) {
		t.Fatalf("bundle is not JSON: %s", bundle)
	}

	result, err := Verify(context.Background(), VerifyRequest{
		Bundle:  bundle,
		Subject: subject,
	})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if result.SBOMFormat != "spdx-2.3+json" {
		t.Fatalf("SBOMFormat = %q", result.SBOMFormat)
	}
	original, err := os.ReadFile(sbomPath)
	if err != nil {
		t.Fatalf("read original sbom: %v", err)
	}
	if !bytes.Equal(result.SBOM, original) {
		t.Fatalf("verified SBOM bytes differ from original\noriginal: %s\nverified: %s", original, result.SBOM)
	}
}

func TestVerifyRejectsWrongSubject(t *testing.T) {
	dir := t.TempDir()
	sbomPath := filepath.Join(dir, "bomly.spdx.json")
	if err := os.WriteFile(sbomPath, []byte(minimalSPDXDocument()), 0o644); err != nil {
		t.Fatalf("write sbom: %v", err)
	}
	onePath := filepath.Join(dir, "one.txt")
	twoPath := filepath.Join(dir, "two.txt")
	if err := os.WriteFile(onePath, []byte("one"), 0o644); err != nil {
		t.Fatalf("write subject one: %v", err)
	}
	if err := os.WriteFile(twoPath, []byte("two"), 0o644); err != nil {
		t.Fatalf("write subject two: %v", err)
	}
	one, err := ResolveSubject("file:"+onePath, SubjectOptions{})
	if err != nil {
		t.Fatalf("ResolveSubject(one) error = %v", err)
	}
	two, err := ResolveSubject("file:"+twoPath, SubjectOptions{})
	if err != nil {
		t.Fatalf("ResolveSubject(two) error = %v", err)
	}
	bundle, err := Attest(context.Background(), AttestRequest{SBOMPath: sbomPath, Subject: one, Keyless: true})
	if err != nil {
		t.Fatalf("Attest() error = %v", err)
	}
	_, err = Verify(context.Background(), VerifyRequest{Bundle: bundle, Subject: two})
	if err == nil || !strings.Contains(err.Error(), "subject digest does not match") {
		t.Fatalf("expected subject mismatch, got %v", err)
	}
}

func TestWriteVerifiedSBOMPreservesBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "verified.spdx.json")
	data := []byte(`{"spdxVersion":"SPDX-2.3","packages":[]}`)
	if err := WriteVerifiedSBOM(path, data); err != nil {
		t.Fatalf("WriteVerifiedSBOM() error = %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read verified sbom: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("written SBOM bytes differ from verified bytes\ngot:  %q\nwant: %q", got, data)
	}
}

func minimalSPDXDocument() string {
	return `{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "demo",
  "documentNamespace": "https://bomly.dev/test/demo",
  "creationInfo": {
    "created": "2026-01-01T00:00:00Z",
    "creators": ["Tool: bomly-test"]
  },
  "packages": []
}`
}
