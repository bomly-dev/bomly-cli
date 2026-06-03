package attestation

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/sbom"
	intoto "github.com/in-toto/attestation/go/v1"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	// PredicateTypeSBOM identifies Bomly's experimental SBOM predicate.
	PredicateTypeSBOM     = "https://bomly.dev/attestation/sbom/v1"
	payloadTypeInToto     = "application/vnd.in-toto+json"
	bundleMediaType       = "application/vnd.bomly.sbom-attestation.v1+json"
	sigstoreBundleV03Type = "application/vnd.dev.sigstore.bundle.v0.3+json"
	sbomRawBase64Field    = "sbomRawBase64"
)

// AttestRequest describes an SBOM attestation request.
type AttestRequest struct {
	SBOMPath string
	Subject  Subject
	KeyPath  string
	Keyless  bool
}

// VerifyRequest describes an SBOM attestation verification request.
type VerifyRequest struct {
	Bundle  []byte
	Subject Subject
	KeyPath string
}

// VerifyResult describes a verified SBOM attestation.
type VerifyResult struct {
	Subject    Subject
	SBOMFormat string
	SBOM       []byte
}

type bomlyBundle struct {
	MediaType      string          `json:"mediaType"`
	SigstoreBundle json.RawMessage `json:"sigstoreBundle"`
	PublicKeyPEM   string          `json:"publicKeyPem,omitempty"`
}

// BuildStatement builds an in-toto statement carrying a supported SBOM predicate.
func BuildStatement(subject Subject, sbomBytes []byte) (*intoto.Statement, error) {
	target, err := detectSupportedSBOM(sbomBytes)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(sbomBytes)
	predicate, err := structpb.NewStruct(map[string]any{
		"schemaVersion": "experimental/v1",
		"sbomFormat":    string(target),
		"sbomDigest": map[string]any{
			"sha256": hex.EncodeToString(sum[:]),
		},
		sbomRawBase64Field: base64.StdEncoding.EncodeToString(sbomBytes),
	})
	if err != nil {
		return nil, fmt.Errorf("build sbom predicate: %w", err)
	}
	statement := &intoto.Statement{
		Type:          intoto.StatementTypeUri,
		Subject:       []*intoto.ResourceDescriptor{resourceDescriptor(subject)},
		PredicateType: PredicateTypeSBOM,
		Predicate:     predicate,
	}
	if err := statement.Validate(); err != nil {
		return nil, fmt.Errorf("validate in-toto statement: %w", err)
	}
	return statement, nil
}

// Attest creates a signed experimental SBOM attestation bundle.
func Attest(ctx context.Context, req AttestRequest) ([]byte, error) {
	sbomBytes, err := os.ReadFile(req.SBOMPath)
	if err != nil {
		return nil, fmt.Errorf("read sbom: %w", err)
	}
	statement, err := BuildStatement(req.Subject, sbomBytes)
	if err != nil {
		return nil, err
	}
	statementBytes, err := protojson.MarshalOptions{UseProtoNames: false}.Marshal(statement)
	if err != nil {
		return nil, fmt.Errorf("marshal in-toto statement: %w", err)
	}
	keypair, err := loadSigningKey(req)
	if err != nil {
		return nil, err
	}
	protoBundle, err := signDSSEBundle(ctx, statementBytes, keypair)
	if err != nil {
		return nil, fmt.Errorf("sign sbom attestation: %w", err)
	}
	bundleBytes, err := protojson.MarshalOptions{UseProtoNames: false}.Marshal(protoBundle)
	if err != nil {
		return nil, fmt.Errorf("marshal sigstore bundle: %w", err)
	}
	publicKeyPEM, err := keypair.GetPublicKeyPem()
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}
	return json.MarshalIndent(bomlyBundle{
		MediaType:      bundleMediaType,
		SigstoreBundle: bundleBytes,
		PublicKeyPEM:   publicKeyPEM,
	}, "", "  ")
}

// Verify verifies an experimental SBOM attestation bundle and returns the embedded SBOM.
func Verify(_ context.Context, req VerifyRequest) (VerifyResult, error) {
	var wrapped bomlyBundle
	if err := json.Unmarshal(req.Bundle, &wrapped); err != nil {
		return VerifyResult{}, fmt.Errorf("parse attestation bundle: %w", err)
	}
	if wrapped.MediaType != bundleMediaType {
		return VerifyResult{}, fmt.Errorf("unsupported attestation media type %q", wrapped.MediaType)
	}
	var protoBundle protobundle.Bundle
	if err := protojson.Unmarshal(wrapped.SigstoreBundle, &protoBundle); err != nil {
		return VerifyResult{}, fmt.Errorf("parse sigstore bundle: %w", err)
	}
	envelope := protoBundle.GetDsseEnvelope()
	if envelope == nil {
		return VerifyResult{}, fmt.Errorf("attestation bundle does not contain a DSSE envelope")
	}
	if envelope.PayloadType != payloadTypeInToto {
		return VerifyResult{}, fmt.Errorf("unsupported DSSE payload type %q", envelope.PayloadType)
	}
	if len(envelope.Signatures) != 1 {
		return VerifyResult{}, fmt.Errorf("expected exactly one DSSE signature, got %d", len(envelope.Signatures))
	}
	publicKeyPEM := strings.TrimSpace(wrapped.PublicKeyPEM)
	if strings.TrimSpace(req.KeyPath) != "" {
		data, err := os.ReadFile(req.KeyPath)
		if err != nil {
			return VerifyResult{}, fmt.Errorf("read verification key: %w", err)
		}
		publicKeyPEM = string(data)
	}
	if err := verifyECDSADSSE(publicKeyPEM, envelope.PayloadType, envelope.Payload, envelope.Signatures[0].Sig); err != nil {
		return VerifyResult{}, err
	}
	var statement intoto.Statement
	if err := protojson.Unmarshal(envelope.Payload, &statement); err != nil {
		return VerifyResult{}, fmt.Errorf("parse in-toto statement: %w", err)
	}
	if err := statement.Validate(); err != nil {
		return VerifyResult{}, fmt.Errorf("validate in-toto statement: %w", err)
	}
	if statement.PredicateType != PredicateTypeSBOM {
		return VerifyResult{}, fmt.Errorf("unsupported predicate type %q", statement.PredicateType)
	}
	if !subjectMatches(req.Subject, statement.Subject) {
		return VerifyResult{}, fmt.Errorf("subject digest does not match attestation")
	}
	sbomBytes, target, err := sbomFromPredicate(statement.Predicate)
	if err != nil {
		return VerifyResult{}, err
	}
	return VerifyResult{Subject: req.Subject, SBOMFormat: string(target), SBOM: sbomBytes}, nil
}

func resourceDescriptor(subject Subject) *intoto.ResourceDescriptor {
	return &intoto.ResourceDescriptor{
		Name:   subject.Name,
		Uri:    subject.URI,
		Digest: subject.Digest,
	}
}

func detectSupportedSBOM(data []byte) (sbom.Target, error) {
	target, err := sbom.DetectJSONTarget(data)
	if err != nil {
		return "", fmt.Errorf("detect sbom format: %w", err)
	}
	switch target {
	case sbom.TargetSPDX23JSON, sbom.TargetCycloneDX14JSON, sbom.TargetCycloneDX15JSON, sbom.TargetCycloneDX16JSON:
		return target, nil
	default:
		return "", fmt.Errorf("unsupported sbom format %q for attestation", target)
	}
}

func sbomFromPredicate(predicate *structpb.Struct) ([]byte, sbom.Target, error) {
	if predicate == nil {
		return nil, "", fmt.Errorf("sbom predicate is missing")
	}
	formatValue := predicate.Fields["sbomFormat"].GetStringValue()
	if formatValue == "" {
		return nil, "", fmt.Errorf("sbom predicate is missing required fields")
	}
	raw, err := sbomBytesFromPredicate(predicate)
	if err != nil {
		return nil, "", err
	}
	target, err := detectSupportedSBOM(raw)
	if err != nil {
		return nil, "", err
	}
	if string(target) != formatValue {
		return nil, "", fmt.Errorf("sbom predicate format %q does not match embedded sbom %q", formatValue, target)
	}
	if err := verifySBOMDigest(predicate, raw); err != nil {
		return nil, "", err
	}
	return raw, target, nil
}

func sbomBytesFromPredicate(predicate *structpb.Struct) ([]byte, error) {
	rawBase64 := predicate.Fields[sbomRawBase64Field].GetStringValue()
	if rawBase64 == "" {
		return nil, fmt.Errorf("sbom predicate is missing required fields")
	}
	raw, err := base64.StdEncoding.DecodeString(rawBase64)
	if err != nil {
		return nil, fmt.Errorf("decode embedded sbom bytes: %w", err)
	}
	return raw, nil
}

func verifySBOMDigest(predicate *structpb.Struct, raw []byte) error {
	digestValue := predicate.Fields["sbomDigest"]
	if digestValue == nil {
		return nil
	}
	digestStruct := digestValue.GetStructValue()
	if digestStruct == nil {
		return fmt.Errorf("sbom predicate digest is malformed")
	}
	expected := digestStruct.Fields["sha256"].GetStringValue()
	if expected == "" {
		return fmt.Errorf("sbom predicate digest is missing sha256")
	}
	sum := sha256.Sum256(raw)
	if !strings.EqualFold(expected, hex.EncodeToString(sum[:])) {
		return fmt.Errorf("sbom digest does not match predicate")
	}
	return nil
}

func subjectMatches(expected Subject, actual []*intoto.ResourceDescriptor) bool {
	if len(actual) != 1 {
		return false
	}
	for alg, digest := range expected.Digest {
		if !strings.EqualFold(actual[0].Digest[alg], digest) {
			return false
		}
	}
	return true
}

func loadSigningKey(req AttestRequest) (*ecdsaKeypair, error) {
	if req.Keyless {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate keyless signing key: %w", err)
		}
		return newECDSAKeypair(privateKey)
	}
	if strings.TrimSpace(req.KeyPath) == "" {
		return nil, fmt.Errorf("--key or --keyless is required")
	}
	data, err := os.ReadFile(req.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("read signing key: %w", err)
	}
	privateKey, err := parseECDSAPrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("parse signing key: %w", err)
	}
	return newECDSAKeypair(privateKey)
}

func signDSSEBundle(ctx context.Context, payload []byte, keypair *ecdsaKeypair) (*protobundle.Bundle, error) {
	pae := dssePAE(payloadTypeInToto, payload)
	signature, _, err := keypair.SignData(ctx, pae)
	if err != nil {
		return nil, err
	}
	return &protobundle.Bundle{
		MediaType: sigstoreBundleV03Type,
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_PublicKey{
				PublicKey: &protocommon.PublicKeyIdentifier{Hint: string(keypair.GetHint())},
			},
		},
		Content: &protobundle.Bundle_DsseEnvelope{
			DsseEnvelope: &protodsse.Envelope{
				Payload:     payload,
				PayloadType: payloadTypeInToto,
				Signatures: []*protodsse.Signature{{
					Sig: signature,
				}},
			},
		},
	}, nil
}

func parseECDSAPrivateKey(data []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("PEM private key is required")
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("only ECDSA P-256 private keys are supported")
	}
	return key, nil
}

func verifyECDSADSSE(publicKeyPEM, payloadType string, payload, sig []byte) error {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return fmt.Errorf("public verification key is missing")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse public verification key: %w", err)
	}
	publicKey, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("only ECDSA public keys are supported")
	}
	pae := dssePAE(payloadType, payload)
	digest := sha256.Sum256(pae)
	if !ecdsa.VerifyASN1(publicKey, digest[:], sig) {
		return fmt.Errorf("attestation signature verification failed")
	}
	return nil
}

type ecdsaKeypair struct {
	privateKey *ecdsa.PrivateKey
	hint       []byte
}

func newECDSAKeypair(privateKey *ecdsa.PrivateKey) (*ecdsaKeypair, error) {
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(privateKey.Public())
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(pubKeyBytes)
	return &ecdsaKeypair{privateKey: privateKey, hint: []byte(base64.StdEncoding.EncodeToString(sum[:]))}, nil
}

func (k *ecdsaKeypair) GetHashAlgorithm() protocommon.HashAlgorithm {
	return protocommon.HashAlgorithm_SHA2_256
}

func (k *ecdsaKeypair) GetSigningAlgorithm() protocommon.PublicKeyDetails {
	return protocommon.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256
}

func (k *ecdsaKeypair) GetHint() []byte {
	return k.hint
}

func (k *ecdsaKeypair) GetKeyAlgorithm() string {
	return "ECDSA"
}

func (k *ecdsaKeypair) GetPublicKey() crypto.PublicKey {
	return k.privateKey.Public()
}

func (k *ecdsaKeypair) GetPublicKeyPem() (string, error) {
	data, err := x509.MarshalPKIXPublicKey(k.privateKey.Public())
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: data})), nil
}

func (k *ecdsaKeypair) SignData(_ context.Context, data []byte) ([]byte, []byte, error) {
	digest := sha256.Sum256(data)
	signature, err := k.privateKey.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return nil, nil, err
	}
	return signature, digest[:], nil
}

func dssePAE(payloadType string, payload []byte) []byte {
	return []byte(fmt.Sprintf("DSSEv1 %d %s %d %s", len(payloadType), payloadType, len(payload), payload))
}

// WriteVerifiedSBOM writes a verified SBOM to path.
func WriteVerifiedSBOM(path string, data []byte) error {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	if parent := filepath.Dir(path); parent != "." && parent != "" {
		if err := os.MkdirAll(parent, 0o755); err != nil {
			return fmt.Errorf("create verified sbom directory: %w", err)
		}
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write verified sbom: %w", err)
	}
	return nil
}
