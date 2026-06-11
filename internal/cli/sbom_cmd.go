package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/attestation"
	"github.com/bomly-dev/bomly-cli/internal/cli/exit"
	"github.com/spf13/cobra"
)

func newSBOMCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sbom",
		Short: "Work with SBOM artifacts",
		Example: "  bomly sbom attest --sbom bomly.spdx.json --subject git --output bomly.att.json --keyless\n" +
			"  bomly sbom verify --attestation bomly.att.json --subject git --extract-sbom verified.spdx.json",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}
	cmd.AddCommand(newSBOMAttestCmd(), newSBOMVerifyCmd())
	return cmd
}

func newSBOMAttestCmd() *cobra.Command {
	var sbomPath string
	var subjectSpec string
	var outputPath string
	var keyPath string
	var keyless bool
	cmd := &cobra.Command{
		Use:   "attest",
		Short: "[Experimental] Create a signed SBOM attestation",
		Example: "  bomly sbom attest --sbom bomly.spdx.json --subject git --output bomly.att.json --keyless\n" +
			"  bomly sbom attest --sbom bomly.cdx.json --subject dir:. --output bomly.att.json --key signing-key.pem\n" +
			"  bomly sbom attest --sbom image.spdx.json --subject container:ghcr.io/acme/app@sha256:<digest> --output image.att.json --keyless",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(sbomPath) == "" {
				return exit.InvalidInputError("--sbom is required")
			}
			if strings.TrimSpace(subjectSpec) == "" {
				return exit.InvalidInputError("--subject is required")
			}
			if strings.TrimSpace(outputPath) == "" {
				return exit.InvalidInputError("--output is required")
			}
			if keyless && strings.TrimSpace(keyPath) != "" {
				return exit.InvalidInputError("--keyless cannot be combined with --key")
			}
			if !keyless && strings.TrimSpace(keyPath) == "" {
				return exit.InvalidInputError("--key or --keyless is required")
			}
			subject, err := resolveAttestationSubject(subjectSpec, sbomPath, outputPath)
			if err != nil {
				return exit.InvalidInputError("%v", err)
			}
			bundle, err := attestation.Attest(context.Background(), attestation.AttestRequest{
				SBOMPath: sbomPath,
				Subject:  subject,
				KeyPath:  keyPath,
				Keyless:  keyless,
			})
			if err != nil {
				return err
			}
			if err := writeAttestationOutput(outputPath, bundle); err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Wrote SBOM attestation to %s\n", outputPath)
			return err
		},
	}
	cmd.Flags().StringVar(&sbomPath, "sbom", "", "SBOM JSON file to attest (SPDX 2.3 or CycloneDX)")
	cmd.Flags().StringVar(&subjectSpec, "subject", "", "Attestation subject: file:<path>, dir:<path>, git, or container:<image@sha256:...>")
	cmd.Flags().StringVar(&outputPath, "output", "", "Path to write the attestation bundle")
	cmd.Flags().StringVar(&keyPath, "key", "", "ECDSA P-256 PEM private key used to sign the attestation")
	cmd.Flags().BoolVar(&keyless, "keyless", false, "Generate an experimental self-contained keyless bundle")
	return cmd
}

func newSBOMVerifyCmd() *cobra.Command {
	var attestationPath string
	var subjectSpec string
	var keyPath string
	var certIdentity string
	var certIssuer string
	var extractPath string
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "[Experimental] Verify a signed SBOM attestation",
		Example: "  bomly sbom verify --attestation bomly.att.json --subject git\n" +
			"  bomly sbom verify --attestation bomly.att.json --subject dir:. --key signing-key.pub.pem\n" +
			"  bomly sbom verify --attestation bomly.att.json --subject dir:. --extract-sbom verified.spdx.json",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(attestationPath) == "" {
				return exit.InvalidInputError("--attestation is required")
			}
			if strings.TrimSpace(subjectSpec) == "" {
				return exit.InvalidInputError("--subject is required")
			}
			if strings.TrimSpace(certIdentity) != "" || strings.TrimSpace(certIssuer) != "" {
				return exit.InvalidInputError("certificate identity verification is not available in the experimental local-key MVP; use --key or a self-contained bundle")
			}
			subject, err := resolveAttestationSubject(subjectSpec, "", "")
			if err != nil {
				return exit.InvalidInputError("%v", err)
			}
			bundle, err := os.ReadFile(attestationPath)
			if err != nil {
				return fmt.Errorf("read attestation: %w", err)
			}
			result, err := attestation.Verify(context.Background(), attestation.VerifyRequest{
				Bundle:  bundle,
				Subject: subject,
				KeyPath: keyPath,
			})
			if err != nil {
				return err
			}
			if err := attestation.WriteVerifiedSBOM(extractPath, result.SBOM); err != nil {
				return err
			}
			if extractPath != "" {
				_, err = fmt.Fprintf(cmd.OutOrStdout(), "Verified SBOM attestation (%s); extracted SBOM to %s\n", result.SBOMFormat, extractPath)
			} else {
				_, err = fmt.Fprintf(cmd.OutOrStdout(), "Verified SBOM attestation (%s)\n", result.SBOMFormat)
			}
			return err
		},
	}
	cmd.Flags().StringVar(&attestationPath, "attestation", "", "Attestation bundle to verify")
	cmd.Flags().StringVar(&subjectSpec, "subject", "", "Expected attestation subject: file:<path>, dir:<path>, git, or container:<image@sha256:...>")
	cmd.Flags().StringVar(&keyPath, "key", "", "ECDSA P-256 PEM public key used to verify a key-signed attestation")
	cmd.Flags().StringVar(&certIdentity, "certificate-identity", "", "Expected Sigstore certificate identity (reserved for future identity bundles)")
	cmd.Flags().StringVar(&certIssuer, "certificate-oidc-issuer", "", "Expected Sigstore OIDC issuer (reserved for future identity bundles)")
	cmd.Flags().StringVar(&extractPath, "extract-sbom", "", "Write the verified embedded SBOM to this path")
	return cmd
}

func resolveAttestationSubject(subjectSpec, sbomPath, outputPath string) (attestation.Subject, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return attestation.Subject{}, fmt.Errorf("resolve current directory: %w", err)
	}
	excludes := []string{}
	for _, path := range []string{sbomPath, outputPath} {
		if strings.TrimSpace(path) == "" {
			continue
		}
		absPath, err := filepath.Abs(path)
		if err == nil {
			excludes = append(excludes, absPath)
		}
	}
	return attestation.ResolveSubject(subjectSpec, attestation.SubjectOptions{
		BaseDir:      cwd,
		ExcludePaths: excludes,
	})
}

func writeAttestationOutput(path string, data []byte) error {
	if parent := filepath.Dir(path); parent != "." && parent != "" {
		if err := os.MkdirAll(parent, 0o755); err != nil {
			return fmt.Errorf("create attestation output directory: %w", err)
		}
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		return fmt.Errorf("write attestation output: %w", err)
	}
	return nil
}
