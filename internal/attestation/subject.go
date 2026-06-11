// Package attestation signs and verifies SBOM attestations.
package attestation

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/system"
)

// SubjectKind identifies the type of artifact an SBOM attestation describes.
type SubjectKind string

const (
	// SubjectKindFile identifies a single file subject.
	SubjectKindFile SubjectKind = "file"
	// SubjectKindDir identifies a deterministic filesystem tree subject.
	SubjectKindDir SubjectKind = "dir"
	// SubjectKindGit identifies a clean Git HEAD snapshot subject.
	SubjectKindGit SubjectKind = "git"
	// SubjectKindContainer identifies an immutable container image digest subject.
	SubjectKindContainer SubjectKind = "container"
)

var containerDigestPattern = regexp.MustCompile(`^(.+)@sha256:([a-fA-F0-9]{64})$`)

// SubjectOptions controls subject resolution.
type SubjectOptions struct {
	BaseDir      string
	ExcludePaths []string
}

// Subject describes the artifact bound to an SBOM attestation.
type Subject struct {
	Kind     SubjectKind       `json:"kind"`
	Name     string            `json:"name"`
	URI      string            `json:"uri,omitempty"`
	Digest   map[string]string `json:"digest"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// ResolveSubject resolves a user-facing subject spec into a stable attestation subject.
func ResolveSubject(spec string, opts SubjectOptions) (Subject, error) {
	spec = strings.TrimSpace(spec)
	switch {
	case spec == "git":
		return resolveGitSubject(opts)
	case strings.HasPrefix(spec, "file:"):
		return resolveFileSubject(strings.TrimPrefix(spec, "file:"))
	case strings.HasPrefix(spec, "dir:"):
		return resolveDirSubject(strings.TrimPrefix(spec, "dir:"), opts)
	case strings.HasPrefix(spec, "container:"):
		return resolveContainerSubject(strings.TrimPrefix(spec, "container:"))
	default:
		return Subject{}, fmt.Errorf("unsupported subject %q (accepted: file:<path>, dir:<path>, git, container:<image@sha256:...>)", spec)
	}
}

func resolveFileSubject(path string) (Subject, error) {
	absPath, err := system.ResolveExistingFile(path)
	if err != nil {
		return Subject{}, fmt.Errorf("resolve file subject: %w", err)
	}
	digest, err := fileSHA256(absPath)
	if err != nil {
		return Subject{}, fmt.Errorf("hash file subject %q: %w", path, err)
	}
	return Subject{
		Kind:   SubjectKindFile,
		Name:   "file:" + absPath,
		URI:    "file://" + filepath.ToSlash(absPath),
		Digest: map[string]string{"sha256": digest},
	}, nil
}

func resolveDirSubject(path string, opts SubjectOptions) (Subject, error) {
	selectedPath := strings.TrimSpace(path)
	if selectedPath == "" {
		selectedPath = opts.BaseDir
	}
	if selectedPath == "" {
		selectedPath = "."
	}
	absPath, err := filepath.Abs(selectedPath)
	if err != nil {
		return Subject{}, fmt.Errorf("resolve dir subject %q: %w", selectedPath, err)
	}
	info, err := os.Stat(absPath)
	if err != nil {
		return Subject{}, fmt.Errorf("stat dir subject %q: %w", selectedPath, err)
	}
	if !info.IsDir() {
		return Subject{}, fmt.Errorf("dir subject %q is not a directory", selectedPath)
	}
	digest, err := dirSHA256(absPath, opts.ExcludePaths)
	if err != nil {
		return Subject{}, fmt.Errorf("hash dir subject %q: %w", selectedPath, err)
	}
	return Subject{
		Kind:   SubjectKindDir,
		Name:   "dir:" + absPath,
		URI:    "file://" + filepath.ToSlash(absPath),
		Digest: map[string]string{"sha256": digest},
	}, nil
}

func resolveContainerSubject(ref string) (Subject, error) {
	ref = strings.TrimSpace(ref)
	match := containerDigestPattern.FindStringSubmatch(ref)
	if match == nil {
		return Subject{}, fmt.Errorf("container subject requires image@sha256:<digest>; tags are not accepted for attestation subjects")
	}
	digest := strings.ToLower(match[2])
	return Subject{
		Kind:   SubjectKindContainer,
		Name:   "container:" + ref,
		URI:    "oci://" + ref,
		Digest: map[string]string{"sha256": digest},
		Metadata: map[string]string{
			"image":  match[1],
			"digest": "sha256:" + digest,
		},
	}, nil
}

func resolveGitSubject(opts SubjectOptions) (Subject, error) {
	repoPath := strings.TrimSpace(opts.BaseDir)
	if repoPath == "" {
		repoPath = "."
	}
	root, err := gitOutput(repoPath, "rev-parse", "--show-toplevel")
	if err != nil {
		return Subject{}, fmt.Errorf("find git repository root: %w", err)
	}
	root = strings.TrimSpace(root)
	status, err := gitOutput(root, "status", "--porcelain")
	if err != nil {
		return Subject{}, fmt.Errorf("inspect git worktree: %w", err)
	}
	if strings.TrimSpace(status) != "" {
		return Subject{}, fmt.Errorf("git subject requires a clean worktree")
	}
	head, err := gitOutput(root, "rev-parse", "HEAD")
	if err != nil {
		return Subject{}, fmt.Errorf("resolve git HEAD: %w", err)
	}
	head = strings.TrimSpace(head)
	remote, err := gitOutput(root, "remote", "get-url", "origin")
	if err != nil {
		remote = root
	}
	remote = strings.TrimSpace(remote)
	if remote == "" {
		remote = root
	}
	archiveDigest, err := gitArchiveSHA256(root)
	if err != nil {
		return Subject{}, fmt.Errorf("hash git archive: %w", err)
	}
	return Subject{
		Kind: SubjectKindGit,
		Name: "git:" + remote + "@" + head,
		URI:  "git+" + remote + "@" + head,
		Digest: map[string]string{
			"sha256": archiveDigest,
		},
		Metadata: map[string]string{
			"commit": head,
			"remote": remote,
		},
	}, nil
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func dirSHA256(root string, excludePaths []string) (string, error) {
	excluded := normalizedExcludeSet(excludePaths)
	entries := make([]string, 0)
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := entry.Name()
		if entry.IsDir() {
			switch name {
			case ".git", ".hg", ".svn":
				return filepath.SkipDir
			}
			return nil
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		absPath, err := filepath.Abs(path)
		if err != nil {
			return err
		}
		if _, ok := excluded[filepath.Clean(absPath)]; ok {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		digest, err := fileSHA256(path)
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		entries = append(entries, filepath.ToSlash(rel)+"\x00"+digest+"\x00"+fmt.Sprint(info.Size()))
		return nil
	}); err != nil {
		return "", err
	}
	sort.Strings(entries)
	hash := sha256.New()
	for _, entry := range entries {
		_, _ = io.WriteString(hash, entry)
		_, _ = hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func normalizedExcludeSet(paths []string) map[string]struct{} {
	out := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		if strings.TrimSpace(path) == "" {
			continue
		}
		absPath, err := filepath.Abs(path)
		if err != nil {
			continue
		}
		out[filepath.Clean(absPath)] = struct{}{}
	}
	return out
}

func gitArchiveSHA256(repoPath string) (string, error) {
	cmd := system.Command("git", "archive", "--format=tar", "HEAD")
	cmd.Dir = repoPath
	data, err := cmd.Output()
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	reader := tar.NewReader(bytes.NewReader(data))
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
		if header.Typeflag != tar.TypeReg {
			continue
		}
		_, _ = io.WriteString(hash, header.Name)
		_, _ = hash.Write([]byte{0})
		fileHash := sha256.New()
		if _, err := io.Copy(fileHash, reader); err != nil {
			return "", err
		}
		_, _ = io.WriteString(hash, hex.EncodeToString(fileHash.Sum(nil)))
		_, _ = hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func gitOutput(workingDir string, args ...string) (string, error) {
	cmd := system.Command("git", args...)
	cmd.Dir = workingDir
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			return "", fmt.Errorf("%w: %s", err, msg)
		}
		return "", err
	}
	return stdout.String(), nil
}
