package sdk

// ExecutionTargetKind identifies the top-level source selected by the user for one scan execution.
type ExecutionTargetKind string

const (
	// ExecutionTargetFilesystem points at a local filesystem path. The path may be a
	// directory or a single file depending on the selected scan target.
	ExecutionTargetFilesystem ExecutionTargetKind = "filesystem"
	// ExecutionTargetWorkingDirectory is kept as an alias for the existing local-path model.
	ExecutionTargetWorkingDirectory ExecutionTargetKind = ExecutionTargetFilesystem
	ExecutionTargetGitRepository    ExecutionTargetKind = "git-repository"
	ExecutionTargetContainerImage   ExecutionTargetKind = "container-image"
)

type ExecutionTarget struct {
	Kind          ExecutionTargetKind `json:"kind,omitempty"`
	Location      string              `json:"location,omitempty"`
	RepositoryURL string              `json:"repositoryUrl,omitempty"`
	Ref           string              `json:"ref,omitempty"`
}

// Subproject identifies one package-manager root discovered beneath the execution target.
type Subproject struct {
	ExecutionTarget         ExecutionTarget  `json:"executionTarget"`
	RelativePath            string           `json:"relativePath,omitempty"`
	PrimaryDetector         string           `json:"primaryDetector,omitempty"`
	DetectedPackageManagers []PackageManager `json:"detectedPackageManagers,omitempty"`
	PlannedDetectors        []string         `json:"plannedDetectors,omitempty"`
	Ecosystem               Ecosystem        `json:"ecosystem,omitempty"`
}

// PrimaryPackageManager returns the first entry in DetectedPackageManagers, or
// PackageManagerUnknown if the list is empty.
func (s Subproject) PrimaryPackageManager() PackageManager {
	if len(s.DetectedPackageManagers) == 0 || s.ExecutionTarget.Kind == ExecutionTargetContainerImage {
		return PackageManagerUnknown
	}
	return s.DetectedPackageManagers[0]
}

// PackageQuery identifies a specific package target.
type PackageQuery struct {
	Name string `json:"name,omitempty"`
	ID   string `json:"id,omitempty"`
}
