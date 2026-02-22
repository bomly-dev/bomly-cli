package auditors

import "github.com/bomly/bomly-cli/internal/scan"

// Descriptor re-exports the shared auditor descriptor type.
type Descriptor = scan.AuditorDescriptor

// Auditor re-exports the shared auditor contract for concrete auditor packages.
type Auditor = scan.Auditor
