// Package detectors is a stand-in for the CLI's detectors package: the two
// functions a detection result may be returned through.
package detectors

import "github.com/bomly-dev/bomly-sdk"

// Attributed records module roots on the result's locations.
func Attributed(result sdk.DetectionResult, declarations ...any) sdk.DetectionResult { return result }

// Unattributed returns the result unchanged, with the reason there is no root.
func Unattributed(result sdk.DetectionResult, reason string) sdk.DetectionResult { return result }
