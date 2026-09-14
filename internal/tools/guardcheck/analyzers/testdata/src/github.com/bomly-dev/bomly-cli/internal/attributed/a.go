package attributed

import (
	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-sdk"
)

func wrapped(graphs *sdk.GraphContainer) (sdk.DetectionResult, error) {
	return detectors.Attributed(sdk.DetectionResult{Graphs: graphs}), nil
}

func exempt(graphs *sdk.GraphContainer) (sdk.DetectionResult, error) {
	return detectors.Unattributed(sdk.DetectionResult{Graphs: graphs}, "a workflow file is not a module"), nil
}

func bare(graphs *sdk.GraphContainer) (sdk.DetectionResult, error) {
	return sdk.DetectionResult{ // want `builds a detection result that carries graphs`
		DetectorName: "x",
		Graphs:       graphs,
	}, nil
}

// A result with no graphs has nothing to attribute.
func failed() (sdk.DetectionResult, error) {
	return sdk.DetectionResult{}, nil
}

func emptyReason(graphs *sdk.GraphContainer) sdk.DetectionResult {
	return detectors.Unattributed(sdk.DetectionResult{Graphs: graphs}, "") // want `needs a non-empty reason`
}

func computedReason(graphs *sdk.GraphContainer, why string) sdk.DetectionResult {
	return detectors.Unattributed(sdk.DetectionResult{Graphs: graphs}, why) // want `needs its reason as a string literal`
}

func staleExemption() sdk.DetectionResult {
	return detectors.Unattributed(sdk.DetectionResult{DetectorName: "x"}, "nothing here") // want `does not name Graphs`
}

// A result held in a variable and returned bare is reported where it is
// built, not where it is returned.
func viaVariable(graphs *sdk.GraphContainer) (sdk.DetectionResult, error) {
	result := sdk.DetectionResult{Graphs: graphs} // want `builds a detection result that carries graphs`
	return result, nil
}

// Wrapping later is reported too: the wrap belongs at the construction site.
func wrappedLater(graphs *sdk.GraphContainer) (sdk.DetectionResult, error) {
	result := sdk.DetectionResult{Graphs: graphs} // want `builds a detection result that carries graphs`
	return detectors.Attributed(result), nil
}

// A parenthesized argument is still the wrapper's argument.
func parenthesized(graphs *sdk.GraphContainer) sdk.DetectionResult {
	return detectors.Attributed((sdk.DetectionResult{Graphs: graphs}))
}
