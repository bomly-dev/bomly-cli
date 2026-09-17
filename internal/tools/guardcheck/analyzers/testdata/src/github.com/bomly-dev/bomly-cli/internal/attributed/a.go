package attributed

import (
	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-sdk/model"
	"github.com/bomly-dev/bomly-sdk/plugin"
)

func wrapped(graphs *model.GraphContainer) (plugin.DetectionResult, error) {
	return detectors.Attributed(plugin.DetectionResult{Graphs: graphs}), nil
}

func exempt(graphs *model.GraphContainer) (plugin.DetectionResult, error) {
	return detectors.Unattributed(plugin.DetectionResult{Graphs: graphs}, "a workflow file is not a module"), nil
}

func bare(graphs *model.GraphContainer) (plugin.DetectionResult, error) {
	return plugin.DetectionResult{ // want `builds a detection result that carries graphs`
		DetectorName: "x",
		Graphs:       graphs,
	}, nil
}

// A result with no graphs has nothing to attribute.
func failed() (plugin.DetectionResult, error) {
	return plugin.DetectionResult{}, nil
}

func emptyReason(graphs *model.GraphContainer) plugin.DetectionResult {
	return detectors.Unattributed(plugin.DetectionResult{Graphs: graphs}, "") // want `needs a non-empty reason`
}

func computedReason(graphs *model.GraphContainer, why string) plugin.DetectionResult {
	return detectors.Unattributed(plugin.DetectionResult{Graphs: graphs}, why) // want `needs its reason as a string literal`
}

func staleExemption() plugin.DetectionResult {
	return detectors.Unattributed(plugin.DetectionResult{DetectorName: "x"}, "nothing here") // want `does not name Graphs`
}

// A result held in a variable and returned bare is reported where it is
// built, not where it is returned.
func viaVariable(graphs *model.GraphContainer) (plugin.DetectionResult, error) {
	result := plugin.DetectionResult{Graphs: graphs} // want `builds a detection result that carries graphs`
	return result, nil
}

// Wrapping later is reported too: the wrap belongs at the construction site.
func wrappedLater(graphs *model.GraphContainer) (plugin.DetectionResult, error) {
	result := plugin.DetectionResult{Graphs: graphs} // want `builds a detection result that carries graphs`
	return detectors.Attributed(result), nil
}

// A parenthesized argument is still the wrapper's argument.
func parenthesized(graphs *model.GraphContainer) plugin.DetectionResult {
	return detectors.Attributed((plugin.DetectionResult{Graphs: graphs}))
}

// Graphs set after construction escapes a literal-keyed rule; the assignment
// itself is reported.
func assignedLater(graphs *model.GraphContainer) (plugin.DetectionResult, error) {
	result := plugin.DetectionResult{}
	result.Graphs = graphs // want `assigns graphs onto a detection result`
	return result, nil
}

// Through a pointer as well.
func assignedThroughPointer(graphs *model.GraphContainer) (plugin.DetectionResult, error) {
	result := &plugin.DetectionResult{}
	result.Graphs = graphs // want `assigns graphs onto a detection result`
	return *result, nil
}

// A Graphs field on some other type is not the rule's business.
type unrelated struct{ Graphs *model.GraphContainer }

func otherType(graphs *model.GraphContainer) unrelated {
	u := unrelated{}
	u.Graphs = graphs
	return u
}
