// Package plugin is a stand-in for bomly-sdk/plugin with just the surface the
// analyzers resolve: the detection result a detector returns.
package plugin

import "github.com/bomly-dev/bomly-sdk/model"

// DetectionResult is what a detector returns.
type DetectionResult struct {
	DetectorName string
	Graphs       *model.GraphContainer
}
