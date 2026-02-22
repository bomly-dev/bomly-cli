package plugin

import (
	"errors"
	"fmt"

	"github.com/bomly/bomly-cli/internal/model"
	"github.com/bomly/bomly-cli/internal/sbom"
)

var (
	// ErrResolverNotFound indicates no plugin-backed resolver is available.
	ErrResolverNotFound = errors.New("plugin resolver not found")
)

func findPluginByName(plugins []Plugin, name string) (Plugin, bool) {
	for _, pluginInfo := range plugins {
		if pluginInfo.Metadata.Name == name {
			return pluginInfo, true
		}
	}
	return Plugin{}, false
}

func graphFromOutput(data []byte) (*model.Graph, error) {
	doc, _, err := sbom.UnmarshalAutoJSON(data)
	if err == nil && doc != nil {
		return sbom.ToGraph(doc)
	}
	return nil, fmt.Errorf("unsupported plugin dependency output")
}
