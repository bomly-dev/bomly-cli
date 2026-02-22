package registry

import "github.com/bomly/bomly-cli/internal/model"

// RenderSupportMatrixMarkdown renders the canonical markdown support matrix document.
func RenderSupportMatrixMarkdown() string {
	return model.RenderSupportMatrixMarkdown()
}
