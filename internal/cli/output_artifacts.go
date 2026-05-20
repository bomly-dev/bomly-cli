package cli

import (
	"bytes"
	"fmt"
	"io"

	"github.com/bomly-dev/bomly-cli/internal/cli/render"
)

func parseOutputSpecs(values []string) ([]render.OutputSpec, error) {
	if len(values) == 0 {
		return nil, nil
	}
	return render.ParseOutputSpecs(values)
}

func hasStdoutOutput(specs []render.OutputSpec) bool {
	for _, spec := range specs {
		if spec.Path == "" {
			return true
		}
	}
	return false
}

func hasOutputFormat(specs []render.OutputSpec, format render.OutputFormat) bool {
	for _, spec := range specs {
		if spec.Format == format {
			return true
		}
	}
	return false
}

func allOutputsAreSBOM(specs []render.OutputSpec) bool {
	if len(specs) == 0 {
		return false
	}
	for _, spec := range specs {
		if !spec.IsSBOM() {
			return false
		}
	}
	return true
}

func validateMarkdownOnlyOutputs(specs []render.OutputSpec) error {
	for _, spec := range specs {
		if spec.Format != render.OutputFormatMarkdown {
			return fmt.Errorf("output format %q is only supported by scan", spec.Label)
		}
	}
	return nil
}

func validateReportOutputs(specs []render.OutputSpec) error {
	for _, spec := range specs {
		switch spec.Format {
		case render.OutputFormatMarkdown, render.OutputFormatSARIF:
		default:
			return fmt.Errorf("output format %q is only supported by scan", spec.Label)
		}
	}
	return nil
}

func writeRenderedOutput(stdout io.Writer, spec render.OutputSpec, renderer func(io.Writer) error) error {
	var buf bytes.Buffer
	if err := renderer(&buf); err != nil {
		return err
	}
	if err := render.WriteOutputDocument(stdout, spec, bytes.TrimRight(buf.Bytes(), "\n")); err != nil {
		return fmt.Errorf("write %s output: %w", spec.Label, err)
	}
	return nil
}
