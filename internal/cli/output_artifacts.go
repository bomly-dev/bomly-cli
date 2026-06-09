package cli

import (
	"bytes"
	"fmt"
	"io"

	"github.com/bomly-dev/bomly-cli/internal/cli/render"
	"github.com/bomly-dev/bomly-cli/internal/output"
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

func hasOutputFormat(specs []render.OutputSpec, format output.Format) bool {
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

func validateReportOutputs(specs []render.OutputSpec) error {
	for _, spec := range specs {
		switch spec.Format {
		case output.FormatText, output.FormatJSON, output.FormatMarkdown, output.FormatSARIF:
		default:
			return fmt.Errorf("output format %q is only supported by scan", spec.Label)
		}
	}
	return nil
}

func validatePrimaryReportFormat(format output.Format) error {
	if format.IsSBOM() {
		return fmt.Errorf("--format %s is only supported by scan", format)
	}
	return nil
}

func writeReportOutput(stdout io.Writer, spec render.OutputSpec, payload any, renderers output.Renderers, sarifRenderer func(io.Writer) error) error {
	switch spec.Format {
	case output.FormatJSON, output.FormatMarkdown, output.FormatText:
		return writeRenderedOutput(stdout, spec, func(w io.Writer) error {
			return output.Write(w, spec.Format, payload, renderers)
		})
	case output.FormatSARIF:
		if sarifRenderer == nil {
			return fmt.Errorf("sarif output is not implemented")
		}
		return writeRenderedOutput(stdout, spec, sarifRenderer)
	default:
		return fmt.Errorf("output format %q is only supported by scan", spec.Label)
	}
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
