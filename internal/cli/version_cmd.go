package cli

import (
	"fmt"
	"runtime/debug"
	"strings"

	"github.com/spf13/cobra"
)

type dependencyVersion struct {
	Label   string
	Module  string
	Version string
}

var trackedDependencyVersions = []dependencyVersion{
	{Label: "Syft", Module: "github.com/anchore/syft"},
	{Label: "Grype", Module: "github.com/anchore/grype"},
}

func newVersionCmd(version string) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			options, err := commandOptions(cmd)
			if err != nil {
				return err
			}
			current := options.GetConfig()
			streams := newCommandStreams(cmd, current.Quiet, current.Verbosity)
			_, err = fmt.Fprintln(streams.reportWriter(), renderVersionDetails(version))
			return err
		},
	}
}

func versionDetailsTemplateValue(cmd *cobra.Command) string {
	if cmd == nil {
		return ""
	}
	return renderVersionDetails(cmd.Version)
}

func renderVersionDetails(coreVersion string) string {
	lines := []string{"bomly " + coreVersion, "", "Built-in third-party plugins:"}
	for _, item := range selectedDependencyVersions() {
		lines = append(lines, item.Label+" ("+item.Module+"): "+item.Version)
	}
	return strings.Join(lines, "\n")
}

func selectedDependencyVersions() []dependencyVersion {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return nil
	}

	resolved := make([]dependencyVersion, 0, len(trackedDependencyVersions))
	for _, tracked := range trackedDependencyVersions {
		version := moduleVersion(info, tracked.Module)
		if version == "" {
			continue
		}
		resolved = append(resolved, dependencyVersion{
			Label:   tracked.Label,
			Module:  tracked.Module,
			Version: version,
		})
	}
	return resolved
}

func moduleVersion(info *debug.BuildInfo, modulePath string) string {
	if info == nil || modulePath == "" {
		return ""
	}
	for _, dep := range info.Deps {
		if dep == nil || dep.Path != modulePath {
			continue
		}
		if dep.Replace != nil && dep.Replace.Version != "" {
			return dep.Replace.Version
		}
		return dep.Version
	}
	return ""
}

const rootVersionTemplate = `{{versionDetails .}}
`
