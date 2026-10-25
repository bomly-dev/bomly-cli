package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/engine"
	managedplugin "github.com/bomly-dev/bomly-cli/internal/plugin"

	"github.com/bomly-dev/bomly-sdk/plugin"
)

// renderAccessDisclosure writes a managed plugin's declared access, labelled
// as the publisher's unverified claim. Bomly enforces none of it: a managed
// plugin is a native process with the invoking user's authority, so the
// wording never says the plugin is limited to what it declares. A manifest
// with no access block is shown as unknown, which means unrestricted.
//
// Every install, enable, info, verify and doctor view goes through this one
// function, so the label cannot drift between them.
func renderAccessDisclosure(w io.Writer, access *plugin.Access) error {
	if access == nil {
		_, err := fmt.Fprint(w, "Declared access: unknown\n"+
			"  The manifest declares no access. Assume the plugin can use everything your\n"+
			"  user account can: files, network, environment variables, and child processes.\n")
		return err
	}
	rows := [][2]string{
		{"Filesystem read", accessList(scopeStrings(access.FilesystemRead), "")},
		{"Filesystem write", accessList(scopeStrings(access.FilesystemWrite), "")},
		{"Network", accessList(access.Network, "any destination")},
		{"Environment", accessList(access.Environment, "any variable")},
		{"Subprocesses", accessList(access.Subprocesses, "any command")},
	}
	if _, err := fmt.Fprint(w, "Declared access (the publisher's claim; Bomly does not verify or enforce it):\n"); err != nil {
		return err
	}
	for _, row := range rows {
		if _, err := fmt.Fprintf(w, "  %-16s : %s\n", row[0], row[1]); err != nil {
			return err
		}
	}
	return nil
}

// accessList joins one declared list for display. An empty list is the
// publisher's claim of no access of that kind. anyLabel names the
// plugin.AccessAny entry in words, when the list allows one.
func accessList(values []string, anyLabel string) string {
	if len(values) == 0 {
		return "none declared"
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == plugin.AccessAny && anyLabel != "" {
			value = anyLabel
		}
		out = append(out, value)
	}
	return strings.Join(out, ", ")
}

func scopeStrings(scopes []plugin.FilesystemScope) []string {
	out := make([]string, len(scopes))
	for i, scope := range scopes {
		out[i] = string(scope)
	}
	return out
}

// renderInstalledAccess writes the disclosure for an installed managed
// plugin and nothing for a built-in component, which is part of Bomly.
func renderInstalledAccess(w io.Writer, info managedplugin.Info) error {
	if info.BuiltIn {
		return nil
	}
	return renderAccessDisclosure(w, info.Access)
}

// pluginInfoRequirements returns the requirements a component's descriptor
// declares, whichever kind it is.
func pluginInfoRequirements(info managedplugin.Info) plugin.Requirements {
	switch {
	case info.DetectorDescriptor != nil:
		return info.DetectorDescriptor.Requires.Normalized()
	case info.MatcherDescriptor != nil:
		return info.MatcherDescriptor.Requires.Normalized()
	case info.AuditorDescriptor != nil:
		return info.AuditorDescriptor.Requires.Normalized()
	case info.AnalyzerDescriptor != nil:
		return info.AnalyzerDescriptor.Requires.Normalized()
	default:
		return nil
	}
}

// joinRequirements renders declared requirements, marking any token this
// Bomly cannot evaluate, since preflight treats it as never satisfied.
func joinRequirements(requirements plugin.Requirements) string {
	out := make([]string, 0, len(requirements))
	for _, requirement := range requirements {
		value := string(requirement)
		if !engine.Evaluates(requirement) {
			value += " (unknown to this Bomly version)"
		}
		out = append(out, value)
	}
	return strings.Join(out, ", ")
}
