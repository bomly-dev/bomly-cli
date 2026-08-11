//go:build !bomly_external_grype

package grype

import (
	"regexp"
	"slices"
	"strings"

	grypedistro "github.com/anchore/grype/grype/distro"
	grypepkg "github.com/anchore/grype/grype/pkg"
	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/bomly-dev/bomly-sdk"
)

// sourceRPMPattern extracts the name, version, release, and arch from a source
// RPM file name (e.g. "util-linux-ng-2.17.2-12.28.el6_9.2.src.rpm"). It mirrors
// the pattern Grype uses for the same purpose so upstream matching behaves the
// same whether Grype reads the package or Bomly hands it over.
var sourceRPMPattern = regexp.MustCompile(`^(?P<name>.*)-(?P<version>.*)-(?P<release>.*)\.(?P<arch>[a-zA-Z][^.]+)(\.rpm)$`)

// distroFromPURL derives the Grype distro from the `distro` PURL qualifier.
//
// Grype's OS matchers (apk, dpkg, rpm, portage, pacman) are distro-namespace
// driven: a package without a distro matches nothing at all. Syft records the
// distro it detected while cataloguing an image as a PURL qualifier, so the
// qualifier is the one carrier that survives both live image scans and SBOM
// input. This mirrors Grype's own PURL provider.
func distroFromPURL(purl string) *grypedistro.Distro {
	parsed := sdk.ParsePackageURL(purl)
	if parsed == nil {
		return nil
	}
	for _, qualifier := range parsed.Qualifiers {
		if qualifier.Key != syftPkg.PURLQualifierDistro {
			continue
		}
		name, version := grypedistro.ParseDistroString(qualifier.Value)
		if name == "" {
			continue
		}
		if distro := grypedistro.NewFromNameVersion(name, version); distro != nil {
			return distro
		}
	}
	return nil
}

// upstreamsFromPURL derives the origin (source) packages from the `upstream`
// PURL qualifier. Distro advisories are frequently recorded against the source
// package rather than the binary package built from it (an Alpine origin
// package, a Debian source package, a source RPM), so without upstreams the OS
// matchers still under-report. This mirrors Grype's own PURL provider.
func upstreamsFromPURL(purl, name string, syftType syftPkg.Type) []grypepkg.UpstreamPackage {
	parsed := sdk.ParsePackageURL(purl)
	if parsed == nil {
		return nil
	}
	var upstreams []grypepkg.UpstreamPackage
	for _, qualifier := range parsed.Qualifiers {
		if qualifier.Key != syftPkg.PURLQualifierUpstream {
			continue
		}
		for _, upstream := range parseUpstream(name, qualifier.Value, syftType) {
			if slices.Contains(upstreams, upstream) {
				continue
			}
			upstreams = append(upstreams, upstream)
		}
	}
	return upstreams
}

func parseUpstream(name, value string, syftType syftPkg.Type) []grypepkg.UpstreamPackage {
	if syftType == syftPkg.RpmPkg {
		return upstreamsFromSourceRPM(name, value)
	}
	fields := strings.Split(value, "@")
	switch len(fields) {
	case 1:
		if fields[0] == name || fields[0] == "" {
			return nil
		}
		return []grypepkg.UpstreamPackage{{Name: fields[0]}}
	case 2:
		if fields[0] == name || fields[0] == "" {
			return nil
		}
		return []grypepkg.UpstreamPackage{{Name: fields[0], Version: fields[1]}}
	}
	return nil
}

func upstreamsFromSourceRPM(name, sourceRPM string) []grypepkg.UpstreamPackage {
	groups := sourceRPMPattern.FindStringSubmatch(sourceRPM)
	if groups == nil {
		return nil
	}
	upstreamName := groups[sourceRPMPattern.SubexpIndex("name")]
	version := groups[sourceRPMPattern.SubexpIndex("version")]
	release := groups[sourceRPMPattern.SubexpIndex("release")]
	if upstreamName == "" || upstreamName == name || version == "" || release == "" {
		return nil
	}
	return []grypepkg.UpstreamPackage{{Name: upstreamName, Version: version + "-" + release}}
}
