//go:build !bomly_external_grype

package grype

import (
	"testing"

	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/bomly-dev/bomly-cli/sdk"
)

// The declared ecosystem list is what the generated docs and `bomly plugins
// list` show, so it has to stay in step with what ecosystemToSyftType can
// actually map. This fails if a case is added to one without the other.
func TestSupportedEcosystemsMatchSyftTypeMapping(t *testing.T) {
	all := []sdk.Ecosystem{
		sdk.EcosystemNPM, sdk.EcosystemMaven, sdk.EcosystemGo, sdk.EcosystemPython,
		sdk.EcosystemALPM, sdk.EcosystemAPK, sdk.EcosystemCPP, sdk.EcosystemConda,
		sdk.EcosystemDart, sdk.EcosystemDPKG, sdk.EcosystemElixir, sdk.EcosystemErlang,
		sdk.EcosystemGitHub, sdk.EcosystemHaskell, sdk.EcosystemHomebrew, sdk.EcosystemLua,
		sdk.EcosystemDotNet, sdk.EcosystemNix, sdk.EcosystemOCaml, sdk.EcosystemPHP,
		sdk.EcosystemPortage, sdk.EcosystemProlog, sdk.EcosystemR, sdk.EcosystemRPM,
		sdk.EcosystemRuby, sdk.EcosystemRust, sdk.EcosystemScala, sdk.EcosystemSBOM,
		sdk.EcosystemSnap, sdk.EcosystemSwift, sdk.EcosystemTerraform,
		sdk.EcosystemWordPress, sdk.EcosystemOther,
	}

	declared := make(map[sdk.Ecosystem]bool, len(supportedEcosystems))
	for _, eco := range supportedEcosystems {
		declared[eco] = true
	}

	for _, eco := range all {
		mappable := ecosystemToSyftType(string(eco)) != syftPkg.UnknownPkg
		if mappable && !declared[eco] {
			t.Errorf("ecosystemToSyftType maps %q but supportedEcosystems omits it", eco)
		}
		if !mappable && declared[eco] {
			t.Errorf("supportedEcosystems declares %q but ecosystemToSyftType does not map it", eco)
		}
	}
}
