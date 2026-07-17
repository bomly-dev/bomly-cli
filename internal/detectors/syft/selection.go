package syft

import (
	"strings"

	"github.com/anchore/syft/syft/cataloging"
	"github.com/bomly-dev/bomly-cli/sdk"
)

func syftCatalogerExpressions(req sdk.DetectionRequest) []string {
	if expressions := syftCatalogerExpressionsForManager(req.PackageManager); len(expressions) > 0 {
		return expressions
	}
	return syftCatalogerExpressionsForEcosystem(req.Ecosystem)
}

func syftCatalogerExpressionsForManager(manager sdk.PackageManager) []string {
	switch manager {
	case sdk.PackageManagerNPM, sdk.PackageManagerPNPM, sdk.PackageManagerYarn, sdk.PackageManagerBun:
		return []string{"npm"}
	case sdk.PackageManagerGoMod:
		return []string{"gomod"}
	case sdk.PackageManagerMaven:
		return []string{"maven"}
	case sdk.PackageManagerGradle:
		return []string{"gradle"}
	case sdk.PackageManagerPip, sdk.PackageManagerPipenv, sdk.PackageManagerPoetry, sdk.PackageManagerUV:
		return []string{"python"}
	case sdk.PackageManagerComposer:
		return []string{"composer"}
	case sdk.PackageManagerBundler:
		return []string{"ruby"}
	case sdk.PackageManagerCargo:
		return []string{"cargo"}
	case sdk.PackageManagerAPK:
		return []string{"apk"}
	case sdk.PackageManagerDPKG:
		return []string{"dpkg"}
	case sdk.PackageManagerRPM:
		return []string{"rpm"}
	case sdk.PackageManagerHomebrew:
		return []string{"homebrew"}
	case sdk.PackageManagerNix:
		return []string{"nix"}
	case sdk.PackageManagerALPM:
		return []string{"alpm"}
	case sdk.PackageManagerConda:
		return []string{"conda"}
	case sdk.PackageManagerNuGet:
		return []string{"dotnet"}
	case sdk.PackageManagerSwiftPM, sdk.PackageManagerCocoaPods:
		return []string{"swift"}
	case sdk.PackageManagerPub:
		return []string{"dart"}
	case sdk.PackageManagerRPackage:
		return []string{"r"}
	case sdk.PackageManagerCabal, sdk.PackageManagerStack:
		return []string{"haskell"}
	case sdk.PackageManagerLuaRocks:
		return []string{"lua"}
	case sdk.PackageManagerOpam:
		return []string{"ocaml"}
	case sdk.PackageManagerRebar, sdk.PackageManagerOTP:
		return []string{"erlang"}
	case sdk.PackageManagerMix:
		return []string{"elixir"}
	case sdk.PackageManagerTerraform:
		return []string{"terraform"}
	case sdk.PackageManagerWordPress:
		return []string{"wordpress"}
	case sdk.PackageManagerConan:
		return []string{"cpp"}
	case sdk.PackageManagerPortage:
		return []string{"portage"}
	case sdk.PackageManagerSWIPLPack:
		return []string{"prolog"}
	case sdk.PackageManagerSnap:
		return []string{"snap"}
	default:
		return nil
	}
}

func syftCatalogerExpressionsForEcosystem(ecosystem sdk.Ecosystem) []string {
	switch ecosystem {
	case sdk.EcosystemNPM:
		return []string{"npm"}
	case sdk.EcosystemGo:
		return []string{"gomod"}
	case sdk.EcosystemMaven:
		return []string{"maven"}
	case sdk.EcosystemPython:
		return []string{"python"}
	case sdk.EcosystemPHP:
		return []string{"composer"}
	case sdk.EcosystemRuby:
		return []string{"ruby"}
	case sdk.EcosystemRust:
		return []string{"cargo"}
	case sdk.EcosystemAPK:
		return []string{"apk"}
	case sdk.EcosystemDPKG:
		return []string{"dpkg"}
	case sdk.EcosystemRPM:
		return []string{"rpm"}
	case sdk.EcosystemALPM:
		return []string{"alpm"}
	case sdk.EcosystemConda:
		return []string{"conda"}
	case sdk.EcosystemDotNet:
		return []string{"dotnet"}
	case sdk.EcosystemHomebrew:
		return []string{"homebrew"}
	case sdk.EcosystemNix:
		return []string{"nix"}
	case sdk.EcosystemSwift:
		return []string{"swift"}
	case sdk.EcosystemDart:
		return []string{"dart"}
	case sdk.EcosystemR:
		return []string{"r"}
	case sdk.EcosystemHaskell:
		return []string{"haskell"}
	case sdk.EcosystemLua:
		return []string{"lua"}
	case sdk.EcosystemOCaml:
		return []string{"ocaml"}
	case sdk.EcosystemErlang:
		return []string{"erlang"}
	case sdk.EcosystemElixir:
		return []string{"elixir"}
	case sdk.EcosystemTerraform:
		return []string{"terraform"}
	case sdk.EcosystemWordPress:
		return []string{"wordpress"}
	case sdk.EcosystemCPP:
		return []string{"cpp"}
	case sdk.EcosystemPortage:
		return []string{"portage"}
	case sdk.EcosystemProlog:
		return []string{"prolog"}
	case sdk.EcosystemSnap:
		return []string{"snap"}
	default:
		return nil
	}
}

func syftCatalogerSelection(req sdk.DetectionRequest) cataloging.SelectionRequest {
	expressions := syftCatalogerExpressions(req)
	if len(expressions) == 0 {
		return cataloging.SelectionRequest{}
	}
	return cataloging.NewSelectionRequest().WithExpression(expressions...)
}

func syftCatalogerSelectionArgs(req sdk.DetectionRequest) []string {
	expressions := syftCatalogerExpressions(req)
	if len(expressions) == 0 {
		return nil
	}
	return []string{"--select-catalogers", strings.Join(expressions, ",")}
}
