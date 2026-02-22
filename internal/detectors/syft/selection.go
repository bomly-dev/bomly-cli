package syft

import (
	"strings"

	"github.com/anchore/syft/syft/cataloging"
	model "github.com/bomly-dev/bomly-cli/sdk"
)

func syftCatalogerExpressions(req model.DetectionRequest) []string {
	if expressions := syftCatalogerExpressionsForManager(req.PackageManager); len(expressions) > 0 {
		return expressions
	}
	return syftCatalogerExpressionsForEcosystem(req.Ecosystem)
}

func syftCatalogerExpressionsForManager(manager model.PackageManager) []string {
	switch manager {
	case model.PackageManagerNPM, model.PackageManagerPNPM, model.PackageManagerYarn:
		return []string{"npm"}
	case model.PackageManagerGoMod:
		return []string{"gomod"}
	case model.PackageManagerMaven:
		return []string{"maven"}
	case model.PackageManagerGradle:
		return []string{"gradle"}
	case model.PackageManagerPip, model.PackageManagerPipenv, model.PackageManagerPoetry, model.PackageManagerUV:
		return []string{"python"}
	case model.PackageManagerComposer:
		return []string{"composer"}
	case model.PackageManagerBundler:
		return []string{"ruby"}
	case model.PackageManagerCargo:
		return []string{"cargo"}
	case model.PackageManagerAPK:
		return []string{"apk"}
	case model.PackageManagerDPKG:
		return []string{"dpkg"}
	case model.PackageManagerRPM:
		return []string{"rpm"}
	case model.PackageManagerHomebrew:
		return []string{"homebrew"}
	case model.PackageManagerNix:
		return []string{"nix"}
	case model.PackageManagerALPM:
		return []string{"alpm"}
	case model.PackageManagerConda:
		return []string{"conda"}
	case model.PackageManagerNuGet:
		return []string{"dotnet"}
	case model.PackageManagerSwiftPM, model.PackageManagerCocoaPods:
		return []string{"swift"}
	case model.PackageManagerPub:
		return []string{"dart"}
	case model.PackageManagerRPackage:
		return []string{"r"}
	case model.PackageManagerCabal, model.PackageManagerStack:
		return []string{"haskell"}
	case model.PackageManagerLuaRocks:
		return []string{"lua"}
	case model.PackageManagerOpam:
		return []string{"ocaml"}
	case model.PackageManagerRebar, model.PackageManagerOTP:
		return []string{"erlang"}
	case model.PackageManagerMix:
		return []string{"elixir"}
	case model.PackageManagerTerraform:
		return []string{"terraform"}
	case model.PackageManagerWordPress:
		return []string{"wordpress"}
	case model.PackageManagerConan:
		return []string{"cpp"}
	case model.PackageManagerPortage:
		return []string{"portage"}
	case model.PackageManagerSWIPLPack:
		return []string{"prolog"}
	case model.PackageManagerSnap:
		return []string{"snap"}
	default:
		return nil
	}
}

func syftCatalogerExpressionsForEcosystem(ecosystem model.Ecosystem) []string {
	switch ecosystem {
	case model.EcosystemNPM:
		return []string{"npm"}
	case model.EcosystemGo:
		return []string{"gomod"}
	case model.EcosystemMaven:
		return []string{"maven"}
	case model.EcosystemPython:
		return []string{"python"}
	case model.EcosystemPHP:
		return []string{"composer"}
	case model.EcosystemRuby:
		return []string{"ruby"}
	case model.EcosystemRust:
		return []string{"cargo"}
	case model.EcosystemAPK:
		return []string{"apk"}
	case model.EcosystemDPKG:
		return []string{"dpkg"}
	case model.EcosystemRPM:
		return []string{"rpm"}
	case model.EcosystemALPM:
		return []string{"alpm"}
	case model.EcosystemConda:
		return []string{"conda"}
	case model.EcosystemDotNet:
		return []string{"dotnet"}
	case model.EcosystemHomebrew:
		return []string{"homebrew"}
	case model.EcosystemNix:
		return []string{"nix"}
	case model.EcosystemSwift:
		return []string{"swift"}
	case model.EcosystemDart:
		return []string{"dart"}
	case model.EcosystemR:
		return []string{"r"}
	case model.EcosystemHaskell:
		return []string{"haskell"}
	case model.EcosystemLua:
		return []string{"lua"}
	case model.EcosystemOCaml:
		return []string{"ocaml"}
	case model.EcosystemErlang:
		return []string{"erlang"}
	case model.EcosystemElixir:
		return []string{"elixir"}
	case model.EcosystemTerraform:
		return []string{"terraform"}
	case model.EcosystemWordPress:
		return []string{"wordpress"}
	case model.EcosystemCPP:
		return []string{"cpp"}
	case model.EcosystemPortage:
		return []string{"portage"}
	case model.EcosystemProlog:
		return []string{"prolog"}
	case model.EcosystemSnap:
		return []string{"snap"}
	default:
		return nil
	}
}

func syftCatalogerSelection(req model.DetectionRequest) cataloging.SelectionRequest {
	expressions := syftCatalogerExpressions(req)
	if len(expressions) == 0 {
		return cataloging.SelectionRequest{}
	}
	return cataloging.NewSelectionRequest().WithExpression(expressions...)
}

func syftCatalogerSelectionArgs(req model.DetectionRequest) []string {
	expressions := syftCatalogerExpressions(req)
	if len(expressions) == 0 {
		return nil
	}
	return []string{"--select-catalogers", strings.Join(expressions, ",")}
}
