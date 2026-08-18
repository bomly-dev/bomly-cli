package sbom

import (
	"fmt"
	"strings"

	"github.com/bomly-dev/bomly-sdk"
)

// ToGraph converts a neutral SBOM document back into a dependency graph.
func ToGraph(doc *Document) (*sdk.Graph, error) {
	if doc == nil {
		return nil, ErrNilDocument
	}

	depsGraph := sdk.New()
	idMap := make(map[string]string, len(doc.Components))
	skipped := make(map[string]struct{})
	for _, component := range doc.Components {
		if isDocumentRootPseudoPackage(component) {
			skipped[component.ID] = struct{}{}
			continue
		}
		ecosystem := sdk.Ecosystem(strings.TrimSpace(component.Ecosystem))
		if ecosystem == sdk.EcosystemUnknown {
			if purl := parsePURL(component.PURL); purl != nil {
				ecosystem = ecosystemFromPURLType(purl.Type)
			}
		}
		packageManager := sdk.PackageManagerUnknown
		if manager, err := sdk.ParsePackageManager(component.PackageManager); err == nil {
			packageManager = manager
		}
		if packageManager == sdk.PackageManagerUnknown {
			packageManager = packageManagerForPURL(component.PURL, string(ecosystem), component.PackageManager)
		}
		packageID := strings.TrimSpace(component.ID)
		if purl := strings.TrimSpace(component.PURL); purl != "" {
			packageID = purl
		}
		// Deliberately no Source: sdk.Dependency.Source feeds
		// RegistryMatchEligible, so classifying an ingested component as git
		// or url would quietly make it ineligible for enrichment and break
		// `scan --sbom --enrich`. ResolvedURL alone is safe — eligibility
		// never reads it.
		pkg := sdk.NewDependencyWithID(packageID, sdk.Dependency{Coordinates: sdk.Coordinates{Name: component.Name,
			Version: component.Version,

			Ecosystem:      ecosystem,
			PackageManager: packageManager,
			Type:           sdk.ParsePackageType(component.Type),
			PURL:           strings.TrimSpace(component.PURL)}, Scopes: sdk.ScopesOf(sdk.Scope(component.Scope)),

			Copyright:   component.Copyright,
			CPEs:        append([]string(nil), component.CPEs...),
			Digests:     graphDigests(component.Digests),
			ResolvedURL: firstNonEmpty(component.ArtifactURL, component.VCSURL, component.RegistryURL),
		})
		sdk.SetDetectionLicenses(pkg, graphLicenses(component.Licenses))
		setIngestedMetadata(pkg, component)

		if existing, exists := depsGraph.Node(packageID); exists {
			// Several component IDs can share one PURL (a lockfile entry and
			// an installed-metadata entry for the same package). Only the
			// first becomes a graph node, so the duplicate's assertions have
			// to be folded in rather than dropped with the discarded object.
			mergeIngestedNode(existing, pkg)
		} else if err := depsGraph.AddNode(pkg); err != nil {
			return nil, fmt.Errorf("add package %q: %w", component.ID, err)
		}
		idMap[component.ID] = packageID
	}

	for _, dependency := range doc.Dependencies {
		if _, ok := skipped[dependency.Ref]; ok {
			continue
		}
		fromID, ok := idMap[dependency.Ref]
		if !ok {
			// Dependency entries may reference the synthesized document root
			// (present only in CycloneDX metadata.component) or otherwise
			// dangling refs; neither has a graph node to anchor an edge.
			continue
		}
		for _, child := range dependency.DependsOn {
			if _, ok := skipped[child]; ok {
				continue
			}
			toID, ok := idMap[child]
			if !ok {
				continue
			}
			if fromID == toID {
				continue
			}
			if err := depsGraph.AddEdge(fromID, toID); err != nil {
				return nil, fmt.Errorf("add dependency %q -> %q: %w", fromID, toID, err)
			}
		}
	}

	return depsGraph, nil
}

func isDocumentRootPseudoPackage(component Component) bool {
	// Bomly's synthesized project root carries a pkg:generic PURL but is
	// still a stand-in for the scanned tree, not a resolved package.
	if IsProjectRootComponent(component) {
		return true
	}
	if strings.TrimSpace(component.PURL) != "" {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(component.Type), "file") && strings.TrimSpace(component.Version) == "" {
		return true
	}
	return false
}

// mergeIngestedNode folds a duplicate-PURL component's assertions into the
// graph node that already represents that package.
//
// Fill-gaps semantics: the first component wins any conflict, and later ones
// only supply what is still missing. Set-valued fields are unioned, since two
// entries for the same package may each carry a digest or CPE the other does
// not.
func mergeIngestedNode(existing, incoming *sdk.Dependency) {
	if existing == nil || incoming == nil {
		return
	}
	if existing.Copyright == "" {
		existing.Copyright = incoming.Copyright
	}
	if existing.ResolvedURL == "" {
		existing.ResolvedURL = incoming.ResolvedURL
	}
	existing.CPEs = unionStrings(existing.CPEs, incoming.CPEs)
	existing.Digests = unionDigests(existing.Digests, incoming.Digests)

	// Licenses are set-valued here too: two components collapsing onto one
	// PURL may each declare a different choice.
	if incomingLicenses := sdk.DetectionLicenses(incoming); len(incomingLicenses) > 0 {
		merged := sdk.DetectionLicenses(existing)
		seen := make(map[sdk.PackageLicense]struct{}, len(merged))
		for _, license := range merged {
			seen[license] = struct{}{}
		}
		for _, license := range incomingLicenses {
			if _, ok := seen[license]; ok {
				continue
			}
			seen[license] = struct{}{}
			merged = append(merged, license)
		}
		sdk.SetDetectionLicenses(existing, merged)
	}
	conflictedSlots := mergeLocatorPairs(existing, incoming)
	for key, value := range incoming.Metadata {
		if existing.Metadata == nil {
			existing.Metadata = make(map[string]any, len(incoming.Metadata))
		}
		// External references are a set carried under one key, so a key-level
		// fill-gaps merge would drop the duplicate's whole list whenever the
		// first component had any. Union them instead.
		// NONE is part of the locator assertion, not an independent fact: a
		// first component asserting an exact URL and a second asserting NONE
		// are contradictory, and merging the marker alone would make SPDX emit
		// NONE while CycloneDX still emitted the artifact. First component
		// wins, matching the locator policy.
		if key == metadataKeyNoDownload {
			if _, hasLocator := existing.Metadata[metadataKeyArtifactURL]; hasLocator {
				continue
			}
			if _, hasLocator := existing.Metadata[metadataKeyVCSURL]; hasLocator {
				continue
			}
			if _, hasLocator := existing.Metadata[metadataKeyRegistryURL]; hasLocator {
				continue
			}
		}
		if key == metadataKeyLocatorDigests {
			existing.Metadata[key] = mergeLocatorDigestMaps(existing.Metadata[key], value, conflictedSlots)
			continue
		}
		if _, paired := locatorCommentKeys[key]; paired {
			// Handled atomically below so a URL never picks up another
			// locator's comment.
			continue
		}
		if key == metadataKeySupplierPeople {
			existing.Metadata[key] = unionAnyRecords(existing.Metadata[key], value, "name", "email", "phone")
			continue
		}
		if key == metadataKeySupplierURLs {
			existing.Metadata[key] = unionAnyStrings(existing.Metadata[key], value)
			continue
		}
		if key == metadataKeyExternalRefs {
			existing.Metadata[key] = unionExternalRefValues(existing.Metadata[key], value)
			continue
		}
		if _, present := existing.Metadata[key]; !present {
			existing.Metadata[key] = value
		}
	}
}

// locatorCommentKeys pairs each classified locator with its comment. The two
// must merge together: filling them independently can attach one locator's
// comment to a different locator's URL.
var locatorCommentKeys = map[string]string{
	metadataKeyArtifactURL:  metadataKeyArtifactNote,
	metadataKeyVCSURL:       metadataKeyVCSNote,
	metadataKeyRegistryURL:  metadataKeyRegistryNote,
	metadataKeyArtifactNote: metadataKeyArtifactURL,
	metadataKeyVCSNote:      metadataKeyVCSURL,
	metadataKeyRegistryNote: metadataKeyRegistryURL,
}

// mergeLocatorPairs fills each empty locator slot from incoming, moving the
// URL and its comment as one unit.
func mergeLocatorPairs(existing, incoming *sdk.Dependency) (conflicted map[string]struct{}) {
	conflicted = map[string]struct{}{}
	for _, pair := range []struct{ url, note, slot, refType string }{
		{metadataKeyArtifactURL, metadataKeyArtifactNote, "artifact", "distribution"},
		{metadataKeyVCSURL, metadataKeyVCSNote, "vcs", "vcs"},
		{metadataKeyRegistryURL, metadataKeyRegistryNote, "registry", "distribution"},
	} {
		incomingURL, ok := incoming.Metadata[pair.url].(string)
		if !ok || incomingURL == "" {
			continue
		}
		if existing.Metadata == nil {
			existing.Metadata = make(map[string]any)
		}

		existingURL, present := existing.Metadata[pair.url].(string)
		switch {
		case !present || existingURL == "":
			existing.Metadata[pair.url] = incomingURL
			if note, ok := incoming.Metadata[pair.note]; ok {
				existing.Metadata[pair.note] = note
			}
			existing.Metadata[metadataKeyLocatorDigests] = mergeLocatorDigestSlot(
				existing.Metadata[metadataKeyLocatorDigests], incoming.Metadata[metadataKeyLocatorDigests], pair.slot)
		case existingURL == incomingURL:
			// Same locator described twice: union its integrity assertions
			// rather than keeping only the first list.
			existing.Metadata[metadataKeyLocatorDigests] = mergeLocatorDigestSlot(
				existing.Metadata[metadataKeyLocatorDigests], incoming.Metadata[metadataKeyLocatorDigests], pair.slot)
			if note, ok := existing.Metadata[pair.note].(string); !ok || note == "" {
				if incomingNote, ok := incoming.Metadata[pair.note]; ok {
					existing.Metadata[pair.note] = incomingNote
				}
			}
		default:
			// A different locator for the same slot is a mirror, not a
			// replacement. Keep it as an external reference so the assertion
			// survives without displacing the first.
			note, _ := incoming.Metadata[pair.note].(string)
			ref := map[string]any{"type": pair.refType, "url": incomingURL, "comment": note}
			if digests := locatorDigestSlot(incoming.Metadata[metadataKeyLocatorDigests], pair.slot); digests != nil {
				ref["digests"] = digests
			}
			existing.Metadata[metadataKeyExternalRefs] = unionExternalRefValues(
				existing.Metadata[metadataKeyExternalRefs], []any{ref})
			// The incoming digests belong to the reference just preserved, not
			// to the URL that kept the slot. Marking the slot conflicted stops
			// the generic map merge below from attaching them to the survivor
			// and fabricating an integrity assertion.
			conflicted[pair.slot] = struct{}{}
		}
	}
	return conflicted
}

// locatorDigestSlot returns the serialized digest list for one locator slot.
func locatorDigestSlot(encoded any, slot string) any {
	slots, ok := encoded.(map[string]any)
	if !ok {
		return nil
	}
	return slots[slot]
}

// mergeLocatorDigestSlot folds one slot's digests from incoming into existing,
// leaving the other slots untouched.
func mergeLocatorDigestSlot(existing, incoming any, slot string) any {
	incomingDigests := locatorDigestSlot(incoming, slot)
	if incomingDigests == nil {
		return existing
	}
	slots, ok := existing.(map[string]any)
	if !ok {
		slots = map[string]any{}
	}
	merged := make(map[string]any, len(slots)+1)
	for k, v := range slots {
		merged[k] = v
	}
	merged[slot] = unionAnyRecords(merged[slot], incomingDigests, "algorithm", "value")
	return merged
}

// unionAnyStrings merges two serialized string lists, preserving order and
// dropping duplicates.
func unionAnyStrings(base, extra any) any {
	baseList, _ := base.([]any)
	extraList, _ := extra.([]any)
	if len(extraList) == 0 {
		return base
	}
	if len(baseList) == 0 {
		return extra
	}
	seen := make(map[string]struct{}, len(baseList))
	for _, entry := range baseList {
		if value, ok := entry.(string); ok {
			seen[value] = struct{}{}
		}
	}
	for _, entry := range extraList {
		value, ok := entry.(string)
		if !ok {
			continue
		}
		if _, present := seen[value]; present {
			continue
		}
		seen[value] = struct{}{}
		baseList = append(baseList, entry)
	}
	return baseList
}

// mergeLocatorDigestMaps merges the per-slot locator digest maps.
//
// The three slots ride under one key, so keeping the whole existing map
// discarded a duplicate's hashes for a slot the first component never filled
// — and mergeLocatorPairs can still adopt that duplicate's URL, which would
// then be re-emitted without its asserted hash.
func mergeLocatorDigestMaps(existing, incoming any, conflicted map[string]struct{}) any {
	incomingMap, ok := incoming.(map[string]any)
	if !ok {
		return existing
	}
	existingMap, _ := existing.(map[string]any)
	merged := make(map[string]any, len(existingMap)+len(incomingMap))
	for slot, value := range existingMap {
		merged[slot] = value
	}
	for slot, value := range incomingMap {
		// A conflicted slot kept a different URL, and mergeLocatorPairs has
		// already moved this slot's digests onto the preserved reference.
		if _, isConflicted := conflicted[slot]; isConflicted {
			continue
		}
		if _, present := merged[slot]; !present {
			merged[slot] = value
		}
	}
	return merged
}

// unionAnyRecords merges two serialized lists of maps, deduplicating on the
// named fields. Contacts are maps rather than strings, so the string union
// would silently discard every one of them.
func unionAnyRecords(base, extra any, keyFields ...string) any {
	baseList, _ := base.([]any)
	extraList, _ := extra.([]any)
	if len(extraList) == 0 {
		return base
	}
	if len(baseList) == 0 {
		return extra
	}

	identity := func(entry any) (string, bool) {
		fields, ok := entry.(map[string]any)
		if !ok {
			return "", false
		}
		parts := make([]string, 0, len(keyFields))
		for _, name := range keyFields {
			value, _ := fields[name].(string)
			parts = append(parts, value)
		}
		return strings.Join(parts, "\x00"), true
	}

	seen := make(map[string]struct{}, len(baseList))
	for _, entry := range baseList {
		if id, ok := identity(entry); ok {
			seen[id] = struct{}{}
		}
	}
	for _, entry := range extraList {
		id, ok := identity(entry)
		if !ok {
			continue
		}
		if _, present := seen[id]; present {
			continue
		}
		seen[id] = struct{}{}
		baseList = append(baseList, entry)
	}
	return baseList
}

// unionExternalRefValues merges two serialized external-reference lists,
// keyed by type and URL. Entries that are not the expected shape are kept
// as-is on the base side and skipped on the incoming side.
func unionExternalRefValues(base, extra any) any {
	baseList, _ := base.([]any)
	extraList, _ := extra.([]any)
	if len(extraList) == 0 {
		return base
	}
	if len(baseList) == 0 {
		return extra
	}

	type key struct{ refType, url string }
	refKey := func(entry any) (key, bool) {
		fields, ok := entry.(map[string]any)
		if !ok {
			return key{}, false
		}
		refType, _ := fields["type"].(string)
		url, _ := fields["url"].(string)
		return key{refType, url}, true
	}

	index := make(map[key]int, len(baseList))
	for i, entry := range baseList {
		if k, ok := refKey(entry); ok {
			index[k] = i
		}
	}
	for _, entry := range extraList {
		k, ok := refKey(entry)
		if !ok {
			continue
		}
		i, present := index[k]
		if !present {
			index[k] = len(baseList)
			baseList = append(baseList, entry)
			continue
		}
		// Same reference, possibly different assertions about it: mirror the
		// model-level merge rather than treating it as a plain duplicate.
		existing, okExisting := baseList[i].(map[string]any)
		fields, okIncoming := entry.(map[string]any)
		if !okExisting || !okIncoming {
			continue
		}
		existing["digests"] = unionAnyRecords(existing["digests"], fields["digests"], "algorithm", "value")
		if comment, _ := existing["comment"].(string); comment == "" {
			if incoming, ok := fields["comment"].(string); ok && incoming != "" {
				existing["comment"] = incoming
			}
		}
		baseList[i] = existing
	}
	return baseList
}

// unionStrings appends values from extra that are not already in base.
func unionStrings(base, extra []string) []string {
	seen := make(map[string]struct{}, len(base))
	for _, value := range base {
		seen[value] = struct{}{}
	}
	for _, value := range extra {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		base = append(base, value)
	}
	return base
}

// unionDigests appends digests from extra that are not already in base.
func unionDigests(base, extra []sdk.Digest) []sdk.Digest {
	seen := make(map[sdk.Digest]struct{}, len(base))
	for _, digest := range base {
		seen[digest] = struct{}{}
	}
	for _, digest := range extra {
		if _, ok := seen[digest]; ok {
			continue
		}
		seen[digest] = struct{}{}
		base = append(base, digest)
	}
	return base
}

// graphDigests projects component digests onto a graph node. Ingest dropped
// these previously, so an incoming document's hashes did not survive a format
// conversion.
func graphDigests(digests []Digest) []sdk.Digest {
	if len(digests) == 0 {
		return nil
	}
	out := make([]sdk.Digest, 0, len(digests))
	for _, digest := range digests {
		out = append(out, sdk.Digest{
			Algorithm: sdk.DigestAlgorithm(digest.Algorithm),
			Value:     digest.Value,
		})
	}
	return out
}

func graphLicenses(licenses []License) []sdk.PackageLicense {
	if len(licenses) == 0 {
		return nil
	}
	out := make([]sdk.PackageLicense, 0, len(licenses))
	for _, license := range licenses {
		out = append(out, sdk.PackageLicense{
			Value:          license.Value,
			SPDXExpression: license.SPDXExpression,
			Type:           sdk.LicenseType(license.Type),
		})
	}
	return out
}
