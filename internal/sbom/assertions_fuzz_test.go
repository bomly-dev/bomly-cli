package sbom

import (
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-sdk"
	"github.com/bomly-dev/bomly-sdk/testkit"
)

// FuzzIngestedAssertions drives an arbitrary document's component assertions
// through the ingest gates and asserts that nothing unpublishable survives.
//
// This is the hostile-document half of #396. Ingest reads values a stranger
// wrote and Bomly re-emits them under its own name, so the interesting input
// is not a malformed document -- the codec rejects those -- but a
// well-formed one carrying a local path, an embedded credential, a control
// character, or a malformed CPE or digest. Two credential leaks in #391 came
// through URL positions nobody had thought to test.
func FuzzIngestedAssertions(f *testing.F) {
	f.Add("Acme Corp", "https://acme.example/", "a description", "https://acme.example/home", "cpe:2.3:a:acme:widget:1:*:*:*:*:*:*:*", "SHA-256", strings.Repeat("a", 64))
	f.Add("Acme\nCorp", "https://user:pass@acme.example/", "desc", "file:///etc/passwd", "cpe:not-a-cpe", "SHA-256", "short")
	f.Add("", "", "", "", "", "", "")
	f.Add("Acme (bob@acme.example)", "https://acme.example/?token=abc", "d", "http://127.0.0.1/", "cpe:/a:acme:widget", "MD5", strings.Repeat("f", 32))
	f.Add(strings.Repeat("n", 5000), "https://[::1]/", "x", "ssh://git@host/repo", "cpe:2.3:*:*:*:*:*:*:*:*:*:*:*", "SHA-512", "zz")

	f.Fuzz(func(t *testing.T, name, contactURL, description, homepage, cpe, algorithm, digestValue string) {
		for _, value := range []string{name, contactURL, description, homepage, cpe, algorithm, digestValue} {
			if len(value) > testkit.MaxFuzzInputSize {
				t.Skip("input beyond the documented bound")
			}
		}

		component := Component{
			Name:        "widget",
			Supplier:    &sdk.Contact{Kind: sdk.ContactKindOrganization, Name: name, URL: contactURL},
			Description: description,
			Homepage:    homepage,
			CPEs:        []string{cpe},
			Digests:     []Digest{{Algorithm: algorithm, Value: digestValue}},
		}

		node, err := sdk.NewDependencyNode(sdk.Coordinates{Ecosystem: "npm", Name: "widget", Version: "1.0.0"})
		if err != nil {
			t.Fatalf("construct node: %v", err)
		}
		applyIngestedAssertions(node, component)

		// Whatever arrived, what the node now carries must be publishable:
		// re-running each gate on the stored value has to agree with it.
		if node.Supplier != nil {
			if _, ok := node.Supplier.Normalized(); !ok {
				t.Fatalf("stored supplier %+v does not clear its own gate", node.Supplier)
			}
		}
		if node.Description != sdk.NormalizeDescription(node.Description) {
			t.Fatalf("stored description %q is not normalized", node.Description)
		}
		if node.Homepage != sdk.NormalizeHomepage(node.Homepage) {
			t.Fatalf("stored homepage %q is not normalized", node.Homepage)
		}
		for _, digest := range node.Digests {
			if _, ok := digest.Normalized(); !ok {
				t.Fatalf("stored digest %+v does not clear its own gate", digest)
			}
		}
		for _, reference := range node.ExternalReferences {
			if _, ok := reference.Normalized(); !ok {
				t.Fatalf("stored reference %+v does not clear its own gate", reference)
			}
		}
		// A stored CPE must still be a CPE the SDK accepts.
		for _, stored := range node.CPEs {
			if len(ingestedCPEs([]string{stored})) != 1 {
				t.Fatalf("stored CPE %q would not be admitted again", stored)
			}
		}

		// Re-running ingest on what was stored changes nothing: the gates are
		// a fixed point, so a value cannot be laundered by another hop.
		again, err := sdk.NewDependencyNode(sdk.Coordinates{Ecosystem: "npm", Name: "widget", Version: "1.0.0"})
		if err != nil {
			t.Fatalf("construct node: %v", err)
		}
		applyIngestedAssertions(again, Component{
			Supplier:    node.Supplier,
			Description: node.Description,
			Homepage:    node.Homepage,
			CPEs:        node.CPEs,
			Digests:     componentDigests(node.Digests),
		})
		if again.Description != node.Description || again.Homepage != node.Homepage {
			t.Fatalf("a second ingest changed the value: %q/%q then %q/%q",
				node.Description, node.Homepage, again.Description, again.Homepage)
		}
		if len(again.CPEs) != len(node.CPEs) || len(again.Digests) != len(node.Digests) {
			t.Fatalf("a second ingest changed the set sizes")
		}
	})
}
