package sbom

import (
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-sdk"
	"github.com/bomly-dev/bomly-sdk/testkit"
)

// FuzzDocumentAssertions drives arbitrary document-level claims through the
// export projection and asserts that nothing unpublishable reaches a
// document, and that a second pass changes nothing.
//
// The component half of this lives in FuzzIngestedAssertions. This half
// covers the other trust boundary ADR-0037 opens: a graph entry's Document
// field is reachable by any detector or external plugin, so a value written
// straight onto it -- never having passed a decoder -- is exactly as
// untrusted as one that arrived in a document, and gets re-gated on export.
//
// Idempotence is asserted rather than assumed. bomly-dev/bomly-sdk#54 was
// found by the component target this way: a gate that repairs a value and
// then bounds it can grow the value past its own bound, and the next pass
// empties it -- which would break the fixed point #396 requires.
func FuzzDocumentAssertions(f *testing.F) {
	f.Add("https://acme.example/spdx/doc-1", "acme-bom", "CC0-1.0", "2026-01-02T03:04:05Z", "Acme Corp", "acme-sbom-2.4.1", "a comment")
	f.Add("urn:cdx:3e671687-395b-41f5-a30f-a58921a69b79/1", "n", "MIT", "not a date", "Person\nName", "tool", "line\nbreak")
	f.Add("", "", "", "", "", "", "")
	f.Add("file:///etc/passwd", "name\x00", "not-a-license", "2026", "bob@acme.example", "", strings.Repeat("c", 9000))
	f.Add("https://user:pass@acme.example/ns", strings.Repeat("n", 9000), "", "", "Acme (bob@acme.example)", "t\x07ool", "")

	f.Fuzz(func(t *testing.T, identity, name, dataLicense, created, creator, tool, comment string) {
		for _, value := range []string{identity, name, dataLicense, created, creator, tool, comment} {
			if len(value) > testkit.MaxFuzzInputSize {
				t.Skip("input beyond the documented bound")
			}
		}

		hostile := sdk.DocumentAssertions{
			Identity:    identity,
			Name:        name,
			DataLicense: dataLicense,
			Created:     created,
			Creators:    []sdk.Contact{{Kind: sdk.ContactKindOrganization, Name: creator}},
			Tools:       []sdk.DocumentTool{{Name: tool}},
			Comment:     comment,
		}

		g := mustFuzzGraph(t)
		entry := sdk.GraphEntry{Graph: g, Document: &hostile}
		doc, err := FromGraphEntries(g, []sdk.GraphEntry{entry}, BuildOptions{})
		if err != nil {
			t.Fatalf("export: %v", err)
		}

		// A document always identifies itself, whatever the source claimed.
		if doc.Namespace == "" || doc.SerialNumber == "" {
			t.Fatalf("document has no identity: ns=%q serial=%q", doc.Namespace, doc.SerialNumber)
		}
		// Every value the document now carries must clear its own gate: an
		// unpublishable claim must not become publishable by being written
		// onto an entry instead of parsed from a document.
		if _, ok := (sdk.DocumentAssertions{Identity: doc.Namespace}).Normalized(); !ok {
			t.Fatalf("document namespace %q does not clear the identity gate", doc.Namespace)
		}
		stored, _ := doc.Assertions.Normalized()
		if stored.Comment != doc.Assertions.Comment {
			t.Fatalf("stored comment %q is not normalized (%q)", doc.Assertions.Comment, stored.Comment)
		}
		for _, contact := range doc.Assertions.Creators {
			if _, ok := contact.Normalized(); !ok {
				t.Fatalf("stored creator %+v does not clear its own gate", contact)
			}
			if strings.Contains(contact.Name, "@") {
				t.Fatalf("an address survived into a creator: %q", contact.Name)
			}
		}
		for _, stored := range doc.Assertions.Tools {
			if _, ok := stored.Normalized(); !ok {
				t.Fatalf("stored tool %+v does not clear its own gate", stored)
			}
		}
		for _, link := range documentSourceLinks(doc) {
			if _, ok := link.Normalized(); !ok {
				t.Fatalf("source link %+v does not clear its own gate", link)
			}
		}

		// Feeding the projection back its own output changes nothing.
		second := sdk.GraphEntry{Graph: g, Document: &sdk.DocumentAssertions{
			Identity:    doc.Namespace,
			Name:        doc.Name,
			DataLicense: doc.Assertions.DataLicense,
			Created:     doc.Assertions.Created,
			Creators:    doc.Assertions.Creators,
			Tools:       doc.Assertions.Tools,
			Comment:     doc.Assertions.Comment,
		}}
		again, err := FromGraphEntries(g, []sdk.GraphEntry{second}, BuildOptions{})
		if err != nil {
			t.Fatalf("second export: %v", err)
		}
		if again.Namespace != doc.Namespace {
			t.Fatalf("a second pass changed the identity: %q then %q", doc.Namespace, again.Namespace)
		}
		if again.Name != doc.Name {
			t.Fatalf("a second pass changed the name: %q then %q", doc.Name, again.Name)
		}
		if again.Assertions.Comment != doc.Assertions.Comment {
			t.Fatalf("a second pass changed the comment: %q then %q", doc.Assertions.Comment, again.Assertions.Comment)
		}
		if len(again.Assertions.Creators) != len(doc.Assertions.Creators) ||
			len(again.Assertions.Tools) != len(doc.Assertions.Tools) {
			t.Fatalf("a second pass changed the credited set sizes")
		}
	})
}

// mustFuzzGraph returns the smallest graph an export accepts, so the fuzzer
// spends its budget on the document claims rather than on graph shapes the
// component target already covers.
func mustFuzzGraph(t *testing.T) *sdk.Graph {
	t.Helper()
	g := sdk.New()
	node, err := sdk.NewDependencyNode(sdk.Coordinates{Ecosystem: "npm", Name: "widget", Version: "1.0.0"})
	if err != nil {
		t.Fatalf("construct node: %v", err)
	}
	if err := g.AddNode(node); err != nil {
		t.Fatalf("add node: %v", err)
	}
	return g
}
