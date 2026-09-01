package detectors

import (
	"fmt"

	sdk "github.com/bomly-dev/bomly-sdk"
)

// NewDependencyFrom builds a dependency node from a prototype: the identity is
// minted from the prototype's coordinates, and every other field it states is
// copied onto the result.
//
// A node's identity is fixed at construction under ADR-0041, so a detector
// that used to describe a package as one struct literal now has to construct
// first and assign after. Doing that by hand at each site is how a detector
// silently stops recording what it detected -- the npm, pnpm, yarn, and bun
// parsers each lost ResolvedURL and their integrity digests exactly that way,
// and nothing but a fixture assertion noticed. Detectors that still build a
// prototype call this instead, so the field list lives in one place and a
// field added to the model is copied everywhere at once.
func NewDependencyFrom(proto sdk.DependencyNode) (*sdk.DependencyNode, error) {
	node, err := sdk.NewDependencyNode(proto.Coordinates)
	if err != nil {
		return nil, fmt.Errorf("build dependency node %q: %w", proto.Name, err)
	}
	node.Relationship = proto.Relationship
	node.Source = proto.Source
	node.Scopes = append([]sdk.Scope(nil), proto.Scopes...)
	node.Locations = append([]sdk.PackageLocation(nil), proto.Locations...)
	node.CPEs = append([]string(nil), proto.CPEs...)
	node.Digests = append([]sdk.Digest(nil), proto.Digests...)
	node.Copyright = proto.Copyright
	node.FoundBy = proto.FoundBy
	node.ResolvedURL = proto.ResolvedURL
	node.Origins = sdk.MergeOrigins(nil, proto.Origins)
	node.Licenses = sdk.MergeLicenses(nil, proto.Licenses)
	node.Description = proto.Description
	node.Homepage = proto.Homepage
	node.Supplier = proto.Supplier
	node.Originator = proto.Originator
	node.ExternalReferences = append([]sdk.ExternalReference(nil), proto.ExternalReferences...)
	node.Metadata = proto.Metadata
	node.Matched = proto.Matched
	node.PackageRef = proto.PackageRef
	return node, nil
}
