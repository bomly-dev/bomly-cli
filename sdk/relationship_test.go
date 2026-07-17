package sdk

import "testing"

func TestRelationshipForPathHonorsUnknownTarget(t *testing.T) {
	root := NewDependencyWithID("root", Dependency{Coordinates: Coordinates{Name: "root", Type: PackageTypeApplication}})
	orphan := NewDependencyWithID("orphan", Dependency{Coordinates: Coordinates{Name: "orphan"}, Relationship: DependencyRelationshipUnknown})
	if got := RelationshipForPath([]*Dependency{root, orphan}); got != DependencyRelationshipUnknown {
		t.Fatalf("RelationshipForPath() = %q, want unknown", got)
	}
}

func TestRelationshipForPathDerivesDirectAndTransitive(t *testing.T) {
	nodes := []*Dependency{NewDependencyRef("root", ""), NewDependencyRef("parent", "1"), NewDependencyRef("child", "1")}
	if got := RelationshipForPath(nodes[:2]); got != DependencyRelationshipDirect {
		t.Fatalf("direct relationship = %q", got)
	}
	if got := RelationshipForPath(nodes); got != DependencyRelationshipTransitive {
		t.Fatalf("transitive relationship = %q", got)
	}
}

func TestMergeDependencyRelationshipUsesBestKnownRelationship(t *testing.T) {
	got := MergeDependencyRelationship(DependencyRelationshipUnknown, DependencyRelationshipTransitive)
	got = MergeDependencyRelationship(got, DependencyRelationshipDirect)
	if got != DependencyRelationshipDirect {
		t.Fatalf("merged relationship = %q, want direct", got)
	}
}
