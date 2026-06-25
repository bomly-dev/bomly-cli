package git

import "testing"

func TestParseChangedLineRanges(t *testing.T) {
	diff := `diff --git a/package-lock.json b/package-lock.json
index 1111111..2222222 100644
--- a/package-lock.json
+++ b/package-lock.json
@@ -8 +8 @@
-      "version": "4.17.20"
+      "version": "4.17.21"
diff --git a/README.md b/README.md
index 3333333..4444444 100644
--- a/README.md
+++ b/README.md
@@ -0,0 +1,2 @@
+hello
+world
@@ -5,2 +6,0 @@
-old
-lines
`
	got := parseChangedLineRanges(diff)
	if len(got["package-lock.json"]) != 1 || got["package-lock.json"][0] != (LineRange{Start: 8, End: 8}) {
		t.Fatalf("package-lock ranges = %#v, want line 8", got["package-lock.json"])
	}
	if len(got["README.md"]) != 1 || got["README.md"][0] != (LineRange{Start: 1, End: 2}) {
		t.Fatalf("README ranges = %#v, want lines 1-2", got["README.md"])
	}
}
