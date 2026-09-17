// Package purlprefix hands a "pkg:" prefix to another package.
package purlprefix

// Scheme returns a package URL prefix.
func Scheme() string { return "pkg:npm/" } // want Scheme:"returnsPURLPrefix"
