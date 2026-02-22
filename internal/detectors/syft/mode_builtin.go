//go:build bomly_builtin_syft

package syft

// IsBuiltin reports whether the Syft detector is compiled with the Syft library.
func IsBuiltin() bool { return true }
