package config

import _ "embed"

// resolvedSource embeds the config schema source so documentation generators
// can parse struct tags and section comments from a shipped binary without
// access to the repository checkout.
//
//go:embed config.go
var resolvedSource []byte

// ResolvedSource returns the embedded source of config.go, the file that
// declares the Resolved configuration schema.
func ResolvedSource() []byte {
	return append([]byte(nil), resolvedSource...)
}
