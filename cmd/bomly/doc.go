// Command bomly scans source trees, SBOMs, Git refs, and container images for
// dependency intelligence.
//
// Bomly can generate and ingest SBOMs, explain why packages are present,
// compare dependency graphs, enrich packages with vulnerability and license
// data, evaluate policy, and run as an MCP server:
//
//	bomly scan
//	bomly scan --enrich --audit --fail-on high
//	bomly diff --base main --head HEAD
//	bomly explain pkg:npm/react
//	bomly mcp serve
//
// Scans run locally and do not make outbound matcher calls unless enrichment is
// requested with flags such as --enrich. See the repository README and docs for
// installation, configuration, output formats, CI integration, and plugin
// authoring guides.
package main
