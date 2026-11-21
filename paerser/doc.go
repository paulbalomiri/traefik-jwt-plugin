// Package parser holds Traefik's own code for reading a container's labels, copied from
// github.com/traefik/paerser v0.2.2 (the version Traefik v3.7 uses), Apache License 2.0:
//
//   - labels_decode.go and node.go, as they are there;
//   - raw_map.go, the "RawMap section" of nodes_metadata.go as it is there, which makes of a node the settings a
//     plugin is handed.
//
// The package as a whole does not load in Yaegi, the interpreter Traefik runs a plugin with; these parts do. They
// are kept unchanged so that a service's labels are read here exactly as Traefik reads them. What this plugin adds
// is in export.go.
package parser
