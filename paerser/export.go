package parser

// RawMap is the settings below a node, as Traefik hands them to a plugin: a map for named entries, a list for
// indexed ones, a text for a value. It panics, as Traefik's code does, where a name is a value in one line and a map
// in another.
func RawMap(node *Node) map[string]interface{} {
	return nodeToRawMap(node)
}
