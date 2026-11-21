package parser

import "fmt"

/*
RawMap section
*/

func addRawValue(node *Node) {
	if node.RawValue == nil {
		node.RawValue = nodeToRawMap(node)
	}

	node.Children = nil
}

func nodeToRawMap(node *Node) map[string]interface{} {
	result := map[string]interface{}{}

	squashNode(node, result, true)

	return result
}

func squashNode(node *Node, acc map[string]interface{}, root bool) {
	if len(node.Children) == 0 {
		acc[node.Name] = node.Value

		return
	}

	// slice
	if isArrayKey(node.Children[0].Name) {
		var accChild []interface{}

		for _, child := range node.Children {
			tmp := map[string]interface{}{}
			squashNode(child, tmp, false)
			accChild = append(accChild, tmp[child.Name])
		}

		acc[node.Name] = accChild

		return
	}

	// map
	var accChild map[string]interface{}
	if root {
		accChild = acc
	} else {
		accChild = typedRawMap(acc, node.Name)
	}

	for _, child := range node.Children {
		squashNode(child, accChild, false)
	}
}

func typedRawMap(m map[string]interface{}, k string) map[string]interface{} {
	if m[k] == nil {
		m[k] = map[string]interface{}{}
	}

	r, ok := m[k].(map[string]interface{})
	if !ok {
		panic(fmt.Sprintf("unsupported value (key: %s): %T", k, m[k]))
	}

	return r
}

func isArrayKey(name string) bool {
	return name[0] == '[' && name[len(name)-1] == ']'
}
