package traefik_jwt_plugin

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	parser "github.com/paulbalomiri/traefik-jwt-plugin/paerser"
)

// The settings a service may write: its rules, its scope groups, or one rule's fields at the top; and the scopes of
// a group that writes none, where the service has its own.
var serviceSettings = []string{
	"Rules", "Groups", groupDefaultScopes,
	"Paths", "Methods", "Public", "Group", "Scopes", "RequestOtherGroupScopes", "Missing", "Priority",
	"ClaimChecks", "AdditionalChecks",
}

const groupDefaultScopes = "GroupDefaultScopes"

func sortedKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// settingsOfLabels reads the settings of a service from the service's docker labels, as a compose file writes them:
//
//	traefik.http.middlewares.docs-policy.plugin.policy.Scopes: stack.docs.view
//	traefik.http.middlewares.docs-policy.plugin.policy.Missing: login
//
// It reads the keys with Traefik's own code for a container's labels (the package paerser here) and gives the
// settings Traefik would have handed this plugin had the lines been labels of a container. So one block of lines
// serves both: compose reads it as labels, and a cluster's Middleware takes it whole as Labels.
//
// The lines are those of one middleware's plugin, whatever the two are named. A label of anything else (a router, a
// service) is passed over. A line that sets something other than a service's settings is an error: what a
// deployment's middlewares share is not a service's to write.
func settingsOfLabels(labels interface{}) (map[string]interface{}, error) {
	given, ok := labels.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("Labels is a map of a service's label lines, not %T", labels)
	}
	texts := make(map[string]string, len(given))
	for key, value := range given {
		texts[key] = labelText(value)
	}
	plugin, err := pluginNode(texts)
	if err != nil {
		return nil, err
	}
	raw, err := rawMap(plugin)
	if err != nil {
		return nil, err
	}
	settings := make(map[string]interface{}, len(raw))
	for key, value := range raw {
		name := ""
		for _, setting := range serviceSettings {
			if strings.EqualFold(key, setting) {
				name = setting
			}
		}
		if name == "" {
			return nil, fmt.Errorf("Labels sets %s, which is no setting of a service (%s)", key, strings.Join(serviceSettings, ", "))
		}
		settings[name] = value
	}
	return settings, nil
}

// labelText is a label's value as compose writes it for a container: a text as it is, a switch as true or false, a
// number in digits.
func labelText(value interface{}) string {
	switch v := value.(type) {
	case string:
		return v
	case bool:
		return strconv.FormatBool(v)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case nil:
		return ""
	default:
		return fmt.Sprint(v)
	}
}

// pluginNode is the node of the one middleware's one plugin among the labels: traefik.http.middlewares.<name>.plugin.<name>.
func pluginNode(labels map[string]string) (*parser.Node, error) {
	const none = "Labels holds no setting of a middleware's plugin (traefik.http.middlewares.<name>.plugin.<name>.<setting>)"
	root, err := parser.DecodeToNode(labels, parser.DefaultRootName, "traefik.http.middlewares.")
	if err != nil {
		return nil, fmt.Errorf("Labels: %w", err)
	}
	if root == nil {
		return nil, fmt.Errorf(none)
	}
	middlewares := root
	for _, name := range []string{"http", "middlewares"} {
		middlewares = child(middlewares, name)
		if middlewares == nil {
			return nil, fmt.Errorf(none)
		}
	}
	if len(middlewares.Children) != 1 {
		return nil, fmt.Errorf("Labels holds the lines of %s: it is one middleware's", names(middlewares.Children))
	}
	middleware := middlewares.Children[0]
	plugins := child(middleware, "plugin")
	if plugins == nil || len(middleware.Children) != 1 {
		return nil, fmt.Errorf("%s: the middleware %s sets %s", none, middleware.Name, names(middleware.Children))
	}
	if len(plugins.Children) != 1 {
		return nil, fmt.Errorf("Labels holds the lines of the plugins %s of the middleware %s: it is one plugin's", names(plugins.Children), middleware.Name)
	}
	return plugins.Children[0], nil
}

func child(node *parser.Node, name string) *parser.Node {
	for _, c := range node.Children {
		if strings.EqualFold(c.Name, name) {
			return c
		}
	}
	return nil
}

func names(nodes []*parser.Node) string {
	list := make([]string, 0, len(nodes))
	for _, node := range nodes {
		list = append(list, node.Name)
	}
	sort.Strings(list)
	return strings.Join(list, ", ")
}

// rawMap is the settings below a node as Traefik hands them to a plugin. Traefik's code panics where a name is a
// value in one line and a map in another; here that is an error.
func rawMap(node *parser.Node) (settings map[string]interface{}, err error) {
	defer func() {
		if r := recover(); r != nil {
			settings, err = nil, fmt.Errorf("Labels: %v", r)
		}
	}()
	return parser.RawMap(node), nil
}
