package traefik_jwt_plugin

// The tests of Labels: a middleware takes the settings of its service as the service's docker labels, as they are
// written in a compose file, and reads them as Traefik reads the labels of a container. A cluster's Middleware so
// holds the same lines as the compose definition of the service, taken from there whole.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

// rulesAndGroups is what OPA receives of a service's settings.
func rulesAndGroups(t *testing.T, cfg *Config) map[string]interface{} {
	t.Helper()
	var input map[string]interface{}
	opa := opaReceiving(t, &input)
	cfg.OpaUrl, cfg.OpaAllowField = opa.URL, "allow"
	serve(t, cfg, httptest.NewRequest(http.MethodGet, "http://localhost/", nil))
	return map[string]interface{}{"rules": input["rules"], "groups": input["groups"]}
}

func TestLabelsOfAServiceGiveTheSettingsItsOwnLinesGive(t *testing.T) {
	written := rulesAndGroups(t, &Config{Scopes: "stack.docs.view", Missing: "login"})

	fromLabels := rulesAndGroups(t, &Config{Labels: map[string]interface{}{
		"traefik.http.middlewares.docs-policy.plugin.policy.Scopes":  "stack.docs.view",
		"traefik.http.middlewares.docs-policy.plugin.policy.Missing": "login",
	}})

	if !reflect.DeepEqual(fromLabels, written) {
		t.Fatalf("the labels gave %v, the settings written on the middleware %v", fromLabels, written)
	}
}

// What Traefik's own label parser hands a plugin for these lines (parser.Decode of paerser v0.2.2, compiled): a list
// for indexed entries, a map for named ones, the first spelling of a name for all its spellings, every value a text.
func TestLabelsAreReadAsTraefikReadsAContainersLabels(t *testing.T) {
	got, err := settingsOfLabels(map[string]interface{}{
		"traefik.http.middlewares.docs-policy.plugin.policy.Rules.open.Paths":         "/open/**",
		"traefik.http.middlewares.docs-policy.plugin.policy.Rules.open.Public":        "true",
		"traefik.http.middlewares.docs-policy.plugin.policy.Rules.read.Paths[0]":      "/reports/**",
		"traefik.http.middlewares.docs-policy.plugin.policy.Rules.read.Paths[1]":      "/more/**",
		"traefik.http.middlewares.docs-policy.plugin.policy.Rules.read.Scopes.0.name": "reports.read",
		"traefik.http.middlewares.docs-policy.plugin.policy.rules.READ.Missing":       "login",
		"traefik.http.middlewares.docs-policy.plugin.policy.Groups.users.Scopes":      "a b",
		"traefik.http.routers.docs.rule":                                              "Host(`x.test`)",
		"traefik.enable":                                                              "true",
	})
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]interface{}{
		"Groups": map[string]interface{}{"users": map[string]interface{}{"Scopes": "a b"}},
		"Rules": map[string]interface{}{
			"open": map[string]interface{}{"Paths": "/open/**", "Public": "true"},
			"read": map[string]interface{}{
				"Paths":   []interface{}{"/reports/**", "/more/**"},
				"Scopes":  map[string]interface{}{"0": map[string]interface{}{"name": "reports.read"}},
				"Missing": "login",
			},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("the settings read from the labels:\n got %v\nwant %v", got, want)
	}
}

// A compose file may write a value without quotes; compose makes a text of it for the label, and a cluster's object
// keeps the switch or the number. Both are the same setting.
func TestLabelValueThatIsNoTextIsTheTextComposeMakesOfIt(t *testing.T) {
	asTexts := rulesAndGroups(t, &Config{Labels: map[string]interface{}{
		"traefik.http.middlewares.app-policy.plugin.policy.Public":   "true",
		"traefik.http.middlewares.app-policy.plugin.policy.Priority": "7",
	}})

	asValues := rulesAndGroups(t, &Config{Labels: map[string]interface{}{
		"traefik.http.middlewares.app-policy.plugin.policy.Public":   true,
		"traefik.http.middlewares.app-policy.plugin.policy.Priority": float64(7),
	}})

	if !reflect.DeepEqual(asValues, asTexts) {
		t.Fatalf("the values gave %v, the texts %v", asValues, asTexts)
	}
}

func TestLabelsThatAreNoServicesSettingsStopTheMiddleware(t *testing.T) {
	policy := "traefik.http.middlewares.docs-policy.plugin.policy."
	for name, test := range map[string]struct {
		cfg  *Config
		says string
	}{
		"no line of a middleware's plugin": {
			&Config{Labels: map[string]interface{}{"traefik.http.routers.docs.rule": "Host(`x.test`)"}},
			"no setting of a middleware's plugin",
		},
		"two middlewares": {
			&Config{Labels: map[string]interface{}{policy + "Scopes": "a", "traefik.http.middlewares.other.plugin.policy.Scopes": "b"}},
			"one middleware",
		},
		"a setting that is not a service's": {
			&Config{Labels: map[string]interface{}{policy + "Scopes": "a", policy + "OpaUrl": "http://elsewhere"}},
			"OpaUrl",
		},
		"a middleware of another kind": {
			&Config{Labels: map[string]interface{}{"traefik.http.middlewares.docs-policy.headers.customrequestheaders.X-A": "b"}},
			"no setting of a middleware's plugin",
		},
		"a setting of the service beside its labels": {
			&Config{Scopes: "b", Labels: map[string]interface{}{policy + "Scopes": "a"}},
			"Scopes",
		},
		"labels that are no map": {
			&Config{Labels: "traefik.http.middlewares.docs-policy.plugin.policy.Scopes=a"},
			"Labels",
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := New(context.Background(), http.NotFoundHandler(), test.cfg, "test-labels")

			if err == nil || !strings.Contains(err.Error(), test.says) {
				t.Fatalf("the middleware is created, or the refusal does not say %q: %v", test.says, err)
			}
		})
	}
}
