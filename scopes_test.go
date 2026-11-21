package traefik_jwt_plugin

// The tests of what this plugin does around the grammar's settings since its library reads required and optional
// scopes: where the scopes of a group that writes none come from, that a rule's checks reach OPA as written, and
// that a setting the grammar has no more is refused.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

// scopesOf is the scopes OPA receives for the one rule of a middleware: its required and its optional list.
func scopesOf(t *testing.T, cfg *Config) (required, optional []interface{}) {
	t.Helper()
	rule := ruleOf(t, cfg)
	scopes := rule["scopes"].(map[string]interface{})
	return scopes["required"].([]interface{}), scopes["optional"].([]interface{})
}

func ruleOf(t *testing.T, cfg *Config) map[string]interface{} {
	t.Helper()
	var input map[string]interface{}
	opa := opaReceiving(t, &input)
	cfg.OpaUrl, cfg.OpaAllowField = opa.URL, "allow"
	cfg.Required = false // the request brings no token, and OPA is to be asked all the same
	serve(t, cfg, httptest.NewRequest(http.MethodGet, "http://localhost/", nil))
	rules, sent := input["rules"].([]interface{})
	if !sent || len(rules) != 1 {
		t.Fatalf("OPA received the rules %v", input["rules"])
	}
	return rules[0].(map[string]interface{})
}

func list(scopes ...string) []interface{} {
	l := make([]interface{}, 0, len(scopes))
	for _, scope := range scopes {
		l = append(l, scope)
	}
	return l
}

func TestDefaultScopesOfAGroupComeFromTheEnvironment(t *testing.T) {
	setenv(t, "JWT_PLUGIN_GROUPDEFAULTSCOPES_REQUIRED", "openid")
	setenv(t, "JWT_PLUGIN_GROUPDEFAULTSCOPES_OPTIONAL", "profile email offline")
	cfg := CreateConfig()
	cfg.Scopes = "admin"

	required, optional := scopesOf(t, cfg)

	if !reflect.DeepEqual(required, list("admin", "openid")) || !reflect.DeepEqual(optional, list("email", "offline", "profile")) {
		t.Fatalf("required %v, optional %v", required, optional)
	}
}

func TestDefaultScopesGivenAsOneValueAreAllRequired(t *testing.T) {
	setenv(t, "JWT_PLUGIN_GROUPDEFAULTSCOPES", "openid profile")
	cfg := CreateConfig()
	cfg.Scopes = "admin"

	required, optional := scopesOf(t, cfg)

	if !reflect.DeepEqual(required, list("admin", "openid", "profile")) || len(optional) != 0 {
		t.Fatalf("required %v, optional %v", required, optional)
	}
}

func TestDefaultScopesGivenBothWaysStopTheMiddleware(t *testing.T) {
	setenv(t, "JWT_PLUGIN_GROUPDEFAULTSCOPES", "openid")
	setenv(t, "JWT_PLUGIN_GROUPDEFAULTSCOPES_OPTIONAL", "profile")

	_, err := New(context.Background(), http.NotFoundHandler(), CreateConfig(), "test")

	if err == nil || !strings.Contains(err.Error(), "JWT_PLUGIN_GROUPDEFAULTSCOPES") {
		t.Fatalf("the middleware is created, or the refusal does not name the variable: %v", err)
	}
}

// One source replaces the other whole: the middleware's own scopes in the place of the environment's, a service's
// labels in the place of both.
func TestDefaultScopesAMiddlewareWritesReplaceTheEnvironments(t *testing.T) {
	setenv(t, "JWT_PLUGIN_GROUPDEFAULTSCOPES_REQUIRED", "openid")
	setenv(t, "JWT_PLUGIN_GROUPDEFAULTSCOPES_OPTIONAL", "profile email offline")
	cfg := CreateConfig()
	cfg.Scopes = "admin"
	cfg.GroupDefaultScopes = map[string]interface{}{"optional": "tenant"}

	required, optional := scopesOf(t, cfg)

	if !reflect.DeepEqual(required, list("admin")) || !reflect.DeepEqual(optional, list("tenant")) {
		t.Fatalf("required %v, optional %v", required, optional)
	}
}

func TestDefaultScopesBesideLabelsAreTheDeploymentsUnlessTheLabelsGiveTheirOwn(t *testing.T) {
	policy := "traefik.http.middlewares.docs-policy.plugin.policy."
	deployment := map[string]interface{}{"required": "openid", "optional": "profile"}

	required, optional := scopesOf(t, &Config{GroupDefaultScopes: deployment, Labels: map[string]interface{}{
		policy + "Scopes": "stack.docs.view",
	}})
	if !reflect.DeepEqual(required, list("openid", "stack.docs.view")) || !reflect.DeepEqual(optional, list("profile")) {
		t.Errorf("the deployment's: required %v, optional %v", required, optional)
	}

	required, optional = scopesOf(t, &Config{GroupDefaultScopes: deployment, Labels: map[string]interface{}{
		policy + "Scopes":                      "stack.docs.view",
		policy + "GroupDefaultScopes.optional": "tenant",
	}})
	if !reflect.DeepEqual(required, list("stack.docs.view")) || !reflect.DeepEqual(optional, list("tenant")) {
		t.Errorf("the labels' own: required %v, optional %v", required, optional)
	}
}

func TestChecksOfARuleReachOpaAsWritten(t *testing.T) {
	rule := ruleOf(t, &Config{Scopes: "admin", AdditionalChecks: "weekdays,internal_client"})
	if rule["claimChecks"] != nil || !reflect.DeepEqual(rule["additionalChecks"], list("weekdays", "internal_client")) {
		t.Errorf("a rule that adds checks: claimChecks %v, additionalChecks %v", rule["claimChecks"], rule["additionalChecks"])
	}

	rule = ruleOf(t, &Config{Scopes: "admin", ClaimChecks: []interface{}{}})
	if checks, isList := rule["claimChecks"].([]interface{}); !isList || len(checks) != 0 {
		t.Errorf("a rule that writes an empty list of checks: claimChecks %v", rule["claimChecks"])
	}
}

func TestSettingsOfARuleAtTheTopAreRead(t *testing.T) {
	// the rule's own setting says false: nothing of its group is merged, the default scopes neither
	required, optional := scopesOf(t, &Config{Scopes: "admin", Group: "staff", RequestOtherGroupScopes: "false"})

	if !reflect.DeepEqual(required, list("admin")) || len(optional) != 0 {
		t.Fatalf("required %v, optional %v", required, optional)
	}
}

func TestAnyIsRefused(t *testing.T) {
	_, err := New(context.Background(), http.NotFoundHandler(), &Config{Any: "a b"}, "test")

	if err == nil || !strings.Contains(err.Error(), `unknown key "Any"`) {
		t.Fatalf("the middleware is created, or the refusal does not name the key: %v", err)
	}
}
