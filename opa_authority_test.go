package traefik_jwt_plugin

// The tests of this fork's changes: OPA is the authority for the whole answer. A header it sets replaces the caller's,
// a form body reaches it, a token that fails its checks is OPA's to answer (OpaDecidesToken), the call to OPA ends
// after a time and no answer is a 503 (OpaTimeoutMs), and a denial's body is the decision's (OpaBodyField).

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

// opaAnswering starts an OPA that answers every decision with the given result object.
func opaAnswering(t *testing.T, result string) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, `{ "result": %s }`, result)
	}))
	t.Cleanup(ts.Close)
	return ts
}

// serve passes the request through the plugin and reports the response and whether the next handler was reached.
func serve(t *testing.T, cfg *Config, req *http.Request) (*http.Response, bool) {
	t.Helper()
	reached := false
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { reached = true })
	plugin, err := New(context.Background(), next, cfg, "test-traefik-jwt-plugin")
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	plugin.ServeHTTP(recorder, req)
	return recorder.Result(), reached
}

func bodyOf(t *testing.T, resp *http.Response) string {
	t.Helper()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// A token whose claims are the given JSON. Its signature is not checked where no key is configured.
func bearer(claims string) string {
	return "Bearer eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9." + base64.RawURLEncoding.EncodeToString([]byte(claims)) + ".c2lnbmF0dXJl"
}

func TestOpaHeaderReplacesTheCallersValue(t *testing.T) {
	opa := opaAnswering(t, `{ "allow": true, "user": "alice" }`)
	cfg := &Config{OpaUrl: opa.URL, OpaAllowField: "allow", OpaHeaders: map[string]string{"X-User": "user"}}
	req := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	req.Header.Set("X-User", "mallory")

	_, reached := serve(t, cfg, req)

	if !reached {
		t.Fatal("the request did not pass")
	}
	if got := req.Header.Values("X-User"); !reflect.DeepEqual(got, []string{"alice"}) {
		t.Fatalf("the upstream sees X-User %q, expected only OPA's value", got)
	}
}

func TestOpaHeaderTheDecisionLacksIsRemoved(t *testing.T) {
	opa := opaAnswering(t, `{ "allow": true }`)
	cfg := &Config{OpaUrl: opa.URL, OpaAllowField: "allow", OpaHeaders: map[string]string{"X-User": "user"}}
	req := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	req.Header.Set("X-User", "mallory")

	_, reached := serve(t, cfg, req)

	if !reached {
		t.Fatal("the request did not pass")
	}
	if got := req.Header.Values("X-User"); len(got) != 0 {
		t.Fatalf("the upstream sees the caller's X-User %q", got)
	}
}

func TestFormBodyReachesOpa(t *testing.T) {
	var form url.Values
	opa := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload Payload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Error(err)
		}
		form = payload.Input.Form
		_, _ = fmt.Fprint(w, `{ "result": { "allow": true } }`)
	}))
	defer opa.Close()
	cfg := &Config{OpaUrl: opa.URL, OpaAllowField: "allow", OpaBody: true}
	req := httptest.NewRequest(http.MethodPost, "http://localhost/", strings.NewReader("a=1&b=2"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	serve(t, cfg, req)

	if expected := (url.Values{"a": {"1"}, "b": {"2"}}); !reflect.DeepEqual(form, expected) {
		t.Fatalf("OPA received the form %v, expected %v", form, expected)
	}
}

func TestOpaDecidesATokenThatFailsItsChecks(t *testing.T) {
	var input map[string]interface{}
	opa := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Error(err)
		}
		input = payload["input"]
		_, _ = fmt.Fprint(w, `{ "result": { "allow": false, "status": 401 } }`)
	}))
	defer opa.Close()
	cfg := &Config{
		OpaUrl: opa.URL, OpaAllowField: "allow", OpaHttpStatusField: "status",
		PayloadFields: []string{"exp"}, OpaDecidesToken: true,
	}
	req := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	req.Header.Set("Authorization", bearer(fmt.Sprintf(`{"sub": "alice", "exp": %d}`, time.Now().Add(-time.Minute).Unix())))

	resp, reached := serve(t, cfg, req)

	if reached {
		t.Fatal("the request passed")
	}
	if input == nil {
		t.Fatal("OPA was not asked")
	}
	if input["tokenPayload"] != nil {
		t.Fatalf("OPA received the claims of a token that failed its checks: %v", input["tokenPayload"])
	}
	if input["tokenError"] != "token is expired" {
		t.Fatalf("OPA received the reason %q, expected %q", input["tokenError"], "token is expired")
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("the answer is %d, expected OPA's 401", resp.StatusCode)
	}
}

func TestPluginRefusesATokenThatFailsItsChecksWithoutTheSetting(t *testing.T) {
	asked := false
	opa := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = true
		_, _ = fmt.Fprint(w, `{ "result": { "allow": true } }`)
	}))
	defer opa.Close()
	cfg := &Config{OpaUrl: opa.URL, OpaAllowField: "allow", PayloadFields: []string{"exp"}}
	req := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	req.Header.Set("Authorization", bearer(fmt.Sprintf(`{"exp": %d}`, time.Now().Add(-time.Minute).Unix())))

	resp, reached := serve(t, cfg, req)

	if reached || asked {
		t.Fatalf("the request passed (%t) or OPA was asked (%t)", reached, asked)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("the answer is %d, expected the plugin's 403", resp.StatusCode)
	}
}

func TestOpaThatDoesNotAnswerInTimeIs503(t *testing.T) {
	answered := make(chan struct{})
	opa := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(answered)
		time.Sleep(300 * time.Millisecond) // an OPA that answers late, and would let the request pass
		_, _ = fmt.Fprint(w, `{ "result": { "allow": true } }`)
	}))
	defer opa.Close()
	cfg := &Config{OpaUrl: opa.URL, OpaAllowField: "allow", OpaTimeoutMs: 50}
	req := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)

	resp, reached := serve(t, cfg, req)
	<-answered // the late answer is out before the server closes: under Yaegi a deferred Close does not wait for it

	if reached {
		t.Fatal("the request passed on an answer that came after OpaTimeoutMs")
	}
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("the answer is %d, expected 503", resp.StatusCode)
	}
}

func TestOpaThatCannotBeReachedIs503(t *testing.T) {
	opa := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	opa.Close()
	cfg := &Config{OpaUrl: opa.URL, OpaAllowField: "allow"}
	req := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)

	resp, reached := serve(t, cfg, req)

	if reached {
		t.Fatal("the request passed without OPA")
	}
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("the answer is %d, expected 503", resp.StatusCode)
	}
}

func TestOpaAnswerWithoutTheAllowFieldIs503(t *testing.T) {
	tests := map[string]string{
		"no allow field":   `{ "result": { "status": 302 } }`,
		"no result":        `{}`,
		"refused by OPA":   `{ "code": "unauthorized", "message": "request rejected by administrative policy" }`,
		"allow no boolean": `{ "result": { "allow": "yes" } }`,
		"no JSON":          `<html>`,
	}
	for name, answer := range tests {
		t.Run(name, func(t *testing.T) {
			opa := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = fmt.Fprint(w, answer)
			}))
			defer opa.Close()
			cfg := &Config{OpaUrl: opa.URL, OpaAllowField: "allow", OpaHttpStatusField: "status"}
			req := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)

			resp, reached := serve(t, cfg, req)

			if reached {
				t.Fatal("the request passed without a decision")
			}
			if resp.StatusCode != http.StatusServiceUnavailable {
				t.Fatalf("the answer is %d, expected 503", resp.StatusCode)
			}
		})
	}
}

func TestOpaBodyIsTheDenialsBody(t *testing.T) {
	opa := opaAnswering(t, `{ "allow": false, "status": 403, "content_type": "text/html; charset=utf-8", "body": "<h1>No permission</h1>" }`)
	cfg := &Config{
		OpaUrl: opa.URL, OpaAllowField: "allow", OpaHttpStatusField: "status", OpaBodyField: "body",
		OpaResponseHeaders: map[string]string{"Content-Type": "content_type"},
	}
	req := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)

	resp, reached := serve(t, cfg, req)

	if reached {
		t.Fatal("the request passed")
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("the answer is %d, expected 403", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Fatalf("the content type is %q, expected the decision's", got)
	}
	if got := bodyOf(t, resp); got != "<h1>No permission</h1>" {
		t.Fatalf("the body is %q, expected the decision's", got)
	}
}

func TestDenialWithoutABodyKeepsThePluginsText(t *testing.T) {
	opa := opaAnswering(t, `{ "allow": false, "status": 401 }`)
	cfg := &Config{OpaUrl: opa.URL, OpaAllowField: "allow", OpaHttpStatusField: "status", OpaBodyField: "body"}
	req := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)

	resp, _ := serve(t, cfg, req)

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("the answer is %d, expected 401", resp.StatusCode)
	}
	if got := strings.TrimSpace(bodyOf(t, resp)); got != "forbidden" {
		t.Fatalf("the body is %q, expected the plugin's text", got)
	}
}

// What the policy's login redirect relies on: the status, the Location and the cookie are the decision's.
func TestOpaRedirectCarriesItsLocationAndCookie(t *testing.T) {
	opa := opaAnswering(t, `{ "allow": false, "status": 302, "location": "/login?scope=a+b", "set_cookie": "policy-asked=a+b; Max-Age=60; Path=/" }`)
	cfg := &Config{
		OpaUrl: opa.URL, OpaAllowField: "allow", OpaHttpStatusField: "status",
		OpaResponseHeaders: map[string]string{"Location": "location", "Set-Cookie": "set_cookie"},
	}
	req := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)

	resp, reached := serve(t, cfg, req)

	if reached {
		t.Fatal("the request passed")
	}
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("the answer is %d, expected 302", resp.StatusCode)
	}
	if got := resp.Header.Get("Location"); got != "/login?scope=a+b" {
		t.Fatalf("the Location is %q", got)
	}
	if got := resp.Header.Get("Set-Cookie"); got != "policy-asked=a+b; Max-Age=60; Path=/" {
		t.Fatalf("the cookie is %q", got)
	}
}

// Without an OPA to ask, nobody answers for a token that failed its checks: the plugin refuses it.
func TestOpaDecidesTokenNeedsAnOpa(t *testing.T) {
	cfg := &Config{PayloadFields: []string{"exp"}, OpaDecidesToken: true}
	req := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	req.Header.Set("Authorization", bearer(fmt.Sprintf(`{"exp": %d}`, time.Now().Add(-time.Minute).Unix())))

	resp, reached := serve(t, cfg, req)

	if reached {
		t.Fatal("a request with an expired token passed")
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("the answer is %d, expected the plugin's 403", resp.StatusCode)
	}
}

// opaReceiving starts an OPA that lets every request pass and keeps the input of the last one in *input.
func opaReceiving(t *testing.T, input *map[string]interface{}) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Error(err)
		}
		*input = payload["input"]
		_, _ = fmt.Fprint(w, `{ "result": { "allow": true } }`)
	}))
	t.Cleanup(ts.Close)
	return ts
}

// The settings of the service a middleware is on are its own configuration, written in compusib's grammar for a
// plugin's settings. The plugin normalizes them when the middleware is created and passes the one form to OPA with
// every request, as input.rules. Here the shortest form: two settings at the top. The scopes beside the rule's own
// are those of its group, which writes none: the built-in default scopes of a group.
func TestSettingsOfTheServiceReachOpaNormalized(t *testing.T) {
	var input map[string]interface{}
	opa := opaReceiving(t, &input)
	cfg := &Config{OpaUrl: opa.URL, OpaAllowField: "allow", Scopes: "admin.cluster", Missing: "login"}

	serve(t, cfg, httptest.NewRequest(http.MethodGet, "http://localhost/", nil))

	rules := []interface{}{map[string]interface{}{
		"name": "default", "priority": float64(3),
		"paths": []interface{}{"/**"}, "methods": []interface{}{}, "public": false,
		"scopes": map[string]interface{}{
			"required": []interface{}{"admin.cluster", "openid"},
			"optional": []interface{}{"address", "email", "offline", "phone", "profile"},
		},
		"missing":          map[string]interface{}{"action": "login"},
		"claimChecks":      nil,
		"additionalChecks": []interface{}{},
	}}
	if !reflect.DeepEqual(input["rules"], rules) {
		t.Fatalf("OPA received the rules %v, expected %v", input["rules"], rules)
	}
	if groups, sent := input["groups"]; sent {
		t.Fatalf("OPA received groups, which are worked into the rules: %v", groups)
	}
}

// Settings as docker labels hand them over, a map whose values are texts, give the same form as a cluster's object.
func TestSettingsWrittenAsLabelsAndAsAnObjectAreOneForm(t *testing.T) {
	asLabels := map[string]interface{}{"page": map[string]interface{}{
		"Paths": "/a/**,/b/**", "Methods": "GET", "Missing": "login",
		"Scopes": map[string]interface{}{"0": map[string]interface{}{"name": "reports.read"}},
	}}
	asObject := []interface{}{map[string]interface{}{
		"Paths": []interface{}{"/a/**", "/b/**"}, "Methods": []interface{}{"GET"}, "Missing": "login",
		"Scopes": []interface{}{"reports.read"},
	}}
	received := func(rules interface{}) map[string]interface{} {
		var input map[string]interface{}
		opa := opaReceiving(t, &input)
		serve(t, &Config{OpaUrl: opa.URL, OpaAllowField: "allow", Rules: rules}, httptest.NewRequest(http.MethodGet, "http://localhost/", nil))
		rule := input["rules"].([]interface{})[0].(map[string]interface{})
		delete(rule, "name") // the key in the one, the place in the list in the other
		return rule
	}

	fromLabels, fromObject := received(asLabels), received(asObject)

	if !reflect.DeepEqual(fromLabels, fromObject) {
		t.Fatalf("the labels gave %v, the object %v", fromLabels, fromObject)
	}
	if paths := fromLabels["paths"]; !reflect.DeepEqual(paths, []interface{}{"/a/**", "/b/**"}) {
		t.Fatalf("the paths are %v", paths)
	}
}

// Settings the grammar cannot read refuse the middleware: Traefik does not create it, and its routes answer 404.
func TestMiddlewareWithUnreadableSettingsIsNotCreated(t *testing.T) {
	cfg := &Config{OpaUrl: "http://localhost:8181", OpaAllowField: "allow", Rules: map[string]interface{}{
		"page": map[string]interface{}{"Scopse": "admin"},
	}}
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	_, err := New(context.Background(), next, cfg, "test-traefik-jwt-plugin")

	if err == nil || !strings.Contains(err.Error(), `Rules.page: unknown key "Scopse"`) {
		t.Fatalf("the middleware was created, or the error does not name the key: %v", err)
	}
}

func TestRequestOfAServiceWithoutSettingsCarriesNone(t *testing.T) {
	var input map[string]interface{}
	opa := opaReceiving(t, &input)
	cfg := &Config{OpaUrl: opa.URL, OpaAllowField: "allow"}

	serve(t, cfg, httptest.NewRequest(http.MethodGet, "http://localhost/", nil))

	for _, key := range []string{"rules", "groups"} {
		if value, sent := input[key]; sent {
			t.Fatalf("OPA received %s %v from a middleware that has none", key, value)
		}
	}
}

// A decision may set several cookies: a header OPA gives as a list has one line per entry.
func TestOpaHeaderGivenAsAListHasOneLinePerEntry(t *testing.T) {
	opa := opaAnswering(t, `{ "allow": false, "status": 302, "location": "/login", "set_cookie": ["asked.a=1; Path=/", "asked.b=1; Path=/"] }`)
	cfg := &Config{
		OpaUrl: opa.URL, OpaAllowField: "allow", OpaHttpStatusField: "status",
		OpaResponseHeaders: map[string]string{"Location": "location", "Set-Cookie": "set_cookie"},
	}
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})
	plugin, err := New(context.Background(), next, cfg, "test-traefik-jwt-plugin")
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	recorder.Header().Add("Set-Cookie", "session=refreshed; Path=/")

	plugin.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://localhost/", nil))

	got := recorder.Result().Header.Values("Set-Cookie")
	want := []string{"session=refreshed; Path=/", "asked.a=1; Path=/", "asked.b=1; Path=/"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("the cookies are %q, expected %q", got, want)
	}
	if got := recorder.Result().Header.Values("Location"); !reflect.DeepEqual(got, []string{"/login"}) {
		t.Fatalf("the Location is %q", got)
	}
}

// A cookie OPA sets is added to the cookies of the response: one an earlier middleware put there, such as a login
// plugin's refreshed session, stays. It reaches the response of a request that passes, too.
func TestOpaCookieIsAddedToTheCookiesOfTheResponse(t *testing.T) {
	opa := opaAnswering(t, `{ "allow": true, "set_cookie": "policy-asked=; Max-Age=0; Path=/" }`)
	cfg := &Config{
		OpaUrl: opa.URL, OpaAllowField: "allow",
		OpaResponseHeaders: map[string]string{"Set-Cookie": "set_cookie"},
	}
	reached := false
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) { reached = true })
	plugin, err := New(context.Background(), next, cfg, "test-traefik-jwt-plugin")
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	recorder.Header().Add("Set-Cookie", "session=refreshed; Path=/")

	plugin.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://localhost/", nil))

	if !reached {
		t.Fatal("the request did not pass")
	}
	got := recorder.Result().Header.Values("Set-Cookie")
	want := []string{"session=refreshed; Path=/", "policy-asked=; Max-Age=0; Path=/"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("the cookies are %q, expected %q", got, want)
	}
}
