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
