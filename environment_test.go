package traefik_jwt_plugin

// The tests of the defaults a deployment gives in Traefik's environment: a setting that a middleware does not write
// takes the value of JWT_PLUGIN_<SETTING>, so that a service's middleware holds the service's own settings alone.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
)

// setenv sets a variable of the environment for one test. It is not t.Setenv: under Yaegi that sets the variable of
// the process, and a plugin reads the interpreter's environment, which Traefik fills from its own when it starts.
func setenv(t *testing.T, name, value string) {
	t.Helper()
	if err := os.Setenv(name, value); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Unsetenv(name) })
}

func TestSettingTakesItsDefaultFromTheEnvironment(t *testing.T) {
	setenv(t, "JWT_PLUGIN_OPAURL", "http://opa:8181/v1/data/policy/decision")
	setenv(t, "JWT_PLUGIN_OPAALLOWFIELD", "let")
	setenv(t, "JWT_PLUGIN_OPAHTTPSTATUSFIELD", "status")
	setenv(t, "JWT_PLUGIN_OPABODYFIELD", "body")
	setenv(t, "JWT_PLUGIN_ALG", "RS256")
	setenv(t, "JWT_PLUGIN_AUD", "host.example")
	setenv(t, "JWT_PLUGIN_OPABODY", "false")
	setenv(t, "JWT_PLUGIN_OPADEBUGMODE", "true")
	setenv(t, "JWT_PLUGIN_REQUIRED", "false")
	setenv(t, "JWT_PLUGIN_FORCEREFRESHKEYS", "true")
	setenv(t, "JWT_PLUGIN_OPADECIDESTOKEN", "true")
	setenv(t, "JWT_PLUGIN_OPATIMEOUTMS", "2000")
	setenv(t, "JWT_PLUGIN_JWKSFETCHTIMEOUTSECS", "5")
	setenv(t, "JWT_PLUGIN_KEYS", "https://auth.example/.well-known/jwks.json, https://other.example/jwks")
	setenv(t, "JWT_PLUGIN_PAYLOADFIELDS", "exp")

	got := CreateConfig()

	want := &Config{
		OpaUrl: "http://opa:8181/v1/data/policy/decision", OpaAllowField: "let", OpaHttpStatusField: "status",
		OpaBodyField: "body", Alg: "RS256", Aud: "host.example",
		OpaBody: false, OpaDebugMode: true, Required: false, ForceRefreshKeys: true, OpaDecidesToken: true,
		OpaTimeoutMs: 2000, JwksFetchTimeoutSecs: 5,
		// a list is kept aside until the middleware is created: Traefik has no list to lay a shorter one over
		defaultKeys:          []string{"https://auth.example/.well-known/jwks.json", "https://other.example/jwks"},
		defaultPayloadFields: []string{"exp"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("the configuration a middleware starts from:\n got %+v\nwant %+v", got, want)
	}
}

func TestWithoutTheEnvironmentTheDefaultsAreThePlugins(t *testing.T) {
	got := CreateConfig()

	want := &Config{Required: true, OpaAllowField: "allow", OpaBody: true}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("the configuration a middleware starts from:\n got %+v\nwant %+v", got, want)
	}
}

func TestEmptyVariableIsAsOneNotSet(t *testing.T) {
	setenv(t, "JWT_PLUGIN_OPAALLOWFIELD", "")
	setenv(t, "JWT_PLUGIN_REQUIRED", "")
	setenv(t, "JWT_PLUGIN_KEYS", "")

	got := CreateConfig()

	want := &Config{Required: true, OpaAllowField: "allow", OpaBody: true}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("the configuration a middleware starts from:\n got %+v\nwant %+v", got, want)
	}
}

// noKeys starts a server of key sets that hold no key, and gives its address.
func noKeys(t *testing.T) string {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"keys": []}`))
	}))
	t.Cleanup(ts.Close)
	return ts.URL
}

func TestListIsTheEnvironmentsWhereTheMiddlewareWritesNone(t *testing.T) {
	jwks := noKeys(t)
	setenv(t, "JWT_PLUGIN_PAYLOADFIELDS", "exp, sub")
	setenv(t, "JWT_PLUGIN_KEYS", jwks+"/one,"+jwks+"/two")

	cfg := CreateConfig()
	if _, err := New(context.Background(), http.NotFoundHandler(), cfg, "test-lists-of-the-environment"); err != nil {
		t.Fatal(err)
	}

	if want := []string{"exp", "sub"}; !reflect.DeepEqual(cfg.PayloadFields, want) {
		t.Errorf("the required fields: got %v, want %v", cfg.PayloadFields, want)
	}
	if want := []string{jwks + "/one", jwks + "/two"}; !reflect.DeepEqual(cfg.Keys, want) {
		t.Errorf("the keys: got %v, want %v", cfg.Keys, want)
	}
}

func TestListTheMiddlewareWritesIsItsWholeList(t *testing.T) {
	jwks := noKeys(t)
	setenv(t, "JWT_PLUGIN_PAYLOADFIELDS", "exp, sub")
	setenv(t, "JWT_PLUGIN_KEYS", jwks+"/one,"+jwks+"/two")

	cfg := CreateConfig()
	cfg.PayloadFields = []string{"iat"} // what the middleware writes: one entry where the environment has two
	cfg.Keys = []string{jwks + "/own"}
	if _, err := New(context.Background(), http.NotFoundHandler(), cfg, "test-lists-of-the-middleware"); err != nil {
		t.Fatal(err)
	}

	if want := []string{"iat"}; !reflect.DeepEqual(cfg.PayloadFields, want) {
		t.Errorf("the required fields: got %v, want %v", cfg.PayloadFields, want)
	}
	if want := []string{jwks + "/own"}; !reflect.DeepEqual(cfg.Keys, want) {
		t.Errorf("the keys: got %v, want %v", cfg.Keys, want)
	}
}

// The environment's list is in force: a token that lacks a field it names is refused, one that has them all passes.
func TestFieldTheEnvironmentRequiresIsRequired(t *testing.T) {
	setenv(t, "JWT_PLUGIN_PAYLOADFIELDS", "exp, tenant")
	ask := func(claims string) bool {
		req := httptest.NewRequest(http.MethodGet, "http://docs.example/", nil)
		req.Header.Set("Authorization", bearer(claims))
		_, reached := serve(t, CreateConfig(), req)
		return reached
	}

	if ask(`{"exp": 4102444800}`) {
		t.Error("a token without the field tenant reached the service")
	}
	if !ask(`{"exp": 4102444800, "tenant": "a"}`) {
		t.Error("a token with both fields did not reach the service")
	}
}

func TestEntryOfAMapIsAVariableOfItsOwn(t *testing.T) {
	setenv(t, "JWT_PLUGIN_OPARESPONSEHEADERS_LOCATION", "location")
	setenv(t, "JWT_PLUGIN_OPARESPONSEHEADERS_SET_COOKIE", "set_cookie")
	setenv(t, "JWT_PLUGIN_OPARESPONSEHEADERS_CONTENT_TYPE", "content_type")
	setenv(t, "JWT_PLUGIN_OPAHEADERS_X_USER", "user")
	setenv(t, "JWT_PLUGIN_JWTHEADERS_X_SUBJECT", "sub")
	setenv(t, "JWT_PLUGIN_JWKSHEADERS_AUTHORIZATION", "Basic a2V5OnZhbHVl")

	got := CreateConfig()

	// A header's name is written in a variable's name with _ for its -, in upper case.
	maps := map[string][2]map[string]string{
		"OpaResponseHeaders": {got.OpaResponseHeaders, {"Location": "location", "Set-Cookie": "set_cookie", "Content-Type": "content_type"}},
		"OpaHeaders":         {got.OpaHeaders, {"X-User": "user"}},
		"JwtHeaders":         {got.JwtHeaders, {"X-Subject": "sub"}},
		"JwksHeaders":        {got.JwksHeaders, {"Authorization": "Basic a2V5OnZhbHVl"}},
	}
	for name, pair := range maps {
		if !reflect.DeepEqual(pair[0], pair[1]) {
			t.Errorf("%s: got %v, want %v", name, pair[0], pair[1])
		}
	}
}

func TestVariableThatNamesNoSettingStopsTheMiddleware(t *testing.T) {
	for _, name := range []string{
		"JWT_PLUGIN_OPAURLL",            // a slip of the pen
		"JWT_PLUGIN_SCOPES",             // a service's own setting has no default
		"JWT_PLUGIN_RULES",              // 〃
		"JWT_PLUGIN_JWTSOURCES",         // a list of maps is written in a middleware
		"JWT_PLUGIN_OPARESPONSEHEADERS", // a map is given entry by entry
	} {
		t.Run(name, func(t *testing.T) {
			setenv(t, name, "x")

			_, err := New(context.Background(), http.NotFoundHandler(), CreateConfig(), "test")

			if err == nil || !strings.Contains(err.Error(), name) {
				t.Fatalf("the middleware is created, or the refusal does not name the variable: %v", err)
			}
		})
	}
}

func TestValueOfTheWrongKindStopsTheMiddleware(t *testing.T) {
	for name, value := range map[string]string{
		"JWT_PLUGIN_REQUIRED":     "maybe",
		"JWT_PLUGIN_OPATIMEOUTMS": "soon",
	} {
		t.Run(name, func(t *testing.T) {
			setenv(t, name, value)

			_, err := New(context.Background(), http.NotFoundHandler(), CreateConfig(), "test")

			if err == nil || !strings.Contains(err.Error(), name) {
				t.Fatalf("the middleware is created, or the refusal does not name the variable: %v", err)
			}
		})
	}
}

// A middleware that writes a service's own lines alone asks the OPA of the environment and carries its answer out.
func TestMiddlewareWithTheServicesLinesAloneAsksTheOpaOfTheEnvironment(t *testing.T) {
	opa := opaAnswering(t, `{"allow": false, "status": 302, "location": "/login?scope=docs"}`)
	setenv(t, "JWT_PLUGIN_OPAURL", opa.URL)
	setenv(t, "JWT_PLUGIN_REQUIRED", "false")
	setenv(t, "JWT_PLUGIN_OPADECIDESTOKEN", "true")
	setenv(t, "JWT_PLUGIN_OPAHTTPSTATUSFIELD", "status")
	setenv(t, "JWT_PLUGIN_OPARESPONSEHEADERS_LOCATION", "location")
	cfg := CreateConfig()
	cfg.Scopes = "stack.docs.view" // the service's two lines
	cfg.Missing = "login"

	resp, reached := serve(t, cfg, httptest.NewRequest(http.MethodGet, "http://docs.example/", nil))

	if reached || resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/login?scope=docs" {
		t.Fatalf("reached %v, status %d, Location %q", reached, resp.StatusCode, resp.Header.Get("Location"))
	}
}
