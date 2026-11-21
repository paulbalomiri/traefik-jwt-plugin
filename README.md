# traefik-jwt-plugin ![Build](https://github.com/paulbalomiri/traefik-jwt-plugin/actions/workflows/build.yaml/badge.svg)

> [!NOTE]
> This is a fork of [traefik-plugins/traefik-jwt-plugin](https://github.com/traefik-plugins/traefik-jwt-plugin), which has
> no maintainer. It is kept as a pure Go plugin: no dependencies, no build tooling besides Go, a release is a tag. On
> top of upstream it makes OPA the authority for the whole answer: see `OpaDecidesToken`, `OpaTimeoutMs` and
> `OpaBodyField` below.

Traefik plugin for verifying JSON Web Tokens (JWT). Supports public keys, certificates or JWKS endpoints.
Supports RSA, ECDSA and symmetric keys. Supports Open Policy Agent (OPA) for additional authorization checks.

Features:

* RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512, HS256, HS384, HS512
* Certificates or public keys can be configured in the dynamic config
* Supports JWK endpoints for fetching keys remotely
* Reject a request or Log warning when required field is missing from JWT payload
* Validate request with Open Policy Agent
* Adds the verified and decoded token to the OPA input

## Installation

The plugin needs to be configured in the Traefik static configuration before it can be used.

### Kubernetes

Tested with [official Traefik chart](https://artifacthub.io/packages/helm/traefik/traefik) version 26.0.0.

The following snippet should be added to `values.yaml`:

```yaml
experimental:
  plugins:
    jwt:
      moduleName: github.com/paulbalomiri/traefik-jwt-plugin
      version: v0.11.0
```

### Command line

```sh
traefik \
  --experimental.plugins.jwt.moduleName=github.com/paulbalomiri/traefik-jwt-plugin \
  --experimental.plugins.jwt.version=v0.11.0
```

## Configuration

The plugin currently supports the following configuration settings: (all fields are optional)

Name | Description
---- | ----
OpaUrl | URL of OPA policy document requested for decision, e.g. http://opa:8181/v1/data/example.
OpaAllowField | Field in the JSON result which contains a boolean, indicating whether the request is allowed or not. Default `allow`.
OpaBody | Boolean indicating whether the request body should be added to the OPA input.
OpaDebugMode | Set the opa response in the http response body when the request isn't allowed otherwise the response body is `forbidden`
PayloadFields | The field-name in the JWT payload that are required (e.g. `exp`). Multiple field names may be specified (string array)
Required | Is `Authorization` header with JWT token required for every request.
Keys | Used to validate JWT signature. Multiple keys are supported. Allowed values include certificates, public keys, symmetric keys. In case the value is a valid URL, the plugin will fetch keys from the JWK endpoint.
ForceRefreshKeys | Force fetching keys from JWKS service when the key of current JWT token is not found. If set false, keys will only be refreshed every 15 minutes by default.
JwksFetchTimeoutSecs | Timeout in seconds for JWKS endpoint HTTP requests, and for how long a request will wait for a forced key refresh (when `ForceRefreshKeys` is true) before continuing with cached keys. Default `0` (no timeout).
Alg | Used to verify which PKI algorithm is used in the JWT.
JwksHeaders | Map used to add headers to a JWKS request (e.g. credentials for a 3rd party JWKS service).
JwtHeaders | Map used to inject JWT payload fields as HTTP request headers.
OpaHeaders | Map used to inject OPA result fields as HTTP request headers. Populated if request is allowed by OPA. Only 1st level keys from OPA document are supported. A header named here is OPA's alone: the caller's value is replaced, and removed where the result lacks the field.
OpaResponseHeaders | Map used to inject OPA result fields as HTTP response headers. Populated if OPA response has `OpaAllowField` present, regardless of value. Only 1st level keys from OPA document are supported. A field that holds a list gives one header line per entry. A `Set-Cookie` is added to the cookies already on the response; any other header replaces.
OpaHttpStatusField | Field in OPA JSON result, which contains int or string HTTP status code that will be returned in case of disallowed OPA response. Accepted range is >= 300 and < 600. Only 1st level keys from OPA document are supported.
OpaBodyField | Field in OPA JSON result which contains the body of the response in case of disallowed OPA response, as a string. Set its `Content-Type` with `OpaResponseHeaders`. Where the result lacks the field the body is `forbidden`.
OpaDecidesToken | Boolean. A token that fails its checks (signature, expiry, required fields, audience) is not refused by the plugin: the request reaches OPA without `tokenPayload` and with the reason as `tokenError`, and OPA answers. Needs `OpaUrl`. Default `false`.
OpaTimeoutMs | Timeout in milliseconds for the request to OPA. Default `0` (no timeout). A request that gets no decision from OPA — no answer in time, OPA unreachable, a result without `OpaAllowField` — is answered `503`.
Rules, Groups | The settings of the service this middleware is on: its rules and its scope groups, written in compusib's grammar for a plugin's settings (`github.com/compusib/compugo-oss/libs/traefik`). A service with one rule writes that rule's fields at the top instead: `Paths`, `Methods`, `Public`, `Group`, `Scopes`, `RequestOtherGroupScopes`, `Missing`, `Priority`, `ClaimChecks`, `AdditionalChecks`. The plugin normalizes them when the middleware is created, logs the normalized form, and is not created on what the grammar cannot read. It passes the normalized form to OPA with every request as `input.rules`: each rule with its required and its optional scopes, the groups worked in. What they mean is the policy's.
GroupDefaultScopes | The scopes of every group that writes none of its own, in the same grammar. A deployment gives them once, in Traefik's environment or on each middleware; a service that writes them itself has its own. One source replaces the other whole.
Labels | The settings of the service as the service's docker labels, the lines a compose file writes for its middleware of this plugin: a map of label to value. See [The service's labels as one setting](#the-services-labels-as-one-setting). With `Labels` a middleware writes none of `Rules`, `Groups` and a rule's fields itself.
JwtCookieKey | (Deprecated, use JwtSources)Name of the cookie to extract JWT if not found in `Authorization` header.
JwtQueryKey | (Deprecated, use JwtSources) Name of the query parameter to extract JWT if not found in `Authorization` header or in the specified cookie.
JwtSources | Ordered List of sources [bearer, header, query, cookie] of the JWT. config format is a list of maps e.g. [{type: bearer, key: Authorization}, {type: query, key, jwt}]


### Defaults from Traefik's environment

A setting that a middleware does not write takes the value of the environment variable `JWT_PLUGIN_<SETTING>` of
Traefik's process, where one is set: the setting's name in upper case. A deployment so says once what all its
middlewares of this plugin share (where OPA is, the keys, the fields of the decision), and a service's middleware
holds the service's own settings alone.

Kind of setting | Example | The variable's value
---- | ---- | ----
a text | `JWT_PLUGIN_OPAURL` | the text
a switch | `JWT_PLUGIN_REQUIRED` | `true` or `false`
a number | `JWT_PLUGIN_OPATIMEOUTMS` | digits
a list: `Keys`, `PayloadFields` | `JWT_PLUGIN_KEYS` | the entries, separated by commas
a map: `OpaHeaders`, `JwtHeaders`, `JwksHeaders`, `OpaResponseHeaders` | `JWT_PLUGIN_OPARESPONSEHEADERS_SET_COOKIE` | one variable per entry: the header's name follows the setting's, in upper case with `_` for its `-`

- What a middleware writes replaces the default. A list it writes is its whole list. An entry of a map is a setting
  of its own: a middleware that writes one keeps the other entries of the default.
- An empty variable is as one not set.
- A variable that names no such setting, or whose value is not of its setting's kind, is an error: no middleware of
  the plugin is created.
- The settings of a service (`Rules`, `Groups` and a rule's fields), `JwtSources`, `JwtCookieKey` and `JwtQueryKey`
  have no default in the environment.
- `GroupDefaultScopes` has: `JWT_PLUGIN_GROUPDEFAULTSCOPES` for scopes that are all required, or
  `JWT_PLUGIN_GROUPDEFAULTSCOPES_REQUIRED` and `JWT_PLUGIN_GROUPDEFAULTSCOPES_OPTIONAL`, each a list of scopes
  separated by spaces.

With these in Traefik's environment a service's middleware is the service's two lines:

```yaml
# Traefik's environment
JWT_PLUGIN_OPAURL: http://opa:8181/v1/data/policy/decision
JWT_PLUGIN_KEYS: https://auth.example/.well-known/jwks.json
JWT_PLUGIN_REQUIRED: 'false'
JWT_PLUGIN_OPADECIDESTOKEN: 'true'
JWT_PLUGIN_OPAHTTPSTATUSFIELD: status
JWT_PLUGIN_OPARESPONSEHEADERS_LOCATION: location
```

```yaml
# the service's labels
traefik.http.middlewares.docs-policy.plugin.jwt.Scopes: stack.docs.view
traefik.http.middlewares.docs-policy.plugin.jwt.Missing: login
```

### The service's labels as one setting

A service that runs in docker and on a cluster writes what it requires once, as the labels of its compose
definition. Compose reads them as labels of the container. A cluster's Middleware takes the same lines whole, as
`Labels`:

```yaml
# compose: the service's labels
traefik.http.middlewares.docs-policy.plugin.jwt.Scopes: stack.docs.view
traefik.http.middlewares.docs-policy.plugin.jwt.Missing: login
```

```yaml
# a cluster: the Middleware of the same service
spec:
  plugin:
    jwt:
      Labels:
        traefik.http.middlewares.docs-policy.plugin.jwt.Scopes: stack.docs.view
        traefik.http.middlewares.docs-policy.plugin.jwt.Missing: login
```

- The keys are read by Traefik's own code for a container's labels (`paerser/`, copied from
  `github.com/traefik/paerser`), so the settings are the ones Traefik hands the plugin in docker: a list for indexed
  entries, a map for named ones, every value a text.
- The lines are those of one middleware's plugin, whatever the two are named. A label of anything else, a router's
  or a service's, is passed over.
- A value that is a switch or a number in the object is the text compose makes of it.
- A line that sets anything but a service's settings is an error, and so is `Labels` beside one of those settings
  written on the middleware: the middleware is not created.

### Example configuration

This example uses Kubernetes Custom Resource Descriptors (CRD) :

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: jwt
spec:
  plugin:
    jwt:
      OpaUrl: http://localhost:8181/v1/data/example
      OpaAllowField: allow
      OpaBody: true
      PayloadFields:
        - exp
      Required: true
      Keys:
        - https://samples.auth0.com/.well-known/jwks.json
        - |
          -----BEGIN PUBLIC KEY-----
          MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSv
          vkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHc
          aT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIy
          tvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0
          e+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWb
          V6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9
          MwIDAQAB
        -----END PUBLIC KEY-----
      OpaHeaders:
        X-Allowed: allow
      JwtHeaders:
        X-Subject: sub
      OpaResponseHeaders:
        X-Allowed: allow
      OpaHttpStatusField: allow_status_code
      JwtSources:
        - type: bearer
          key: Authorization
        - type: cookie
          key: jwt
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: test-server
  labels:
    app: test-server
  annotations:
    kubernetes.io/ingress.class: traefik
    traefik.ingress.kubernetes.io/router.middlewares: default-jwt@kubernetescrd
```

## Open Policy Agent

The following section describes how to use this plugin with Open Policy Agent (OPA)

![OPA diagram](http://www.plantuml.com/plantuml/proxy?cache=no&src=https://raw.githubusercontent.com/paulbalomiri/traefik-jwt-plugin/main/opa.puml)

### OPA input payload

The plugin will translate the HTTP request (including headers and parameters) and forwards the payload as JSON to OPA.
For example, the following URL: `http://localhost/api/path?param1=foo&param2=bar`
will result in the following payload (headers are reduced for readability):

```json
{
    "headers": {
      "Accept-Encoding": [
        "gzip, deflate, br"
      ],
      "Authorization": [
        "Bearer XXX.XXX.XXX"
      ],
      "X-Forwarded-Host": [
        "localhost"
      ],
      "X-Forwarded-Port": [
        "80"
      ],
      "X-Forwarded-Proto": [
        "http"
      ],
      "X-Forwarded-Server": [
        "traefik-84c77c5547-sm2cb"
      ],
      "X-Real-Ip": [
        "172.18.0.1"
      ]
    },
    "host": "localhost",
    "method": "POST",
    "parameters": {
      "param1": [
        "foo"
      ],
      "param2": [
        "bar"
      ]
    },
    "body": {
      "foo": "bar"
    },
    "path": [
      "api",
      "path"
    ],
    "tokenHeader": {
        "alg": "RS512",
        "kid": "abc123"
    },
    "tokenPayload": {
        "exp": 1652263686,
        "sub": "johndoe@host.com"
    }
}
```

### Example OPA policy in Rego

The policies you enforce can be as complex or simple as you prefer.
For example, the policy could decode the JWT token and verify the token is valid and has not expired,
and that the user has the required claims in the token.

The policy below shows an simplified example:

```rego
package example

import future.keywords.in
import future.keywords.if

default allow := false

allow if {
    input.method == "GET"
    input.path[0] == "public"
}

allow if {
    input.method == "GET"
    input.path[0] == "secure"
    input.path[1] in {"123", "456"}
}
```

In the above example, requesting `/public/anything` or `/secure/123` or `/secure/456` is allowed,
however requesting `/secure/xxx` would be rejected and results in a 403 Forbidden.

## License

This software is released under the Apache 2.0 License
