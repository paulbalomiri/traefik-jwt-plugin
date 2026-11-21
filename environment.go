package traefik_jwt_plugin

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

// envPrefix starts the name of an environment variable of Traefik that gives a setting its default. The setting's
// name follows in upper case: JWT_PLUGIN_OPAURL is the default of OpaUrl.
const envPrefix = "JWT_PLUGIN_"

// defaultsFromEnvironment gives every setting that a variable of the environment names that variable's value. It is
// the configuration a middleware starts from: what the middleware writes itself replaces it. So a deployment says
// once, in Traefik's environment, what all its middlewares of this plugin share (where OPA is, the keys, the fields
// of the decision), and a service's middleware holds the service's own settings alone.
//
//   - a text, a switch (true, false) and a number are the variable's value;
//
//   - a list is its value, separated by commas. It is kept aside and taken when the middleware is created, where
//     the middleware writes none (listDefaults): laid over a default by Traefik, a shorter list would keep the
//     default's last entries;
//
//   - a map has one variable per entry, JWT_PLUGIN_<SETTING>_<HEADER>: every map of this plugin is keyed by a
//     header's name, written here in upper case with _ for its - (OPARESPONSEHEADERS_SET_COOKIE is Set-Cookie).
//     An entry is a setting of its own: a middleware that writes one keeps the others.
//
//   - GroupDefaultScopes, the scopes of every group that writes none, are the one setting of the grammar a
//     deployment gives: JWT_PLUGIN_GROUPDEFAULTSCOPES for scopes that are all required, or
//     JWT_PLUGIN_GROUPDEFAULTSCOPES_REQUIRED and JWT_PLUGIN_GROUPDEFAULTSCOPES_OPTIONAL, each a list of scopes as
//     the grammar writes one, separated by spaces. They are kept aside like a list.
//
// An empty variable is as one not set. A variable that names no such setting, or whose value is not of the setting's
// kind, is an error: the middleware is not created. The settings of a service (Rules, Groups and a rule's fields)
// and JwtSources have no default here.
func (config *Config) defaultsFromEnvironment(environ []string) error {
	entries := make([]string, 0)
	for _, entry := range environ {
		if strings.HasPrefix(entry, envPrefix) {
			entries = append(entries, entry)
		}
	}
	sort.Strings(entries) // of several errors the same one is reported at every start
	plain, members := "", map[string]interface{}{}
	for _, entry := range entries {
		parts := strings.SplitN(entry, "=", 2)
		if len(parts) != 2 || parts[1] == "" {
			continue
		}
		variable, value := parts[0], parts[1]
		name := variable[len(envPrefix):]
		var err error
		switch name {
		case "OPAURL":
			config.OpaUrl = value
		case "OPAALLOWFIELD":
			config.OpaAllowField = value
		case "OPAHTTPSTATUSFIELD":
			config.OpaHttpStatusField = value
		case "OPABODYFIELD":
			config.OpaBodyField = value
		case "ALG":
			config.Alg = value
		case "AUD":
			config.Aud = value
		case "OPABODY":
			config.OpaBody, err = strconv.ParseBool(value)
		case "OPADEBUGMODE":
			config.OpaDebugMode, err = strconv.ParseBool(value)
		case "REQUIRED":
			config.Required, err = strconv.ParseBool(value)
		case "FORCEREFRESHKEYS":
			config.ForceRefreshKeys, err = strconv.ParseBool(value)
		case "OPADECIDESTOKEN":
			config.OpaDecidesToken, err = strconv.ParseBool(value)
		case "OPATIMEOUTMS":
			config.OpaTimeoutMs, err = strconv.Atoi(value)
		case "JWKSFETCHTIMEOUTSECS":
			config.JwksFetchTimeoutSecs, err = strconv.Atoi(value)
		case "KEYS":
			config.defaultKeys = listOf(value)
		case "PAYLOADFIELDS":
			config.defaultPayloadFields = listOf(value)
		case "GROUPDEFAULTSCOPES":
			plain = value
		case "GROUPDEFAULTSCOPES_REQUIRED":
			members["required"] = value
		case "GROUPDEFAULTSCOPES_OPTIONAL":
			members["optional"] = value
		default:
			setting, header := mapEntry(name)
			switch setting {
			case "OPAHEADERS":
				config.OpaHeaders = withEntry(config.OpaHeaders, header, value)
			case "JWTHEADERS":
				config.JwtHeaders = withEntry(config.JwtHeaders, header, value)
			case "JWKSHEADERS":
				config.JwksHeaders = withEntry(config.JwksHeaders, header, value)
			case "OPARESPONSEHEADERS":
				config.OpaResponseHeaders = withEntry(config.OpaResponseHeaders, header, value)
			default:
				return fmt.Errorf("%s names no setting that takes its default from the environment", variable)
			}
		}
		if err != nil {
			// The value is not repeated: only a switch and a number can fail here, and neither is a secret, but the
			// rule is the same for every variable.
			return fmt.Errorf("%s is not of its setting's kind (true or false for a switch, digits for a number)", variable)
		}
	}
	switch {
	case plain != "" && len(members) > 0:
		return fmt.Errorf("%sGROUPDEFAULTSCOPES is set beside its _REQUIRED or _OPTIONAL: the scopes are all required, or are given by the two", envPrefix)
	case plain != "":
		config.defaultGroupDefaultScopes = plain
	case len(members) > 0:
		config.defaultGroupDefaultScopes = members
	}
	return nil
}

// listDefaults gives a list that the middleware does not write the environment's.
func (config *Config) listDefaults() {
	if len(config.Keys) == 0 {
		config.Keys = config.defaultKeys
	}
	if len(config.PayloadFields) == 0 {
		config.PayloadFields = config.defaultPayloadFields
	}
}

// listOf is a list written as one value: its entries, separated by commas.
func listOf(value string) []string {
	list := make([]string, 0)
	for _, entry := range strings.Split(value, ",") {
		if entry = strings.TrimSpace(entry); entry != "" {
			list = append(list, entry)
		}
	}
	return list
}

// mapEntry splits <SETTING>_<HEADER> into the map's setting and the header's name as it is written in a request:
// OPARESPONSEHEADERS_SET_COOKIE is OPARESPONSEHEADERS and Set-Cookie. A name that is no entry of a map gives "".
func mapEntry(name string) (setting, header string) {
	for _, setting := range []string{"OPAHEADERS", "JWTHEADERS", "JWKSHEADERS", "OPARESPONSEHEADERS"} {
		if strings.HasPrefix(name, setting+"_") && len(name) > len(setting)+1 {
			header = strings.ReplaceAll(strings.ToLower(name[len(setting)+1:]), "_", "-")
			return setting, http.CanonicalHeaderKey(header)
		}
	}
	return "", ""
}

func withEntry(entries map[string]string, key, value string) map[string]string {
	if entries == nil {
		entries = make(map[string]string)
	}
	entries[key] = value
	return entries
}
