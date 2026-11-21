// Package policy is the settings of a Traefik plugin named "policy", which checks a request's token against a
// service's rules: the rules, the scopes each asks for, the groups of rules and what happens when a scope is
// missing.
//
// Normalize takes the settings as Traefik hands them to the plugin and returns their one normalized form, or the
// error that refuses the Middleware. It normalizes and refuses, nothing else: matching a request against the rules
// and deciding are the plugin's own.
//
// The grammar the settings are written in, G1 to G9, is the package settings'; the description below says which
// setting takes which form, and the tests show every form with what it gives.
//
// # Scopes and groups
//
// A scope of a rule is required or optional. A rule is in one group, and its group gives it scopes to ask for
// beside its own, so that a login brings what the next page needs. The groups are used up here: the normalized
// form holds rules alone, each with its two finished lists. They are made in two stages, once per rule.
//
// Stage 1, the group. What the rule's group contributes to this rule:
//
//   - the scopes of the other rules of the group, as the group's RequestAllScopesForAnyMember takes them: false
//     none of them, optional all optional, required all required, true each as its rule declares it;
//   - the group's own Scopes, or GroupDefaultScopes where it writes none, as they are written;
//   - never what the rule itself put in;
//   - a scope that arrives more than once is required where every arrival is required, and optional otherwise.
//
// Stage 2, the rule. The rule's own scopes keep the rule's word. What stage 1 gave is merged as the rule's
// RequestOtherGroupScopes takes it: false nothing at all, optional all of it optional, required all of it
// required, true each as it stands. A scope that is among the rule's own and in what stage 1 gave is required
// where either says required, and optional otherwise.
package policy

import (
	"sort"
	"strconv"
	"strings"

	"github.com/compusib/compugo-oss/libs/traefik/settings"
)

// Settings is the normalized form. Its JSON is what the plugin logs at start and hands on.
type Settings struct {
	// Rules are in the order they are tried: the highest priority first, equal priorities by name, or for rules
	// written as a list in the order written.
	Rules []*Rule `json:"rules"`
}

// Rule is one rule of a service.
type Rule struct {
	Name     string   `json:"name"`
	Priority int      `json:"priority"`
	Paths    []string `json:"paths"`
	Methods  []string `json:"methods"`
	Public   bool     `json:"public"`
	Scopes   Scopes   `json:"scopes"`
	Missing  Missing  `json:"missing"`
	// ClaimChecks is the rule's list of checks in the place of the policy's standard one, and nil (in JSON null)
	// where the rule writes none.
	ClaimChecks []string `json:"claimChecks"`
	// AdditionalChecks are run after the others, in the order written.
	AdditionalChecks []string `json:"additionalChecks"`
}

// Scopes are the scopes a rule asks for: its own and what its group gives it. A scope is in one of the two lists,
// once, and each list is in alphabetical order.
type Scopes struct {
	Required []string `json:"required"`
	Optional []string `json:"optional"`
}

// Missing is what a request gets that lacks a scope.
type Missing struct {
	Action string `json:"action"`
}

// The keys the settings are written with. Each is written here once.
const (
	keyRules              = "Rules"
	keyGroups             = "Groups"
	keyGroupDefaultScopes = "GroupDefaultScopes"

	keyPaths                   = "Paths"
	keyMethods                 = "Methods"
	keyPublic                  = "Public"
	keyGroup                   = "Group"
	keyScopes                  = "Scopes"
	keyRequestOtherGroupScopes = "RequestOtherGroupScopes"
	keyMissing                 = "Missing"
	keyPriority                = "Priority"
	keyClaimChecks             = "ClaimChecks"
	keyAdditionalChecks        = "AdditionalChecks"

	keyRequestAllScopesForAnyMember = "RequestAllScopesForAnyMember"

	keyName   = "name"
	keyAction = "action"
)

// The members of Scopes, which are also two of the four values of a group's RequestAllScopesForAnyMember and of a
// rule's RequestOtherGroupScopes; the other two are a boolean's true and false.
const (
	required = "required"
	optional = "optional"
	asItIs   = "true"
	none     = "false"
)

// The defaults that are no setting's own value, and the actions. Each is written here once; the defaults that are
// a setting's value are in the description below.
const (
	defaultRule  = "default"
	defaultGroup = "default"

	actionLogin = "login"
	actionDeny  = "deny"
)

// The description of the settings: what the package settings reads them by.
var (
	scopeType = &settings.Type{What: "a scope", Key: keyName, Fields: []settings.Field{
		{Name: keyName, Kind: settings.Text},
	}}

	actionType = &settings.Type{What: "an action", Key: keyAction, Fields: []settings.Field{
		{Name: keyAction, Kind: settings.Text},
	}}

	// Scopes are delimited by spaces, as an OAuth client writes them, and are required or optional: written
	// without either, required.
	scopesField = settings.Field{
		Name: keyScopes, Kind: settings.Entries, Delimiter: " ", Of: scopeType, Members: []string{required, optional},
	}

	// Paths, methods and checks are delimited by commas.
	ruleType = &settings.Type{What: "a rule", Fields: []settings.Field{
		{Name: keyPaths, Kind: settings.List, Delimiter: ",", Default: "/**"},
		{Name: keyMethods, Kind: settings.List, Delimiter: ","},
		{Name: keyPublic, Kind: settings.Bool},
		{Name: keyGroup, Kind: settings.Text},
		scopesField,
		{Name: keyRequestOtherGroupScopes, Kind: settings.Text, Default: asItIs},
		{Name: keyMissing, Kind: settings.Entries, Of: actionType, Default: actionDeny},
		{Name: keyPriority, Kind: settings.Number},
		{Name: keyClaimChecks, Kind: settings.List, Delimiter: ","},
		{Name: keyAdditionalChecks, Kind: settings.List, Delimiter: ","},
	}}

	groupType = &settings.Type{What: "a group", Fields: []settings.Field{
		scopesField,
		{Name: keyRequestAllScopesForAnyMember, Kind: settings.Text, Default: optional},
	}}

	// The scopes of every group that writes none of its own.
	groupDefaultScopesField = settings.Field{
		Name: keyGroupDefaultScopes, Kind: settings.Entries, Delimiter: " ", Of: scopeType, Members: scopesField.Members,
		Default: map[string]any{required: "openid", optional: "profile email address phone offline"},
	}

	// A service with one rule writes the rule's fields at the top (G6), so the top has them too.
	topType = &settings.Type{What: "a policy", Fields: append([]settings.Field{
		{Name: keyRules, Kind: settings.Entries, Of: ruleType},
		{Name: keyGroups, Kind: settings.Entries, Of: groupType},
		groupDefaultScopesField,
	}, ruleType.Fields...)}
)

// Normalize returns the normalized form of the plugin's settings: what stands under a Middleware's plugin.policy,
// as Traefik hands it over from labels or from a cluster's object. A setting whose value is nil is not written.
// An error names the key it is about, and refuses the Middleware.
func Normalize(raw map[string]any) (*Settings, error) {
	top, err := settings.Read(topType, raw)
	if err != nil {
		return nil, err
	}

	entries := top.Entries(keyRules)
	atTop := ""
	for _, f := range ruleType.Fields {
		if top.Written(f.Name) {
			atTop = f.Name
			break
		}
	}
	switch {
	case atTop != "" && top.Written(keyRules):
		return nil, settings.Errorf(atTop, "the rule's fields at the top and %s cannot both be written", keyRules)
	case atTop != "":
		top.Name = defaultRule
		entries = []*settings.Entry{top}
	}

	// The groups are those Groups defines and those a rule names. A group that writes no Scopes has the default
	// ones.
	defaults, err := scopesOf(top, keyGroupDefaultScopes)
	if err != nil {
		return nil, err
	}
	groups := map[string]*group{}
	for _, e := range top.Entries(keyGroups) {
		g := &group{own: defaults}
		if e.Written(keyScopes) {
			if g.own, err = scopesOf(e, keyScopes); err != nil {
				return nil, err
			}
		}
		if g.request, err = request(e, keyRequestAllScopesForAnyMember); err != nil {
			return nil, err
		}
		groups[e.Name] = g
	}
	define := func(name string) {
		if groups[name] == nil {
			groups[name] = &group{own: defaults, request: optional}
		}
	}
	for _, e := range entries {
		if e.Written(keyGroup) {
			define(e.Text(keyGroup))
		}
	}
	if len(groups) == 0 {
		define(defaultGroup)
	}
	names := make([]string, 0, len(groups))
	for name := range groups {
		names = append(names, name)
	}
	sort.Strings(names)

	// Every rule is read, and put into its group: the one it names, or the one group there is (G6).
	members := make([]*member, 0, len(entries))
	for _, e := range entries {
		m, err := read(e)
		if err != nil {
			return nil, err
		}
		name := e.Text(keyGroup)
		if !e.Written(keyGroup) {
			if len(names) > 1 {
				return nil, settings.Errorf(e.Path, "a rule names its %s where there are several groups (%s)",
					keyGroup, strings.Join(names, ", "))
			}
			name = names[0]
		}
		m.group = groups[name]
		m.group.members = append(m.group.members, m)
		members = append(members, m)
	}

	rules := make([]*Rule, 0, len(members))
	for _, m := range members {
		m.rule.Scopes = m.scopes()
		rules = append(rules, m.rule)
	}
	// The entries come by name, or in the order of a list: a stable sort keeps that among equal priorities.
	sort.SliceStable(rules, func(i, j int) bool { return rules[i].Priority > rules[j].Priority })
	return &Settings{Rules: rules}, nil
}

// group is a group while the settings are read: nothing of it is left in the normalized form.
type group struct {
	// own are the group's own scopes: its Scopes, or the default ones.
	own map[string]bool
	// request is the group's RequestAllScopesForAnyMember.
	request string
	members []*member
}

// member is a rule in its group.
type member struct {
	rule *Rule
	// own are the rule's own scopes.
	own map[string]bool
	// request is the rule's RequestOtherGroupScopes.
	request string
	group   *group
}

// scopesOf is the scopes of a setting that has them as required and optional: each scope's name, and whether it
// is required. A scope is one or the other: written as both in the same setting, it is refused. (Across settings
// it may be both, a rule's and its group's: the two stages say what it is then.)
func scopesOf(e *settings.Entry, field string) (map[string]bool, error) {
	scopes := map[string]bool{}
	for _, s := range e.Member(field, required) {
		scopes[s.Text(keyName)] = true
	}
	var both []string
	for _, s := range e.Member(field, optional) {
		name := s.Text(keyName)
		if scopes[name] {
			both = append(both, name)
		}
		scopes[name] = false
	}
	if len(both) > 0 {
		sort.Strings(both)
		return nil, settings.Errorf(settings.Join(e.Path, field), "%q is both %s and %s", both[0], required, optional)
	}
	return scopes, nil
}

// request reads one of the two settings that say how scopes are asked for: false, true, required or optional. Its
// true and false are read as a boolean is, and required and optional in any case.
func request(e *settings.Entry, field string) (string, error) {
	text := e.Text(field)
	switch word := strings.ToLower(text); word {
	case required, optional:
		return word, nil
	}
	if b, err := strconv.ParseBool(text); err == nil {
		return strconv.FormatBool(b), nil
	}
	return "", settings.Errorf(settings.Join(e.Path, field), "%q is none of %s, %s, %s, %s", text, none, asItIs, required, optional)
}

// taken is scopes as one of the two settings takes them. It answers false where it takes none.
func taken(scopes map[string]bool, request string) (map[string]bool, bool) {
	switch request {
	case none:
		return nil, false
	case asItIs:
		return scopes, true
	}
	all := map[string]bool{}
	for name := range scopes {
		all[name] = request == required
	}
	return all, true
}

// read reads one rule, but for its scopes' two lists: those need the other rules of its group.
func read(e *settings.Entry) (*member, error) {
	r := &Rule{
		Name:             e.Name,
		Paths:            e.List(keyPaths),
		Methods:          e.List(keyMethods),
		Public:           e.Bool(keyPublic),
		AdditionalChecks: e.List(keyAdditionalChecks),
	}
	// Not written, the checks are the policy's standard ones, which is another thing than a list of none.
	if e.Written(keyClaimChecks) {
		r.ClaimChecks = e.List(keyClaimChecks)
	}
	for _, field := range []string{keyClaimChecks, keyAdditionalChecks} {
		for _, name := range e.List(field) {
			if !isCheck(name) {
				return nil, settings.Errorf(settings.Join(e.Path, field),
					"%q is no name of a check (letters, digits and _, beginning with a letter)", name)
			}
		}
	}

	// A rule's default priority is the length of its longest path, as a router's is.
	if e.Written(keyPriority) {
		r.Priority = e.Number(keyPriority)
	} else {
		for _, p := range r.Paths {
			if len(p) > r.Priority {
				r.Priority = len(p)
			}
		}
	}

	m := &member{rule: r}
	var err error
	if m.own, err = scopesOf(e, keyScopes); err != nil {
		return nil, err
	}
	if m.request, err = request(e, keyRequestOtherGroupScopes); err != nil {
		return nil, err
	}

	at := settings.Join(e.Path, keyMissing)
	actions := e.Entries(keyMissing)
	if len(actions) != 1 {
		return nil, settings.Errorf(at, "one action per rule")
	}
	// An action written as a key comes in the key's spelling, and keys are read without regard to case (G8).
	action := strings.ToLower(actions[0].Text(keyAction))
	if action != actionLogin && action != actionDeny {
		if actions[0].Written(keyAction) {
			at = settings.Join(actions[0].Path, keyAction)
		} else {
			at = actions[0].Path
		}
		return nil, settings.Errorf(at, "%q is no action (%s, %s)", actions[0].Text(keyAction), actionLogin, actionDeny)
	}
	// A public rule lets pass whoever is not signed in, and asks whoever is for its scopes: what is missing is
	// fetched by a login. It refuses nobody, so a deny is written on no public rule.
	switch {
	case r.Public && e.Written(keyMissing) && action == actionDeny:
		return nil, settings.Errorf(at, "a public rule refuses nobody (%s, or not written)", actionLogin)
	case r.Public && !e.Written(keyMissing) && len(m.own) > 0:
		action = actionLogin
	}
	r.Missing = Missing{Action: action}
	return m, nil
}

// isCheck says whether name is a check's name: the name of a file of the policy.
func isCheck(name string) bool {
	for i, c := range name {
		letter := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		if !letter && (i == 0 || (c != '_' && (c < '0' || c > '9'))) {
			return false
		}
	}
	return name != ""
}

// scopes is the rule's two lists, by the two stages.
func (m *member) scopes() Scopes {
	// Stage 1: what the group contributes to this rule. A scope that arrives more than once is required where
	// every arrival is required.
	given := map[string]bool{}
	arrive := func(scopes map[string]bool) {
		for name, isRequired := range scopes {
			if before, twice := given[name]; twice {
				isRequired = isRequired && before
			}
			given[name] = isRequired
		}
	}
	for _, other := range m.group.members {
		if other == m {
			continue
		}
		if scopes, some := taken(other.own, m.group.request); some {
			arrive(scopes)
		}
	}
	arrive(m.group.own)

	// Stage 2: the rule's own keep the rule's word, and a scope that is in both is required where either says so.
	all := map[string]bool{}
	for name, isRequired := range m.own {
		all[name] = isRequired
	}
	if scopes, some := taken(given, m.request); some {
		for name, isRequired := range scopes {
			all[name] = all[name] || isRequired
		}
	}

	s := Scopes{Required: []string{}, Optional: []string{}}
	for name, isRequired := range all {
		if isRequired {
			s.Required = append(s.Required, name)
		} else {
			s.Optional = append(s.Optional, name)
		}
	}
	sort.Strings(s.Required)
	sort.Strings(s.Optional)
	return s
}
