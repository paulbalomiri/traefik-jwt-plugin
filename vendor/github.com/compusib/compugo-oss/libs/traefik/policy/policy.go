// Package policy is the settings of a Traefik plugin named "policy", which checks a request's token against a
// service's rules: the rules, their scopes, the groups of scopes and what happens when a scope is missing.
//
// Normalize takes the settings as Traefik hands them to the plugin and returns their one normalized form, or the
// error that refuses the Middleware. It normalizes and refuses, nothing else: matching a request against the rules
// and deciding are the plugin's own.
//
// The grammar the settings are written in, G1 to G9, is the package settings'; the description below says which
// setting takes which form, and the tests show every form with what it gives.
package policy

import (
	"sort"
	"strings"

	"github.com/compusib/compugo-oss/libs/traefik/settings"
)

// Settings is the normalized form. Its JSON is what the plugin logs at start and hands on.
type Settings struct {
	Groups map[string]*Group `json:"groups"`
	// Rules are in the order they are tried: the highest priority first, equal priorities by name, or for rules
	// written as a list in the order written.
	Rules []*Rule `json:"rules"`
}

// Group is a named set of scopes: what a login that names the group fetches.
type Group struct {
	Scopes                       []string `json:"scopes"`
	RequireAllScopesForAnyMember bool     `json:"requireAllScopesForAnyMember"`
}

// Rule is one rule of a service.
type Rule struct {
	Name     string   `json:"name"`
	Priority int      `json:"priority"`
	Paths    []string `json:"paths"`
	Methods  []string `json:"methods"`
	Public   bool     `json:"public"`
	Scopes   []Scope  `json:"scopes"`
	Any      []Scope  `json:"any"`
	Missing  Missing  `json:"missing"`
}

// Scope is a scope a rule needs, and the group that scope is in.
type Scope struct {
	Name  string `json:"name"`
	Group string `json:"group"`
}

// Missing is what a request gets that lacks a scope. Scope is there for a login alone.
type Missing struct {
	Action string      `json:"action"`
	Scope  *LoginScope `json:"scope,omitempty"`
}

// LoginScope is what a login fetches: a group, and whether the login is due while any scope of it is missing.
type LoginScope struct {
	Group                    string `json:"group"`
	RequireOtherGroupMembers bool   `json:"requireOtherGroupMembers"`
}

// The keys the settings are written with. Each is written here once.
const (
	keyRules    = "Rules"
	keyGroups   = "Groups"
	keyPaths    = "Paths"
	keyMethods  = "Methods"
	keyPublic   = "Public"
	keyScopes   = "Scopes"
	keyAny      = "Any"
	keyMissing  = "Missing"
	keyPriority = "Priority"

	keyName  = "name"
	keyGroup = "group"

	keyAction                   = "action"
	keyScope                    = "scope"
	keyRequireOtherGroupMembers = "requireOtherGroupMembers"

	keyRequireAllScopesForAnyMember = "RequireAllScopesForAnyMember"
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
		{Name: keyGroup, Kind: settings.Text},
	}}

	loginScopeType = &settings.Type{What: "a login's scope", Fields: []settings.Field{
		{Name: keyGroup, Kind: settings.Text},
		{Name: keyRequireOtherGroupMembers, Kind: settings.Bool},
	}}

	actionType = &settings.Type{What: "an action", Key: keyAction, Fields: []settings.Field{
		{Name: keyAction, Kind: settings.Text},
		{Name: keyScope, Kind: settings.Object, Of: loginScopeType},
	}}

	// Paths and methods are delimited by commas, scopes by spaces, as an OAuth client writes them.
	ruleType = &settings.Type{What: "a rule", Fields: []settings.Field{
		{Name: keyPaths, Kind: settings.List, Delimiter: ",", Default: "/**"},
		{Name: keyMethods, Kind: settings.List, Delimiter: ","},
		{Name: keyPublic, Kind: settings.Bool},
		{Name: keyScopes, Kind: settings.Entries, Delimiter: " ", Of: scopeType},
		{Name: keyAny, Kind: settings.Entries, Delimiter: " ", Of: scopeType},
		{Name: keyMissing, Kind: settings.Entries, Of: actionType, Default: actionDeny},
		{Name: keyPriority, Kind: settings.Number},
	}}

	groupType = &settings.Type{What: "a group", Fields: []settings.Field{
		{Name: keyScopes, Kind: settings.List, Delimiter: " "},
		{Name: keyRequireAllScopesForAnyMember, Kind: settings.Bool, Default: true},
	}}

	// A service with one rule writes the rule's fields at the top (G6), so the top has them too.
	topType = &settings.Type{What: "a policy", Fields: append([]settings.Field{
		{Name: keyRules, Kind: settings.Entries, Of: ruleType},
		{Name: keyGroups, Kind: settings.Entries, Of: groupType},
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

	// The groups are settled before any scope or login is given one: a group is defined by Groups or by a scope
	// that names it, wherever that is written. Where none is defined, default is made for what names none.
	n := &normalizer{groups: map[string]*Group{}}
	for _, g := range top.Entries(keyGroups) {
		n.groups[g.Name] = newGroup(g)
	}
	unnamed := false
	for _, e := range entries {
		for _, s := range append(append([]*settings.Entry{}, e.Entries(keyScopes)...), e.Entries(keyAny)...) {
			if s.Written(keyGroup) {
				n.define(s.Text(keyGroup))
			} else {
				unnamed = true
			}
		}
		for _, a := range e.Entries(keyMissing) {
			scope := a.Object(keyScope)
			if actionOf(a) == actionLogin && (scope == nil || !scope.Written(keyGroup)) {
				unnamed = true
			}
		}
	}
	if len(n.groups) == 0 && unnamed {
		n.define(defaultGroup)
	}
	n.names = make([]string, 0, len(n.groups))
	for name := range n.groups {
		n.names = append(n.names, name)
	}
	sort.Strings(n.names)

	rules := make([]*Rule, 0, len(entries))
	for _, e := range entries {
		r, err := n.rule(e)
		if err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	// The entries come by name, or in the order of a list: a stable sort keeps that among equal priorities.
	sort.SliceStable(rules, func(i, j int) bool { return rules[i].Priority > rules[j].Priority })

	// Every rule adds its scopes to their groups, after the scopes the group has of its own.
	for _, r := range rules {
		for _, list := range [][]Scope{r.Scopes, r.Any} {
			for _, s := range list {
				g := n.groups[s.Group]
				if !contains(g.Scopes, s.Name) {
					g.Scopes = append(g.Scopes, s.Name)
				}
			}
		}
	}
	return &Settings{Groups: n.groups, Rules: rules}, nil
}

type normalizer struct {
	groups map[string]*Group
	// names are the groups' names, in alphabetical order.
	names []string
}

func newGroup(e *settings.Entry) *Group {
	return &Group{Scopes: e.List(keyScopes), RequireAllScopesForAnyMember: e.Bool(keyRequireAllScopesForAnyMember)}
}

// define makes the group of that name where it is not there yet, with a group's defaults.
func (n *normalizer) define(name string) {
	if _, ok := n.groups[name]; !ok {
		e, _ := settings.Read(groupType, nil)
		n.groups[name] = newGroup(e)
	}
}

// theGroup is the group a scope or a login means that names none (G6): the one group there is. It answers false
// where there are several.
func (n *normalizer) theGroup() (string, bool) {
	if len(n.names) == 1 {
		return n.names[0], true
	}
	return "", false
}

// actionOf is an entry's action. Written as a key it comes in the key's spelling, and keys are read without
// regard to case (G8).
func actionOf(e *settings.Entry) string { return strings.ToLower(e.Text(keyAction)) }

func (n *normalizer) rule(e *settings.Entry) (*Rule, error) {
	r := &Rule{
		Name:    e.Name,
		Paths:   e.List(keyPaths),
		Methods: e.List(keyMethods),
		Public:  e.Bool(keyPublic),
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

	var err error
	if r.Scopes, err = n.scopes(e.Entries(keyScopes)); err != nil {
		return nil, err
	}
	if r.Any, err = n.scopes(e.Entries(keyAny)); err != nil {
		return nil, err
	}
	if r.Public && len(r.Scopes)+len(r.Any) > 0 {
		return nil, settings.Errorf(e.Path, "a public rule has no scopes")
	}

	actions := e.Entries(keyMissing)
	if len(actions) != 1 {
		return nil, settings.Errorf(settings.Join(e.Path, keyMissing), "one action per rule")
	}
	if r.Missing, err = n.missing(actions[0]); err != nil {
		return nil, err
	}
	return r, nil
}

func (n *normalizer) scopes(entries []*settings.Entry) ([]Scope, error) {
	scopes := make([]Scope, 0, len(entries))
	for _, e := range entries {
		s := Scope{Name: e.Text(keyName), Group: e.Text(keyGroup)}
		if !e.Written(keyGroup) {
			group, ok := n.theGroup()
			if !ok {
				return nil, settings.Errorf(e.Path, "a scope names its %s where there are several groups (%s)",
					keyGroup, strings.Join(n.names, ", "))
			}
			s.Group = group
		}
		scopes = append(scopes, s)
	}
	return scopes, nil
}

func (n *normalizer) missing(e *settings.Entry) (Missing, error) {
	action := actionOf(e)
	scope := e.Object(keyScope)
	switch action {
	case actionDeny:
		if scope != nil {
			return Missing{}, settings.Errorf(scope.Path, "only a %s has a %s", actionLogin, keyScope)
		}
		return Missing{Action: action}, nil
	case actionLogin:
	default:
		at := e.Path
		if e.Written(keyAction) {
			at = settings.Join(at, keyAction)
		}
		return Missing{}, settings.Errorf(at, "%q is no action (%s, %s)", e.Text(keyAction), actionLogin, actionDeny)
	}

	login := &LoginScope{}
	groupWritten := scope != nil && scope.Written(keyGroup)
	if groupWritten {
		login.Group = scope.Text(keyGroup)
		// A login defines no group: the one it names is defined by Groups or by a scope.
		if _, ok := n.groups[login.Group]; !ok {
			defined := "none is defined"
			if len(n.names) > 0 {
				defined = strings.Join(n.names, ", ")
			}
			return Missing{}, settings.Errorf(settings.Join(scope.Path, keyGroup), "no group %q (%s)", login.Group, defined)
		}
	} else {
		group, ok := n.theGroup()
		if !ok {
			return Missing{}, settings.Errorf(e.Path, "a %s names its %s.%s where there are several groups (%s)",
				actionLogin, keyScope, keyGroup, strings.Join(n.names, ", "))
		}
		login.Group = group
	}
	// Not written, it is its group's setting.
	if scope != nil && scope.Written(keyRequireOtherGroupMembers) {
		login.RequireOtherGroupMembers = scope.Bool(keyRequireOtherGroupMembers)
	} else {
		login.RequireOtherGroupMembers = n.groups[login.Group].RequireAllScopesForAnyMember
	}
	return Missing{Action: action, Scope: login}, nil
}

func contains(list []string, value string) bool {
	for _, v := range list {
		if v == value {
			return true
		}
	}
	return false
}
