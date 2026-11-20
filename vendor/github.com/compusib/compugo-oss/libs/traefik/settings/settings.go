// Package settings reads the settings of a Traefik plugin written in a grammar of short forms, taken from the way
// Traefik's own docker labels are written: the short forms go in, one form comes out, and what cannot be read is
// refused with an error that names the key.
//
// A plugin describes its settings with a Type; Read takes the settings as Traefik hands them to the plugin (from
// labels a map of texts, maps and lists; from a cluster's Middleware object the same with booleans and numbers)
// and returns them as an Entry. Both give the same result.
//
// The grammar, with the numbers the comments here cite:
//
//   - G1: one value stands for a list of one, and a text with the setting's delimiter is a list
//     ("Paths: /a,/b").
//   - G2: indexed entries are a list: "Paths[0]", "Paths[1]", or "Paths.0", "Paths.1"; in an object, a list.
//   - G3: named entries: "Rules.<name>.<field>". The name is the key.
//   - G4: the name is the default of one field of the entry (Type.Key): "Scopes.admin: true" is the scope whose
//     name is admin, and "Scopes.operator.name: admin.cluster" says otherwise.
//   - G5: a bare true is the entry with its defaults; fields refine it.
//   - G6: what has one candidate need not be named. This is the plugin's to apply, not this package's.
//   - G7: a dot nests, everywhere, so a key has no dot: "scope.group: x" and "scope: {group: x}" are the same. A
//     name with a dot is written as a value, or as an entry's field.
//   - G8: keys are read without regard to case; values are text, read as what the setting expects ("true", "10").
//   - G9: anything else is refused, with an error that names the key: an unknown key, two forms mixed in one
//     setting, a value that is no such thing.
//
// It is plain Go on the standard library: a Traefik plugin runs interpreted, under Yaegi.
package settings

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Kind is what a setting holds.
type Kind int

const (
	// Text is one value.
	Text Kind = iota
	// Bool is true or false.
	Bool
	// Number is a whole number.
	Number
	// List is a list of values: one value, a text with the field's Delimiter, indexed entries or a list (G1, G2).
	List
	// Entries are entries with fields of their own, described by the field's Of: named (G3), indexed (G2), or
	// written as values where the type has a Key (G4).
	Entries
	// Object is one set of fields, described by the field's Of.
	Object
)

// Field is one setting of a Type.
type Field struct {
	// Name is the key the setting is written with. It is read without regard to case (G8).
	Name string
	Kind Kind
	// Delimiter splits a text into the values of a List or the entries of Entries; empty, a text is one value.
	Delimiter string
	// Default is what the setting is when it is not written, in any form the setting itself may be written in.
	// Without one a Bool is false, a List and Entries are empty, and the rest are not there (Entry.Written).
	Default any
	// Of describes the fields of Entries and of an Object.
	Of *Type
}

// Type describes entries: a plugin's settings as a whole, or the entries of one of its settings.
type Type struct {
	// What names such an entry in an error, with its article: "a rule".
	What string
	// Fields are the settings an entry has, in the order an error lists them.
	Fields []Field
	// Key names the field whose default is the entry's name (G4): written as a key, the key; written as a value,
	// the value. Only a type with a Key can be written as a value.
	Key string
}

// Entry is one entry as it was read: every field of its Type, with its default where it was not written.
type Entry struct {
	// Name is the entry's key, its index, or the value it was written as.
	Name string
	// Path is where the entry is written, for an error about it.
	Path string
	// Indexed says the entry is one of a list and Name its index.
	Indexed bool

	values  map[string]any
	written map[string]bool
}

// Written says whether the field was written. A field that took its default was not.
func (e *Entry) Written(field string) bool { return e.written[field] }

// Text is the value of a Text field, and empty where there is none.
func (e *Entry) Text(field string) string {
	v, _ := e.values[field].(string)
	return v
}

// Bool is the value of a Bool field.
func (e *Entry) Bool(field string) bool {
	v, _ := e.values[field].(bool)
	return v
}

// Number is the value of a Number field, and 0 where there is none.
func (e *Entry) Number(field string) int {
	v, _ := e.values[field].(int)
	return v
}

// List is the values of a List field.
func (e *Entry) List(field string) []string {
	v, _ := e.values[field].([]string)
	return v
}

// Entries is the entries of an Entries field: indexed ones in their order, named ones by name.
func (e *Entry) Entries(field string) []*Entry {
	v, _ := e.values[field].([]*Entry)
	return v
}

// Object is the fields of an Object field, and nil where there is none.
func (e *Entry) Object(field string) *Entry {
	v, _ := e.values[field].(*Entry)
	return v
}

// Join is the path of key under path.
func Join(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

// Errorf is an error about what is written at path.
func Errorf(path, format string, args ...any) error {
	msg := fmt.Sprintf(format, args...)
	if path == "" {
		return errors.New(msg)
	}
	return errors.New(path + ": " + msg)
}

// Read reads a plugin's settings as Traefik hands them over, by the type that describes them.
func Read(t *Type, raw map[string]any) (*Entry, error) {
	return readEntry(t, "", "", false, raw)
}

// readEntry reads the fields of one entry from the map they are written in.
func readEntry(t *Type, name, path string, indexed bool, raw map[string]any) (*Entry, error) {
	m, keys, err := expand(path, raw)
	if err != nil {
		return nil, err
	}
	e := &Entry{Name: name, Path: path, Indexed: indexed, values: map[string]any{}, written: map[string]bool{}}
	for _, key := range keys {
		f := t.field(key)
		if f == nil {
			return nil, t.unknown(path, key, m[key])
		}
		v, err := readField(f, Join(path, f.Name), m[key])
		if err != nil {
			return nil, err
		}
		e.values[f.Name] = v
		e.written[f.Name] = true
	}
	if t.Key != "" && !e.written[t.Key] {
		if indexed {
			return nil, Errorf(path, "%s without a key writes its %s", t.What, t.Key)
		}
		e.values[t.Key] = name
	}
	for i := range t.Fields {
		f := &t.Fields[i]
		if _, ok := e.values[f.Name]; ok {
			continue
		}
		v, err := defaultOf(f, Join(path, f.Name))
		if err != nil {
			return nil, err
		}
		if v != nil {
			e.values[f.Name] = v
		}
	}
	return e, nil
}

func (t *Type) field(key string) *Field {
	for i := range t.Fields {
		if strings.EqualFold(t.Fields[i].Name, key) {
			return &t.Fields[i]
		}
	}
	return nil
}

func (t *Type) fieldNames() string {
	names := make([]string, 0, len(t.Fields))
	for _, f := range t.Fields {
		names = append(names, f.Name)
	}
	return strings.Join(names, ", ")
}

// unknown is the refusal of a key the type has no field for. Under a type with a Key, a key that holds true or
// further keys is most likely the rest of a name with a dot (G7), and the error says how such a name is written.
func (t *Type) unknown(path, key string, v any) error {
	msg := fmt.Sprintf("unknown key %q (%s has %s)", key, t.What, t.fieldNames())
	if t.Key != "" {
		_, nested := v.(map[string]any)
		if nested || isTrue(v) {
			msg += "; a name with a dot is a value, or an entry's " + t.Key
		}
	}
	return Errorf(path, "%s", msg)
}

func defaultOf(f *Field, path string) (any, error) {
	if f.Default != nil {
		return readField(f, path, f.Default)
	}
	switch f.Kind {
	case Bool:
		return false, nil
	case List:
		return []string{}, nil
	case Entries:
		return []*Entry{}, nil
	}
	return nil, nil
}

// readField reads one field's value as its kind. Each result is taken into a variable of its own type before it
// is returned as any: Yaegi v0.16.3 loses the error of a call whose results are returned converted
// ("return readBool(path, v)" here).
func readField(f *Field, path string, v any) (any, error) {
	var value any
	var err error
	switch f.Kind {
	case Bool:
		var b bool
		b, err = readBool(path, v)
		value = b
	case Number:
		var n int
		n, err = readNumber(path, v)
		value = n
	case List:
		var list []string
		list, err = readList(f, path, v)
		value = list
	case Entries:
		var entries []*Entry
		entries, err = readEntries(f, path, v)
		value = entries
	case Object:
		m, ok := v.(map[string]any)
		if !ok {
			return nil, Errorf(path, "%s is written with its fields (%s)", f.Of.What, f.Of.fieldNames())
		}
		var e *Entry
		e, err = readEntry(f.Of, f.Name, path, false, m)
		value = e
	default:
		var text string
		text, err = readText(path, v)
		if err == nil && text == "" {
			err = Errorf(path, "an empty value")
		}
		value = text
	}
	if err != nil {
		return nil, err
	}
	return value, nil
}

// readText reads one value. A cluster's boolean or number is the text a label would have had (G8).
func readText(path string, v any) (string, error) {
	switch x := v.(type) {
	case string:
		return x, nil
	case bool:
		return strconv.FormatBool(x), nil
	case int:
		return strconv.Itoa(x), nil
	case int64:
		return strconv.FormatInt(x, 10), nil
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64), nil
	case map[string]any:
		if keys := sortedKeys(x); len(keys) > 0 {
			return "", Errorf(path, "unknown key %q (it is one value)", keys[0])
		}
		return "", Errorf(path, "an empty value")
	case []any:
		return "", Errorf(path, "one value, not a list")
	}
	return "", Errorf(path, "a %T cannot be read", v)
}

func readBool(path string, v any) (bool, error) {
	s, err := readText(path, v)
	if err != nil {
		return false, err
	}
	switch strings.ToLower(s) {
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	return false, Errorf(path, "%q is neither true nor false", s)
}

func readNumber(path string, v any) (int, error) {
	s, err := readText(path, v)
	if err != nil {
		return 0, err
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, Errorf(path, "%q is no number", s)
	}
	return n, nil
}

// isTrue says whether v is a bare true: the entry with its defaults (G5).
func isTrue(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return strings.EqualFold(x, "true")
	}
	return false
}

// split is the values of a text: one, or as many as the delimiter makes of it (G1).
func split(path, text, delimiter string) ([]string, error) {
	var parts []string
	switch delimiter {
	case "":
		parts = []string{text}
	case " ":
		parts = strings.Fields(text)
	default:
		parts = strings.Split(text, delimiter)
	}
	values := []string{}
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" {
			values = append(values, part)
		}
	}
	if len(values) == 0 {
		return nil, Errorf(path, "an empty value")
	}
	return values, nil
}

// item is one entry of a list, with the path it is written at.
type item struct {
	path  string
	index string
	value any
}

// items is the entries of a list, in their order, from either of its forms: a list, or a map whose keys are all
// indexes (G2: from labels Paths.0 arrives as a map with the key 0). It answers false for a map with other keys.
func items(path string, v any) ([]item, bool, error) {
	switch x := v.(type) {
	case []any:
		list := make([]item, 0, len(x))
		for i, value := range x {
			index := strconv.Itoa(i)
			list = append(list, item{path: Join(path, index), index: index, value: value})
		}
		return list, true, nil
	case map[string]any:
		m, keys, err := expand(path, x)
		if err != nil {
			return nil, false, err
		}
		indexes := make([]int, 0, len(keys))
		byIndex := map[int]string{}
		named := 0
		for _, key := range keys {
			n, ok := index(key)
			if !ok {
				named++
				continue
			}
			if other, twice := byIndex[n]; twice {
				return nil, false, Errorf(path, "%q and %q are the same index", other, key)
			}
			byIndex[n] = key
			indexes = append(indexes, n)
		}
		if named > 0 && len(indexes) > 0 {
			return nil, false, Errorf(path, "indexed and named entries cannot be mixed")
		}
		if named > 0 {
			return nil, false, nil
		}
		sort.Ints(indexes)
		list := make([]item, 0, len(indexes))
		for _, n := range indexes {
			key := byIndex[n]
			list = append(list, item{path: Join(path, key), index: strconv.Itoa(n), value: m[key]})
		}
		return list, true, nil
	}
	return nil, false, nil
}

// index reads a key that is an index: digits alone.
func index(key string) (int, bool) {
	for _, c := range key {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	n, err := strconv.Atoi(key)
	return n, err == nil
}

func readList(f *Field, path string, v any) ([]string, error) {
	list, ok, err := items(path, v)
	if err != nil {
		return nil, err
	}
	if !ok {
		if m, isMap := v.(map[string]any); isMap {
			for _, key := range sortedKeys(m) {
				if _, isIndex := index(key); !isIndex {
					return nil, Errorf(path, "unknown key %q (a list has values or indexed entries)", key)
				}
			}
		}
		text, err := readText(path, v)
		if err != nil {
			return nil, err
		}
		return split(path, text, f.Delimiter)
	}
	values := make([]string, 0, len(list))
	for _, it := range list {
		// An entry of its own is one value, whatever it contains: it is not split.
		text, err := readText(it.path, it.value)
		if err != nil {
			return nil, err
		}
		if text == "" {
			return nil, Errorf(it.path, "an empty value")
		}
		values = append(values, text)
	}
	return values, nil
}

func readEntries(f *Field, path string, v any) ([]*Entry, error) {
	t := f.Of
	list, ok, err := items(path, v)
	if err != nil {
		return nil, err
	}
	entries := []*Entry{}
	if ok {
		for _, it := range list {
			var e *Entry
			if m, isMap := it.value.(map[string]any); isMap {
				e, err = readEntry(t, it.index, it.path, true, m)
			} else {
				e, err = valueEntry(t, it.path, it.value)
			}
			if err != nil {
				return nil, err
			}
			entries = append(entries, e)
		}
		return entries, nil
	}
	if raw, isMap := v.(map[string]any); isMap {
		m, keys, err := expand(path, raw)
		if err != nil {
			return nil, err
		}
		for _, key := range keys {
			at := Join(path, key)
			fields, isMap := m[key].(map[string]any)
			if !isMap {
				if !isTrue(m[key]) {
					text, err := readText(at, m[key])
					if err != nil {
						return nil, err
					}
					return nil, Errorf(at, "%q is neither true nor fields (%s has %s)", text, t.What, t.fieldNames())
				}
				fields = map[string]any{}
			}
			e, err := readEntry(t, key, at, false, fields)
			if err != nil {
				return nil, err
			}
			entries = append(entries, e)
		}
		return entries, nil
	}
	text, err := readText(path, v)
	if err != nil {
		return nil, err
	}
	if t.Key == "" {
		return nil, Errorf(path, "%q is no entry (%s has %s)", text, t.What, t.fieldNames())
	}
	values, err := split(path, text, f.Delimiter)
	if err != nil {
		return nil, err
	}
	for _, value := range values {
		e, err := readEntry(t, value, path, false, map[string]any{})
		if err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// valueEntry is the entry a value of a list stands for: the one with that name and its defaults (G4).
func valueEntry(t *Type, path string, v any) (*Entry, error) {
	text, err := readText(path, v)
	if err != nil {
		return nil, err
	}
	if t.Key == "" {
		return nil, Errorf(path, "%q is no entry (%s has %s)", text, t.What, t.fieldNames())
	}
	if text == "" {
		return nil, Errorf(path, "an empty value")
	}
	return readEntry(t, text, path, false, map[string]any{})
}

// expand makes a map's keys plain (G7): a key with a dot nests, so "scope.group: x" becomes "scope: {group: x}",
// one part at a time. It returns the map and its keys in alphabetical order, leaves out what holds nothing, and
// refuses keys that differ only by case: Traefik reads those as one (G8).
func expand(path string, raw map[string]any) (map[string]any, []string, error) {
	m := map[string]any{}
	for _, key := range sortedKeys(raw) {
		v := raw[key]
		if v == nil {
			continue
		}
		head, rest, dotted := strings.Cut(key, ".")
		if head == "" || (dotted && rest == "") {
			return nil, nil, Errorf(path, "the key %q has an empty part", key)
		}
		if dotted {
			v = map[string]any{rest: v}
		}
		old, twice := m[head]
		if !twice {
			m[head] = v
			continue
		}
		oldMap, ok1 := old.(map[string]any)
		newMap, ok2 := v.(map[string]any)
		if !ok1 || !ok2 {
			return nil, nil, Errorf(path, "the key %q is written twice", head)
		}
		merged := map[string]any{}
		for k, x := range oldMap {
			merged[k] = x
		}
		for k, x := range newMap {
			if _, both := merged[k]; both {
				return nil, nil, Errorf(Join(path, head), "the key %q is written twice", k)
			}
			merged[k] = x
		}
		m[head] = merged
	}
	keys := sortedKeys(m)
	seen := map[string]string{}
	for _, key := range keys {
		folded := strings.ToLower(key)
		if other, twice := seen[folded]; twice {
			return nil, nil, Errorf(path, "%q and %q are the same key", other, key)
		}
		seen[folded] = key
	}
	return m, keys, nil
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
