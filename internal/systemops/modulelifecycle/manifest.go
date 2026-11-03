package modulelifecycle

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"panasms.local/backend/internal/systemops"
)

type Manifest map[string]any
type Registry map[string]Manifest

var identifierPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{1,39}$`)
var versionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
var constraintPattern = regexp.MustCompile(`^\s*(>=|<=|>|<|=)?\s*([0-9]+\.[0-9]+\.[0-9]+)\s*$`)
var packagePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]{0,79}$`)
var packageVersionPattern = regexp.MustCompile(`^[a-zA-Z0-9.+:~_-]{1,100}$`)
var widgetPattern = regexp.MustCompile(`^[a-z0-9:-]{1,80}$`)
var payloadPattern = regexp.MustCompile(`^(ui|bin|backend)/[a-zA-Z0-9_./-]+$`)
var digestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

var blockedIDs = strings.Fields("core users storage settings system history sharing modules network")
var coreIDs = strings.Fields("account-details account-sessions accounts core data-folders disk file filesystem folder group history home-folders homes homes-check hostname job jobs journal luks module module-catalog module-sources modules mount mount-folders network network-access nfs partition personal-folders power raid raid-candidates service services settings share share-folders sharing smart smb storage storage-luks storage-options storage-snapshots system system-updates updates user users web-access")

func reject(message string) error              { return &systemops.Rejected{Message: message} }
func text(m map[string]any, key string) string { s, _ := m[key].(string); return s }
func contains(items []string, value string) bool {
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
}
func identifier(value string) error {
	if !identifierPattern.MatchString(value) {
		return reject("Invalid module identifier")
	}
	if contains(blockedIDs, value) {
		return reject("The identifier belongs to the core")
	}
	return nil
}
func parseVersion(value string) ([3]uint64, error) {
	var result [3]uint64
	if !versionPattern.MatchString(value) {
		return result, reject("Version must use X.Y.Z format")
	}
	for index, part := range strings.Split(value, ".") {
		v, err := strconv.ParseUint(part, 10, 64)
		if err != nil {
			return result, reject("Version must use X.Y.Z format")
		}
		result[index] = v
	}
	return result, nil
}
func compareVersions(left, right string) (int, error) {
	a, err := parseVersion(left)
	if err != nil {
		return 0, err
	}
	b, err := parseVersion(right)
	if err != nil {
		return 0, err
	}
	for i := range a {
		if a[i] < b[i] {
			return -1, nil
		}
		if a[i] > b[i] {
			return 1, nil
		}
	}
	return 0, nil
}
func satisfies(actual, required string) (bool, error) {
	if _, err := parseVersion(actual); err != nil {
		return false, err
	}
	if len(required) > 100 {
		return false, reject("Invalid version constraint")
	}
	all := true
	for _, part := range strings.Split(required, ",") {
		match := constraintPattern.FindStringSubmatch(part)
		if match == nil {
			return false, reject("Use version constraints such as >=0.1.0,<1.0.0")
		}
		comparison, err := compareVersions(actual, match[2])
		if err != nil {
			return false, err
		}
		allowed := false
		switch match[1] {
		case ">=":
			allowed = comparison >= 0
		case "<=":
			allowed = comparison <= 0
		case ">":
			allowed = comparison > 0
		case "<":
			allowed = comparison < 0
		default:
			allowed = comparison == 0
		}
		if !allowed {
			all = false
		}
	}
	return all, nil
}
func object(m map[string]any, key string) (map[string]any, bool) {
	value, present := m[key]
	if !present {
		return map[string]any{}, true
	}
	result, ok := value.(map[string]any)
	return result, ok
}
func integer(value any) (int64, bool) {
	switch v := value.(type) {
	case json.Number:
		n, err := v.Int64()
		return n, err == nil
	case int:
		return int64(v), true
	case int64:
		return v, true
	default:
		return 0, false
	}
}
func validateManifest(m Manifest, core, architecture string, installing bool) error {
	id := text(m, "id")
	if err := identifier(id); err != nil {
		return err
	}
	if installing && contains(coreIDs, id) {
		return reject("The identifier belongs to the core")
	}
	if _, err := parseVersion(text(m, "version")); err != nil {
		return err
	}
	api, ok := integer(m["api"])
	compatible, err := satisfies(core, text(m, "core"))
	if err != nil {
		return err
	}
	if !ok || api != 1 || !compatible {
		return reject("Module is incompatible with PaNasMs core " + core)
	}
	arch := text(m, "architecture")
	if arch != "all" && arch != architecture {
		return reject("The archive targets another architecture")
	}
	title := text(m, "title")
	if !utf8.ValidString(title) || utf8.RuneCountInString(title) == 0 || utf8.RuneCountInString(title) > 100 {
		return reject("Invalid module title")
	}
	labels := []map[string]any{m}
	translations, ok := object(m, "translations")
	if !ok {
		return reject("Invalid module translations")
	}
	for _, value := range translations {
		label, ok := value.(map[string]any)
		if !ok {
			return reject("Invalid module translations")
		}
		labels = append(labels, label)
	}
	for _, label := range labels {
		if value, exists := label["longDescription"]; exists {
			s, ok := value.(string)
			if !ok || utf8.RuneCountInString(s) > 16000 {
				return reject("Invalid detailed module description")
			}
		}
	}
	for _, field := range []string{"service", "operations"} {
		if value := m[field]; value != nil && value != "bin/server" {
			if field == "service" {
				return reject("Unknown service format")
			}
			return reject("Unknown native operation format")
		}
	}
	dependencies, ok := object(m, "dependencies")
	if !ok || len(dependencies) > 32 {
		return reject("Invalid dependencies")
	}
	for dep, value := range dependencies {
		if err := identifier(dep); err != nil {
			return err
		}
		constraint, ok := value.(string)
		if !ok {
			return reject("Invalid version constraint")
		}
		if _, err := satisfies("0.0.0", constraint); err != nil {
			return err
		}
	}
	packages, ok := object(m, "packages")
	if !ok || len(packages) > 64 {
		return reject("Invalid system dependencies")
	}
	for name, value := range packages {
		if !packagePattern.MatchString(name) {
			return reject("Invalid OS package name")
		}
		minimum, ok := value.(string)
		if !ok || !packageVersionPattern.MatchString(minimum) {
			return reject("Invalid OS package version")
		}
	}
	widgets, ok := object(m, "widgets")
	if !ok {
		return reject("Invalid widget description")
	}
	for kind, value := range widgets {
		if !strings.HasPrefix(kind, id+":") || !widgetPattern.MatchString(kind) {
			return reject("Widget names must use the module prefix")
		}
		dimensions, ok := value.([]any)
		if !ok || len(dimensions) != 2 {
			return reject("The widget size must fit a mobile screen")
		}
		for _, dimension := range dimensions {
			n, ok := integer(dimension)
			if !ok || n < 1 || n > 2 {
				return reject("The widget size must fit a mobile screen")
			}
		}
	}
	for _, field := range []string{"userShell", "memberAccess"} {
		if v, exists := m[field]; exists {
			if _, ok := v.(bool); !ok {
				if field == "userShell" {
					return reject("Invalid user-shell capability")
				}
				return reject("Invalid member-access capability")
			}
		}
	}
	files, ok := object(m, "files")
	if !ok || len(files) == 0 || len(files) > 2000 {
		return reject("Module has no files")
	}
	for path, value := range files {
		valid := path == "LICENSE" || path == "NOTICE" || payloadPattern.MatchString(path)
		for _, part := range strings.Split(path, "/") {
			valid = valid && part != "" && part != "." && part != ".."
		}
		if !valid {
			return reject("Invalid path in module")
		}
		digest, ok := value.(string)
		if !ok || !digestPattern.MatchString(digest) {
			return reject("Invalid checksum")
		}
	}
	for _, kind := range []string{"actions", "queries"} {
		value, exists := m[kind]
		if !exists {
			continue
		}
		handlers, ok := value.([]any)
		if !ok {
			return reject("Invalid module handlers")
		}
		prefix := id
		if id == "files" && kind == "actions" {
			prefix = "file"
		}
		seen := map[string]bool{}
		for _, value := range handlers {
			handler, ok := value.(string)
			if !ok || (handler != prefix && !strings.HasPrefix(handler, prefix+".")) {
				return reject("Handlers must use the module prefix")
			}
			if installing && seen[handler] {
				return reject("Duplicate module handler")
			}
			seen[handler] = true
		}
	}
	if _, exists := files["ui/index.js"]; !exists {
		return reject("Module UI is missing")
	}
	if text(m, "service") != "" {
		if _, exists := files[text(m, "service")]; !exists {
			return reject("Service executable is missing")
		}
	}
	if text(m, "operations") != "" {
		if _, exists := files[text(m, "operations")]; !exists {
			return reject("Native operation executable is missing")
		}
	}
	return nil
}

func decodeManifest(raw []byte) (Manifest, error) {
	if len(raw) > 256*1024 {
		return nil, reject("Module manifest too large")
	}
	if !utf8.Valid(raw) {
		return nil, reject("Invalid module manifest")
	}
	var m Manifest
	if err := systemops.Decode(raw, &m); err != nil || m == nil {
		return nil, reject("Invalid module manifest")
	}
	return m, nil
}
func copyRegistry(source Registry) (Registry, error) {
	raw, err := json.Marshal(source)
	if err != nil {
		return nil, fmt.Errorf("module registry: %w", err)
	}
	var result Registry
	if err = systemops.Decode(raw, &result); err != nil {
		return nil, err
	}
	return result, nil
}
