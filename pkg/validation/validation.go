// File: pkg/validation/validation.go

// Package validation is the single place where inbound data entering the CLI is
// checked against a declared schema before it is used.
//
// "Inbound" means everything the CLI does not itself produce: command flags,
// environment variables, the YAML config file, and the identifiers those carry
// into API URLs. The commands used to check a handful of these ad hoc — one
// switch here, one string comparison there — so a value nobody thought to check
// travelled straight into an HTTP path or an output file name.
//
// The schemas live on the input structs below as `validate` tags, evaluated by
// go-playground/validator. Each field also carries a `flag` tag naming the
// option the user actually typed, so a rejection reads as advice about a flag
// rather than as a Go field path.
package validation

import (
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"
)

// ScanTypes is the accepted set of --type values, kept as the `oneof` parameter
// so the tag and the error message cannot drift apart.
const ScanTypes = "sast sca iac secret cicd container all"

// OutputFormats lists the --output formats the results command can render.
const OutputFormats = "json html sarif markdown"

// ReportFormats lists the --format values the report commands can render.
const ReportFormats = "json html pdf"

// Severities lists the --break-on-severity values, "none" being the explicit
// way to disable the gate.
const Severities = "critical high medium low none"

// TeamRoles lists the roles a team member can hold.
const TeamRoles = "team_manager analyst_developer developer read_only"

// resourceIDPattern accepts the identifiers the CLI interpolates into API URL
// paths (project, organization, team, user, credential).
//
// The character set is what makes this a security check and not decoration:
// `/`, `?`, `#` and `%` are what turn `fmt.Sprintf("%s/project/%s/scan", ...)`
// into a request against a different endpoint than the one the code reads as.
// Every id the API issues is a UUID, so nothing legitimate is excluded.
var resourceIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// branchNamePattern mirrors git-check-ref-format: no ASCII control characters,
// no space, and none of the characters git itself refuses in a ref.
var branchNamePattern = regexp.MustCompile(`^[^\x00-\x20~^:?*\[\\]+$`)

// isoDateLayouts are the shapes the --start-date / --end-date flags accept. A
// plain day is the common case; the two datetime forms are accepted because the
// API documents its timestamps in that shape.
var isoDateLayouts = []string{"2006-01-02", time.RFC3339, "2006-01-02T15:04:05"}

var validate = newValidator()

func newValidator() *validator.Validate {
	v := validator.New(validator.WithRequiredStructEnabled())

	// Report the flag the user typed, not the Go field name.
	v.RegisterTagNameFunc(func(field reflect.StructField) string {
		if name := field.Tag.Get("flag"); name != "" {
			return name
		}
		return field.Name
	})

	mustRegister(v, "resourceid", isResourceID)
	mustRegister(v, "branchname", isBranchName)
	mustRegister(v, "safepath", isSafePath)
	mustRegister(v, "httpurl", isHTTPURL)
	mustRegister(v, "isodate", isISODate)
	mustRegister(v, "imageref", isImageRef)

	return v
}

func mustRegister(v *validator.Validate, tag string, fn validator.Func) {
	if err := v.RegisterValidation(tag, fn); err != nil {
		// Only reachable if a tag name is empty or duplicated, which is a
		// programming error in this file rather than bad user input.
		panic(fmt.Sprintf("validation: cannot register %q: %v", tag, err))
	}
}

func isResourceID(fl validator.FieldLevel) bool {
	return resourceIDPattern.MatchString(fl.Field().String())
}

func isBranchName(fl validator.FieldLevel) bool {
	name := fl.Field().String()
	if len(name) > 255 || strings.Contains(name, "..") {
		return false
	}
	if strings.HasPrefix(name, "/") || strings.HasPrefix(name, "-") ||
		strings.HasSuffix(name, "/") || strings.HasSuffix(name, ".") {
		return false
	}
	return branchNamePattern.MatchString(name)
}

// isSafePath checks a local file path the CLI will read from or write to.
//
// It deliberately allows `..` and absolute paths: these paths name where the
// user wants their own report written, and `--filepath ../artifacts` is a
// normal thing to ask for in CI. What it refuses is a path that cannot be one:
// a NUL byte, a control character, or a length no filesystem accepts.
func isSafePath(fl validator.FieldLevel) bool {
	path := fl.Field().String()
	if len(path) > 4096 {
		return false
	}
	return strings.IndexFunc(path, func(r rune) bool { return r < 0x20 || r == 0x7f }) == -1
}

func isHTTPURL(fl validator.FieldLevel) bool {
	raw := fl.Field().String()
	parsed, err := url.Parse(raw)
	if err != nil {
		return false
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return false
	}
	return parsed.Host != ""
}

func isISODate(fl validator.FieldLevel) bool {
	value := fl.Field().String()
	for _, layout := range isoDateLayouts {
		if _, err := time.Parse(layout, value); err == nil {
			return true
		}
	}
	return false
}

// isImageRef checks a container image reference. The reference is sent in a
// JSON body rather than interpolated into a path, so this stays a sanity check
// on shape — no whitespace, no control characters, not a stray flag — rather
// than a full parse of the registry grammar, which would reject valid images.
func isImageRef(fl validator.FieldLevel) bool {
	ref := fl.Field().String()
	if len(ref) > 512 || strings.HasPrefix(ref, "-") {
		return false
	}
	return strings.IndexFunc(ref, func(r rune) bool {
		return r <= 0x20 || r == 0x7f
	}) == -1
}

// Struct validates one of the input schemas declared in this package and
// returns a single error naming every flag that was rejected, in the terms the
// user typed them.
func Struct(input any) error {
	err := validate.Struct(input)
	if err == nil {
		return nil
	}

	var fieldErrs validator.ValidationErrors
	if !errors.As(err, &fieldErrs) {
		// An InvalidValidationError: the caller passed something that is not a
		// struct. That is a bug here, not bad input.
		return fmt.Errorf("validation failed: %w", err)
	}

	messages := make([]string, 0, len(fieldErrs))
	for _, fieldErr := range fieldErrs {
		messages = append(messages, describe(fieldErr))
	}
	return errors.New(strings.Join(messages, "; "))
}

// ResourceID checks a single identifier that will be interpolated into an API
// URL path, naming the flag it came from. It is the one-value form of the
// `resourceid` rule the input schemas use, for the commands that resolve an id
// through a shared helper rather than through a struct.
func ResourceID(flag, value string) error {
	if value == "" {
		return fmt.Errorf("%s is required", flag)
	}
	if !resourceIDPattern.MatchString(value) {
		return errors.New(badResourceID(flag, value))
	}
	return nil
}

func badResourceID(flag, value string) string {
	return fmt.Sprintf("invalid %s: %q is not a valid identifier "+
		"(letters, digits, '.', '_' and '-' only)", flag, value)
}

// describe turns one field error into the sentence a CLI user can act on.
func describe(fieldErr validator.FieldError) string {
	field := fieldErr.Field()
	value := fmt.Sprintf("%v", fieldErr.Value())

	switch fieldErr.Tag() {
	case "required":
		return fmt.Sprintf("%s is required", field)
	case "oneof":
		allowed := strings.Join(strings.Fields(fieldErr.Param()), ", ")
		return fmt.Sprintf("invalid %s: %q (allowed: %s)", field, value, allowed)
	case "resourceid":
		return badResourceID(field, value)
	case "branchname":
		return fmt.Sprintf("invalid %s: %q is not a valid branch name", field, value)
	case "safepath":
		return fmt.Sprintf("invalid %s: %q is not a usable file path", field, value)
	case "httpurl":
		return fmt.Sprintf("invalid %s: %q is not an http(s) URL", field, value)
	case "isodate":
		return fmt.Sprintf("invalid %s: %q is not an ISO date "+
			"(YYYY-MM-DD or YYYY-MM-DDThh:mm:ssZ)", field, value)
	case "imageref":
		return fmt.Sprintf("invalid %s: %q is not a valid image reference "+
			"(e.g. my-app:v1.0.0)", field, value)
	case "gte", "min":
		return fmt.Sprintf("invalid %s: %v must be at least %s", field, value, fieldErr.Param())
	case "lte", "max":
		return fmt.Sprintf("invalid %s: %v must be at most %s", field, value, fieldErr.Param())
	default:
		return fmt.Sprintf("invalid %s: %q", field, value)
	}
}
