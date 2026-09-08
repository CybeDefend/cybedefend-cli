// File: pkg/validation/inputs.go

package validation

// The structs below are the schemas for everything that enters the CLI from
// outside: flags, environment variables and the config file. Each field names
// the flag it came from so a rejection tells the user which option to fix.
//
// Fields that are `omitempty` are the ones a command may legitimately leave
// unset — a filter, an override, a value the API defaults for us. Whether a
// value is *required* is stated here rather than in the command, so that the
// command reads as "validate, then run".

// ConfigInput is the resolved configuration, after the flag / environment /
// config-file / region precedence has been applied. It is checked once, in
// utils.LoadConfig, so no command has to re-derive whether the endpoints it was
// handed are usable.
type ConfigInput struct {
	APIURL       string `flag:"api_url" validate:"required,httpurl"`
	AuthEndpoint string `flag:"auth_endpoint" validate:"required,httpurl"`
	Region       string `flag:"region" validate:"omitempty,oneof=us eu"`
	ProjectID    string `flag:"project_id" validate:"omitempty,resourceid"`
	Branch       string `flag:"branch" validate:"omitempty,branchname"`
}

// ScanInput is what `cybedefend scan` was asked to do.
type ScanInput struct {
	ProjectID       string `flag:"--project-id" validate:"required,resourceid"`
	Branch          string `flag:"--branch" validate:"omitempty,branchname"`
	Directory       string `flag:"--dir" validate:"omitempty,safepath"`
	ZipFile         string `flag:"--file" validate:"omitempty,safepath"`
	BreakOnSeverity string `flag:"--break-on-severity" validate:"omitempty,oneof=critical high medium low none"`
	// A zero interval would poll the scan status in a tight loop, and a zero
	// timeout would fail every policy evaluation before it starts.
	Interval      int `flag:"--interval" validate:"gte=1,lte=3600"`
	PolicyTimeout int `flag:"--policy-timeout" validate:"gte=1,lte=86400"`
}

// ResultsInput is what `cybedefend results` was asked to fetch and where it was
// asked to write it.
type ResultsInput struct {
	ProjectID    string `flag:"--project-id" validate:"required,resourceid"`
	ScanType     string `flag:"--type" validate:"required,oneof=sast sca iac secret cicd container all"`
	OutputFormat string `flag:"--output" validate:"required,oneof=json html sarif markdown"`
	OutputFile   string `flag:"--filename" validate:"required,safepath"`
	OutputPath   string `flag:"--filepath" validate:"required,safepath"`
	Branch       string `flag:"--branch" validate:"omitempty,branchname"`
	// Page is only read when --all is off; the command passes 1 otherwise.
	Page int `flag:"--page" validate:"gte=1"`
}

// ReportInput covers the report subcommands. Which id is required depends on
// the subcommand, so all three are optional here and the command asserts the
// one it needs — what this schema guarantees is that any id that *was* given is
// safe to interpolate into the report URL.
type ReportInput struct {
	ProjectID      string   `flag:"--project-id" validate:"omitempty,resourceid"`
	OrganizationID string   `flag:"--organization-id" validate:"omitempty,resourceid"`
	TeamID         string   `flag:"--team-id" validate:"omitempty,resourceid"`
	ProjectIDs     []string `flag:"--project-ids" validate:"omitempty,dive,resourceid"`
	ReportType     string   `flag:"--type" validate:"omitempty,oneof=owasp cwe"`
	Format         string   `flag:"--format" validate:"omitempty,oneof=json html pdf"`
	Output         string   `flag:"--output" validate:"omitempty,safepath"`
	// Reports are generated asynchronously, so a report command waits. A zero
	// wait would abandon every report before the API has finished the first one.
	TimeoutSeconds int `flag:"--timeout" validate:"gte=1,lte=3600"`
}

// TeamMemberInput covers the add-member / update-member / remove-member
// subcommands. Role is optional because remove-member does not take one.
type TeamMemberInput struct {
	TeamID string `flag:"--team-id" validate:"required,resourceid"`
	UserID string `flag:"--user-id" validate:"required,resourceid"`
	Role   string `flag:"--role" validate:"omitempty,oneof=team_manager analyst_developer developer read_only"`
}

// TeamInput covers the team commands that address a team or an organization
// without touching a member.
type TeamInput struct {
	OrganizationID string `flag:"--organization-id" validate:"omitempty,resourceid"`
	TeamID         string `flag:"--team-id" validate:"omitempty,resourceid"`
}

// ContainerScanInput is what `cybedefend container scan <registry>` was asked
// to scan. Severities arrives as a comma-separated flag and is split by the
// command before it gets here.
type ContainerScanInput struct {
	ProjectID    string   `flag:"--project-id" validate:"required,resourceid"`
	Image        string   `flag:"--image" validate:"required,imageref"`
	CredentialID string   `flag:"--credential-id" validate:"omitempty,resourceid"`
	Branch       string   `flag:"--branch" validate:"omitempty,branchname"`
	Severities   []string `flag:"--severities" validate:"omitempty,dive,oneof=CRITICAL HIGH MEDIUM LOW"`
}

// PageInput is the pagination shared by the listing commands. The upper bound
// keeps a typo from asking the API for an unbounded page.
type PageInput struct {
	Page     int `flag:"--page" validate:"gte=1"`
	PageSize int `flag:"--page-size" validate:"gte=1,lte=1000"`
}

// DateRangeInput is the --start-date / --end-date filter. Both are optional:
// omitting them means "no bound on that side".
type DateRangeInput struct {
	StartDate string `flag:"--start-date" validate:"omitempty,isodate"`
	EndDate   string `flag:"--end-date" validate:"omitempty,isodate"`
}

// OverviewInput is the organization overview filter set. The list filters are
// passed through to the API, which owns their vocabulary, so they are only
// checked for the shape that would break the query string.
type OverviewInput struct {
	ProjectID       string   `flag:"--project-id" validate:"omitempty,resourceid"`
	OrganizationID  string   `flag:"--organization-id" validate:"omitempty,resourceid"`
	TeamIDs         []string `flag:"--team-ids" validate:"omitempty,dive,resourceid"`
	Branches        []string `flag:"--branches" validate:"omitempty,dive,branchname"`
	DateFrom        string   `flag:"--date-from" validate:"omitempty,isodate"`
	DateTo          string   `flag:"--date-to" validate:"omitempty,isodate"`
	TrendPeriodDays int      `flag:"--trend-period-days" validate:"gte=0,lte=3650"`
}
