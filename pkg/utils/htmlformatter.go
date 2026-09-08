package utils

import (
	"bytes"
	"fmt"
	"html/template"
	"os"
	"regexp"
	"strings"

	"cybedefend-cli/pkg/cvss"
)

// markdownToHTML converts a subset of Markdown to safe HTML for use in templates.
func markdownToHTML(s string) template.HTML {
	// Split on fenced code blocks to process them separately.
	codeBlock := regexp.MustCompile("(?s)```[^\\n]*\\n(.*?)```")
	parts := codeBlock.Split(s, -1)
	codeMatches := codeBlock.FindAllStringSubmatch(s, -1)

	var out strings.Builder
	for i, part := range parts {
		out.WriteString(renderMarkdownSegment(part))
		if i < len(codeMatches) {
			code := template.HTMLEscapeString(strings.TrimSpace(codeMatches[i][1]))
			out.WriteString(`<pre class="bg-gray-900 rounded p-3 overflow-x-auto text-xs mt-2 mb-2 whitespace-pre-wrap break-all"><code>` + code + `</code></pre>`)
		}
	}
	return template.HTML(out.String())
}

// renderMarkdownSegment converts basic markdown in a plain-text segment to HTML.
func renderMarkdownSegment(s string) string {
	// Escape HTML first (before adding any HTML tags).
	s = template.HTMLEscapeString(s)

	// Links: [text](url) → <a href="url">text</a>  (must run before inline-code to avoid double-escaping)
	link := regexp.MustCompile(`\[([^\]]+)\]\((https?://[^)]+)\)`)
	s = link.ReplaceAllString(s, `<a href="$2" class="text-purple-400 underline break-all" target="_blank" rel="noopener">$1</a>`)

	// Inline code: `code`
	inlineCode := regexp.MustCompile("`([^`\n]+)`")
	s = inlineCode.ReplaceAllString(s, `<code class="bg-gray-900 px-1 rounded text-purple-300 break-all">$1</code>`)

	// Bold: **text**
	bold := regexp.MustCompile(`\*\*([^*\n]+)\*\*`)
	s = bold.ReplaceAllString(s, `<strong>$1</strong>`)

	lines := strings.Split(s, "\n")
	var result strings.Builder
	inUL, inOL := false, false
	olNum := regexp.MustCompile(`^(\d+)\. `)

	closeList := func() {
		if inUL {
			result.WriteString("</ul>")
			inUL = false
		}
		if inOL {
			result.WriteString("</ol>")
			inOL = false
		}
	}

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			closeList()
			continue
		}
		// Headings: ###, ##, #
		if strings.HasPrefix(trimmed, "### ") {
			closeList()
			result.WriteString(`<h4 class="font-semibold text-purple-300 mt-3 mb-1">` + trimmed[4:] + `</h4>`)
		} else if strings.HasPrefix(trimmed, "## ") {
			closeList()
			result.WriteString(`<h3 class="font-semibold text-purple-300 mt-3 mb-1">` + trimmed[3:] + `</h3>`)
		} else if strings.HasPrefix(trimmed, "# ") {
			closeList()
			result.WriteString(`<h2 class="font-bold text-purple-200 mt-3 mb-1 text-base">` + trimmed[2:] + `</h2>`)
		} else if trimmed == "---" || trimmed == "***" {
			closeList()
			result.WriteString(`<hr class="border-gray-600 my-2">`)
		} else if strings.HasPrefix(trimmed, "- ") {
			if inOL {
				result.WriteString("</ol>")
				inOL = false
			}
			if !inUL {
				result.WriteString(`<ul class="list-disc list-inside mt-1 space-y-1 text-gray-300">`)
				inUL = true
			}
			result.WriteString(`<li class="break-words">` + trimmed[2:] + "</li>")
		} else if olNum.MatchString(trimmed) {
			if inUL {
				result.WriteString("</ul>")
				inUL = false
			}
			if !inOL {
				result.WriteString(`<ol class="list-decimal list-inside mt-1 space-y-1 text-gray-300">`)
				inOL = true
			}
			result.WriteString(`<li class="break-words">` + olNum.ReplaceAllString(trimmed, "") + "</li>")
		} else {
			closeList()
			result.WriteString(`<p class="mt-1 break-words">` + trimmed + `</p>`)
		}
	}
	closeList()
	return result.String()
}

type VulnerabilityReport struct {
	ProjectName       string
	ProjectID         string
	Total             int
	Page              int
	TotalPages        int
	Severity          []string
	Vulnerabilities   []Vulnerability
	VulnerabilityType string
}

type Vulnerability struct {
	ID                  string
	Name                string
	Description         string
	Severity            string
	Language            string
	Path                string
	VulnerableStartLine int
	VulnerableEndLine   int
	HowToPrevent        string
	CWE                 []string
	OWASP               []string
	CVE                 string

	// Platform risk scores. Pointers distinguish "0" from "not computed".
	Priority                 string // critical_urgent | urgent | normal | low | very_low
	PriorityScore            *float64
	Cvss4BaseScore           *float64
	Cvss4EnvironmentalScore  *float64
	Cvss4Vector              string
	Cvss4EnvironmentalVector string
	Cvss4Breakdown           *cvss.Breakdown // decoded vectors, nil when no CVSS 4.0 vector
	EpssScore                *float64        // exploitation probability, 0–1
	EpssPercentile           *float64        // percentile among all CVEs, 0–1
	ExploitabilityVerdict    string          // not_exploitable | theoretical | proven | actively_exploited
}

// HasScores reports whether at least one platform score is available.
func (v Vulnerability) HasScores() bool {
	return v.PriorityScore != nil || v.Cvss4BaseScore != nil || v.Cvss4EnvironmentalScore != nil ||
		v.EpssScore != nil || v.EpssPercentile != nil ||
		v.Cvss4Vector != "" || v.Cvss4EnvironmentalVector != "" || v.ExploitabilityVerdict != ""
}

// cveIDPattern matches a well-formed CVE identifier (CVE-YYYY-NNNN...).
var cveIDPattern = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

// nvdURL returns the NVD page of a CVE, or "" when the identifier is not a
// well-formed CVE id (so malformed advisory data never ends up in a link).
func nvdURL(cve string) string {
	if !cveIDPattern.MatchString(cve) {
		return ""
	}
	return "https://nvd.nist.gov/vuln/detail/" + cve
}

// formatScore renders a *float64 score with one decimal ("" when absent).
func formatScore(p *float64) string {
	if p == nil {
		return ""
	}
	return fmt.Sprintf("%.1f", *p)
}

// formatPercent renders a 0–1 ratio as a percentage with one decimal ("" when absent).
func formatPercent(p *float64) string {
	if p == nil {
		return ""
	}
	return fmt.Sprintf("%.1f%%", *p*100)
}

const htmlTemplate = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Scan Results</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        body {
            background-color: #1E1E2F;
            color: #FFFFFF;
            overflow-x: hidden;
        }
        * {
            box-sizing: border-box;
        }
        .break-anywhere {
            overflow-wrap: anywhere;
            word-break: break-word;
        }
    </style>
</head>
<body>
    <div class="w-full max-w-5xl mx-auto px-4 py-6">
        <header class="flex justify-between items-center bg-gray-800 p-4 rounded-lg shadow-md">
            <img src="https://storage.googleapis.com/cybedefend-images/white_logo_big.png" alt="Logo" class="h-10">
            <h1 class="text-2xl font-bold text-purple-400">Scan Results</h1>
        </header>

        <section class="bg-gray-900 p-6 mt-4 rounded-lg shadow-md">
            <div class="mb-4">
                <h2 class="text-xl font-semibold text-purple-300">Project: {{ .ProjectName }}</h2>
                <p>Project ID: <span class="font-mono break-all">{{ .ProjectID }}</span></p>
                <p>Total Vulnerabilities: <span class="font-bold text-purple-300">{{ .Total }}</span></p>
                <p>Type: <span class="font-bold text-purple-300">{{ .VulnerabilityType }}</span></p>
                <p>Page: <span class="font-bold text-purple-300">{{ .Page }}</span> of <span class="font-bold text-purple-300">{{ .TotalPages }}</span></p>
            </div>

            <div class="space-y-4">
                {{ range .Vulnerabilities }}
                <div class="rounded-lg shadow-lg bg-gray-800 overflow-hidden">
                    <div class="flex items-start justify-between gap-3 p-4">
                        <h3 class="text-base font-semibold leading-snug break-words min-w-0 flex-1">{{ .Name }}{{ if .CVE }} <span class="font-mono text-sm text-purple-300">({{ .CVE }})</span>{{ end }}</h3>
                        <div class="flex-shrink-0 flex items-center gap-2">
                            {{ if .Priority }}
                            <span class="px-3 py-1 text-xs font-bold rounded-lg whitespace-nowrap uppercase
                                {{ if eq .Priority "critical_urgent" }}bg-fuchsia-600 text-white{{ end }}
                                {{ if eq .Priority "urgent" }}bg-pink-500 text-white{{ end }}
                                {{ if eq .Priority "normal" }}bg-indigo-500 text-white{{ end }}
                                {{ if eq .Priority "low" }}bg-slate-500 text-white{{ end }}
                                {{ if eq .Priority "very_low" }}bg-slate-600 text-white{{ end }}">
                                {{ .Priority }}{{ if .PriorityScore }} · {{ score .PriorityScore }}/100{{ end }}
                            </span>
                            {{ end }}
                            <span class="px-3 py-1 text-xs font-bold rounded-lg whitespace-nowrap
                                {{ if eq .Severity "CRITICAL" }}bg-red-500 text-white{{ end }}
                                {{ if eq .Severity "HIGH" }}bg-orange-500 text-white{{ end }}
                                {{ if eq .Severity "MEDIUM" }}bg-yellow-500 text-gray-800{{ end }}
                                {{ if eq .Severity "LOW" }}bg-blue-500 text-white{{ end }}
                                {{ if eq .Severity "" }}bg-gray-500 text-white{{ end }}">
                                {{ if .Severity }}{{ .Severity }}{{ else }}UNKNOWN{{ end }}
                            </span>
                        </div>
                    </div>
                    {{ if or .Language .Path }}
                    <div class="px-4 pb-2">
                        <p class="text-xs font-mono text-gray-400 break-all">
                            {{ if .Language }}<span class="text-purple-400">{{ .Language }}</span>{{ end }}
                            {{ if and .Language .Path }} — {{ end }}
                            {{ if .Path }}{{ .Path }}{{ end }}
                            {{ if and .VulnerableStartLine (ne .VulnerableStartLine 0) }}:<span class="text-yellow-400">{{ .VulnerableStartLine }}–{{ .VulnerableEndLine }}</span>{{ end }}
                        </p>
                    </div>
                    {{ end }}
                    <div class="mx-4 mb-4 bg-gray-700 p-3 rounded-lg text-sm space-y-3">
                        {{ if .HasScores }}
                        <div>
                            <p class="font-semibold text-gray-200 mb-1">Risk Scores</p>
                            <div class="grid grid-cols-2 md:grid-cols-5 gap-2 text-xs">
                                {{ if .PriorityScore }}
                                <div class="bg-gray-800 rounded p-2">
                                    <p class="text-gray-400">Priority</p>
                                    <p class="font-bold text-purple-300">{{ score .PriorityScore }}/100</p>
                                </div>
                                {{ end }}
                                {{ if .Cvss4BaseScore }}
                                <div class="bg-gray-800 rounded p-2">
                                    <p class="text-gray-400">CVSS 4.0 Base</p>
                                    <p class="font-bold text-purple-300">{{ score .Cvss4BaseScore }}</p>
                                </div>
                                {{ end }}
                                {{ if .Cvss4EnvironmentalScore }}
                                <div class="bg-gray-800 rounded p-2">
                                    <p class="text-gray-400">CVSS 4.0 Env.</p>
                                    <p class="font-bold text-purple-300">{{ score .Cvss4EnvironmentalScore }}</p>
                                </div>
                                {{ end }}
                                {{ if .EpssScore }}
                                <div class="bg-gray-800 rounded p-2">
                                    <p class="text-gray-400">EPSS{{ if .EpssPercentile }} (pctl {{ pct .EpssPercentile }}){{ end }}</p>
                                    <p class="font-bold text-purple-300">{{ pct .EpssScore }}</p>
                                </div>
                                {{ end }}
                                {{ if .ExploitabilityVerdict }}
                                <div class="bg-gray-800 rounded p-2">
                                    <p class="text-gray-400">Exploitability</p>
                                    <p class="font-bold text-purple-300">{{ .ExploitabilityVerdict }}</p>
                                </div>
                                {{ end }}
                            </div>
                            {{ if .Cvss4Vector }}
                            <p class="text-xs font-mono text-gray-400 break-all mt-2">Base vector: {{ .Cvss4Vector }}</p>
                            {{ end }}
                            {{ if .Cvss4EnvironmentalVector }}
                            <p class="text-xs font-mono text-gray-400 break-all">Env. vector: {{ .Cvss4EnvironmentalVector }}</p>
                            {{ end }}
                            {{ if .Cvss4Breakdown }}
                            <div class="mt-2 grid grid-cols-1 md:grid-cols-2 gap-x-6 text-xs">
                                {{ range .Cvss4Breakdown.Sections }}
                                <div class="mt-2">
                                    <p class="uppercase tracking-wide text-gray-400 mb-1">{{ .Title }}</p>
                                    {{ range .Metrics }}
                                    <div class="flex justify-between gap-2 border-b border-gray-600 py-0.5">
                                        <span><span class="font-mono text-gray-500">{{ .Metric }}:{{ .Value }}</span> {{ .Name }}</span>
                                        <span class="font-semibold text-gray-100">{{ .Label }}</span>
                                    </div>
                                    {{ end }}
                                </div>
                                {{ end }}
                            </div>
                            {{ end }}
                        </div>
                        {{ end }}
                        {{ if .Description }}
                        <div>
                            <p class="font-semibold text-gray-200 mb-1">Description</p>
                            <div class="text-gray-300 text-xs leading-relaxed break-anywhere">{{ markdownToHTML .Description }}</div>
                        </div>
                        {{ end }}
                        {{ if .HowToPrevent }}
                        <div>
                            <p class="font-semibold text-gray-200 mb-1">How to Fix</p>
                            <div class="text-gray-300 text-xs leading-relaxed break-anywhere">{{ markdownToHTML .HowToPrevent }}</div>
                        </div>
                        {{ end }}
                        {{ if .CVE }}
                        <div>
                            <p class="font-semibold text-gray-200 mb-1">CVE</p>
                            <div class="flex flex-wrap gap-1">
                                {{ if nvdURL .CVE }}
                                <a href="{{ nvdURL .CVE }}" target="_blank" rel="noopener" class="bg-gray-600 text-white px-2 py-0.5 text-xs rounded underline">{{ .CVE }}</a>
                                {{ else }}
                                <span class="bg-gray-600 text-white px-2 py-0.5 text-xs rounded">{{ .CVE }}</span>
                                {{ end }}
                            </div>
                        </div>
                        {{ end }}
                        {{ if .CWE }}
                        <div>
                            <p class="font-semibold text-gray-200 mb-1">CWE</p>
                            <div class="flex flex-wrap gap-1">
                                {{ range .CWE }}
                                <span class="bg-gray-600 text-white px-2 py-0.5 text-xs rounded">{{ . }}</span>
                                {{ end }}
                            </div>
                        </div>
                        {{ end }}
                        {{ if .OWASP }}
                        <div>
                            <p class="font-semibold text-gray-200 mb-1">OWASP</p>
                            <div class="flex flex-wrap gap-1">
                                {{ range .OWASP }}
                                <span class="bg-gray-600 text-white px-2 py-0.5 text-xs rounded">{{ . }}</span>
                                {{ end }}
                            </div>
                        </div>
                        {{ end }}
                    </div>
                </div>
                {{ end }}
            </div>
        </section>
    </div>
</body>
</html>
`

// RenderHTMLReport generates a styled HTML report for vulnerabilities.
func RenderHTMLReport(report VulnerabilityReport, outputFilePath string) error {
	tmpl, err := template.New("htmlReport").Funcs(template.FuncMap{
		"ToLower":        func(s string) string { return fmt.Sprintf("%s", s) },
		"markdownToHTML": markdownToHTML,
		"score":          formatScore,
		"pct":            formatPercent,
		"nvdURL":         nvdURL,
	}).Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("error parsing HTML template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, report); err != nil {
		return fmt.Errorf("error rendering HTML template: %w", err)
	}

	file, err := os.Create(outputFilePath)
	if err != nil {
		return fmt.Errorf("error creating output file: %w", err)
	}
	defer file.Close()

	_, err = file.Write(buf.Bytes())
	if err != nil {
		return fmt.Errorf("error writing HTML file: %w", err)
	}

	return nil
}
