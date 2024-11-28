package utils

import (
	"bytes"
	"fmt"
	"html/template"
	"os"
)

type VulnerabilityReport struct {
	ProjectName     string
	ProjectID       string
	Total           int
	Page            int
	TotalPages      int
	Severity        []string
	Vulnerabilities []Vulnerability
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
        }
    </style>
</head>
<body>
    <div class="container mx-auto px-4 py-6">
        <header class="flex justify-between items-center bg-gray-800 p-4 rounded-lg shadow-md">
            <img src="https://i.ibb.co/Ksb6994/Logo-Responsive-01-CYBEDEFEND-blanc.png" alt="Logo" class="h-10">
            <h1 class="text-2xl font-bold text-purple-400">Scan Results</h1>
        </header>

        <section class="bg-gray-900 p-6 mt-4 rounded-lg shadow-md">
            <div class="mb-4">
                <h2 class="text-xl font-semibold text-purple-300">Project: {{ .ProjectName }}</h2>
                <p>Project ID: <span class="font-mono">{{ .ProjectID }}</span></p>
                <p>Total Vulnerabilities: <span class="font-bold text-purple-300">{{ .Total }}</span></p>
				<p>Page: <span class="font-bold text-purple-300">{{ .Page }}</span> of <span class="font-bold text-purple-300">{{ .TotalPages }}</span></p>
            </div>

            <div class="space-y-6">
                {{ range .Vulnerabilities }}
                <div class="p-4 rounded-lg shadow-lg bg-gray-800">
                    <div class="flex justify-between items-center">
                        <h3 class="text-lg font-semibold">{{ .Name }}</h3>
                        <span class="px-3 py-1 text-xs font-bold rounded-lg
                            {{ if eq .Severity "CRITICAL" }}bg-red-500 text-white{{ end }}
                            {{ if eq .Severity "HIGH" }}bg-orange-500 text-white{{ end }}
                            {{ if eq .Severity "MEDIUM" }}bg-yellow-500 text-gray-800{{ end }}
                            {{ if eq .Severity "LOW" }}bg-blue-500 text-white{{ end }}">
                            {{ .Severity }}
                        </span>
                    </div>
                    <p class="text-sm font-mono mt-1">{{ .Language }} - {{ .Path }}:{{ .VulnerableStartLine }}-{{ .VulnerableEndLine }}</p>
                    <div class="mt-3 bg-gray-700 p-3 rounded-lg text-sm">
                        <p><strong>Description:</strong> {{ .Description }}</p>
                        <p  class="mt-2"><strong>How to Fix:</strong> {{ .HowToPrevent }}</p>
                        <p class="mt-2"><strong>CWE:</strong> 
                            {{ range .CWE }}
                                <span class="inline-block bg-gray-600 text-white px-2 py-1 text-xs rounded-lg">{{ . }}</span>
                            {{ end }}
                        </p>
						<p class="mt-2"><strong>OWASP:</strong>
							{{ range .OWASP }}
							 	<span class="inline-block bg-gray-600 text-white px-2 py-1 text-xs rounded-lg">{{ . }}</span>
							{{ end }}
						</p>
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
		"ToLower": func(s string) string { return fmt.Sprintf("%s", s) },
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
