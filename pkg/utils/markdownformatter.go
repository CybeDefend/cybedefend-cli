package utils

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// RenderMarkdownReport generates a Markdown report for vulnerabilities.
func RenderMarkdownReport(report VulnerabilityReport, outputFilePath string) error {
	var sb strings.Builder

	// ── Header ──────────────────────────────────────────────────────────────
	sb.WriteString("# 🔒 CybeDefend Security Scan Report\n\n")
	sb.WriteString(fmt.Sprintf("| | |\n|---|---|\n"))
	sb.WriteString(fmt.Sprintf("| **Project** | %s |\n", report.ProjectName))
	sb.WriteString(fmt.Sprintf("| **Project ID** | `%s` |\n", report.ProjectID))
	sb.WriteString(fmt.Sprintf("| **Scan type** | `%s` |\n", report.VulnerabilityType))
	sb.WriteString(fmt.Sprintf("| **Total vulnerabilities** | **%d** |\n", report.Total))
	sb.WriteString(fmt.Sprintf("| **Generated** | %s |\n", time.Now().Format("2006-01-02 15:04:05 UTC")))
	if report.TotalPages > 1 {
		sb.WriteString(fmt.Sprintf("| **Page** | %d / %d |\n", report.Page, report.TotalPages))
	}
	sb.WriteString("\n")

	if len(report.Vulnerabilities) == 0 {
		sb.WriteString("> ✅ No vulnerabilities found.\n")
		return writeStringToFile(sb.String(), outputFilePath)
	}

	// ── Severity summary table ───────────────────────────────────────────────
	counts := map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
	for _, v := range report.Vulnerabilities {
		counts[strings.ToUpper(v.Severity)]++
	}
	sb.WriteString("## Summary\n\n")
	sb.WriteString("| Severity | Count |\n|---|---|\n")
	sb.WriteString(fmt.Sprintf("| 🔴 CRITICAL | %d |\n", counts["CRITICAL"]))
	sb.WriteString(fmt.Sprintf("| 🟠 HIGH     | %d |\n", counts["HIGH"]))
	sb.WriteString(fmt.Sprintf("| 🟡 MEDIUM   | %d |\n", counts["MEDIUM"]))
	sb.WriteString(fmt.Sprintf("| 🔵 LOW      | %d |\n", counts["LOW"]))
	sb.WriteString("\n")

	// ── Vulnerability list ───────────────────────────────────────────────────
	sb.WriteString("## Vulnerabilities\n\n")

	for i, order := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} {
		_ = i
		var group []Vulnerability
		for _, v := range report.Vulnerabilities {
			if strings.ToUpper(v.Severity) == order {
				group = append(group, v)
			}
		}
		if len(group) == 0 {
			continue
		}

		severityIcon := map[string]string{
			"CRITICAL": "🔴",
			"HIGH":     "🟠",
			"MEDIUM":   "🟡",
			"LOW":      "🔵",
		}[order]

		sb.WriteString(fmt.Sprintf("### %s %s (%d)\n\n", severityIcon, order, len(group)))

		for _, v := range group {
			sb.WriteString(fmt.Sprintf("<details>\n<summary><strong>%s</strong> — <code>%s:%d</code></summary>\n\n",
				escapeMarkdown(v.Name), v.Path, v.VulnerableStartLine))

			sb.WriteString(fmt.Sprintf("**Language:** `%s`  \n", v.Language))
			sb.WriteString(fmt.Sprintf("**Location:** `%s` lines %d–%d  \n\n",
				v.Path, v.VulnerableStartLine, v.VulnerableEndLine))

			if v.Description != "" {
				sb.WriteString("**Description:**  \n")
				sb.WriteString(v.Description + "\n\n")
			}

			if v.HowToPrevent != "" {
				sb.WriteString("**How to Fix:**  \n")
				sb.WriteString(v.HowToPrevent + "\n\n")
			}

			if len(v.CWE) > 0 {
				sb.WriteString("**CWE:** ")
				cweLinks := make([]string, len(v.CWE))
				for i, c := range v.CWE {
					id := strings.TrimPrefix(c, "CWE-")
					cweLinks[i] = fmt.Sprintf("[%s](https://cwe.mitre.org/data/definitions/%s.html)", c, id)
				}
				sb.WriteString(strings.Join(cweLinks, ", ") + "  \n")
			}

			if len(v.OWASP) > 0 {
				tags := make([]string, len(v.OWASP))
				for i, o := range v.OWASP {
					tags[i] = "`" + o + "`"
				}
				sb.WriteString("**OWASP:** " + strings.Join(tags, ", ") + "  \n")
			}

			sb.WriteString("\n</details>\n\n")
		}
	}

	return writeStringToFile(sb.String(), outputFilePath)
}

func writeStringToFile(content, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("error creating file: %w", err)
	}
	defer f.Close()
	_, err = f.WriteString(content)
	return err
}

func escapeMarkdown(s string) string {
	// Escape characters that break markdown table cells / inline formatting.
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}
