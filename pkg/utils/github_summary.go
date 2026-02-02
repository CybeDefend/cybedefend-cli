package utils

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// GitHubSummaryWriter handles writing markdown summaries to GITHUB_STEP_SUMMARY
type GitHubSummaryWriter struct {
	content  strings.Builder
	enabled  bool
	filePath string
}

// NewGitHubSummaryWriter creates a new GitHubSummaryWriter
// It checks if GITHUB_STEP_SUMMARY environment variable is set
func NewGitHubSummaryWriter() *GitHubSummaryWriter {
	summaryPath := os.Getenv("GITHUB_STEP_SUMMARY")
	return &GitHubSummaryWriter{
		enabled:  summaryPath != "",
		filePath: summaryPath,
	}
}

// IsEnabled returns true if GitHub Step Summary is available
func (w *GitHubSummaryWriter) IsEnabled() bool {
	return w.enabled
}

// AddLine adds a line to the summary
func (w *GitHubSummaryWriter) AddLine(format string, args ...interface{}) {
	if !w.enabled {
		return
	}
	w.content.WriteString(fmt.Sprintf(format, args...))
	w.content.WriteString("\n")
}

// AddRaw adds raw content without formatting
func (w *GitHubSummaryWriter) AddRaw(content string) {
	if !w.enabled {
		return
	}
	w.content.WriteString(content)
}

// AddHeader adds a markdown header
func (w *GitHubSummaryWriter) AddHeader(level int, text string) {
	if !w.enabled {
		return
	}
	prefix := strings.Repeat("#", level)
	w.content.WriteString(fmt.Sprintf("%s %s\n\n", prefix, text))
}

// AddScanHeader adds the main header with scan info
func (w *GitHubSummaryWriter) AddScanHeader(scanID, projectID, branch string) {
	if !w.enabled {
		return
	}
	w.AddHeader(1, "🔒 CybeDefend Security Scan Report")
	w.AddLine("")
	w.AddLine("| Property | Value |")
	w.AddLine("|----------|-------|")
	w.AddLine("| **Scan ID** | `%s` |", scanID)
	w.AddLine("| **Project ID** | `%s` |", projectID)
	if branch != "" {
		w.AddLine("| **Branch** | `%s` |", branch)
	}
	w.AddLine("| **Date** | %s |", time.Now().Format("2006-01-02 15:04:05 UTC"))
	w.AddLine("")
}

// AddScanStatus adds the scan status section
func (w *GitHubSummaryWriter) AddScanStatus(status string, progress int, vulnerabilityCount int) {
	if !w.enabled {
		return
	}

	statusEmoji := "✅"
	if status == "failed" {
		statusEmoji = "❌"
	} else if status == "running" || status == "pending" {
		statusEmoji = "🔄"
	}

	w.AddHeader(2, fmt.Sprintf("%s Scan Status: %s", statusEmoji, strings.ToUpper(status)))

	if vulnerabilityCount >= 0 {
		w.AddLine("")
		w.AddLine("**Vulnerabilities Detected:** %d", vulnerabilityCount)
	}
	w.AddLine("")
}

// AddVulnerabilitySummary adds vulnerability breakdown table
func (w *GitHubSummaryWriter) AddVulnerabilitySummary(critical, high, medium, low int) {
	if !w.enabled {
		return
	}

	w.AddHeader(3, "📊 Vulnerability Summary")
	w.AddLine("")
	w.AddLine("| Severity | Count |")
	w.AddLine("|----------|-------|")

	if critical > 0 {
		w.AddLine("| 🔴 **Critical** | %d |", critical)
	}
	if high > 0 {
		w.AddLine("| 🟠 **High** | %d |", high)
	}
	if medium > 0 {
		w.AddLine("| 🟡 **Medium** | %d |", medium)
	}
	if low > 0 {
		w.AddLine("| 🟢 **Low** | %d |", low)
	}

	total := critical + high + medium + low
	w.AddLine("| **Total** | **%d** |", total)
	w.AddLine("")
}

// AddPolicyEvaluationHeader adds the policy evaluation section header
func (w *GitHubSummaryWriter) AddPolicyEvaluationHeader(hasViolations bool) {
	if !w.enabled {
		return
	}

	if hasViolations {
		w.AddHeader(2, "⚠️ Policy Evaluation")
	} else {
		w.AddHeader(2, "✅ Policy Evaluation")
		w.AddLine("No policy violations found.")
		w.AddLine("")
	}
}

// AddPolicyViolationSummary adds the policy violation summary
func (w *GitHubSummaryWriter) AddPolicyViolationSummary(blockCount, warnCount, acknowledgedCount int) {
	if !w.enabled {
		return
	}

	w.AddLine("")
	w.AddLine("| Status | Count |")
	w.AddLine("|--------|-------|")
	if blockCount > 0 {
		w.AddLine("| 🚫 **Blocking** | %d |", blockCount)
	}
	if warnCount > 0 {
		w.AddLine("| ⚠️ **Warnings** | %d |", warnCount)
	}
	if acknowledgedCount > 0 {
		w.AddLine("| ✅ **Acknowledged** | %d |", acknowledgedCount)
	}
	w.AddLine("")
}

// PolicyViolationInfo contains information about a policy violation for summary
type PolicyViolationInfo struct {
	RuleName        string
	RuleDescription string
	ActionTaken     string
	Acknowledged    bool
	AckReason       string
	VulnCount       int
	Vulnerabilities []VulnerabilityInfo
}

// VulnerabilityInfo contains vulnerability details for summary
type VulnerabilityInfo struct {
	ID             string
	Name           string
	Severity       string
	FilePath       string
	StartLine      int
	EndLine        int
	VulnType       string
	PackageName    string
	PackageVersion string
	Link           string
}

// AddBlockingViolations adds the blocking violations section
func (w *GitHubSummaryWriter) AddBlockingViolations(violations []PolicyViolationInfo) {
	if !w.enabled || len(violations) == 0 {
		return
	}

	w.AddHeader(3, "🚫 Blocking Violations")
	w.AddLine("")

	for _, v := range violations {
		w.AddLine("<details>")
		w.AddLine("<summary><strong>%s</strong> - %d vulnerabilities</summary>", v.RuleName, v.VulnCount)
		w.AddLine("")

		if v.RuleDescription != "" {
			w.AddLine("> %s", v.RuleDescription)
			w.AddLine("")
		}

		if len(v.Vulnerabilities) > 0 {
			w.AddLine("| Severity | Name | Location | Link |")
			w.AddLine("|----------|------|----------|------|")
			for _, vuln := range v.Vulnerabilities {
				location := formatVulnLocation(vuln)
				severityEmoji := getSeverityEmoji(vuln.Severity)
				w.AddLine("| %s %s | %s | %s | [View](%s) |", severityEmoji, vuln.Severity, vuln.Name, location, vuln.Link)
			}
		}
		w.AddLine("")
		w.AddLine("</details>")
		w.AddLine("")
	}
}

// AddWarningViolations adds the warning violations section
func (w *GitHubSummaryWriter) AddWarningViolations(violations []PolicyViolationInfo) {
	if !w.enabled || len(violations) == 0 {
		return
	}

	w.AddHeader(3, "⚠️ Warning Violations")
	w.AddLine("")

	for _, v := range violations {
		w.AddLine("<details>")
		w.AddLine("<summary><strong>%s</strong> - %d vulnerabilities</summary>", v.RuleName, v.VulnCount)
		w.AddLine("")

		if v.RuleDescription != "" {
			w.AddLine("> %s", v.RuleDescription)
			w.AddLine("")
		}

		if len(v.Vulnerabilities) > 0 {
			w.AddLine("| Severity | Name | Location | Link |")
			w.AddLine("|----------|------|----------|------|")
			for _, vuln := range v.Vulnerabilities {
				location := formatVulnLocation(vuln)
				severityEmoji := getSeverityEmoji(vuln.Severity)
				w.AddLine("| %s %s | %s | %s | [View](%s) |", severityEmoji, vuln.Severity, vuln.Name, location, vuln.Link)
			}
		}
		w.AddLine("")
		w.AddLine("</details>")
		w.AddLine("")
	}
}

// AddAcknowledgedViolations adds the acknowledged violations section
func (w *GitHubSummaryWriter) AddAcknowledgedViolations(violations []PolicyViolationInfo) {
	if !w.enabled || len(violations) == 0 {
		return
	}

	w.AddHeader(3, "✅ Acknowledged Violations")
	w.AddLine("")

	for _, v := range violations {
		w.AddLine("<details>")
		w.AddLine("<summary><strong>%s</strong> - %d vulnerabilities (Acknowledged)</summary>", v.RuleName, v.VulnCount)
		w.AddLine("")

		if v.AckReason != "" {
			w.AddLine("> **Acknowledgement Reason:** %s", v.AckReason)
			w.AddLine("")
		}

		if len(v.Vulnerabilities) > 0 {
			w.AddLine("| Severity | Name | Location | Link |")
			w.AddLine("|----------|------|----------|------|")
			for _, vuln := range v.Vulnerabilities {
				location := formatVulnLocation(vuln)
				severityEmoji := getSeverityEmoji(vuln.Severity)
				w.AddLine("| %s %s | %s | %s | [View](%s) |", severityEmoji, vuln.Severity, vuln.Name, location, vuln.Link)
			}
		}
		w.AddLine("")
		w.AddLine("</details>")
		w.AddLine("")
	}
}

// AddFinalStatus adds the final status message
func (w *GitHubSummaryWriter) AddFinalStatus(passed bool, message string) {
	if !w.enabled {
		return
	}

	w.AddLine("---")
	w.AddLine("")
	if passed {
		w.AddLine("## ✅ Result: PASSED")
	} else {
		w.AddLine("## ❌ Result: FAILED")
	}
	if message != "" {
		w.AddLine("")
		w.AddLine(message)
	}
	w.AddLine("")
}

// Write writes the accumulated content to GITHUB_STEP_SUMMARY file
func (w *GitHubSummaryWriter) Write() error {
	if !w.enabled {
		return nil
	}

	f, err := os.OpenFile(w.filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open GITHUB_STEP_SUMMARY file: %w", err)
	}
	defer f.Close()

	if _, err := f.WriteString(w.content.String()); err != nil {
		return fmt.Errorf("failed to write to GITHUB_STEP_SUMMARY: %w", err)
	}

	return nil
}

// GetContent returns the current content (for testing purposes)
func (w *GitHubSummaryWriter) GetContent() string {
	return w.content.String()
}

// Helper functions

func formatVulnLocation(vuln VulnerabilityInfo) string {
	if vuln.VulnType == "sca" && vuln.PackageName != "" {
		return fmt.Sprintf("`%s@%s`", vuln.PackageName, vuln.PackageVersion)
	}
	if vuln.EndLine > 0 && vuln.EndLine != vuln.StartLine {
		return fmt.Sprintf("`%s` (L%d-%d)", vuln.FilePath, vuln.StartLine, vuln.EndLine)
	}
	return fmt.Sprintf("`%s` (L%d)", vuln.FilePath, vuln.StartLine)
}

func getSeverityEmoji(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "🔴"
	case "high":
		return "🟠"
	case "medium":
		return "🟡"
	case "low":
		return "🟢"
	default:
		return "⚪"
	}
}
