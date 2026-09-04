package utils

import (
	"encoding/json"
	"fmt"
	"os"
)

// SarifReport represents the root structure of a SARIF report.
type SarifReport struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []SarifRun `json:"runs"`
}

type SarifRun struct {
	Tool        SarifTool         `json:"tool"`
	Results     []SarifResult     `json:"results"`
	Invocations []SarifInvocation `json:"invocations,omitempty"`
}

type SarifTool struct {
	Driver SarifDriver `json:"driver"`
}

type SarifDriver struct {
	Name           string `json:"name"`
	InformationURI string `json:"informationUri,omitempty"`
	Version        string `json:"version,omitempty"`
}

type SarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   SarifMessage    `json:"message"`
	Locations []SarifLocation `json:"locations"`
	// Properties carries the platform risk data (CVE, CVSS 4, EPSS, priority)
	// as a standard SARIF property bag.
	Properties map[string]any `json:"properties,omitempty"`
}

type SarifMessage struct {
	Text string `json:"text"`
}

type SarifLocation struct {
	PhysicalLocation SarifPhysicalLocation `json:"physicalLocation"`
}

type SarifPhysicalLocation struct {
	ArtifactLocation SarifArtifactLocation `json:"artifactLocation"`
	Region           SarifRegion           `json:"region"`
}

type SarifArtifactLocation struct {
	URI string `json:"uri"`
}

type SarifRegion struct {
	StartLine   int `json:"startLine"`
	EndLine     int `json:"endLine,omitempty"`
	StartColumn int `json:"startColumn,omitempty"`
	EndColumn   int `json:"endColumn,omitempty"`
}

type SarifInvocation struct {
	CommandLine string `json:"commandLine"`
}

// ConvertToSARIF converts the vulnerability report to a SARIF report.
func ConvertToSARIF(report VulnerabilityReport, outputFilePath string) error {
	sarif := SarifReport{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0",
		Runs: []SarifRun{
			{
				Tool: SarifTool{
					Driver: SarifDriver{
						Name:           "Cybedefend CLI",
						InformationURI: "https://example.com/docs",
						Version:        "1.0.0",
					},
				},
				Results: mapVulnerabilitiesToSarifResults(report.Vulnerabilities),
			},
		},
	}

	file, err := os.Create(outputFilePath)
	if err != nil {
		return fmt.Errorf("error creating SARIF file: %w", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(sarif); err != nil {
		return fmt.Errorf("error writing SARIF file: %w", err)
	}

	return nil
}

// mapVulnerabilitiesToSarifResults maps vulnerabilities to SARIF results.
func mapVulnerabilitiesToSarifResults(vulnerabilities []Vulnerability) []SarifResult {
	var results []SarifResult
	for _, v := range vulnerabilities {
		// Use the vulnerability name as ruleId (falling back to instance ID if empty).
		ruleID := v.Name
		if ruleID == "" {
			ruleID = v.ID
		}
		// Build a descriptive message: name + description.
		msgText := v.Description
		if v.Name != "" && v.Description != "" {
			msgText = v.Name + ": " + v.Description
		} else if v.Name != "" {
			msgText = v.Name
		}
		startLine := v.VulnerableStartLine
		if startLine == 0 {
			startLine = 1
		}
		endLine := v.VulnerableEndLine
		if endLine == 0 {
			endLine = startLine
		}
		results = append(results, SarifResult{
			RuleID: ruleID,
			Level:  mapSeverityToLevel(v.Severity),
			Message: SarifMessage{
				Text: msgText,
			},
			Locations: []SarifLocation{
				{
					PhysicalLocation: SarifPhysicalLocation{
						ArtifactLocation: SarifArtifactLocation{
							URI: v.Path,
						},
						Region: SarifRegion{
							StartLine: startLine,
							EndLine:   endLine,
						},
					},
				},
			},
			Properties: sarifProperties(v),
		})
	}
	return results
}

// sarifProperties builds the property bag of one result, nil when no risk data
// is available. "security-severity" follows the GitHub code-scanning convention
// (decimal string), preferring the environmental score over the base score.
func sarifProperties(v Vulnerability) map[string]any {
	props := map[string]any{}
	if v.CVE != "" {
		props["cve"] = v.CVE
	}
	if v.Priority != "" {
		props["priority"] = v.Priority
	}
	if v.PriorityScore != nil {
		props["priorityScore"] = *v.PriorityScore
	}
	if v.Cvss4BaseScore != nil {
		props["cvss4BaseScore"] = *v.Cvss4BaseScore
	}
	if v.Cvss4EnvironmentalScore != nil {
		props["cvss4EnvironmentalScore"] = *v.Cvss4EnvironmentalScore
	}
	if v.Cvss4Vector != "" {
		props["cvss4Vector"] = v.Cvss4Vector
	}
	if v.Cvss4EnvironmentalVector != "" {
		props["cvss4EnvironmentalVector"] = v.Cvss4EnvironmentalVector
	}
	if v.Cvss4Breakdown != nil {
		props["cvss4Breakdown"] = v.Cvss4Breakdown
	}
	if v.EpssScore != nil {
		props["epssScore"] = *v.EpssScore
	}
	if v.EpssPercentile != nil {
		props["epssPercentile"] = *v.EpssPercentile
	}
	if v.ExploitabilityVerdict != "" {
		props["exploitabilityVerdict"] = v.ExploitabilityVerdict
	}
	switch {
	case v.Cvss4EnvironmentalScore != nil:
		props["security-severity"] = fmt.Sprintf("%.1f", *v.Cvss4EnvironmentalScore)
	case v.Cvss4BaseScore != nil:
		props["security-severity"] = fmt.Sprintf("%.1f", *v.Cvss4BaseScore)
	}
	if len(props) == 0 {
		return nil
	}
	return props
}

// mapSeverityToLevel maps the severity to SARIF level.
func mapSeverityToLevel(severity string) string {
	switch severity {
	case "CRITICAL":
		return "error"
	case "HIGH":
		return "error"
	case "MEDIUM":
		return "warning"
	case "LOW":
		return "note"
	default:
		return "none"
	}
}
