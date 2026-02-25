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
		})
	}
	return results
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
