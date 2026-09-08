// Package cvss decodes CVSS 4.0 vector strings into human-readable metrics,
// mirroring the "vector details" panel of the CybeDefend platform.
package cvss

import "strings"

// Metric is one decoded vector component.
type Metric struct {
	Metric string `json:"metric"` // e.g. "AV"
	Name   string `json:"name"`   // e.g. "Attack Vector"
	Value  string `json:"value"`  // e.g. "N"
	Label  string `json:"label"`  // e.g. "Network"
}

// Section groups related metrics under a title.
type Section struct {
	Title   string   `json:"title"`
	Metrics []Metric `json:"metrics"`
}

// Breakdown is the decoded form of a CVSS 4.0 vector. Metrics left "Not
// Defined" (X) in the vector are omitted.
type Breakdown struct {
	Base          []Section `json:"base"`
	Threat        []Metric  `json:"threat,omitempty"`
	Environmental []Metric  `json:"environmental,omitempty"`
	Supplemental  []Metric  `json:"supplemental,omitempty"`
}

// Sections flattens the breakdown into ordered sections, for renderers.
func (b *Breakdown) Sections() []Section {
	if b == nil {
		return nil
	}
	out := append([]Section{}, b.Base...)
	for _, extra := range []struct {
		title   string
		metrics []Metric
	}{
		{"Threat", b.Threat},
		{"Environmental", b.Environmental},
		{"Supplemental", b.Supplemental},
	} {
		if len(extra.metrics) > 0 {
			out = append(out, Section{Title: extra.title, Metrics: extra.metrics})
		}
	}
	return out
}

type metricDef struct {
	key    string
	name   string
	labels map[string]string
}

var (
	impactLabels         = map[string]string{"H": "High", "L": "Low", "N": "None"}
	modifiedImpactLabels = map[string]string{"H": "High", "L": "Low", "N": "None", "S": "Safety"}
	requirementLabels    = map[string]string{"H": "High", "M": "Medium", "L": "Low"}
	attackVectorLabels   = map[string]string{"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"}
	complexityLabels     = map[string]string{"L": "Low", "H": "High"}
	attackReqLabels      = map[string]string{"N": "None", "P": "Present"}
	privilegesLabels     = map[string]string{"N": "None", "L": "Low", "H": "High"}
	interactionLabels    = map[string]string{"N": "None", "P": "Passive", "A": "Active"}
)

var baseSections = []struct {
	title string
	defs  []metricDef
}{
	{"Exploitability", []metricDef{
		{"AV", "Attack Vector", attackVectorLabels},
		{"AC", "Attack Complexity", complexityLabels},
		{"AT", "Attack Requirements", attackReqLabels},
		{"PR", "Privileges Required", privilegesLabels},
		{"UI", "User Interaction", interactionLabels},
	}},
	{"Vulnerable System Impact", []metricDef{
		{"VC", "Confidentiality", impactLabels},
		{"VI", "Integrity", impactLabels},
		{"VA", "Availability", impactLabels},
	}},
	{"Subsequent System Impact", []metricDef{
		{"SC", "Confidentiality", impactLabels},
		{"SI", "Integrity", impactLabels},
		{"SA", "Availability", impactLabels},
	}},
}

var threatDefs = []metricDef{
	{"E", "Exploit Maturity", map[string]string{"A": "Attacked", "P": "Proof-of-Concept", "U": "Unreported"}},
}

var environmentalDefs = []metricDef{
	{"CR", "Confidentiality Requirement", requirementLabels},
	{"IR", "Integrity Requirement", requirementLabels},
	{"AR", "Availability Requirement", requirementLabels},
	{"MAV", "Modified Attack Vector", attackVectorLabels},
	{"MAC", "Modified Attack Complexity", complexityLabels},
	{"MAT", "Modified Attack Requirements", attackReqLabels},
	{"MPR", "Modified Privileges Required", privilegesLabels},
	{"MUI", "Modified User Interaction", interactionLabels},
	{"MVC", "Modified Vulnerable System Confidentiality", impactLabels},
	{"MVI", "Modified Vulnerable System Integrity", impactLabels},
	{"MVA", "Modified Vulnerable System Availability", impactLabels},
	{"MSC", "Modified Subsequent System Confidentiality", impactLabels},
	{"MSI", "Modified Subsequent System Integrity", modifiedImpactLabels},
	{"MSA", "Modified Subsequent System Availability", modifiedImpactLabels},
}

var supplementalDefs = []metricDef{
	{"S", "Safety", map[string]string{"N": "Negligible", "P": "Present"}},
	{"AU", "Automatable", map[string]string{"N": "No", "Y": "Yes"}},
	{"R", "Recovery", map[string]string{"A": "Automatic", "U": "User", "I": "Irrecoverable"}},
	{"V", "Value Density", map[string]string{"D": "Diffuse", "C": "Concentrated"}},
	{"RE", "Vulnerability Response Effort", map[string]string{"L": "Low", "M": "Moderate", "H": "High"}},
	{"U", "Provider Urgency", map[string]string{"Clear": "Clear", "Green": "Green", "Amber": "Amber", "Red": "Red"}},
}

// ParseV4 decodes one or more CVSS 4.0 vectors ("CVSS:4.0/AV:N/...") into a
// Breakdown. Later vectors override the metrics of earlier ones, so passing the
// base vector then the environmental vector yields the complete picture.
// Vectors that are empty or not CVSS 4.0 are ignored; nil is returned when no
// base metric could be decoded.
func ParseV4(vectors ...string) *Breakdown {
	values := map[string]string{}
	for _, vector := range vectors {
		parts := strings.Split(strings.TrimSpace(vector), "/")
		if len(parts) < 2 || !strings.EqualFold(parts[0], "CVSS:4.0") {
			continue
		}
		for _, p := range parts[1:] {
			k, v, ok := strings.Cut(p, ":")
			if ok && k != "" && v != "" {
				values[strings.ToUpper(k)] = v
			}
		}
	}

	b := &Breakdown{}
	for _, sec := range baseSections {
		if ms := decode(values, sec.defs); len(ms) > 0 {
			b.Base = append(b.Base, Section{Title: sec.title, Metrics: ms})
		}
	}
	if len(b.Base) == 0 {
		return nil
	}
	b.Threat = decode(values, threatDefs)
	b.Environmental = decode(values, environmentalDefs)
	b.Supplemental = decode(values, supplementalDefs)
	return b
}

// decode keeps the defined metrics in definition order. Unknown values are
// kept with the raw value as label rather than silently dropped.
func decode(values map[string]string, defs []metricDef) []Metric {
	var out []Metric
	for _, d := range defs {
		v, ok := values[d.key]
		if !ok || strings.EqualFold(v, "X") {
			continue
		}
		label, known := d.labels[v]
		if !known {
			label = v
		}
		out = append(out, Metric{Metric: d.key, Name: d.name, Value: v, Label: label})
	}
	return out
}
