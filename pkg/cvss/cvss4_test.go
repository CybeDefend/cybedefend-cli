package cvss

import "testing"

const prodEnvVector = "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:P/CR:H/IR:H/AR:M/MAV:N/MAC:X/MAT:N/MPR:X/MUI:X/MVC:X/MVI:X/MVA:X/MSC:X/MSI:X/MSA:X"

func metric(ms []Metric, key string) *Metric {
	for i := range ms {
		if ms[i].Metric == key {
			return &ms[i]
		}
	}
	return nil
}

func TestParseV4_DecodesBaseThreatAndEnvironmental(t *testing.T) {
	b := ParseV4(prodEnvVector)
	if b == nil {
		t.Fatal("expected a breakdown")
	}
	if len(b.Base) != 3 || b.Base[0].Title != "Exploitability" || b.Base[1].Title != "Vulnerable System Impact" || b.Base[2].Title != "Subsequent System Impact" {
		t.Fatalf("unexpected base sections: %+v", b.Base)
	}
	if m := metric(b.Base[0].Metrics, "AV"); m == nil || m.Label != "Network" || m.Value != "N" || m.Name != "Attack Vector" {
		t.Errorf("AV = %+v, want Network", m)
	}
	if m := metric(b.Base[0].Metrics, "AC"); m == nil || m.Label != "High" {
		t.Errorf("AC = %+v, want High", m)
	}
	if m := metric(b.Base[1].Metrics, "VC"); m == nil || m.Label != "High" {
		t.Errorf("VC = %+v, want High", m)
	}
	if m := metric(b.Base[2].Metrics, "SA"); m == nil || m.Label != "None" {
		t.Errorf("SA = %+v, want None", m)
	}
	if m := metric(b.Threat, "E"); m == nil || m.Label != "Proof-of-Concept" {
		t.Errorf("E = %+v, want Proof-of-Concept", m)
	}

	// Only the defined environmental metrics are kept, in vector order.
	var envKeys []string
	for _, m := range b.Environmental {
		envKeys = append(envKeys, m.Metric+":"+m.Value)
	}
	want := "CR:H IR:H AR:M MAV:N MAT:N"
	if got := joinSpace(envKeys); got != want {
		t.Errorf("environmental = %q, want %q", got, want)
	}
	if m := metric(b.Environmental, "AR"); m.Label != "Medium" {
		t.Errorf("AR label = %q, want Medium", m.Label)
	}
	if len(b.Supplemental) != 0 {
		t.Errorf("supplemental should be empty when all X, got %+v", b.Supplemental)
	}
}

func TestParseV4_MergesBaseThenEnvironmentalVector(t *testing.T) {
	base := "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
	env := "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N/CR:L/MAV:N"
	b := ParseV4(base, env)
	if b == nil {
		t.Fatal("expected a breakdown")
	}
	if m := metric(b.Base[0].Metrics, "AV"); m.Label != "Local" {
		t.Errorf("AV = %q, want Local", m.Label)
	}
	if m := metric(b.Environmental, "MAV"); m == nil || m.Label != "Network" {
		t.Errorf("MAV = %+v, want Network from the environmental vector", m)
	}
	if m := metric(b.Environmental, "CR"); m == nil || m.Label != "Low" {
		t.Errorf("CR = %+v, want Low", m)
	}
}

func TestParseV4_IgnoresNonV4AndEmptyVectors(t *testing.T) {
	if b := ParseV4("", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"); b != nil {
		t.Errorf("expected nil for non-4.0 vectors, got %+v", b)
	}
	if b := ParseV4("CVSS:4.0/E:P"); b != nil {
		t.Errorf("expected nil when no base metric is present, got %+v", b)
	}
	if b := ParseV4("cvss:4.0/av:n"); b == nil || metric(b.Base[0].Metrics, "AV") == nil {
		t.Errorf("metric keys should be case-insensitive, got %+v", b)
	}
}

func TestSections_AppendsExtraGroupsWhenPresent(t *testing.T) {
	b := ParseV4(prodEnvVector)
	secs := b.Sections()
	if len(secs) != 5 || secs[3].Title != "Threat" || secs[4].Title != "Environmental" {
		t.Errorf("unexpected sections: %+v", secs)
	}
	var nilB *Breakdown
	if nilB.Sections() != nil {
		t.Error("nil breakdown must yield nil sections")
	}
}

func joinSpace(ss []string) string {
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += " "
		}
		out += s
	}
	return out
}
