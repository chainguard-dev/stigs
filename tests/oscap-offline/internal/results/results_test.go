package results_test

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/chainguard-dev/stigs/tests/oscap-offline/internal/results"
)

const (
	rulePackageSignature = "xccdf_mil.disa.stig_rule_SV-203720r982212_rule"
	ruleRemoteAccess     = "xccdf_mil.disa.stig_rule_SV-263659r982563_rule"
)

func TestParseFiles(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		file      string
		wantErr   bool
		wantRules map[string]results.Result
		// absent rules: each must return ok=false.
		wantAbsent []string
	}{
		{
			name: "mixed results across rules",
			file: "testdata/mixed.xml",
			wantRules: map[string]results.Result{
				rulePackageSignature: results.Pass,
				ruleRemoteAccess:     results.Fail,
				"xccdf_mil.disa.stig_rule_SV-203591r958362_rule": results.NotApplicable,
				"xccdf_mil.disa.stig_rule_SV-203592r958364_rule": results.NotChecked,
				"xccdf_mil.disa.stig_rule_SV-203594r958388_rule": results.Error,
			},
			wantAbsent: []string{"xccdf_mil.disa.stig_rule_SV-000000r000000_rule"},
		},
		{
			name:       "single passing rule",
			file:       "testdata/minimal-pass.xml",
			wantRules:  map[string]results.Result{rulePackageSignature: results.Pass},
			wantAbsent: []string{ruleRemoteAccess},
		},
		{
			name:       "no rule results",
			file:       "testdata/empty.xml",
			wantRules:  map[string]results.Result{},
			wantAbsent: []string{rulePackageSignature},
		},
		{
			name:    "truncated document is a parse error",
			file:    "testdata/truncated.xml",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f, err := os.Open(tc.file)
			if err != nil {
				t.Fatalf("open %q: %v", tc.file, err)
			}
			t.Cleanup(func() { _ = f.Close() })

			report, err := results.Parse(f)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Parse(%q) = nil error, want error", tc.file)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse(%q) unexpected error: %v", tc.file, err)
			}

			for id, want := range tc.wantRules {
				got, ok := report.RuleResult(id)
				if !ok {
					t.Errorf("RuleResult(%q) ok=false, want present with %q", id, want)
					continue
				}
				if got != want {
					t.Errorf("RuleResult(%q) = %q, want %q", id, got, want)
				}
			}
			for _, id := range tc.wantAbsent {
				if got, ok := report.RuleResult(id); ok {
					t.Errorf("RuleResult(%q) ok=true (=%q), want absent", id, got)
				}
			}
		})
	}
}

// TestParseNestedRoot proves the parser finds rule-result elements regardless
// of the document's outer wrapper (real oscap emits a TestResult nested inside
// a Benchmark or data-stream-collection root).
func TestParseNestedRoot(t *testing.T) {
	t.Parallel()

	const doc = `<?xml version="1.0"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2">
  <TestResult id="t">
    <rule-result idref="rule-A"><result>pass</result></rule-result>
    <rule-result idref="rule-B"><result>fail</result></rule-result>
  </TestResult>
</Benchmark>`

	report, err := results.Parse(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("Parse nested: %v", err)
	}
	if got, ok := report.RuleResult("rule-A"); !ok || got != results.Pass {
		t.Errorf("rule-A = %q ok=%v, want pass true", got, ok)
	}
	if got, ok := report.RuleResult("rule-B"); !ok || got != results.Fail {
		t.Errorf("rule-B = %q ok=%v, want fail true", got, ok)
	}
}

// TestParseRejectsUnknownResult ensures a result value outside the XCCDF
// vocabulary is rejected rather than silently treated as a verdict.
func TestParseRejectsUnknownResult(t *testing.T) {
	t.Parallel()

	const doc = `<?xml version="1.0"?>
<TestResult xmlns="http://checklists.nist.gov/xccdf/1.2">
  <rule-result idref="rule-A"><result>definitely-not-valid</result></rule-result>
</TestResult>`

	if _, err := results.Parse(strings.NewReader(doc)); err == nil {
		t.Fatal("Parse accepted an out-of-vocabulary result; want error")
	}
}

// TestParseEmptyIdrefRejected ensures a rule-result without an idref is an
// error: a verdict with no rule to attach it to is meaningless.
func TestParseEmptyIdrefRejected(t *testing.T) {
	t.Parallel()

	const doc = `<?xml version="1.0"?>
<TestResult xmlns="http://checklists.nist.gov/xccdf/1.2">
  <rule-result><result>pass</result></rule-result>
</TestResult>`

	if _, err := results.Parse(strings.NewReader(doc)); err == nil {
		t.Fatal("Parse accepted a rule-result with empty idref; want error")
	}
}

func TestParseNilReaderIsError(t *testing.T) {
	t.Parallel()

	if _, err := results.Parse(errReader{}); err == nil {
		t.Fatal("Parse(errReader) = nil, want wrapped read error")
	}
}

// errReader always fails, standing in for a broken stream.
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("boom") }
