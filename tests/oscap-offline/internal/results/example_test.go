package results_test

import (
	"fmt"
	"strings"

	"github.com/chainguard-dev/stigs/tests/oscap-offline/internal/results"
)

// ExampleParse parses a small results document and reads two rule verdicts.
func ExampleParse() {
	const doc = `<?xml version="1.0"?>
<TestResult xmlns="http://checklists.nist.gov/xccdf/1.2">
  <rule-result idref="rule-A"><result>pass</result></rule-result>
  <rule-result idref="rule-B"><result>fail</result></rule-result>
</TestResult>`

	report, err := results.Parse(strings.NewReader(doc))
	if err != nil {
		fmt.Println("parse:", err)
		return
	}

	a, _ := report.RuleResult("rule-A")
	b, _ := report.RuleResult("rule-B")
	fmt.Printf("rule-A=%s\n", a)
	fmt.Printf("rule-B=%s\n", b)
	// Output:
	// rule-A=pass
	// rule-B=fail
}

// ExampleReport_RuleResult shows that a rule absent from the scan returns
// ok=false, distinct from any specific verdict.
func ExampleReport_RuleResult() {
	report, err := results.Parse(strings.NewReader(
		`<TestResult xmlns="http://checklists.nist.gov/xccdf/1.2"></TestResult>`))
	if err != nil {
		fmt.Println("parse:", err)
		return
	}

	_, ok := report.RuleResult("rule-never-evaluated")
	fmt.Println("present:", ok)
	// Output:
	// present: false
}
