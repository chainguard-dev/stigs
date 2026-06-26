package results

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Result is an XCCDF rule verdict. Its value comes only from the parsed results
// document, never from any process exit code: a scan that exits non-zero merely
// signals "some rule failed", which is itself derivable from the per-rule
// verdicts here.
type Result string

// The XCCDF 1.2 result vocabulary. These are the only values a <result> element
// may carry; any other text is a malformed document.
const (
	Pass          Result = "pass"
	Fail          Result = "fail"
	Error         Result = "error"
	Unknown       Result = "unknown"
	NotApplicable Result = "notapplicable"
	NotChecked    Result = "notchecked"
	NotSelected   Result = "notselected"
	Fixed         Result = "fixed"
	Informational Result = "informational"
)

// ErrMalformed is returned when the document cannot be parsed or carries a
// rule-result that is not well formed (missing idref or an out-of-vocabulary
// verdict). Callers should match with errors.Is.
var ErrMalformed = errors.New("malformed results document")

// vocabulary is the membership set used to reject unknown verdicts in O(1).
var vocabulary = map[Result]struct{}{
	Pass: {}, Fail: {}, Error: {}, Unknown: {}, NotApplicable: {},
	NotChecked: {}, NotSelected: {}, Fixed: {}, Informational: {},
}

// valid reports whether r is a member of the XCCDF result vocabulary.
func (r Result) valid() bool {
	_, ok := vocabulary[r]
	return ok
}

// Report is the parsed set of per-rule verdicts keyed by XCCDF rule idref.
type Report struct {
	byRule map[string]Result
}

// RuleResult returns the verdict for the rule identified by id and whether it
// was present in the document. A rule absent from the scan returns ok=false so
// callers can distinguish "not evaluated" from any specific verdict.
func (r Report) RuleResult(id string) (Result, bool) {
	v, ok := r.byRule[id]
	return v, ok
}

// ruleResult mirrors a single <rule-result idref="..."><result>..</result>
// element. The empty xmlns on the local names lets the decoder match the XCCDF
// namespace tolerantly via the streaming token walk below.
type ruleResult struct {
	IDRef  string `xml:"idref,attr"`
	Result string `xml:"result"`
}

// Parse reads an XCCDF results document from r and returns the per-rule
// verdicts. It walks the token stream so rule-result elements are found at any
// nesting depth (oscap nests TestResult inside Benchmark or a data-stream
// collection). A read error, malformed XML, a missing idref, or an
// out-of-vocabulary verdict yields a wrapped error.
func Parse(r io.Reader) (Report, error) {
	dec := xml.NewDecoder(r)
	byRule := make(map[string]Result)

	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return Report{}, fmt.Errorf("reading results document: %w", err)
		}

		start, ok := tok.(xml.StartElement)
		if !ok || start.Name.Local != "rule-result" {
			continue
		}

		var rr ruleResult
		if err := dec.DecodeElement(&rr, &start); err != nil {
			return Report{}, fmt.Errorf("decoding rule-result: %w", err)
		}

		idref := strings.TrimSpace(rr.IDRef)
		if idref == "" {
			return Report{}, fmt.Errorf("rule-result with empty idref: %w", ErrMalformed)
		}
		verdict := Result(strings.TrimSpace(rr.Result))
		if !verdict.valid() {
			return Report{}, fmt.Errorf("rule %q has unknown result %q: %w", idref, verdict, ErrMalformed)
		}
		byRule[idref] = verdict
	}

	return Report{byRule: byRule}, nil
}
