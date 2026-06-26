// Package results parses an OpenSCAP XCCDF results document into per-rule
// verdicts keyed by rule idref.
//
// Parse walks the document's token stream so rule-result elements are found at
// any nesting depth, tolerating the several wrappers oscap may emit (a bare
// TestResult, a Benchmark, or a data-stream collection). Each verdict is
// validated against the XCCDF 1.2 result vocabulary; an out-of-vocabulary
// value or a rule-result missing its idref is reported as a malformed
// document rather than silently accepted.
//
// A rule's verdict comes only from the parsed document, never from the
// scanner's process exit code. A scan that exits non-zero merely signals
// "some rule failed", which is itself derivable from the per-rule verdicts
// here, so the parser is deliberately independent of exit status.
package results
