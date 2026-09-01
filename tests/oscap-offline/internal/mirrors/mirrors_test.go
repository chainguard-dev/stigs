package mirrors_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chainguard-dev/stigs/tests/oscap-offline/internal/mirrors"
)

const (
	ovalNS        = "http://oval.mitre.org/XMLSchema/oval-definitions-5"
	independentNS = ovalNS + "#independent"
)

// block renders an oval_definitions document with one definition, one test and
// one object. The knobs are the properties the comparison is meant to be
// sensitive (pattern) or insensitive (source is metadata, prefixed changes only
// how namespaces are written) to.
type block struct {
	pattern  string
	source   string
	prefixed bool // bind the independent namespace to a prefix instead of redeclaring it as the default
	extraID  string
	dupChild bool
	movedPat bool
}

func render(b block) string {
	if b.pattern == "" {
		b.pattern = "^P:(openssh)$"
	}
	if b.source == "" {
		b.source = "Custom"
	}

	indOpen, rootAttrs := ` xmlns="`+independentNS+`"`, ""
	testOpen, testClose := "textfilecontent54_test", "textfilecontent54_test"
	objOpen, objClose := "textfilecontent54_object", "textfilecontent54_object"
	if b.prefixed {
		// Same meaning, written the other way: prefix on the elements and the
		// binding on the root. This is how the datastream writes it while the
		// standalone files redeclare the default namespace inline.
		indOpen = ""
		rootAttrs = ` xmlns:ind="` + independentNS + `"`
		testOpen, testClose = "ind:textfilecontent54_test", "ind:textfilecontent54_test"
		objOpen, objClose = "ind:textfilecontent54_object", "ind:textfilecontent54_object"
	}

	dup := ""
	if b.dupChild {
		dup = "\n      <instance datatype=\"int\">1</instance>"
	}

	patternLine := `      <pattern operation="pattern match">` + b.pattern + `</pattern>`
	secondObject := ""
	if b.movedPat {
		// The pattern relocated into a second object: the same nodes exist, but
		// under a different parent.
		patternLine = ""
		secondObject = "\n    <" + objOpen + indOpen + ` id="oval:org.Example:obj:2" version="1">` + "\n" +
			`      <pattern operation="pattern match">` + b.pattern + `</pattern>` + "\n" +
			"    </" + objClose + ">"
	}

	extraTest := ""
	if b.extraID != "" {
		extraTest = "\n    <" + testOpen + indOpen +
			` id="oval:org.Example:tst:` + b.extraID + `" version="1" check="all" check_existence="none_exist">` + "\n" +
			`      <object object_ref="oval:org.Example:obj:1"/>` + "\n" +
			"    </" + testClose + ">"
	}

	return `<?xml version="1.0"?>
<oval_definitions xmlns="` + ovalNS + `"` + rootAttrs + `>
  <definitions>
    <definition id="oval:org.Example:def:1" version="1" class="compliance">
      <metadata>
        <title>Example</title>
        <reference source="` + b.source + `"/>
      </metadata>
      <criteria>
        <criterion test_ref="oval:org.Example:tst:1" comment="c"/>
      </criteria>
    </definition>
  </definitions>
  <tests>
    <` + testOpen + indOpen + ` id="oval:org.Example:tst:1" version="1" check="all" check_existence="none_exist">
      <object object_ref="oval:org.Example:obj:1"/>
    </` + testClose + `>` + extraTest + `
  </tests>
  <objects>
    <` + objOpen + indOpen + ` id="oval:org.Example:obj:1" version="1">
      <path>/lib/apk/db</path>
      <filename>installed</filename>
` + patternLine + `
      <instance datatype="int">1</instance>` + dup + `
    </` + objClose + `>` + secondObject + `
  </objects>
</oval_definitions>`
}

// swapTests moves the second test ahead of the first without changing either.
// Sibling order is schema-valid either way and changes no verdict.
func swapTests(doc string) string {
	one := `    <textfilecontent54_test xmlns="` + independentNS + `" id="oval:org.Example:tst:1" version="1" check="all" check_existence="none_exist">
      <object object_ref="oval:org.Example:obj:1"/>
    </textfilecontent54_test>`
	two := `    <textfilecontent54_test xmlns="` + independentNS + `" id="oval:org.Example:tst:2" version="1" check="all" check_existence="none_exist">
      <object object_ref="oval:org.Example:obj:1"/>
    </textfilecontent54_test>`
	if !strings.Contains(doc, one) || !strings.Contains(doc, two) {
		panic("swapTests: fixture shape changed; both tests must be present verbatim")
	}
	return strings.Replace(strings.Replace(doc, one+"\n"+two, "@@", 1), "@@", two+"\n"+one, 1)
}

// writeRepo lays out a miniature repository: one standalone file plus a
// datastream embedding the given blocks.
func writeRepo(t *testing.T, standalone map[string]string, embedded []string) (dsPath, dir string) {
	t.Helper()
	root := t.TempDir()
	dir = filepath.Join(root, "OvalDefinitions")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("creating %s: %v", dir, err)
	}
	for name, content := range standalone {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}
	var sb strings.Builder
	sb.WriteString(`<?xml version="1.0"?>` + "\n" +
		`<ds:data-stream-collection xmlns:ds="http://scap.nist.gov/schema/scap/source/1.2">`)
	for i, b := range embedded {
		sb.WriteString("\n<ds:extended-component id=\"c" + string(rune('a'+i)) + "\">\n")
		// Strip each block's XML declaration; only the outer document may carry one.
		sb.WriteString(strings.TrimPrefix(b, `<?xml version="1.0"?>`+"\n"))
		sb.WriteString("\n</ds:extended-component>")
	}
	sb.WriteString("\n</ds:data-stream-collection>\n")

	dsPath = filepath.Join(root, "ds.xml")
	if err := os.WriteFile(dsPath, []byte(sb.String()), 0o600); err != nil {
		t.Fatalf("writing datastream: %v", err)
	}
	return dsPath, dir
}

func TestCheck(t *testing.T) {
	t.Parallel()

	same := render(block{})

	cases := []struct {
		name string
		// standalone content and the blocks embedded in the datastream
		standalone string
		embedded   []string
		// wantFunctional differences change a scan verdict; wantDescriptive do not
		wantFunctional  int
		wantDescriptive int
	}{
		{
			name:       "identical copies produce no findings",
			standalone: same, embedded: []string{same},
		},
		{
			name:       "a pattern that differs is a functional difference",
			standalone: same, embedded: []string{render(block{pattern: "^P:(openssh|openssh-sftp-server)$"})},
			wantFunctional: 1,
		},
		{
			name:       "a reference source that differs is descriptive only",
			standalone: same, embedded: []string{render(block{source: "CIS"})},
			wantDescriptive: 1,
		},
		{
			name:       "functional and descriptive differences are reported separately",
			standalone: same, embedded: []string{render(block{pattern: "^P:(other)$", source: "CIS"})},
			wantFunctional: 1, wantDescriptive: 1,
		},
		{
			name:           "a standalone file with no counterpart is a functional difference",
			standalone:     same,
			embedded:       []string{strings.ReplaceAll(same, "oval:org.Example", "oval:org.Other")},
			wantFunctional: 1,
		},
		// The three cases below pin properties an earlier implementation of this
		// comparison got wrong by flattening both copies into one ordered list
		// of nodes: sibling order counted as drift, and permutations reported no
		// locatable detail.
		{
			name:       "sibling entities in a different order are not a difference",
			standalone: render(block{extraID: "2"}),
			embedded:   []string{swapTests(render(block{extraID: "2"}))},
		},
		{
			name:       "an element duplicated inside an entity is a functional difference",
			standalone: render(block{dupChild: true}), embedded: []string{same},
			wantFunctional: 1,
		},
		{
			name:       "an element relocated to another entity is a functional difference",
			standalone: same, embedded: []string{render(block{movedPat: true})},
			// Twice over, and rightly so: a second object appears, and the first
			// loses the child that moved out of it.
			wantFunctional: 2,
		},
		// Namespaces are written differently in the two copies in the real
		// repository: the standalone files redeclare the independent namespace as
		// the default on each element, the datastream binds it to a prefix. Go
		// surfaces namespace declarations as ordinary attributes, so this is
		// exactly where a port of this comparison breaks.
		{
			name:       "a namespace written by prefix rather than default is not a difference",
			standalone: same, embedded: []string{render(block{prefixed: true})},
		},
		{
			name:       "an entity present in only one copy is a functional difference",
			standalone: render(block{extraID: "2"}), embedded: []string{same},
			wantFunctional: 1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dsPath, dir := writeRepo(t, map[string]string{"Example.xml": tc.standalone}, tc.embedded)
			report, err := mirrors.Check(dsPath, dir)
			if err != nil {
				t.Fatalf("Check: %v", err)
			}
			if len(report.Functional) != tc.wantFunctional || len(report.Descriptive) != tc.wantDescriptive {
				t.Fatalf("want functional=%d descriptive=%d, got functional=%d descriptive=%d\nfunctional: %v\ndescriptive: %v",
					tc.wantFunctional, tc.wantDescriptive,
					len(report.Functional), len(report.Descriptive),
					report.Functional, report.Descriptive)
			}
		})
	}
}

// TestFindingNamesEntityAndBothValues guards legibility. A finding that says
// only "these differ" is close to useless: the earlier implementation could
// report a difference while identifying neither the entity nor the values.
func TestFindingNamesEntityAndBothValues(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name       string
		standalone string
		embedded   string
	}{
		{
			name:       "a changed value",
			standalone: render(block{pattern: "^P:(openssh)$"}),
			embedded:   render(block{pattern: "^P:(other)$"}),
		},
		{
			// A pure count change: the case that previously printed no detail.
			name:       "a duplicated child",
			standalone: render(block{dupChild: true}),
			embedded:   render(block{}),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dsPath, dir := writeRepo(t, map[string]string{"Example.xml": tc.standalone}, []string{tc.embedded})
			report, err := mirrors.Check(dsPath, dir)
			if err != nil {
				t.Fatalf("Check: %v", err)
			}
			if len(report.Functional) == 0 {
				t.Fatalf("no functional difference reported for %s", tc.name)
			}
			got := report.Functional[0].String()
			if !strings.Contains(got, "oval:org.Example:obj:1") {
				t.Errorf("finding does not name the entity:\n%s", got)
			}
			if !strings.Contains(got, "standalone :") || !strings.Contains(got, "datastream :") {
				t.Errorf("finding does not show both values:\n%s", got)
			}
		})
	}
}

// TestUnmirroredDefinitionsReported covers definitions embedded in the
// datastream with no standalone file: they cannot be evaluated with
// `oscap oval eval` and regeneration has no input for them, so they are
// surfaced rather than ignored.
func TestUnmirroredDefinitionsReported(t *testing.T) {
	t.Parallel()

	only := strings.ReplaceAll(render(block{}), "oval:org.Example", "oval:org.Only")
	dsPath, dir := writeRepo(t, map[string]string{"Example.xml": render(block{})},
		[]string{render(block{}), only})

	report, err := mirrors.Check(dsPath, dir)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(report.Functional) != 0 {
		t.Fatalf("unexpected functional differences: %v", report.Functional)
	}
	want := []string{"oval:org.Only:def:1"}
	if len(report.Unmirrored) != 1 || report.Unmirrored[0] != want[0] {
		t.Fatalf("want unmirrored %v, got %v", want, report.Unmirrored)
	}
}

// TestCheckedZeroIsDetectable ensures a run that compared nothing is
// distinguishable from a clean one, so a path or glob mistake cannot read as
// success.
func TestCheckedZeroIsDetectable(t *testing.T) {
	t.Parallel()

	dsPath, dir := writeRepo(t, map[string]string{}, []string{render(block{})})
	report, err := mirrors.Check(dsPath, dir)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if report.Checked != 0 {
		t.Fatalf("want Checked=0, got %d", report.Checked)
	}
}

// TestDatastreamWithoutOVALIsAnError distinguishes a malformed datastream from
// a clean comparison. Reporting per-file "no counterpart" findings for a
// datastream that contains no OVAL at all would point at the wrong problem.
func TestDatastreamWithoutOVALIsAnError(t *testing.T) {
	t.Parallel()

	dsPath, dir := writeRepo(t, map[string]string{"Example.xml": render(block{})}, nil)
	if _, err := mirrors.Check(dsPath, dir); err == nil {
		t.Fatal("want an error for a datastream containing no oval_definitions, got nil")
	}
}

// repoPaths walks up from the test's working directory to the repository root
// and returns the datastream path and the standalone check directory.
func repoPaths(t *testing.T) (dsPath, dir string) {
	t.Helper()
	const (
		relDatastream = "gpos/xml/scap/ssg/content/ssg-chainguard-gpos-ds.xml"
		relStandalone = "gpos/xml/scap/ssg/content/ssg-chainguard-xccdf/OvalDefinitions"
	)
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for d := cwd; ; d = filepath.Dir(d) {
		candidate := filepath.Join(d, relDatastream)
		if _, err := os.Stat(candidate); err == nil {
			return candidate, filepath.Join(d, relStandalone)
		}
		if filepath.Dir(d) == d {
			t.Fatalf("no %s found in any parent of %s", relDatastream, cwd)
		}
	}
}

// TestRepositoryMirrorsMatch is the assertion that guards the repository: every
// standalone OVAL check must match the copy of it embedded in the datastream.
//
// A functional difference fails. A descriptive one is logged, because the two
// copies disagree today on a <reference source> that changes no verdict, and
// failing on that would mean disabling this test rather than fixing content.
func TestRepositoryMirrorsMatch(t *testing.T) {
	t.Parallel()

	dsPath, dir := repoPaths(t)
	report, err := mirrors.Check(dsPath, dir)
	if err != nil {
		t.Fatalf("comparing %s against %s: %v", dir, dsPath, err)
	}

	for _, f := range report.Functional {
		t.Errorf("functional difference: %s", f)
	}
	// Descriptive differences fail too, now that the two copies agree on all of
	// them. They were logged rather than failed while five embedded blocks still
	// carried a <reference source> of "CIS" against the standalone files'
	// "Custom" — a difference that changes no verdict, so failing on it would
	// have meant disabling this test instead of fixing content. The content is
	// fixed, so the gate closes behind it.
	for _, f := range report.Descriptive {
		t.Errorf("descriptive difference: %s", f)
	}

	// A run that paired nothing would otherwise read as success.
	if report.Checked == 0 {
		t.Fatalf("no standalone OVAL files were compared against %s", dsPath)
	}
	t.Logf("compared %d standalone OVAL file(s) against the datastream", report.Checked)

	for _, ids := range report.Unmirrored {
		t.Logf("present only in the datastream, so not evaluable with `oscap oval eval` "+
			"and with no input for regeneration: %s", ids)
	}
}
