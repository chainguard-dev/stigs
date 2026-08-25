package mirrors

import (
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ovalDefinitionsElem is the root element of an OVAL check, both as a standalone
// file and as the child of a ds:extended-component in the datastream.
const ovalDefinitionsElem = "oval_definitions"

// metadataElem holds an entity's descriptive content, split out from the
// functional comparison.
const metadataElem = "metadata"

// sections whose children are the entities that decide a scan verdict.
// definitions is included for its criteria tree.
var sections = []string{"definitions", "tests", "objects", "states", "variables"}

// node is a namespace-resolved element. Decoding through encoding/xml resolves
// prefixes to namespace URIs in XMLName.Space, so a document that binds a
// namespace to a prefix compares equal to one that declares it as the default.
type node struct {
	XMLName  xml.Name
	Attrs    []xml.Attr `xml:",any,attr"`
	Text     string     `xml:",chardata"`
	Children []node     `xml:",any"`
}

// Doc is one parsed oval_definitions tree, reduced to per-entity canonical
// forms keyed by OVAL id.
type Doc struct {
	// DefinitionIDs identifies the document, and is what pairs a standalone
	// file with its embedded counterpart.
	DefinitionIDs []string
	// Functional and Metadata map an entity id to its canonical form.
	Functional map[string][]string
	Metadata   map[string][]string
	// DuplicateIDs lists entity ids seen more than once. Left to the caller to
	// report: silently keeping one and dropping the other would hide content.
	DuplicateIDs []string
}

// isNamespaceDecl reports whether attr declares a namespace rather than
// carrying content. Go surfaces `xmlns="..."` as {Space:"", Local:"xmlns"} and
// `xmlns:p="..."` as {Space:"xmlns", Local:"p"}.
func isNamespaceDecl(attr xml.Attr) bool {
	return attr.Name.Local == "xmlns" || attr.Name.Space == "xmlns" ||
		attr.Name.Space == "http://www.w3.org/2000/xmlns/"
}

// line renders one element as "path|attrs|text". The path is the chain of local
// names from the entity root, so a child that moves to a different parent reads
// as a difference rather than cancelling out.
func line(n node, path string) string {
	pairs := make([]string, 0, len(n.Attrs))
	for _, a := range n.Attrs {
		if isNamespaceDecl(a) {
			continue
		}
		name := a.Name.Local
		if a.Name.Space != "" {
			name = a.Name.Space + ":" + a.Name.Local
		}
		pairs = append(pairs, name+"="+a.Value)
	}
	sort.Strings(pairs)
	return fmt.Sprintf("%s|%s|%s", path, strings.Join(pairs, ";"), strings.TrimSpace(n.Text))
}

// canon walks one entity, preserving child order — which the OVAL schema
// constrains within an element — and skipping any subtree named in skip.
func canon(n node, path string, skip string, out *[]string) {
	if skip != "" && n.XMLName.Local == skip {
		return
	}
	*out = append(*out, line(n, path))
	for _, c := range n.Children {
		canon(c, path+"/"+c.XMLName.Local, skip, out)
	}
}

// findAll returns every descendant (and n itself) whose local name matches.
func findAll(n node, localName string) []node {
	var found []node
	if n.XMLName.Local == localName {
		found = append(found, n)
	}
	for _, c := range n.Children {
		found = append(found, findAll(c, localName)...)
	}
	return found
}

// parse reads one oval_definitions tree and reduces it to per-entity forms.
func parse(root node) *Doc {
	doc := &Doc{
		Functional: map[string][]string{},
		Metadata:   map[string][]string{},
	}
	for _, name := range sections {
		for _, section := range findAll(root, name) {
			for i, entity := range section.Children {
				key := attr(entity, "id")
				if key == "" {
					key = fmt.Sprintf("%s[%d]", name, i)
				}
				if _, seen := doc.Functional[key]; seen {
					doc.DuplicateIDs = append(doc.DuplicateIDs, key)
					continue
				}
				var functional []string
				canon(entity, entity.XMLName.Local, metadataElem, &functional)
				doc.Functional[key] = functional

				for _, meta := range entity.Children {
					if meta.XMLName.Local != metadataElem {
						continue
					}
					var descriptive []string
					canon(meta, meta.XMLName.Local, "", &descriptive)
					doc.Metadata[key] = descriptive
				}
			}
		}
	}
	for _, def := range findAll(root, "definition") {
		if id := attr(def, "id"); id != "" {
			doc.DefinitionIDs = append(doc.DefinitionIDs, id)
		}
	}
	sort.Strings(doc.DefinitionIDs)
	sort.Strings(doc.DuplicateIDs)
	return doc
}

func attr(n node, name string) string {
	for _, a := range n.Attrs {
		if a.Name.Local == name {
			return a.Value
		}
	}
	return ""
}

// Load parses a standalone OVAL check.
func Load(r io.Reader) (*Doc, error) {
	var root node
	if err := xml.NewDecoder(r).Decode(&root); err != nil {
		return nil, fmt.Errorf("decoding OVAL document: %w", err)
	}
	if root.XMLName.Local != ovalDefinitionsElem {
		// A standalone file may in principle be wrapped; take the first
		// oval_definitions found rather than assuming it is the root.
		found := findAll(root, ovalDefinitionsElem)
		if len(found) == 0 {
			return nil, fmt.Errorf("no %s element found", ovalDefinitionsElem)
		}
		root = found[0]
	}
	return parse(root), nil
}

// LoadDatastream parses every oval_definitions block embedded in a datastream,
// keyed by the joined definition ids that identify each block.
func LoadDatastream(r io.Reader) (map[string]*Doc, error) {
	var root node
	if err := xml.NewDecoder(r).Decode(&root); err != nil {
		return nil, fmt.Errorf("decoding datastream: %w", err)
	}
	blocks := map[string]*Doc{}
	for _, block := range findAll(root, ovalDefinitionsElem) {
		doc := parse(block)
		blocks[strings.Join(doc.DefinitionIDs, ",")] = doc
	}
	if len(blocks) == 0 {
		return nil, fmt.Errorf("no %s blocks found in datastream", ovalDefinitionsElem)
	}
	return blocks, nil
}

// Finding is one difference between a standalone file and its embedded copy.
type Finding struct {
	// File is the standalone file's base name.
	File string
	// Entity is the OVAL id the difference is in, empty when the finding is
	// about the file as a whole.
	Entity string
	// Detail says what differs, quoting both sides where there are two.
	Detail string
}

func (f Finding) String() string {
	if f.Entity == "" {
		return fmt.Sprintf("%s: %s", f.File, f.Detail)
	}
	return fmt.Sprintf("%s: %s: %s", f.File, f.Entity, f.Detail)
}

// diff compares two entity maps, naming the entity in every finding.
func diff(file string, a, b map[string][]string) []Finding {
	var out []Finding
	for _, key := range sortedKeys(a) {
		if _, ok := b[key]; !ok {
			out = append(out, Finding{file, key, "present in the standalone file only"})
		}
	}
	for _, key := range sortedKeys(b) {
		if _, ok := a[key]; !ok {
			out = append(out, Finding{file, key, "present in the datastream only"})
		}
	}
	for _, key := range sortedKeys(a) {
		want, ok := b[key]
		if !ok {
			continue
		}
		got := a[key]
		if equal(got, want) {
			continue
		}
		out = append(out, Finding{file, key, firstDifference(got, want)})
	}
	return out
}

// firstDifference quotes the first line that differs, so a finding points at
// the change rather than merely asserting one exists.
func firstDifference(standalone, datastream []string) string {
	n := max(len(standalone), len(datastream))
	for i := range n {
		s, d := "(absent)", "(absent)"
		if i < len(standalone) {
			s = standalone[i]
		}
		if i < len(datastream) {
			d = datastream[i]
		}
		if s != d {
			return fmt.Sprintf("differs\n        standalone : %s\n        datastream : %s", s, d)
		}
	}
	return "differs"
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func sortedKeys(m map[string][]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Report is the outcome of comparing a whole repository.
type Report struct {
	// Functional differences would change a scan verdict.
	Functional []Finding
	// Descriptive differences would not.
	Descriptive []Finding
	// Checked counts the standalone files paired with an embedded block.
	Checked int
	// Unmirrored lists definitions embedded in the datastream with no
	// standalone file: they cannot be evaluated with `oscap oval eval`, and
	// regeneration has no input for them.
	Unmirrored []string
}

// Check compares every standalone OVAL file in standaloneDir against its copy
// in the datastream at datastreamPath.
func Check(datastreamPath, standaloneDir string) (*Report, error) {
	dsFile, err := os.Open(datastreamPath) //nolint:gosec // repo content, not external input
	if err != nil {
		return nil, fmt.Errorf("opening datastream: %w", err)
	}
	defer dsFile.Close()

	blocks, err := LoadDatastream(dsFile)
	if err != nil {
		return nil, err
	}

	paths, err := filepath.Glob(filepath.Join(standaloneDir, "*.xml"))
	if err != nil {
		return nil, fmt.Errorf("globbing %s: %w", standaloneDir, err)
	}
	sort.Strings(paths)

	report := &Report{}
	matched := map[string]bool{}

	for _, path := range paths {
		name := filepath.Base(path)
		f, err := os.Open(path) //nolint:gosec // repo content, not external input
		if err != nil {
			return nil, fmt.Errorf("opening %s: %w", name, err)
		}
		doc, err := Load(f)
		f.Close()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}

		key := strings.Join(doc.DefinitionIDs, ",")
		emb, ok := blocks[key]
		if !ok {
			ids := key
			if ids == "" {
				ids = "(no definitions)"
			}
			report.Functional = append(report.Functional, Finding{
				File:   name,
				Detail: fmt.Sprintf("no datastream block defines %s — the standalone check has no counterpart", ids),
			})
			continue
		}
		matched[key] = true
		report.Checked++

		for where, dups := range map[string][]string{name: doc.DuplicateIDs, "the datastream": emb.DuplicateIDs} {
			if len(dups) > 0 {
				report.Functional = append(report.Functional, Finding{
					File:   name,
					Detail: fmt.Sprintf("duplicate entity id(s) in %s: %s", where, strings.Join(dups, ", ")),
				})
			}
		}

		report.Functional = append(report.Functional, diff(name, doc.Functional, emb.Functional)...)
		report.Descriptive = append(report.Descriptive, diff(name, doc.Metadata, emb.Metadata)...)
	}

	for key := range blocks {
		if key == "" || matched[key] {
			continue
		}
		report.Unmirrored = append(report.Unmirrored, key)
	}
	sort.Strings(report.Unmirrored)

	return report, nil
}
