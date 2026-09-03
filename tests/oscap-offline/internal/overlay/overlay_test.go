package overlay

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"math/rand/v2"
	"os"
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// fileSpec describes a single tar entry used to build a base tar in tests.
type fileSpec struct {
	content []byte
	mode    int64
	uid     int
	gid     int
}

// buildTar produces a deterministic base tar (entries written in sorted path
// order) from the given specs. It lives in the test file only.
func buildTar(t *testing.T, files map[string]fileSpec) []byte {
	t.Helper()

	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, p := range paths {
		f := files[p]
		hdr := &tar.Header{
			Name:     p,
			Typeflag: tar.TypeReg,
			Mode:     f.mode,
			Uid:      f.uid,
			Gid:      f.gid,
			Size:     int64(len(f.content)),
			Format:   tar.FormatPAX,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("writing header for %q: %v", p, err)
		}
		if _, err := tw.Write(f.content); err != nil {
			t.Fatalf("writing content for %q: %v", p, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("closing base tar: %v", err)
	}
	return buf.Bytes()
}

// readEntries reads a tar into an ordered slice of name and a map for lookup.
func readEntries(t *testing.T, b []byte) (order []string, byName map[string]fileSpec) {
	t.Helper()

	byName = make(map[string]fileSpec)
	tr := tar.NewReader(bytes.NewReader(b))
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("reading output tar: %v", err)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("reading entry %q: %v", hdr.Name, err)
		}
		order = append(order, hdr.Name)
		byName[hdr.Name] = fileSpec{
			content: data,
			mode:    hdr.Mode,
			uid:     hdr.Uid,
			gid:     hdr.Gid,
		}
	}
	return order, byName
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(rand.IntN(256))
	}
	return b
}

func apply(t *testing.T, base []byte, ops ...Op) []byte {
	t.Helper()
	var out bytes.Buffer
	if err := Apply(bytes.NewReader(base), ops, &out); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	return out.Bytes()
}

func TestAppendFile(t *testing.T) {
	t.Parallel()

	baseContent := randBytes(40)
	extra := randBytes(40)
	base := buildTar(t, map[string]fileSpec{
		"var/log/app": {content: baseContent, mode: 0o644, uid: 0, gid: 0},
	})

	got := apply(t, base, AppendFile("var/log/app", extra))
	_, byName := readEntries(t, got)

	want := append(append([]byte{}, baseContent...), extra...)
	if diff := cmp.Diff(want, byName["var/log/app"].content); diff != "" {
		t.Errorf("appended content mismatch (-want,+got):\n%s", diff)
	}
}

func TestAddFile(t *testing.T) {
	t.Parallel()

	base := buildTar(t, map[string]fileSpec{
		"etc/existing": {content: []byte("x"), mode: 0o644, uid: 0, gid: 0},
	})

	content := randBytes(32)
	mode := int64(0o600)
	uid := rand.IntN(60000) + 1
	gid := rand.IntN(60000) + 1

	got := apply(t, base, AddFile("etc/new", content, mode, uid, gid))
	order, byName := readEntries(t, got)

	want := fileSpec{content: content, mode: mode, uid: uid, gid: gid}
	if diff := cmp.Diff(want, byName["etc/new"], cmp.AllowUnexported(fileSpec{})); diff != "" {
		t.Errorf("etc/new mismatch (-want,+got):\n%s", diff)
	}
	// added entry comes after base entries
	if diff := cmp.Diff([]string{"etc/existing", "etc/new"}, order); diff != "" {
		t.Errorf("order mismatch (-want,+got):\n%s", diff)
	}
}

// TestAppendFileRejectsNonRegular proves AppendFile on a base member that is not
// a regular file (here a directory) returns a wrapped ErrNotRegular rather than
// letting Apply fail later with a tar write error.
func TestAppendFileRejectsNonRegular(t *testing.T) {
	t.Parallel()

	base := buildRawTar(t,
		tar.Header{Name: "etc/", Typeflag: tar.TypeDir, Mode: 0o755},
	)
	var out bytes.Buffer
	err := Apply(bytes.NewReader(base), []Op{AppendFile("etc/", []byte("x"))}, &out)
	if !errors.Is(err, ErrNotRegular) {
		t.Fatalf("Apply error = %v, want errors.Is ErrNotRegular", err)
	}
}

// TestCopyFile proves the destination reproduces the source's content, mode and
// ownership byte for byte, that the source survives untouched, and that the copy
// reflects an earlier op that mutated the source (ops run in declaration order).
func TestCopyFile(t *testing.T) {
	t.Parallel()

	content := randBytes(48)
	extra := randBytes(16)
	base := buildTar(t, map[string]fileSpec{
		"etc/bundle": {content: content, mode: 0o600, uid: 11, gid: 13},
	})

	got := apply(t, base,
		AppendFile("etc/bundle", extra),
		CopyFile("etc/bundle", "kaniko/bundle"),
	)
	order, byName := readEntries(t, got)

	want := fileSpec{content: append(append([]byte{}, content...), extra...), mode: 0o600, uid: 11, gid: 13}
	if diff := cmp.Diff(want, byName["kaniko/bundle"], cmp.AllowUnexported(fileSpec{})); diff != "" {
		t.Errorf("copy mismatch (-want,+got):\n%s", diff)
	}
	if diff := cmp.Diff(want, byName["etc/bundle"], cmp.AllowUnexported(fileSpec{})); diff != "" {
		t.Errorf("source mutated by copy (-want,+got):\n%s", diff)
	}
	if diff := cmp.Diff([]string{"etc/bundle", "kaniko/bundle"}, order); diff != "" {
		t.Errorf("order mismatch (-want,+got):\n%s", diff)
	}
}

// TestCopyFileRejectsNonRegular proves CopyFile reading a base member that is
// not a regular file (here a directory) returns a wrapped ErrNotRegular, the
// same failure mode AppendFile has, rather than producing a bogus entry.
func TestCopyFileRejectsNonRegular(t *testing.T) {
	t.Parallel()

	base := buildRawTar(t,
		tar.Header{Name: "etc/", Typeflag: tar.TypeDir, Mode: 0o755},
	)
	var out bytes.Buffer
	err := Apply(bytes.NewReader(base), []Op{CopyFile("etc/", "kaniko/etc")}, &out)
	if !errors.Is(err, ErrNotRegular) {
		t.Fatalf("Apply error = %v, want errors.Is ErrNotRegular", err)
	}
}

func TestReplaceFile(t *testing.T) {
	t.Parallel()

	base := buildTar(t, map[string]fileSpec{
		"etc/f": {content: randBytes(40), mode: 0o444, uid: 3, gid: 5},
	})

	content := randBytes(12)
	got := apply(t, base, ReplaceFile("etc/f", content))
	_, byName := readEntries(t, got)

	want := fileSpec{content: content, mode: 0o444, uid: 3, gid: 5}
	if diff := cmp.Diff(want, byName["etc/f"], cmp.AllowUnexported(fileSpec{})); diff != "" {
		t.Errorf("ReplaceFile changed more than content (-want,+got):\n%s", diff)
	}
}

func TestRemoveFile(t *testing.T) {
	t.Parallel()

	base := buildTar(t, map[string]fileSpec{
		"etc/keep": {content: []byte("k"), mode: 0o644, uid: 0, gid: 0},
		"etc/drop": {content: []byte("d"), mode: 0o644, uid: 0, gid: 0},
	})

	got := apply(t, base, RemoveFile("etc/drop"))
	order, _ := readEntries(t, got)

	if diff := cmp.Diff([]string{"etc/keep"}, order); diff != "" {
		t.Errorf("order mismatch after RemoveFile (-want,+got):\n%s", diff)
	}
}

// TestReplaceAndRemoveMissingPath proves both ops surface ErrNotFound for a
// path absent from the base rather than silently no-op'ing.
func TestReplaceAndRemoveMissingPath(t *testing.T) {
	t.Parallel()

	base := buildTar(t, map[string]fileSpec{
		"etc/f": {content: []byte("x"), mode: 0o644, uid: 0, gid: 0},
	})

	for name, op := range map[string]Op{
		"ReplaceFile": ReplaceFile("etc/missing", []byte("y")),
		"RemoveFile":  RemoveFile("etc/missing"),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var out bytes.Buffer
			if err := Apply(bytes.NewReader(base), []Op{op}, &out); !errors.Is(err, ErrNotFound) {
				t.Fatalf("Apply error = %v, want errors.Is ErrNotFound", err)
			}
		})
	}
}

func TestChown(t *testing.T) {
	t.Parallel()

	content := randBytes(16)
	base := buildTar(t, map[string]fileSpec{
		"etc/f": {content: content, mode: 0o644, uid: 7, gid: 9},
	})

	newUID := rand.IntN(60000) + 1
	newGID := rand.IntN(60000) + 1
	got := apply(t, base, Chown("etc/f", newUID, newGID))
	_, byName := readEntries(t, got)

	want := fileSpec{content: content, mode: 0o644, uid: newUID, gid: newGID}
	if diff := cmp.Diff(want, byName["etc/f"], cmp.AllowUnexported(fileSpec{})); diff != "" {
		t.Errorf("Chown changed more than uid/gid (-want,+got):\n%s", diff)
	}
}

// TestBasePreservedINV4 asserts that any path untouched by ops is byte- and
// header-identical to the base entry.
func TestBasePreservedINV4(t *testing.T) {
	t.Parallel()

	untouched := fileSpec{content: randBytes(50), mode: 0o644, uid: 11, gid: 13}
	base := buildTar(t, map[string]fileSpec{
		"etc/untouched": untouched,
		"etc/touched":   {content: []byte("before"), mode: 0o644, uid: 0, gid: 0},
	})

	got := apply(t, base, AppendFile("etc/touched", []byte("-after")), Chown("etc/touched", 1, 1))
	_, byName := readEntries(t, got)

	if diff := cmp.Diff(untouched, byName["etc/untouched"], cmp.AllowUnexported(fileSpec{})); diff != "" {
		t.Errorf("untouched entry not preserved (-want,+got):\n%s", diff)
	}
}

// TestRootOwnershipINV3 asserts that declaring root ownership yields uid==0 &&
// gid==0 in the output header even though the test runs as a non-root user.
func TestRootOwnershipINV3(t *testing.T) {
	t.Parallel()

	if os.Geteuid() == 0 {
		t.Logf("note: test process is running as root (euid=0); invariant still asserted")
	} else {
		t.Logf("note: test process euid=%d (non-root); root ownership is declared, not inherited", os.Geteuid())
	}

	base := buildTar(t, map[string]fileSpec{
		"etc/shadow": {content: []byte("user-owned"), mode: 0o644, uid: 1000, gid: 1000},
	})

	got := apply(t, base,
		AddFile("etc/root-owned", []byte("secret"), 0o600, 0, 0),
		Chown("etc/shadow", 0, 0),
	)

	tr := tar.NewReader(bytes.NewReader(got))
	seen := map[string]*tar.Header{}
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("reading output: %v", err)
		}
		seen[hdr.Name] = hdr
	}

	for _, name := range []string{"etc/root-owned", "etc/shadow"} {
		hdr := seen[name]
		if hdr == nil {
			t.Fatalf("missing entry %q", name)
		}
		if hdr.Uid != 0 || hdr.Gid != 0 {
			t.Errorf("%q: got uid=%d gid=%d, want uid=0 gid=0", name, hdr.Uid, hdr.Gid)
		}
	}
}

func TestApplyErrors(t *testing.T) {
	t.Parallel()

	base := buildTar(t, map[string]fileSpec{
		"etc/present": {content: []byte("x"), mode: 0o644, uid: 0, gid: 0},
	})

	tests := []struct {
		name string
		op   Op
	}{
		{"append missing path", AppendFile("etc/absent", []byte("y"))},
		{"chown missing path", Chown("etc/absent", 1, 1)},
		{"add existing path", AddFile("etc/present", []byte("y"), 0o644, 0, 0)},
		{"copy missing source", CopyFile("etc/absent", "etc/copy")},
		{"copy onto existing path", CopyFile("etc/present", "etc/present")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var out bytes.Buffer
			err := Apply(bytes.NewReader(base), []Op{tt.op}, &out)
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !errors.Is(err, ErrNotFound) && !errors.Is(err, ErrExists) {
				t.Errorf("error %v is neither ErrNotFound nor ErrExists", err)
			}
		})
	}
}

// buildRawTar writes headers verbatim so tests can inject members with
// arbitrary typeflags and link names (symlinks, dirs) that the regular-file
// helper cannot express.
func buildRawTar(t *testing.T, hdrs ...tar.Header) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for i := range hdrs {
		h := hdrs[i]
		if err := tw.WriteHeader(&h); err != nil {
			t.Fatalf("writing header %q: %v", h.Name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("closing tar: %v", err)
	}
	return buf.Bytes()
}

// TestApplyRejectsUnsafeBaseMembers proves that a base tar carrying a non-local
// member name causes Apply to fail with a wrapped ErrUnsafePath, guaranteeing
// every produced fixture tar is safe by construction.
func TestApplyRejectsUnsafeBaseMembers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		hdr  tar.Header
	}{
		{"dotdot member", tar.Header{Name: "../escape", Typeflag: tar.TypeReg, Mode: 0o644}},
		{"absolute member", tar.Header{Name: "/etc/passwd", Typeflag: tar.TypeReg, Mode: 0o644}},
		{"deep dotdot member", tar.Header{Name: "a/b/../../../escape", Typeflag: tar.TypeReg, Mode: 0o644}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			base := buildRawTar(t, tt.hdr)
			var out bytes.Buffer
			err := Apply(bytes.NewReader(base), nil, &out)
			if !errors.Is(err, ErrUnsafePath) {
				t.Fatalf("Apply error = %v, want errors.Is ErrUnsafePath", err)
			}
		})
	}
}

// TestApplyRejectsUnsafeAddedMembers proves that AddFile with a non-local path
// is rejected with a wrapped ErrUnsafePath rather than emitted into the fixture.
func TestApplyRejectsUnsafeAddedMembers(t *testing.T) {
	t.Parallel()

	base := buildTar(t, map[string]fileSpec{
		"etc/present": {content: []byte("x"), mode: 0o644, uid: 0, gid: 0},
	})
	tests := []struct {
		name string
		path string
	}{
		{"dotdot added", "../escape"},
		{"absolute added", "/etc/passwd"},
		{"nul added", "evil\x00.txt"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var out bytes.Buffer
			err := Apply(bytes.NewReader(base), []Op{AddFile(tt.path, []byte("y"), 0o644, 0, 0)}, &out)
			if !errors.Is(err, ErrUnsafePath) {
				t.Fatalf("Apply error = %v, want errors.Is ErrUnsafePath", err)
			}
		})
	}
}

// TestApplyAllowsLegitimateMembers proves the validation does not reject
// well-formed nested paths or legitimate relative symlinks that wolfi-style
// base images contain.
func TestApplyAllowsLegitimateMembers(t *testing.T) {
	t.Parallel()

	base := buildRawTar(t,
		tar.Header{Name: "usr/lib/libc.so.6", Typeflag: tar.TypeReg, Mode: 0o755},
		tar.Header{Name: "usr/lib/libc.so", Typeflag: tar.TypeSymlink, Linkname: "libc.so.6", Mode: 0o777},
		tar.Header{Name: "bin/sh", Typeflag: tar.TypeSymlink, Linkname: "../usr/bin/busybox", Mode: 0o777},
		tar.Header{Name: "etc/", Typeflag: tar.TypeDir, Mode: 0o755},
	)
	var out bytes.Buffer
	if err := Apply(bytes.NewReader(base), nil, &out); err != nil {
		t.Fatalf("Apply rejected legitimate base members: %v", err)
	}
	// The relative symlink survives into the output unchanged.
	tr := tar.NewReader(&out)
	links := map[string]string{}
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("reading output: %v", err)
		}
		if h.Typeflag == tar.TypeSymlink {
			links[h.Name] = h.Linkname
		}
	}
	if got := links["usr/lib/libc.so"]; got != "libc.so.6" {
		t.Errorf("symlink usr/lib/libc.so target = %q, want %q", got, "libc.so.6")
	}
	if got := links["bin/sh"]; got != "../usr/bin/busybox" {
		t.Errorf("symlink bin/sh target = %q, want %q", got, "../usr/bin/busybox")
	}
}

func TestApplyMalformedBase(t *testing.T) {
	t.Parallel()

	// Random bytes are not a valid tar archive.
	var out bytes.Buffer
	err := Apply(bytes.NewReader(randBytes(512)), nil, &out)
	if err == nil {
		t.Fatalf("expected error for malformed base tar, got nil")
	}
}

func TestApplyNoOps(t *testing.T) {
	t.Parallel()

	base := buildTar(t, map[string]fileSpec{
		"etc/a": {content: randBytes(20), mode: 0o644, uid: 5, gid: 6},
		"etc/b": {content: randBytes(20), mode: 0o600, uid: 7, gid: 8},
	})

	got := apply(t, base)
	_, wantByName := readEntries(t, base)
	_, gotByName := readEntries(t, got)

	if diff := cmp.Diff(wantByName, gotByName, cmp.AllowUnexported(fileSpec{})); diff != "" {
		t.Errorf("no-op Apply changed entries (-want,+got):\n%s", diff)
	}
}

// TestPutFile covers both directions of the upsert, plus the property that
// motivated it: the same op works whether or not the base ships the path, so a
// fixture stops depending on that and stops breaking when the base is re-pinned.
func TestPutFile(t *testing.T) {
	t.Parallel()

	content := []byte("fips = yes\n")

	t.Run("replaces an existing file and keeps its header", func(t *testing.T) {
		t.Parallel()
		base := buildTar(t, map[string]fileSpec{
			"etc/ssl/openssl.cnf": {content: randBytes(40), mode: 0o444, uid: 7, gid: 9},
		})
		got := apply(t, base, PutFile("etc/ssl/openssl.cnf", content, 0o600, 0, 0))
		_, byName := readEntries(t, got)
		// mode/uid/gid come from the existing entry, not the PutFile arguments.
		want := fileSpec{content: content, mode: 0o444, uid: 7, gid: 9}
		if diff := cmp.Diff(want, byName["etc/ssl/openssl.cnf"], cmp.AllowUnexported(fileSpec{})); diff != "" {
			t.Errorf("PutFile over an existing entry (-want,+got):\n%s", diff)
		}
	})

	t.Run("adds the file when the base does not have it", func(t *testing.T) {
		t.Parallel()
		base := buildTar(t, map[string]fileSpec{
			"etc/other": {content: []byte("x"), mode: 0o644, uid: 0, gid: 0},
		})
		got := apply(t, base, PutFile("etc/ssl/openssl.cnf", content, 0o600, 3, 4))
		_, byName := readEntries(t, got)
		want := fileSpec{content: content, mode: 0o600, uid: 3, gid: 4}
		if diff := cmp.Diff(want, byName["etc/ssl/openssl.cnf"], cmp.AllowUnexported(fileSpec{})); diff != "" {
			t.Errorf("PutFile creating an entry (-want,+got):\n%s", diff)
		}
	})

	t.Run("same op succeeds against both bases", func(t *testing.T) {
		t.Parallel()
		// The regression this exists for: AddFile fails on the with-file base
		// and ReplaceFile fails on the without-file one, so neither can express
		// a fixture that must survive the base gaining or losing the path.
		withFile := buildTar(t, map[string]fileSpec{
			"etc/ssl/openssl.cnf": {content: []byte("old"), mode: 0o644, uid: 0, gid: 0},
		})
		without := buildTar(t, map[string]fileSpec{
			"etc/keep": {content: []byte("k"), mode: 0o644, uid: 0, gid: 0},
		})
		for name, base := range map[string][]byte{"base has the file": withFile, "base lacks it": without} {
			var out bytes.Buffer
			if err := Apply(bytes.NewReader(base), []Op{PutFile("etc/ssl/openssl.cnf", content, 0o644, 0, 0)}, &out); err != nil {
				t.Errorf("%s: Apply = %v, want nil", name, err)
			}
		}
	})

	t.Run("rejects an unsafe path", func(t *testing.T) {
		t.Parallel()
		base := buildTar(t, map[string]fileSpec{
			"etc/keep": {content: []byte("k"), mode: 0o644, uid: 0, gid: 0},
		})
		var out bytes.Buffer
		if err := Apply(bytes.NewReader(base), []Op{PutFile("../escape", content, 0o644, 0, 0)}, &out); !errors.Is(err, ErrUnsafePath) {
			t.Fatalf("Apply error = %v, want errors.Is ErrUnsafePath", err)
		}
	})
}

// TestPutFileIsDeterministic pins the property that makes fixtures reproducible:
// the same ops over the same base produce byte-identical output, and applying
// PutFile twice is indistinguishable from applying it once. Apply never mutates
// its input, so nothing carries between runs — but that is worth asserting
// rather than assuming, since the matrix shares one immutable base across every
// subtest and a mutation would leak everywhere at once.
func TestPutFileIsDeterministic(t *testing.T) {
	t.Parallel()

	base := buildTar(t, map[string]fileSpec{
		"etc/ssl/openssl.cnf": {content: []byte("original"), mode: 0o644, uid: 0, gid: 0},
		"etc/keep":            {content: []byte("k"), mode: 0o644, uid: 0, gid: 0},
	})
	content := []byte("fips = yes\n")

	once := apply(t, base, PutFile("etc/ssl/openssl.cnf", content, 0o600, 1, 2))
	again := apply(t, base, PutFile("etc/ssl/openssl.cnf", content, 0o600, 1, 2))
	if !bytes.Equal(once, again) {
		t.Errorf("same ops over the same base produced different output: %d vs %d bytes", len(once), len(again))
	}

	twice := apply(t, base,
		PutFile("etc/ssl/openssl.cnf", content, 0o600, 1, 2),
		PutFile("etc/ssl/openssl.cnf", content, 0o600, 1, 2),
	)
	if !bytes.Equal(once, twice) {
		t.Errorf("applying PutFile twice differed from applying it once: %d vs %d bytes", len(once), len(twice))
	}

	// The base bytes must be untouched, or the shared base would drift across subtests.
	pristine := buildTar(t, map[string]fileSpec{
		"etc/ssl/openssl.cnf": {content: []byte("original"), mode: 0o644, uid: 0, gid: 0},
		"etc/keep":            {content: []byte("k"), mode: 0o644, uid: 0, gid: 0},
	})
	if !bytes.Equal(base, pristine) {
		t.Error("Apply mutated the base tar it was given")
	}
}
