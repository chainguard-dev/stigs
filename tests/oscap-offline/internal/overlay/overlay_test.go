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
