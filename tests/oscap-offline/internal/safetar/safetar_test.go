package safetar

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// canaryDir creates a sibling directory next to dest holding a single file that
// no extraction should ever touch. It returns the canary file's absolute path
// and its original content so callers can assert it is unchanged.
func canaryDir(t *testing.T) (canaryFile string, want []byte) {
	t.Helper()
	dir := t.TempDir()
	canaryFile = filepath.Join(dir, "canary.txt")
	want = []byte("do-not-touch")
	if err := os.WriteFile(canaryFile, want, 0o600); err != nil {
		t.Fatalf("seeding canary: %v", err)
	}
	return canaryFile, want
}

// assertCanary fails if the canary file's content changed.
func assertCanary(t *testing.T, canaryFile string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(canaryFile)
	if err != nil {
		t.Fatalf("reading canary %q: %v", canaryFile, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("canary %q was modified: got %q want %q", canaryFile, got, want)
	}
}

// tarEntry describes one member to write into an in-memory adversarial tar.
type tarEntry struct {
	hdr  tar.Header
	body []byte
}

// buildTar serializes entries into a tar byte stream. Sizes are derived from
// the body so callers cannot accidentally desynchronize header and content.
func buildTar(t testing.TB, entries ...tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		hdr := e.hdr
		if hdr.Typeflag == tar.TypeReg {
			hdr.Size = int64(len(e.body))
		}
		if err := tw.WriteHeader(&hdr); err != nil {
			t.Fatalf("writing header %q: %v", hdr.Name, err)
		}
		if len(e.body) > 0 {
			if _, err := tw.Write(e.body); err != nil {
				t.Fatalf("writing body %q: %v", hdr.Name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("closing tar: %v", err)
	}
	return buf.Bytes()
}

func reg(name string, body []byte) tarEntry {
	return tarEntry{hdr: tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644}, body: body}
}

func dir(name string) tarEntry {
	return tarEntry{hdr: tar.Header{Name: name, Typeflag: tar.TypeDir, Mode: 0o755}}
}

func symlink(name, target string) tarEntry {
	return tarEntry{hdr: tar.Header{Name: name, Typeflag: tar.TypeSymlink, Linkname: target, Mode: 0o777}}
}

func hardlink(name, target string) tarEntry {
	return tarEntry{hdr: tar.Header{Name: name, Typeflag: tar.TypeLink, Linkname: target, Mode: 0o644}}
}

// extractInto runs Extract over data into a fresh dest within the temp tree and
// returns dest plus the resulting error.
func extractInto(t *testing.T, data []byte, opts Options) (dest string, err error) {
	t.Helper()
	dest = t.TempDir()
	return dest, Extract(t.Context(), bytes.NewReader(data), dest, opts)
}

func TestExtractTraversal(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr error
		// safeRel, when set, must exist under dest after extraction.
		safeRel string
		// escapeAbs, when set, is an absolute path that must NOT exist after.
		escapeAbs string
	}{
		{
			name:    "dotdot in name is rejected",
			data:    buildTar(t, reg("../escape.txt", []byte("x"))),
			wantErr: ErrUnsafePath,
		},
		{
			name:    "deep dotdot in name is rejected",
			data:    buildTar(t, reg("a/b/../../../escape.txt", []byte("x"))),
			wantErr: ErrUnsafePath,
		},
		{
			name:      "absolute name confined under dest",
			data:      buildTar(t, reg("/etc/passwd", []byte("rooted"))),
			safeRel:   "etc/passwd",
			escapeAbs: "/etc/passwd-safetar-canary-should-never-exist",
		},
		{
			name:    "empty name skipped",
			data:    buildTar(t, tarEntry{hdr: tar.Header{Name: "", Typeflag: tar.TypeReg, Mode: 0o644}}),
			wantErr: nil,
		},
		{
			name:    "dot name skipped",
			data:    buildTar(t, tarEntry{hdr: tar.Header{Name: ".", Typeflag: tar.TypeDir, Mode: 0o755}}),
			wantErr: nil,
		},
		{
			name:    "overlong component rejected",
			data:    buildTar(t, reg(strings.Repeat("a", 256)+"/x", []byte("x"))),
			wantErr: ErrUnsafePath,
		},
		{
			name:    "trailing slash file normalized to dir then file under it",
			data:    buildTar(t, dir("sub/"), reg("sub/x", []byte("ok"))),
			safeRel: "sub/x",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dest, err := extractInto(t, tt.data, DefaultOptions())
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("Extract error = %v, want errors.Is %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Extract unexpected error: %v", err)
			}
			if tt.safeRel != "" {
				if _, statErr := os.Stat(filepath.Join(dest, tt.safeRel)); statErr != nil {
					t.Fatalf("expected safe file %q under dest: %v", tt.safeRel, statErr)
				}
			}
			if tt.escapeAbs != "" {
				if _, statErr := os.Stat(tt.escapeAbs); statErr == nil {
					t.Fatalf("escape path %q was created outside dest", tt.escapeAbs)
				}
			}
		})
	}
}

// TestCleanName exercises the lexical name defense directly because some hostile
// names (embedded NUL, backslashes) cannot be encoded by archive/tar.Writer and
// so cannot reach Extract through a writer-built stream. cleanName is the single
// gate every member name passes through, so testing it covers the real defense.
func TestCleanName(t *testing.T) {
	tests := []struct {
		name      string
		raw       string
		wantClean string
		wantDec   decision
	}{
		{"simple relative", "etc/passwd", "etc/passwd", decisionWrite},
		{"nested relative", "a/b/c.txt", "a/b/c.txt", decisionWrite},
		{"leading slash confined", "/etc/passwd", "etc/passwd", decisionWrite},
		{"dot prefix stripped", "./a.txt", "a.txt", decisionWrite},
		{"empty skipped", "", "", decisionSkip},
		{"dot itself skipped", ".", "", decisionSkip},
		{"root slash skipped", "/", "", decisionSkip},
		{"dotdot rejected", "../escape", "", decisionReject},
		{"deep dotdot rejected", "a/../../escape", "", decisionReject},
		{"embedded NUL rejected", "evil\x00.txt", "", decisionReject},
		{"backslash rejected", "a\\b", "", decisionReject},
		{"overlong component rejected", strings.Repeat("a", 256), "", decisionReject},
		{"max-len component allowed", strings.Repeat("a", 255), strings.Repeat("a", 255), decisionWrite},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotClean, gotDec := cleanName(tt.raw)
			if gotDec != tt.wantDec {
				t.Fatalf("cleanName(%q) decision = %v, want %v (clean=%q)", tt.raw, gotDec, tt.wantDec, gotClean)
			}
			if gotClean != tt.wantClean {
				t.Fatalf("cleanName(%q) clean = %q, want %q", tt.raw, gotClean, tt.wantClean)
			}
		})
	}
}

func TestExtractSymlinkEscape(t *testing.T) {
	canaryFile, want := canaryDir(t)
	canaryRoot := filepath.Dir(canaryFile)

	// evil -> absolute path to the canary's parent, then evil/x tries to write
	// into it. os.Root must refuse to traverse the symlink out of dest.
	data := buildTar(t,
		symlink("evil", canaryRoot),
		reg("evil/pwned.txt", []byte("escaped")),
	)
	dest, err := extractInto(t, data, DefaultOptions())
	// The follow-on write must fail (or be confined); it must never write into
	// canaryRoot.
	if err == nil {
		t.Logf("Extract returned nil; verifying confinement instead")
	}
	if _, statErr := os.Stat(filepath.Join(canaryRoot, "pwned.txt")); statErr == nil {
		t.Fatalf("symlink escape wrote pwned.txt into %q", canaryRoot)
	}
	_ = dest
	assertCanary(t, canaryFile, want)
}

func TestExtractSymlinkTargets(t *testing.T) {
	tests := []struct {
		name    string
		entry   tarEntry
		wantErr error
	}{
		{
			name:    "absolute symlink target rejected",
			entry:   symlink("link", "/etc/passwd"),
			wantErr: ErrUnsafeLink,
		},
		{
			name:    "dotdot symlink target rejected",
			entry:   symlink("link", "../../../etc/passwd"),
			wantErr: ErrUnsafeLink,
		},
		{
			name:    "dotdot escaping deep symlink target rejected",
			entry:   symlink("a/b/link", "../../../../escape"),
			wantErr: ErrUnsafeLink,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			canaryFile, want := canaryDir(t)
			_, err := extractInto(t, buildTar(t, tt.entry), DefaultOptions())
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Extract error = %v, want errors.Is %v", err, tt.wantErr)
			}
			assertCanary(t, canaryFile, want)
		})
	}
}

func TestExtractRelativeSymlinkAllowed(t *testing.T) {
	// A legitimate relative symlink that stays within root must succeed.
	data := buildTar(t,
		reg("real.txt", []byte("content")),
		symlink("alias.txt", "real.txt"),
	)
	dest, err := extractInto(t, data, DefaultOptions())
	if err != nil {
		t.Fatalf("Extract rejected a safe relative symlink: %v", err)
	}
	got, err := os.Readlink(filepath.Join(dest, "alias.txt"))
	if err != nil {
		t.Fatalf("reading link: %v", err)
	}
	if got != "real.txt" {
		t.Fatalf("link target = %q, want %q", got, "real.txt")
	}
}

func TestExtractAbsoluteSymlinkOptIn(t *testing.T) {
	// A container rootfs (e.g. wolfi-base busybox applets) legitimately holds
	// absolute symlinks like usr/bin/[ -> /bin/busybox. With the opt-in enabled,
	// the link is materialized verbatim; os.Root still refuses to *follow* it out
	// of root on any later operation, so confinement is preserved.
	data := buildTar(t, symlink("usr/bin/[", "/bin/busybox"))

	t.Run("rejected by default", func(t *testing.T) {
		canaryFile, want := canaryDir(t)
		if _, err := extractInto(t, data, DefaultOptions()); !errors.Is(err, ErrUnsafeLink) {
			t.Fatalf("Extract error = %v, want errors.Is %v", err, ErrUnsafeLink)
		}
		assertCanary(t, canaryFile, want)
	})

	t.Run("allowed when opted in", func(t *testing.T) {
		opts := DefaultOptions()
		opts.AllowAbsoluteSymlinks = true
		dest, err := extractInto(t, data, opts)
		if err != nil {
			t.Fatalf("Extract rejected an opted-in absolute symlink: %v", err)
		}
		got, err := os.Readlink(filepath.Join(dest, "usr/bin/["))
		if err != nil {
			t.Fatalf("reading link: %v", err)
		}
		if got != "/bin/busybox" {
			t.Fatalf("link target = %q, want %q", got, "/bin/busybox")
		}
	})

	t.Run("dotdot escape still rejected when opted in", func(t *testing.T) {
		canaryFile, want := canaryDir(t)
		opts := DefaultOptions()
		opts.AllowAbsoluteSymlinks = true
		if _, err := extractInto(t, buildTar(t, symlink("link", "../../escape")), opts); !errors.Is(err, ErrUnsafeLink) {
			t.Fatalf("Extract error = %v, want errors.Is %v (opt-in must not allow .. escape)", err, ErrUnsafeLink)
		}
		assertCanary(t, canaryFile, want)
	})
}

func TestExtractSymlinksDisabled(t *testing.T) {
	opts := DefaultOptions()
	opts.AllowSymlinks = false
	data := buildTar(t, symlink("alias.txt", "real.txt"))
	dest, err := extractInto(t, data, opts)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if _, statErr := os.Lstat(filepath.Join(dest, "alias.txt")); statErr == nil {
		t.Fatalf("symlink materialized despite AllowSymlinks=false")
	}
}

func TestExtractHardlink(t *testing.T) {
	t.Run("hardlink to existing in-root file allowed", func(t *testing.T) {
		data := buildTar(t,
			reg("real.txt", []byte("content")),
			hardlink("link.txt", "real.txt"),
		)
		dest, err := extractInto(t, data, DefaultOptions())
		if err != nil {
			t.Fatalf("Extract: %v", err)
		}
		got, err := os.ReadFile(filepath.Join(dest, "link.txt"))
		if err != nil {
			t.Fatalf("reading hardlink: %v", err)
		}
		if string(got) != "content" {
			t.Fatalf("hardlink content = %q, want %q", got, "content")
		}
	})

	t.Run("hardlink to absent target rejected", func(t *testing.T) {
		canaryFile, want := canaryDir(t)
		_, err := extractInto(t, buildTar(t, hardlink("link.txt", "missing.txt")), DefaultOptions())
		if !errors.Is(err, ErrUnsafeLink) {
			t.Fatalf("Extract error = %v, want errors.Is %v", err, ErrUnsafeLink)
		}
		assertCanary(t, canaryFile, want)
	})

	t.Run("hardlink with absolute target rejected", func(t *testing.T) {
		canaryFile, want := canaryDir(t)
		_, err := extractInto(t, buildTar(t, hardlink("link.txt", "/etc/passwd")), DefaultOptions())
		if !errors.Is(err, ErrUnsafeLink) {
			t.Fatalf("Extract error = %v, want errors.Is %v", err, ErrUnsafeLink)
		}
		assertCanary(t, canaryFile, want)
	})

	t.Run("hardlink with dotdot target rejected", func(t *testing.T) {
		canaryFile, want := canaryDir(t)
		_, err := extractInto(t, buildTar(t, hardlink("link.txt", "../../escape")), DefaultOptions())
		if !errors.Is(err, ErrUnsafeLink) {
			t.Fatalf("Extract error = %v, want errors.Is %v", err, ErrUnsafeLink)
		}
		assertCanary(t, canaryFile, want)
	})
}

func TestExtractDeviceNodes(t *testing.T) {
	devices := []struct {
		name     string
		typeflag byte
	}{
		{"char device", tar.TypeChar},
		{"block device", tar.TypeBlock},
		{"fifo", tar.TypeFifo},
	}
	for _, d := range devices {
		t.Run(d.name+" skipped by default", func(t *testing.T) {
			data := buildTar(t, tarEntry{hdr: tar.Header{Name: "dev/node", Typeflag: d.typeflag, Mode: 0o644}})
			dest, err := extractInto(t, data, DefaultOptions())
			if err != nil {
				t.Fatalf("Extract: %v", err)
			}
			if _, statErr := os.Lstat(filepath.Join(dest, "dev/node")); statErr == nil {
				t.Fatalf("device node was materialized; it must never be created")
			}
		})
		t.Run(d.name+" rejected when configured", func(t *testing.T) {
			opts := DefaultOptions()
			opts.RejectUnsupported = true
			data := buildTar(t, tarEntry{hdr: tar.Header{Name: "dev/node", Typeflag: d.typeflag, Mode: 0o644}})
			_, err := extractInto(t, data, opts)
			if !errors.Is(err, ErrUnsupportedEntry) {
				t.Fatalf("Extract error = %v, want errors.Is %v", err, ErrUnsupportedEntry)
			}
		})
	}
}

func TestExtractLimits(t *testing.T) {
	t.Run("max entries exceeded", func(t *testing.T) {
		opts := DefaultOptions()
		opts.Limits = Limits{MaxEntries: 2, MaxTotalBytes: 1 << 20, MaxFileBytes: 1 << 20}
		data := buildTar(t, reg("a", []byte("1")), reg("b", []byte("2")), reg("c", []byte("3")))
		_, err := extractInto(t, data, opts)
		if !errors.Is(err, ErrLimitExceeded) {
			t.Fatalf("Extract error = %v, want errors.Is %v", err, ErrLimitExceeded)
		}
	})

	t.Run("max file bytes exceeded", func(t *testing.T) {
		opts := DefaultOptions()
		opts.Limits = Limits{MaxEntries: 100, MaxTotalBytes: 1 << 20, MaxFileBytes: 4}
		data := buildTar(t, reg("big", []byte("toolarge")))
		dest, err := extractInto(t, data, opts)
		if !errors.Is(err, ErrLimitExceeded) {
			t.Fatalf("Extract error = %v, want errors.Is %v", err, ErrLimitExceeded)
		}
		// Partial write must not have escaped dest; only dest may hold it.
		if _, statErr := os.Stat(filepath.Join(dest, "..", "big")); statErr == nil {
			t.Fatalf("partial write escaped dest")
		}
	})

	t.Run("max total bytes exceeded", func(t *testing.T) {
		opts := DefaultOptions()
		opts.Limits = Limits{MaxEntries: 100, MaxTotalBytes: 6, MaxFileBytes: 1 << 20}
		data := buildTar(t, reg("a", []byte("aaaa")), reg("b", []byte("bbbb")))
		_, err := extractInto(t, data, opts)
		if !errors.Is(err, ErrLimitExceeded) {
			t.Fatalf("Extract error = %v, want errors.Is %v", err, ErrLimitExceeded)
		}
	})
}

func TestExtractModeBits(t *testing.T) {
	t.Run("setuid setgid masked by default", func(t *testing.T) {
		// 0o4755 = setuid + rwxr-xr-x
		data := buildTar(t, tarEntry{hdr: tar.Header{Name: "bin", Typeflag: tar.TypeReg, Mode: 0o4755}, body: []byte("x")})
		dest, err := extractInto(t, data, DefaultOptions())
		if err != nil {
			t.Fatalf("Extract: %v", err)
		}
		info, err := os.Stat(filepath.Join(dest, "bin"))
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if info.Mode()&os.ModeSetuid != 0 || info.Mode()&os.ModeSetgid != 0 {
			t.Fatalf("setuid/setgid bits not masked: mode=%v", info.Mode())
		}
		if perm := info.Mode().Perm(); perm != 0o755 {
			t.Fatalf("ordinary perms not preserved: got %o want %o", perm, 0o755)
		}
	})

	t.Run("setuid preserved when allowed", func(t *testing.T) {
		opts := DefaultOptions()
		opts.PreserveSetID = true
		data := buildTar(t, tarEntry{hdr: tar.Header{Name: "bin", Typeflag: tar.TypeReg, Mode: 0o4755}, body: []byte("x")})
		dest, err := extractInto(t, data, opts)
		if err != nil {
			t.Fatalf("Extract: %v", err)
		}
		info, err := os.Stat(filepath.Join(dest, "bin"))
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if info.Mode()&os.ModeSetuid == 0 {
			t.Fatalf("setuid bit not preserved despite PreserveSetID: mode=%v", info.Mode())
		}
	})

	// With both PreserveSetID and PreserveOwnership on, the chown must not strip
	// the preserved setuid bit. chown(2) clears set-id on a regular file, so an
	// ownership-after-mode order would silently drop it; ownership must precede
	// the final chmod. Ownership uses the current uid/gid so the chown succeeds
	// unprivileged.
	t.Run("setuid survives chown when ownership preserved", func(t *testing.T) {
		uid, gid := os.Getuid(), os.Getgid()
		opts := DefaultOptions()
		opts.PreserveSetID = true
		opts.PreserveOwnership = true
		data := buildTar(t, regOwnedMode("bin", []byte("x"), 0o4755, uid, gid))
		dest, err := extractInto(t, data, opts)
		if err != nil {
			t.Fatalf("Extract: %v", err)
		}
		info, err := os.Stat(filepath.Join(dest, "bin"))
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if info.Mode()&os.ModeSetuid == 0 {
			t.Fatalf("setuid bit stripped by chown: mode=%v", info.Mode())
		}
		gotUID, gotGID := statOwner(t, dest, "bin")
		if gotUID != uid || gotGID != gid {
			t.Fatalf("ownership = %d:%d, want %d:%d", gotUID, gotGID, uid, gid)
		}
	})
}

// TestExtractRegularReplacesSymlink proves a regular-file member replaces an
// existing in-root symlink at the same name rather than following it and
// clobbering the link's target. The link points at another in-root file that
// must be left untouched.
func TestExtractRegularReplacesSymlink(t *testing.T) {
	data := buildTar(t,
		reg("b", []byte("original-b")),
		symlink("a", "b"),
		reg("a", []byte("payload-a")),
	)
	dest, err := extractInto(t, data, DefaultOptions())
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}

	// a must be a regular file (not a symlink) carrying its own payload.
	fi, err := os.Lstat(filepath.Join(dest, "a"))
	if err != nil {
		t.Fatalf("lstat a: %v", err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("a is still a symlink; regular member did not replace it")
	}
	gotA, err := os.ReadFile(filepath.Join(dest, "a"))
	if err != nil {
		t.Fatalf("reading a: %v", err)
	}
	if string(gotA) != "payload-a" {
		t.Fatalf("a content = %q, want %q", gotA, "payload-a")
	}

	// b must be unchanged: the write must not have followed a -> b.
	gotB, err := os.ReadFile(filepath.Join(dest, "b"))
	if err != nil {
		t.Fatalf("reading b: %v", err)
	}
	if string(gotB) != "original-b" {
		t.Fatalf("b content = %q, want %q (write followed the symlink)", gotB, "original-b")
	}
}

func TestExtractDirsAndParents(t *testing.T) {
	// A regular file whose parent directories were never declared must still be
	// created, confined under dest.
	data := buildTar(t, reg("deep/nested/path/file.txt", []byte("ok")))
	dest, err := extractInto(t, data, DefaultOptions())
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dest, "deep/nested/path/file.txt"))
	if err != nil {
		t.Fatalf("reading nested file: %v", err)
	}
	if string(got) != "ok" {
		t.Fatalf("nested content = %q, want %q", got, "ok")
	}
}

func TestExtractExtendedHeadersSkipped(t *testing.T) {
	// Global and extended PAX/GNU headers must not materialize files. We craft
	// them directly so the reader surfaces them as their own typeflags.
	data := buildTar(t,
		tarEntry{hdr: tar.Header{Name: "pax_global_header", Typeflag: tar.TypeXGlobalHeader, Mode: 0}},
		reg("real.txt", []byte("ok")),
	)
	dest, err := extractInto(t, data, DefaultOptions())
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if _, statErr := os.Lstat(filepath.Join(dest, "pax_global_header")); statErr == nil {
		t.Fatalf("global header was materialized as a file")
	}
	if _, statErr := os.Stat(filepath.Join(dest, "real.txt")); statErr != nil {
		t.Fatalf("real file missing: %v", statErr)
	}
}

func TestExtractContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel() // cancel before extraction begins
	data := buildTar(t, reg("a.txt", []byte("x")), reg("b.txt", []byte("y")))
	dest := t.TempDir()
	err := Extract(ctx, bytes.NewReader(data), dest, DefaultOptions())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Extract error = %v, want errors.Is %v", err, context.Canceled)
	}
}

func TestExtractBadDest(t *testing.T) {
	// A nonexistent dest must yield a wrapped error, not a panic.
	err := Extract(t.Context(), strings.NewReader(""), "/nonexistent/path/safetar", DefaultOptions())
	if err == nil {
		t.Fatalf("expected error for nonexistent dest")
	}
}

func TestExtractTruncatedStream(t *testing.T) {
	// Truncate inside the first 512-byte header block so tar.Reader.Next fails
	// with an unexpected-EOF rather than tolerating a missing trailer.
	full := buildTar(t, reg("a.txt", []byte("hello world")))
	truncated := full[:300]
	canaryFile, want := canaryDir(t)
	_, err := extractInto(t, truncated, DefaultOptions())
	if err == nil {
		t.Fatalf("expected error for truncated tar stream")
	}
	assertCanary(t, canaryFile, want)
}

// adversarialCorpus returns the malicious tar streams used both by unit tests
// and as fuzz seeds.
func adversarialCorpus(t testing.TB) [][]byte {
	t.Helper()
	root := t.TempDir()
	return [][]byte{
		buildTar(t, reg("../escape.txt", []byte("x"))),
		buildTar(t, reg("/etc/passwd", []byte("x"))),
		buildTar(t, symlink("evil", root), reg("evil/x", []byte("x"))),
		buildTar(t, symlink("link", "/etc/passwd")),
		buildTar(t, symlink("link", "../../../etc")),
		buildTar(t, hardlink("link", "/etc/passwd")),
		buildTar(t, hardlink("link", "../../escape")),
		buildTar(t, tarEntry{hdr: tar.Header{Name: "dev/node", Typeflag: tar.TypeChar, Mode: 0o644}}),
		buildTar(t, reg(strings.Repeat("a", 300), []byte("x"))),
		// A truncated valid tar: exercises mid-stream read errors.
		func() []byte { b := buildTar(t, reg("a.txt", []byte("hello world"))); return b[:len(b)/2] }(),
	}
}

// Ensure the io.Reader contract is honored for an empty stream.
func TestExtractEmptyStream(t *testing.T) {
	dest, err := extractInto(t, buildTar(t), DefaultOptions())
	if err != nil {
		t.Fatalf("Extract of empty tar: %v", err)
	}
	entries, err := os.ReadDir(dest)
	if err != nil {
		t.Fatalf("reading dest: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("empty tar produced %d entries", len(entries))
	}
}

// regOwned builds a regular-file entry carrying explicit uid/gid so the
// ownership-preservation behavior can be asserted from the header values.
func regOwned(name string, body []byte, uid, gid int) tarEntry {
	e := reg(name, body)
	e.hdr.Uid = uid
	e.hdr.Gid = gid
	return e
}

// regOwnedMode builds a regular-file entry with explicit mode, uid and gid so a
// set-id bit and ownership can be asserted together.
func regOwnedMode(name string, body []byte, mode int64, uid, gid int) tarEntry {
	e := regOwned(name, body, uid, gid)
	e.hdr.Mode = mode
	return e
}

// statOwner returns the uid/gid the OS recorded for the named path under dest.
func statOwner(t *testing.T, dest, name string) (uid, gid int) {
	t.Helper()
	fi, err := os.Lstat(filepath.Join(dest, name))
	if err != nil {
		t.Fatalf("lstat %q: %v", name, err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Skipf("ownership not inspectable on this platform for %q", name)
	}
	return int(st.Uid), int(st.Gid)
}

// TestExtractPreserveOwnershipDisabled proves the default leaves ownership at
// the creating process's identity: a header uid/gid that differs from the
// runner is NOT applied, so the file lands owned by the current user. This is
// the negative case for the opt-in flag.
func TestExtractPreserveOwnershipDisabled(t *testing.T) {
	// A uid/gid the unprivileged test process certainly does not match. With the
	// flag off, no chown is attempted, so extraction must still succeed and the
	// file must end up owned by the current user, not 65534.
	data := buildTar(t, regOwned("file.txt", []byte("x"), 65534, 65534))
	dest, err := extractInto(t, data, DefaultOptions())
	if err != nil {
		t.Fatalf("Extract with ownership disabled: %v", err)
	}
	gotUID, _ := statOwner(t, dest, "file.txt")
	if gotUID == 65534 {
		t.Fatalf("ownership-disabled extraction applied header uid 65534; want current uid %d", os.Getuid())
	}
}

// TestExtractPreserveOwnershipEnabled proves the opt-in flag applies the header
// uid/gid via a confined chown. To stay runnable unprivileged, it uses the
// current process's own uid/gid (a chown to which always succeeds) and asserts
// the file and a symlink both carry exactly those values through the lchown
// path.
func TestExtractPreserveOwnershipEnabled(t *testing.T) {
	uid, gid := os.Getuid(), os.Getgid()
	dirEntry := dir("d")
	dirEntry.hdr.Uid, dirEntry.hdr.Gid = uid, gid
	linkEntry := symlink("link", "file.txt")
	linkEntry.hdr.Uid, linkEntry.hdr.Gid = uid, gid
	data := buildTar(t,
		regOwned("file.txt", []byte("x"), uid, gid),
		dirEntry,
		linkEntry,
	)
	opts := DefaultOptions()
	opts.PreserveOwnership = true
	dest, err := extractInto(t, data, opts)
	if err != nil {
		t.Fatalf("Extract with ownership enabled: %v", err)
	}
	for _, name := range []string{"file.txt", "d", "link"} {
		gotUID, gotGID := statOwner(t, dest, name)
		if gotUID != uid || gotGID != gid {
			t.Errorf("%q ownership = %d:%d, want %d:%d", name, gotUID, gotGID, uid, gid)
		}
	}
}

var _ io.Reader = (*bytes.Reader)(nil)
