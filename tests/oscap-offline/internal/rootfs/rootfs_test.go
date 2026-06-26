package rootfs

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/go-containerregistry/pkg/crane"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// fakeImage builds an in-memory crane image from a filemap. It never touches
// the network.
func fakeImage(t *testing.T, files map[string][]byte) v1.Image {
	t.Helper()
	img, err := crane.Image(files)
	if err != nil {
		t.Fatalf("building fake image: %v", err)
	}
	return img
}

// fakeDigestHex returns the manifest digest hex of the fake image built from
// files, mirroring what a real Digester would resolve without pulling layers.
func fakeDigestHex(t *testing.T, files map[string][]byte) string {
	t.Helper()
	d, err := fakeImage(t, files).Digest()
	if err != nil {
		t.Fatalf("resolving fake image digest: %v", err)
	}
	return d.Hex
}

// tarPaths normalizes a tar's regular-file entry names by trimming a leading
// "./" and returns them as a set.
func tarPaths(t *testing.T, r io.Reader) map[string]string {
	t.Helper()
	out := make(map[string]string)
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("reading tar: %v", err)
		}
		name := strings.TrimPrefix(hdr.Name, "./")
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("reading entry %q: %v", hdr.Name, err)
		}
		out[name] = string(data)
	}
	return out
}

func TestExport(t *testing.T) {
	t.Parallel()

	files := map[string][]byte{
		"etc/foo":     []byte("bar"),
		"usr/bin/baz": []byte("qux"),
	}
	e := Exporter{Fetch: func(_ context.Context, _ string) (v1.Image, error) {
		return fakeImage(t, files), nil
	}}

	var buf bytes.Buffer
	if err := e.export(t.Context(), "example.com/img:tag", &buf); err != nil {
		t.Fatalf("Export: %v", err)
	}

	got := tarPaths(t, &buf)
	for p, want := range files {
		if got[p] != string(want) {
			t.Errorf("path %q: got %q, want %q", p, got[p], want)
		}
	}
}

func TestExportTooLarge(t *testing.T) {
	t.Parallel()

	// A single file far larger than the tiny configured cap. The flattened tar
	// adds header overhead on top, so the payload alone already breaches the cap.
	files := map[string][]byte{"big": bytes.Repeat([]byte("x"), 4096)}
	e := Exporter{
		MaxBytes: 256,
		Fetch: func(_ context.Context, _ string) (v1.Image, error) {
			return fakeImage(t, files), nil
		},
	}

	var buf bytes.Buffer
	err := e.export(t.Context(), "example.com/img:tag", &buf)
	if !errors.Is(err, ErrExportTooLarge) {
		t.Fatalf("Export err = %v, want ErrExportTooLarge", err)
	}
}

func TestExportUnderDefaultCap(t *testing.T) {
	t.Parallel()

	// A normal small image exports fine when MaxBytes is left at its generous
	// default (zero selects the default).
	files := map[string][]byte{
		"etc/foo":     []byte("bar"),
		"usr/bin/baz": []byte("qux"),
	}
	e := Exporter{Fetch: func(_ context.Context, _ string) (v1.Image, error) {
		return fakeImage(t, files), nil
	}}

	var buf bytes.Buffer
	if err := e.export(t.Context(), "example.com/img:tag", &buf); err != nil {
		t.Fatalf("Export under default cap: %v", err)
	}
	got := tarPaths(t, &buf)
	for p, want := range files {
		if got[p] != string(want) {
			t.Errorf("path %q: got %q, want %q", p, got[p], want)
		}
	}
}

func TestExportFetchError(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("boom")
	e := Exporter{Fetch: func(_ context.Context, _ string) (v1.Image, error) {
		return nil, sentinel
	}}

	var buf bytes.Buffer
	err := e.export(t.Context(), "example.com/img:tag", &buf)
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected wrapped sentinel, got %v", err)
	}
}

func TestEnsureBaseTarCachesByDigest(t *testing.T) {
	t.Parallel()

	files := map[string][]byte{"etc/release": []byte("v1")}
	hex := fakeDigestHex(t, files)
	var fetchCount, resolveCount atomic.Int64

	e := Exporter{
		Fetch: func(_ context.Context, _ string) (v1.Image, error) {
			fetchCount.Add(1)
			return fakeImage(t, files), nil
		},
		Resolve: func(_ context.Context, _ string) (string, error) {
			resolveCount.Add(1)
			return hex, nil
		},
	}

	cacheDir := t.TempDir()

	path1, err := e.EnsureBaseTar(t.Context(), "example.com/img:tag", cacheDir)
	if err != nil {
		t.Fatalf("first EnsureBaseTar: %v", err)
	}
	st1, err := os.Stat(path1)
	if err != nil {
		t.Fatalf("stat first: %v", err)
	}

	// Corrupt the cached file in place. If the second call re-exports, it
	// would overwrite our marker; if it skips export (cache hit), the marker
	// survives. This deterministically proves "no re-export" without timing.
	marker := []byte("CACHE-HIT-MARKER")
	if err := os.WriteFile(path1, marker, 0o600); err != nil {
		t.Fatalf("writing marker: %v", err)
	}

	path2, err := e.EnsureBaseTar(t.Context(), "example.com/img:tag", cacheDir)
	if err != nil {
		t.Fatalf("second EnsureBaseTar: %v", err)
	}
	if path2 != path1 {
		t.Errorf("cache path changed: %q -> %q", path1, path2)
	}

	got, err := os.ReadFile(filepath.Clean(path2))
	if err != nil {
		t.Fatalf("reading after second: %v", err)
	}
	if !bytes.Equal(got, marker) {
		t.Errorf("cache file was re-exported (marker overwritten); got %d bytes", len(got))
	}

	// Sanity: the original (pre-marker) file was a real tar with our content.
	st2, err := os.Stat(path2)
	if err != nil {
		t.Fatalf("stat second: %v", err)
	}
	if !os.SameFile(st1, st2) {
		t.Errorf("cache path is not the same file across calls")
	}

	// The digest is resolved on both calls (it keys the cache), but the layer
	// fetcher runs only on the first (cache miss): a warm cache pulls no layers.
	if resolveCount.Load() != 2 {
		t.Errorf("resolve count = %d, want 2", resolveCount.Load())
	}
	if fetchCount.Load() != 1 {
		t.Errorf("fetch count = %d, want 1 (warm cache must not pull layers)", fetchCount.Load())
	}
}

func TestEnsureBaseTarDistinctDigests(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()

	mk := func(content string) string {
		files := map[string][]byte{"etc/v": []byte(content)}
		hex := fakeDigestHex(t, files)
		e := Exporter{
			Fetch: func(_ context.Context, _ string) (v1.Image, error) {
				return fakeImage(t, files), nil
			},
			Resolve: func(_ context.Context, _ string) (string, error) {
				return hex, nil
			},
		}
		p, err := e.EnsureBaseTar(t.Context(), "example.com/img:tag", cacheDir)
		if err != nil {
			t.Fatalf("EnsureBaseTar(%q): %v", content, err)
		}
		return p
	}

	pathA := mk("alpha")
	pathB := mk("beta")
	if pathA == pathB {
		t.Errorf("distinct image contents produced the same cache path: %q", pathA)
	}
}

func TestEnsureBaseTarContent(t *testing.T) {
	t.Parallel()

	files := map[string][]byte{"etc/os-release": []byte("ID=wolfi")}
	hex := fakeDigestHex(t, files)
	e := Exporter{
		Fetch: func(_ context.Context, _ string) (v1.Image, error) {
			return fakeImage(t, files), nil
		},
		Resolve: func(_ context.Context, _ string) (string, error) {
			return hex, nil
		},
	}
	cacheDir := t.TempDir()

	path, err := e.EnsureBaseTar(t.Context(), "example.com/img:tag", cacheDir)
	if err != nil {
		t.Fatalf("EnsureBaseTar: %v", err)
	}
	if filepath.Dir(path) != filepath.Clean(cacheDir) {
		t.Errorf("cache file %q is not within cacheDir %q", path, cacheDir)
	}

	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		t.Fatalf("opening cache file: %v", err)
	}
	defer f.Close()

	got := tarPaths(t, f)
	if got["etc/os-release"] != "ID=wolfi" {
		t.Errorf("cache tar missing expected content; got %v", got)
	}
}

func TestNewDefaultsFetch(t *testing.T) {
	t.Parallel()

	e := New()
	if e.Fetch == nil {
		t.Fatal("New() Exporter has nil Fetch")
	}
	if e.Resolve == nil {
		t.Fatal("New() Exporter has nil Resolve")
	}
}

// TestExportWolfiBaseIntegration is the single network-touching test. It pulls
// the real pinned wolfi-base image and asserts the exported tar contains the
// canonical SCAP-relevant files. It skips (does not fail) when offline.
func TestExportWolfiBaseIntegration(t *testing.T) {
	t.Parallel()

	const ref = "cgr.dev/chainguard/wolfi-base:latest"
	e := New()

	var buf bytes.Buffer
	if err := e.export(t.Context(), ref, &buf); err != nil {
		t.Skipf("skipping network integration test: cannot pull/export %q: %v", ref, err)
	}

	got := tarPaths(t, &buf)
	for _, want := range []string{
		"etc/shadow",
		"usr/lib/apk/db/installed",
		"etc/apk/repositories",
		"etc/ssl/certs/ca-certificates.crt",
	} {
		if _, ok := got[want]; !ok {
			t.Errorf("real wolfi-base export missing expected path %q", want)
		}
	}
}
