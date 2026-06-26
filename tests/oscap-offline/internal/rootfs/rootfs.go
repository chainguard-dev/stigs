package rootfs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/crane"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// ErrExportTooLarge is returned when a flattened image tar exceeds the
// Exporter's configured maximum byte count, aborting the export before it can
// fill the disk. Callers should match with errors.Is.
var ErrExportTooLarge = errors.New("exported image exceeds maximum size")

// DefaultMaxExportBytes caps the flattened export tar. A real wolfi-base
// flattened tree is tens of MiB; this default bounds the export size while
// staying well above any legitimate export.
const DefaultMaxExportBytes int64 = 2 << 30 // 2 GiB

// Fetcher resolves an image reference to a v1.Image, pulling its layers. It is
// injectable so tests can supply in-memory images without touching the network.
type Fetcher func(ctx context.Context, ref string) (v1.Image, error)

// Digester resolves an image reference to its manifest digest hex without
// pulling layers. It is injectable so tests can key the cache deterministically
// and assert that a cache hit performs no layer pull.
type Digester func(ctx context.Context, ref string) (string, error)

// Exporter exports a flattened container filesystem to a tar. A zero-value
// Exporter and one built by New both default Fetch to a crane-based registry
// pull and Resolve to a crane digest lookup when those fields are nil.
type Exporter struct {
	// Fetch resolves a reference to an image, pulling its layers. When nil, a
	// crane pull using the default keychain is used.
	Fetch Fetcher
	// Resolve resolves a reference to its manifest digest hex without pulling
	// layers. When nil, a crane digest lookup using the default keychain is used.
	// EnsureBaseTar uses it to key the cache and skip the layer pull on a hit.
	Resolve Digester
	// MaxBytes caps the number of bytes written for a single flattened export. A
	// zero or negative value selects DefaultMaxExportBytes. Once the cap is
	// breached the export aborts with ErrExportTooLarge.
	MaxBytes int64
}

// New returns an Exporter whose Fetch performs a crane pull and whose Resolve
// performs a crane digest lookup, both against the default keychain.
func New() Exporter {
	return Exporter{Fetch: cranePull, Resolve: craneDigest}
}

// cranePull is the default network fetcher; it pulls the image layers.
func cranePull(ctx context.Context, ref string) (v1.Image, error) {
	img, err := crane.Pull(ref, crane.WithContext(ctx), crane.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return nil, fmt.Errorf("pulling %q: %w", ref, err)
	}
	return img, nil
}

// craneDigest is the default digest resolver; it reads only the manifest digest
// and does not pull layers.
func craneDigest(ctx context.Context, ref string) (string, error) {
	digest, err := crane.Digest(ref, crane.WithContext(ctx), crane.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return "", fmt.Errorf("resolving digest for %q: %w", ref, err)
	}
	hash, err := v1.NewHash(digest)
	if err != nil {
		return "", fmt.Errorf("parsing digest %q: %w", digest, err)
	}
	return hash.Hex, nil
}

// fetch resolves an image using the configured Fetcher, defaulting to a crane
// pull when none was set.
func (e Exporter) fetch(ctx context.Context, ref string) (v1.Image, error) {
	if e.Fetch != nil {
		return e.Fetch(ctx, ref)
	}
	return cranePull(ctx, ref)
}

// resolve resolves an image's digest hex using the configured Digester,
// defaulting to a crane digest lookup when none was set.
func (e Exporter) resolve(ctx context.Context, ref string) (string, error) {
	if e.Resolve != nil {
		return e.Resolve(ctx, ref)
	}
	return craneDigest(ctx, ref)
}

// maxBytes returns the effective export cap, applying DefaultMaxExportBytes when
// the Exporter leaves MaxBytes at its zero/negative value.
func (e Exporter) maxBytes() int64 {
	if e.MaxBytes > 0 {
		return e.MaxBytes
	}
	return DefaultMaxExportBytes
}

// cappedWriter wraps a destination writer and aborts with ErrExportTooLarge once
// more than max bytes have been written, bounding the bytes an export can write
// to disk.
type cappedWriter struct {
	dst     io.Writer
	max     int64
	written int64
}

// Write forwards to the underlying writer until the cap would be exceeded, at
// which point it returns ErrExportTooLarge without writing further. crane.Export
// surfaces this error, halting the export.
func (cw *cappedWriter) Write(p []byte) (int, error) {
	if cw.written+int64(len(p)) > cw.max {
		return 0, fmt.Errorf("export reached cap of %d bytes: %w", cw.max, ErrExportTooLarge)
	}
	n, err := cw.dst.Write(p)
	cw.written += int64(n)
	return n, err
}

// exportCapped writes img's flattened filesystem as a tar to w through a
// cappedWriter, aborting with ErrExportTooLarge once the configured MaxBytes cap
// is breached. It is the single capped-export path shared by export and
// EnsureBaseTar.
func (e Exporter) exportCapped(ref string, img v1.Image, w io.Writer) error {
	if err := crane.Export(img, &cappedWriter{dst: w, max: e.maxBytes()}); err != nil {
		return fmt.Errorf("exporting %q: %w", ref, err)
	}
	return nil
}

// export fetches the image at ref and writes its flattened filesystem as a tar
// to w, aborting with ErrExportTooLarge if the stream exceeds the configured
// MaxBytes cap.
func (e Exporter) export(ctx context.Context, ref string, w io.Writer) error {
	img, err := e.fetch(ctx, ref)
	if err != nil {
		return fmt.Errorf("fetching %q: %w", ref, err)
	}
	return e.exportCapped(ref, img, w)
}

// EnsureBaseTar derives a cache filename from the image's manifest digest and
// ensures a flattened filesystem tar exists at that path under cacheDir. The
// digest is resolved first via a cheap lookup that does not pull layers, so a
// cache hit returns immediately without fetching any layers; only a cache miss
// pulls the image and exports it. The returned path is always within cacheDir.
func (e Exporter) EnsureBaseTar(ctx context.Context, ref, cacheDir string) (string, error) {
	cacheDir = filepath.Clean(cacheDir)
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return "", fmt.Errorf("creating cache dir %q: %w", cacheDir, err)
	}

	hex, err := e.resolve(ctx, ref)
	if err != nil {
		return "", fmt.Errorf("resolving digest for %q: %w", ref, err)
	}

	tarPath := filepath.Join(cacheDir, fmt.Sprintf("base-%s.tar", hex))
	if _, err := os.Stat(tarPath); err == nil {
		return tarPath, nil // cache hit: no layer pull, no export
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("stat cache file %q: %w", tarPath, err)
	}

	// Cache miss: now pull the layers and export.
	img, err := e.fetch(ctx, ref)
	if err != nil {
		return "", fmt.Errorf("fetching %q: %w", ref, err)
	}

	tmp, err := os.CreateTemp(cacheDir, "base-*.tar.tmp")
	if err != nil {
		return "", fmt.Errorf("creating temp file in %q: %w", cacheDir, err)
	}
	tmpName := tmp.Name()
	// Best-effort cleanup if we fail before the rename succeeds.
	defer func() { _ = os.Remove(tmpName) }()

	if err := e.exportCapped(ref, img, tmp); err != nil {
		_ = tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("closing temp file %q: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, tarPath); err != nil {
		return "", fmt.Errorf("renaming %q to %q: %w", tmpName, tarPath, err)
	}
	return tarPath, nil
}
