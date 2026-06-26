package rootfs_test

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/chainguard-dev/stigs/tests/oscap-offline/internal/rootfs"
	"github.com/google/go-containerregistry/pkg/crane"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// ExampleExporter_EnsureBaseTar builds a deterministic in-memory image with an
// injected Fetcher and Digester, caches its flattened filesystem tar on disk,
// and reads back the cached entry names. The Digester keys the cache without
// pulling layers.
func ExampleExporter_EnsureBaseTar() {
	files := map[string][]byte{
		"etc/os-release": []byte("ID=wolfi"),
		"usr/bin/true":   []byte("\x7fELF"),
	}
	img, err := crane.Image(files)
	if err != nil {
		fmt.Println("image:", err)
		return
	}
	digest, err := img.Digest()
	if err != nil {
		fmt.Println("digest:", err)
		return
	}

	e := rootfs.Exporter{
		Fetch: func(_ context.Context, _ string) (v1.Image, error) {
			return img, nil
		},
		Resolve: func(_ context.Context, _ string) (string, error) {
			return digest.Hex, nil
		},
	}

	cacheDir, err := os.MkdirTemp("", "rootfs-example-*")
	if err != nil {
		fmt.Println("tempdir:", err)
		return
	}
	defer func() { _ = os.RemoveAll(cacheDir) }()

	tarPath, err := e.EnsureBaseTar(context.Background(), "example.com/img:tag", cacheDir)
	if err != nil {
		fmt.Println("ensure:", err)
		return
	}

	f, err := os.Open(filepath.Clean(tarPath))
	if err != nil {
		fmt.Println("open:", err)
		return
	}
	defer func() { _ = f.Close() }()

	var names []string
	tr := tar.NewReader(f)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		names = append(names, strings.TrimPrefix(hdr.Name, "./"))
	}
	sort.Strings(names)
	fmt.Println(names)
	// Output:
	// [etc/os-release usr/bin/true]
}
