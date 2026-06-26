package safetar_test

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/chainguard-dev/stigs/tests/oscap-offline/internal/safetar"
)

// ExampleExtract materializes a small in-memory tar into a temporary directory
// using the secure defaults, then reads back one of the extracted files.
func ExampleExtract() {
	// Build a tiny tar stream in memory.
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	body := []byte("hello from safetar")
	_ = tw.WriteHeader(&tar.Header{
		Name:     "etc/greeting.txt",
		Typeflag: tar.TypeReg,
		Mode:     0o644,
		Size:     int64(len(body)),
	})
	_, _ = tw.Write(body)
	_ = tw.Close()

	dest, err := os.MkdirTemp("", "safetar-example-*")
	if err != nil {
		panic(err)
	}
	defer func() { _ = os.RemoveAll(dest) }()

	if err := safetar.Extract(context.Background(), &buf, dest, safetar.DefaultOptions()); err != nil {
		panic(err)
	}

	got, err := os.ReadFile(filepath.Join(dest, "etc", "greeting.txt"))
	if err != nil {
		panic(err)
	}
	fmt.Println(string(got))
	// Output: hello from safetar
}
