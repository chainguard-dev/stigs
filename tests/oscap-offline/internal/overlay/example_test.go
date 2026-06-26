package overlay_test

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/chainguard-dev/stigs/tests/oscap-offline/internal/overlay"
)

// makeBase builds a tiny in-memory base tar for the examples.
func makeBase(entries map[string][]byte) []byte {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, data := range entries {
		_ = tw.WriteHeader(&tar.Header{
			Name:     name,
			Typeflag: tar.TypeReg,
			Mode:     0o644,
			Size:     int64(len(data)),
			Format:   tar.FormatPAX,
		})
		_, _ = tw.Write(data)
	}
	_ = tw.Close()
	return buf.Bytes()
}

// ExampleApply shows appending to a file, chowning it to root, and adding a new
// root-owned file.
func ExampleApply() {
	base := makeBase(map[string][]byte{"etc/motd": []byte("welcome")})

	var out bytes.Buffer
	err := overlay.Apply(bytes.NewReader(base), []overlay.Op{
		overlay.AppendFile("etc/motd", []byte(" home")),
		overlay.Chown("etc/motd", 0, 0),
		overlay.AddFile("etc/secret", []byte("classified"), 0o600, 0, 0),
	}, &out)
	if err != nil {
		fmt.Println("apply:", err)
		return
	}

	tr := tar.NewReader(&out)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		data, _ := io.ReadAll(tr)
		fmt.Printf("%s uid=%d mode=%#o %q\n", hdr.Name, hdr.Uid, hdr.Mode, data)
	}
	// Output:
	// etc/motd uid=0 mode=0644 "welcome home"
	// etc/secret uid=0 mode=0600 "classified"
}

// ExampleApply_missingPath shows the wrapped sentinel returned when an op
// targets a path that is absent from the base tar.
func ExampleApply_missingPath() {
	base := makeBase(map[string][]byte{"etc/motd": []byte("welcome")})

	err := overlay.Apply(bytes.NewReader(base), []overlay.Op{
		overlay.Chown("etc/absent", 0, 0),
	}, io.Discard)
	fmt.Println(errors.Is(err, overlay.ErrNotFound))
	// Output:
	// true
}
