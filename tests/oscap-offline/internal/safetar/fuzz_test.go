package safetar

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// FuzzExtract feeds arbitrary bytes as a tar stream into Extract against a
// fresh dest and asserts two invariants that must never break:
//   - Extract never panics.
//   - No path outside dest is ever created or modified (verified via a canary
//     directory seeded next to dest before extraction).
func FuzzExtract(f *testing.F) {
	// Seed with the adversarial corpus from the unit tests plus a few raw byte
	// patterns so the fuzzer can mutate from realistic malicious starting points.
	for _, seed := range adversarialCorpus(f) {
		f.Add(seed)
	}
	f.Add([]byte{})
	f.Add([]byte("not a tar at all"))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Lay out a parent dir holding both dest and a canary sibling. Nothing
		// the extractor does may alter the canary.
		parent := t.TempDir()
		dest := filepath.Join(parent, "dest")
		if err := os.Mkdir(dest, 0o755); err != nil {
			t.Fatalf("creating dest: %v", err)
		}
		canary := filepath.Join(parent, "canary.txt")
		want := []byte("immutable")
		if err := os.WriteFile(canary, want, 0o600); err != nil {
			t.Fatalf("seeding canary: %v", err)
		}

		// Must not panic regardless of input. Errors are expected and fine.
		_ = Extract(t.Context(), bytes.NewReader(data), dest, DefaultOptions())

		got, err := os.ReadFile(canary)
		if err != nil {
			t.Fatalf("canary unreadable after extract: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("canary mutated by extraction: got %q want %q", got, want)
		}
		// The parent dir must contain only dest and the canary; an escape would
		// create a third sibling.
		entries, err := os.ReadDir(parent)
		if err != nil {
			t.Fatalf("reading parent: %v", err)
		}
		allowed := map[string]struct{}{"dest": {}, "canary.txt": {}}
		for _, e := range entries {
			if _, ok := allowed[e.Name()]; !ok {
				t.Fatalf("extraction created sibling outside dest: %q", e.Name())
			}
		}
	})
}
