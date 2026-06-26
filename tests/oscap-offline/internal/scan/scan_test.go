package scan_test

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chainguard-dev/stigs/tests/oscap-offline/internal/scan"
)

// TestEnsureBinaryPrebuilt covers the SCAN_OFFLINE_BIN injection path without
// invoking the Go toolchain: a usable absolute path is returned cleaned, a
// relative path is rejected, and a missing path is an error.
func TestEnsureBinaryPrebuilt(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "scan-offline")
	if err := os.WriteFile(existing, []byte("#!/bin/true\n"), 0o755); err != nil { //nolint:gosec // test fixture binary
		t.Fatalf("write fixture binary: %v", err)
	}

	t.Run("usable absolute path returned cleaned", func(t *testing.T) {
		t.Setenv("SCAN_OFFLINE_BIN", filepath.Join(dir, ".", "scan-offline"))
		got, err := scan.EnsureBinary(t.Context(), dir, t.TempDir())
		if err != nil {
			t.Fatalf("EnsureBinary: %v", err)
		}
		if got != existing {
			t.Errorf("EnsureBinary = %q, want %q", got, existing)
		}
	})

	t.Run("relative path rejected", func(t *testing.T) {
		t.Setenv("SCAN_OFFLINE_BIN", "relative/scan-offline")
		if _, err := scan.EnsureBinary(t.Context(), dir, t.TempDir()); !errors.Is(err, scan.ErrScanFailed) {
			t.Errorf("EnsureBinary err = %v, want ErrScanFailed", err)
		}
	})

	t.Run("missing path rejected", func(t *testing.T) {
		t.Setenv("SCAN_OFFLINE_BIN", filepath.Join(dir, "does-not-exist"))
		if _, err := scan.EnsureBinary(t.Context(), dir, t.TempDir()); err == nil {
			t.Error("EnsureBinary accepted a missing injected binary; want error")
		}
	})
}

// TestRunRejectsBadConfig proves Run surfaces config validation before any
// container execution is attempted.
func TestRunRejectsBadConfig(t *testing.T) {
	t.Parallel()

	runner := scan.NewRunner(scan.Config{}) // all empty -> invalid
	if _, err := runner.Run(t.Context(), "/f.tar", "/out"); !errors.Is(err, scan.ErrInvalidConfig) {
		t.Errorf("Run err = %v, want ErrInvalidConfig", err)
	}
}

// TestRunMissingResultsNamesCause proves the results-not-produced path keeps the
// underlying os.Stat cause even when the runtime wrote nothing to stderr. The
// runtime is set to "true", a bare command that exits 0 and ignores every
// argument, so the scan "succeeds" yet leaves no results.xml; the error must
// still name the missing file and wrap ErrScanFailed.
func TestRunMissingResultsNamesCause(t *testing.T) {
	t.Parallel()

	if _, err := exec.LookPath("true"); err != nil {
		t.Skipf("the \"true\" command is required for this test: %v", err)
	}

	cfg := baseConfig()
	cfg.Runtime = "true" // exits 0, produces no results.xml
	runner := scan.NewRunner(cfg)

	resultsDir := t.TempDir() // empty: results.xml will be absent
	_, err := runner.Run(t.Context(), "/work/fixture.tar", resultsDir)
	if !errors.Is(err, scan.ErrScanFailed) {
		t.Fatalf("Run err = %v, want ErrScanFailed", err)
	}
	msg := err.Error()
	if !strings.Contains(msg, "results.xml") {
		t.Errorf("error %q does not name the missing results.xml", msg)
	}
	if !strings.Contains(msg, "no such file or directory") {
		t.Errorf("error %q does not carry the underlying stat cause", msg)
	}
}
