package scan

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/chainguard-dev/clog"
)

// envBinary lets CI or the Makefile inject a prebuilt entrypoint binary path,
// skipping the in-process build entirely.
const envBinary = "SCAN_OFFLINE_BIN"

// entrypointPkg is the import path, relative to the repo's tests/oscap-offline
// module root, of the in-container entrypoint binary.
const entrypointPkg = "./cmd/scan-offline"

// scanExitOK and scanExitRuleFailed are the oscap exit codes that mean the scan
// ran successfully. Exit 0 means every selected rule passed; exit 2 means at
// least one rule failed. Both are valid: the verdict is read per-rule from the
// results, never from the exit code.
const (
	scanExitOK         = 0
	scanExitRuleFailed = 2
)

// ErrScanFailed is returned when the container runtime or oscap reports a
// failure that is not a per-rule failure (exit codes other than 0 or 2, or a
// runtime error). Callers should match with errors.Is.
var ErrScanFailed = errors.New("scan failed")

// EnsureBinary returns the path to the static linux/amd64 scan-offline
// entrypoint binary, building it once into outDir when not already provided.
// When SCAN_OFFLINE_BIN names an existing file, that path is returned verbatim
// so CI can prebuild and inject the binary. moduleDir must be the
// tests/oscap-offline module root that contains cmd/scan-offline.
func EnsureBinary(ctx context.Context, moduleDir, outDir string) (string, error) {
	if pre := os.Getenv(envBinary); pre != "" {
		// The injected path comes from operator or CI configuration. Require it to
		// be absolute and clean it so resolution never depends on the current
		// directory and no traversal component survives, then stat.
		clean := filepath.Clean(pre)
		if !filepath.IsAbs(clean) {
			return "", fmt.Errorf("%s=%q must be an absolute path: %w", envBinary, pre, ErrScanFailed)
		}
		if _, err := os.Stat(clean); err != nil {
			return "", fmt.Errorf("%s=%q is not usable: %w", envBinary, pre, err)
		}
		return clean, nil
	}

	moduleDir = filepath.Clean(moduleDir)
	outDir = filepath.Clean(outDir)
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return "", fmt.Errorf("creating binary output dir %q: %w", outDir, err)
	}
	binPath := filepath.Join(outDir, "scan-offline")

	// go build argv is entirely constant: the toolchain, fixed flags, the fixed
	// package import path, and an output path under outDir. No element originates
	// from external input.
	cmd := exec.CommandContext(ctx, "go", "build", "-trimpath", "-o", binPath, entrypointPkg)
	cmd.Dir = moduleDir
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64")
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("building entrypoint binary: %w: %s", err, firstLine(out))
	}
	return binPath, nil
}

// Runner executes scans through a container runtime using a fixed Config.
type Runner struct {
	cfg Config
}

// NewRunner returns a Runner bound to cfg.
func NewRunner(cfg Config) Runner {
	return Runner{cfg: cfg}
}

// Run builds the container argv for fixtureTar, executes it, and returns the
// path to the written results.xml. Exit codes 0 (all pass) and 2 (some rule
// failed) are both treated as a successful scan; any other exit code or a
// runtime error is wrapped with ErrScanFailed and the first line of stderr.
//
// The container runtime is invoked to execute oscap, a C tool with no Go
// equivalent; registry operations elsewhere use go-containerregistry rather than
// process execution. The argv is built by BuildArgs from validated config, so
// every element is a constant or a validated path.
func (r Runner) Run(ctx context.Context, fixtureTar, resultsDir string) (string, error) {
	argv, err := r.cfg.BuildArgs(fixtureTar, resultsDir)
	if err != nil {
		return "", err
	}

	// argv[0] is the configured runtime ("docker"/"podman"); the remainder are
	// constants and validated paths from BuildArgs. No element is arbitrary
	// external input.
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) //nolint:gosec // argv built from validated Config; see BuildArgs
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	runErr := cmd.Run()
	code := exitCode(runErr)

	clog.DebugContextf(ctx, "scan %q exited code=%d runtime=%q", fixtureTar, code, r.cfg.Runtime)

	if runErr != nil && code != scanExitOK && code != scanExitRuleFailed {
		return "", fmt.Errorf("%w: %s exited %d: %s", ErrScanFailed, r.cfg.Runtime, code, firstLine(stderr.Bytes()))
	}

	// When results.xml is absent the stat error names the cause; keep the stderr
	// first line when present so a runtime diagnostic is not lost, but never drop
	// the underlying stat error.
	resultsPath := filepath.Join(filepath.Clean(resultsDir), resultsFileName)
	if _, statErr := os.Stat(resultsPath); statErr != nil {
		if stderrLine := firstLine(stderr.Bytes()); stderrLine != "" {
			return "", fmt.Errorf("%w: results not produced at %q: %w: %s", ErrScanFailed, resultsPath, statErr, stderrLine)
		}
		return "", fmt.Errorf("%w: results not produced at %q: %w", ErrScanFailed, resultsPath, statErr)
	}
	return resultsPath, nil
}

// exitCode extracts the process exit code from a Cmd.Run error, returning 0 for
// a nil error and -1 when the error is not an *exec.ExitError (e.g. the runtime
// binary was not found).
func exitCode(err error) int {
	if err == nil {
		return scanExitOK
	}
	if ee, ok := errors.AsType[*exec.ExitError](err); ok {
		return ee.ExitCode()
	}
	return -1
}

// firstLine returns the first non-empty line of b, trimmed, for compact error
// messages that never dump an entire log into the caller's context.
func firstLine(b []byte) string {
	for line := range strings.Lines(string(b)) {
		if t := strings.TrimSpace(line); t != "" {
			return t
		}
	}
	return ""
}
