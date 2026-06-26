// Command scan-offline is the in-container entrypoint for the offline SCAP
// harness. It runs as root inside the scanner container, extracts a fixture tar
// into a fresh directory using the safetar extractor (preserving the header
// uid/gid that the OVAL permission checks read), points OSCAP_PROBE_ROOT at that
// directory, and execs oscap with the remaining arguments so oscap's exit code
// becomes this process's exit code.
//
// Usage:
//
//	scan-offline <fixture-tar-path> <oscap-args...>
package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/chainguard-dev/stigs/tests/oscap-offline/internal/safetar"
)

func main() {
	// Cancel the extraction context on interrupt or SIGTERM so safetar.Extract's
	// between-member ctx.Err() check can stop a long extraction. stop is released
	// before os.Exit so the signal handler does not leak on the error path; the
	// later syscall.Exec replaces the process image, so the deferred stop only
	// matters while extraction is in flight.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	if err := run(ctx, os.Args[1:]); err != nil {
		stop()
		fmt.Fprintln(os.Stderr, "scan-offline:", err)
		os.Exit(1)
	}
	stop()
}

// run extracts the fixture named by args[0] and execs oscap with args[1:]. On
// success it does not return: syscall.Exec replaces the process image so
// oscap's own exit code (0 = all pass, 2 = some rule failed; both valid)
// surfaces directly to the harness, which asserts per-rule rather than on the
// exit code. Any failure before the exec returns a non-nil error.
func run(ctx context.Context, args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: scan-offline <fixture-tar-path> <oscap-args...> (got %d args)", len(args))
	}
	fixtureTar, oscapArgs := args[0], args[1:]

	root, err := extractFixture(ctx, fixtureTar)
	if err != nil {
		return err
	}

	oscapBin, err := exec.LookPath("oscap")
	if err != nil {
		return fmt.Errorf("locating oscap: %w", err)
	}

	// oscapArgs come from the container command line, which the host-side runner
	// constructs from validated, constant config (internal/scan.Config.BuildArgs).
	// The argv below is an explicit slice with oscapBin as argv[0]; nothing is
	// shell-interpreted. OSCAP_PROBE_ROOT directs oscap to evaluate the extracted
	// tree rather than the live container root.
	argv := append([]string{oscapBin}, oscapArgs...)
	env := append(os.Environ(), "OSCAP_PROBE_ROOT="+root)

	// syscall.Exec replaces this process so oscap's exit code is the final code.
	if err := syscall.Exec(oscapBin, argv, env); err != nil { //nolint:gosec // argv elements are oscapBin and config-built args; no shell
		return fmt.Errorf("exec oscap: %w", err)
	}
	return nil // unreachable: Exec does not return on success.
}

// extractFixture opens the fixture tar and extracts it as root into a fresh
// directory under the system temp dir, returning that directory. Running as
// root preserves the header uid/gid (root:root) that the file-permission OVAL
// checks read, and safetar confines every member to the destination.
func extractFixture(ctx context.Context, fixtureTar string) (string, error) {
	f, err := os.Open(fixtureTar) //nolint:gosec // path is the first CLI arg, fully host-controlled
	if err != nil {
		return "", fmt.Errorf("opening fixture %q: %w", fixtureTar, err)
	}
	defer func() { _ = f.Close() }()

	dest, err := os.MkdirTemp("", "scan-rootfs-")
	if err != nil {
		return "", fmt.Errorf("creating extraction dir: %w", err)
	}

	// A real container rootfs holds absolute symlinks (e.g. busybox applets at
	// usr/bin/* -> /bin/busybox) that the OVAL checks must resolve. Permit them:
	// os.Root still refuses to follow any symlink out of the extracted tree, so
	// confinement is preserved. All other safetar defaults stay in force.
	opts := safetar.DefaultOptions()
	opts.AllowAbsoluteSymlinks = true
	// Preserve each member's header uid/gid so the file-ownership OVAL checks
	// (e.g. /var/log and /usr/lib must be root:root) see the fixture's intended
	// ownership rather than a flattened root:root. This process runs as root in
	// the scanner container, so the confined chown succeeds.
	opts.PreserveOwnership = true
	if err := safetar.Extract(ctx, f, dest, opts); err != nil {
		return "", fmt.Errorf("extracting fixture %q: %w", fixtureTar, err)
	}
	return dest, nil
}
