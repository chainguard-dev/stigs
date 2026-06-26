// Package oscapoffline is the root of an offline SCAP test harness for the
// stigs datastreams. It hosts internal packages that, together, build a
// reproducible filesystem fixture for OpenSCAP evaluation without a running
// container runtime.
//
// The harness is split into focused, single-purpose internal packages:
//
//   - internal/rootfs: exports a pinned wolfi-base image to a cached,
//     flattened filesystem tar via go-containerregistry (no Docker daemon).
//   - internal/overlay: applies a declarative set of tar transforms to a base
//     tar, producing a deterministic fixture tar with explicit ownership and
//     permissions independent of the OS user running the harness.
//   - internal/safetar: extracts a tar into a destination confined by os.Root,
//     preserving header uid/gid; the audited extraction primitive run as root
//     inside the scanner container.
//   - internal/scan: the host-side runner that builds the container-runtime
//     command, executes the in-container entrypoint, and returns the results
//     path.
//   - internal/results: parses the OpenSCAP XCCDF results document into
//     per-rule verdicts.
//
// The cmd/scan-offline binary is the in-container entrypoint: it extracts the
// fixture tar with internal/safetar as root, points OSCAP_PROBE_ROOT at the
// extracted tree, and execs oscap.
//
// Downstream plans consume these packages to assemble fixtures and drive
// offline OpenSCAP scans.
package oscapoffline
