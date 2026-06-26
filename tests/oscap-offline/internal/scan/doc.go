// Package scan is the host-side runner for the offline SCAP harness. It builds
// the container-runtime command that executes the in-container scan-offline
// entrypoint, runs it, and returns the path to the written results.xml.
//
// A Config captures every knob (container runtime, scanner image, platform,
// repo root, datastream path, profile) with defaults and environment overrides
// resolved by ConfigFromEnv (OSCAP_CONTAINER_RUNTIME, SCAP_IMAGE). BuildArgs is
// a pure function that returns the exact argv as a slice without executing
// anything, so it is exhaustively unit-testable; every element is a constant or
// a validated, cleaned path, never interpolated from arbitrary external text.
//
// EnsureBinary builds the static linux/amd64 entrypoint once into a cache dir,
// or returns a prebuilt path injected via SCAN_OFFLINE_BIN. Runner.Run executes
// the argv through the configured runtime and treats oscap exit codes 0 (all
// pass) and 2 (some rule failed) as a successful scan; the per-rule verdict is
// read separately from the results document, never from the exit code.
//
// Running the container runtime to execute oscap is legitimate process
// execution: oscap is a C tool with no Go equivalent. This is distinct from
// registry operations, which the harness performs through a registry library
// rather than by shelling out.
package scan
