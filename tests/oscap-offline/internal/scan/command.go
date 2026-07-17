package scan

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

// ErrInvalidConfig is returned by BuildArgs when the configuration or call
// arguments are incomplete or unsafe. Callers should match with errors.Is.
var ErrInvalidConfig = errors.New("invalid scan configuration")

// Default knobs. The scanner tool image defaults to the floating dev tag per
// repo convention (the e2e harness uses the same floating tag); only the
// scanned wolfi-base content is digest-pinned. SCAP_IMAGE may be set, e.g. to a
// digest, to override the scanner image for reproducibility.
const (
	// DefaultRuntime is the container runtime used when none is configured.
	DefaultRuntime = "docker"
	// DefaultImage is the openscap scanner tool image. It defaults to the
	// floating dev tag per repo convention; set SCAP_IMAGE (e.g. to a digest) to
	// override it for reproducibility.
	DefaultImage = "cgr.dev/chainguard/openscap:latest-dev"
	// DefaultPlatform forces linux/amd64 so the scan matches the static
	// entrypoint binary regardless of the host architecture.
	DefaultPlatform = "linux/amd64"
	// DefaultProfile is the XCCDF profile evaluated by the scan.
	DefaultProfile = "xccdf_basic_profile_.check"
	// DefaultDatastreamRelPath is the in-repo datastream, relative to the repo
	// root, that the scan evaluates.
	DefaultDatastreamRelPath = "gpos/xml/scap/ssg/content/ssg-chainguard-gpos-ds.xml"
)

// Container mount points and the oscap result filename. These are fixed by the
// entrypoint contract, never derived from external input.
const (
	containerBinaryPath  = "/scan-offline"
	containerFixturePath = "/in/fixture.tar"
	containerSrcPath     = "/src"
	containerOutPath     = "/out"
	resultsFileName      = "results.xml"
)

// containerVarsEnv is the environment variable oscap's environmentvariable58
// offline probe reads to source a scanned container's variables. Real
// oscap-docker sets it from the target's Config.Env; the offline harness has no
// daemon, so BuildArgs synthesizes it per-fixture. It is always set (empty when
// a fixture declares no vars) so the probe uses the offline source rather than
// falling back to an empty <OSCAP_PROBE_ROOT>/proc.
const containerVarsEnv = "OSCAP_CONTAINER_VARS"

// Environment variable names recognized by ConfigFromEnv.
const (
	envRuntime = "OSCAP_CONTAINER_RUNTIME"
	envImage   = "SCAP_IMAGE"
)

// Config is the immutable input to the scan command builder. Every field feeds
// an explicit argv element; none is interpolated from arbitrary external text.
// Host mount paths are cleaned and validated before use.
type Config struct {
	// Runtime is the container runtime executable, e.g. "docker" or "podman".
	Runtime string
	// Image is the openscap scanner tool image reference. It defaults to a
	// floating dev tag and may be overridden via SCAP_IMAGE (e.g. a digest).
	Image string
	// Platform forces the container platform, e.g. "linux/amd64".
	Platform string
	// BinaryPath is the host path to the static scan-offline entrypoint binary.
	BinaryPath string
	// RepoRoot is the host path to the repo root mounted read-only at /src.
	RepoRoot string
	// DatastreamRelPath is the datastream path relative to RepoRoot. It must be
	// a clean, local path so it cannot escape the mounted /src tree.
	DatastreamRelPath string
	// Profile is the XCCDF profile id passed to oscap.
	Profile string
}

// ConfigFromEnv builds a Config from the supplied repo root and entrypoint
// binary path, applying defaults and honoring the OSCAP_CONTAINER_RUNTIME and
// SCAP_IMAGE overrides resolved through getenv (injected for testability).
func ConfigFromEnv(repoRoot, binaryPath string, getenv func(string) string) Config {
	runtime := DefaultRuntime
	if v := getenv(envRuntime); v != "" {
		runtime = v
	}
	image := DefaultImage
	if v := getenv(envImage); v != "" {
		image = v
	}
	return Config{
		Runtime:           runtime,
		Image:             image,
		Platform:          DefaultPlatform,
		BinaryPath:        binaryPath,
		RepoRoot:          repoRoot,
		DatastreamRelPath: DefaultDatastreamRelPath,
		Profile:           DefaultProfile,
	}
}

// BuildArgs returns the exact container-runtime argv to scan fixtureTar, writing
// results into resultsDir. It performs no execution. Every element is a constant
// or a validated, cleaned path, and the argv is passed to exec as a slice with no
// shell interpolation. An incomplete config or an unsafe path yields a wrapped
// ErrInvalidConfig.
//
// containerVars are the target's environment variables ("NAME=value" entries)
// exposed to oscap's environmentvariable58 offline probe via OSCAP_CONTAINER_VARS
// (newline-joined). It is fixture/config-controlled content, passed as a single
// argv element with no shell, so it shares the existing argv trust boundary and
// needs no metacharacter screening. Pass nil for fixtures with no relevant env.
func (c Config) BuildArgs(fixtureTar, resultsDir string, containerVars []string) ([]string, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	if fixtureTar == "" {
		return nil, fmt.Errorf("empty fixture tar path: %w", ErrInvalidConfig)
	}
	if resultsDir == "" {
		return nil, fmt.Errorf("empty results dir: %w", ErrInvalidConfig)
	}

	binaryPath := filepath.Clean(c.BinaryPath)
	repoRoot := filepath.Clean(c.RepoRoot)
	fixture := filepath.Clean(fixtureTar)
	out := filepath.Clean(resultsDir)
	datastream := filepath.Clean(c.DatastreamRelPath)

	// The datastream must stay inside the mounted /src tree: reject absolute or
	// escaping paths so the container can only read the in-repo content.
	if !filepath.IsLocal(datastream) {
		return nil, fmt.Errorf("datastream path %q escapes repo root: %w", c.DatastreamRelPath, ErrInvalidConfig)
	}

	return []string{
		c.Runtime, "run", "--rm", "-u", "0:0", "--platform", c.Platform,
		"-v", binaryPath + ":" + containerBinaryPath + ":ro",
		"-v", fixture + ":" + containerFixturePath + ":ro",
		"-v", repoRoot + ":" + containerSrcPath + ":ro",
		"-v", out + ":" + containerOutPath,
		"-e", containerVarsEnv + "=" + strings.Join(containerVars, "\n"),
		"--entrypoint", containerBinaryPath,
		c.Image,
		containerFixturePath,
		"xccdf", "eval",
		"--profile", c.Profile,
		"--results", containerOutPath + "/" + resultsFileName,
		containerSrcPath + "/" + filepath.ToSlash(datastream),
	}, nil
}

// validate rejects any empty required field with a wrapped ErrInvalidConfig,
// then applies shape checks to the externally overridable runtime and image so
// an env value cannot introduce a flag or extra token into the argv.
func (c Config) validate() error {
	for _, f := range []struct {
		name, val string
	}{
		{"runtime", c.Runtime},
		{"image", c.Image},
		{"platform", c.Platform},
		{"binary path", c.BinaryPath},
		{"repo root", c.RepoRoot},
		{"datastream path", c.DatastreamRelPath},
		{"profile", c.Profile},
	} {
		if f.val == "" {
			return fmt.Errorf("empty %s: %w", f.name, ErrInvalidConfig)
		}
	}
	if err := validateRuntime(c.Runtime); err != nil {
		return err
	}
	return validateImage(c.Image)
}

// validateRuntime guards argv[0]. The runtime executable name must not contain a
// path separator or whitespace and must not begin with "-" (which exec would
// otherwise treat, downstream, as a flag rather than a command).
func validateRuntime(runtime string) error {
	if strings.HasPrefix(runtime, "-") {
		return fmt.Errorf("runtime %q must not start with %q: %w", runtime, "-", ErrInvalidConfig)
	}
	if strings.ContainsAny(runtime, "/\\") {
		return fmt.Errorf("runtime %q must not contain a path separator: %w", runtime, ErrInvalidConfig)
	}
	if strings.ContainsFunc(runtime, unicodeIsSpace) {
		return fmt.Errorf("runtime %q must not contain whitespace: %w", runtime, ErrInvalidConfig)
	}
	return nil
}

// validateImage guards the image-reference argv slot. A leading "-" is rejected
// so a value cannot pose as a runtime flag, and any whitespace or shell
// metacharacter is rejected. A registry/repo:tag or registry/repo@sha256:...
// reference passes.
func validateImage(image string) error {
	if strings.HasPrefix(image, "-") {
		return fmt.Errorf("image %q must not start with %q: %w", image, "-", ErrInvalidConfig)
	}
	if strings.ContainsFunc(image, unicodeIsSpace) {
		return fmt.Errorf("image %q must not contain whitespace: %w", image, ErrInvalidConfig)
	}
	// A valid image reference contains no shell metacharacters; reject them. The
	// argv is handed to exec without a shell.
	if i := strings.IndexAny(image, ";|&$<>`(){}[]!*?'\"\\"); i >= 0 {
		return fmt.Errorf("image %q contains disallowed character %q: %w", image, string(image[i]), ErrInvalidConfig)
	}
	return nil
}

// unicodeIsSpace reports whether r is an ASCII whitespace character. It avoids
// pulling in unicode for the narrow set of bytes a runtime or image name is
// checked against.
func unicodeIsSpace(r rune) bool {
	switch r {
	case ' ', '\t', '\n', '\v', '\f', '\r':
		return true
	default:
		return false
	}
}
