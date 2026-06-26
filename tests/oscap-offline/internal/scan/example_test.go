package scan_test

import (
	"fmt"
	"strings"

	"github.com/chainguard-dev/stigs/tests/oscap-offline/internal/scan"
)

// ExampleConfig_BuildArgs shows the deterministic container argv produced for a
// fixture scan, without executing anything.
func ExampleConfig_BuildArgs() {
	cfg := scan.Config{
		Runtime:           "docker",
		Image:             "cgr.dev/chainguard/openscap@sha256:abc",
		Platform:          "linux/amd64",
		BinaryPath:        "/cache/scan-offline",
		RepoRoot:          "/repo",
		DatastreamRelPath: "gpos/xml/scap/ssg/content/ssg-chainguard-gpos-ds.xml",
		Profile:           "xccdf_basic_profile_.check",
	}

	argv, err := cfg.BuildArgs("/work/fixture.tar", "/work/out")
	if err != nil {
		fmt.Println("build:", err)
		return
	}
	fmt.Println(strings.Join(argv, " "))
	// Output:
	// docker run --rm -u 0:0 --platform linux/amd64 -v /cache/scan-offline:/scan-offline:ro -v /work/fixture.tar:/in/fixture.tar:ro -v /repo:/src:ro -v /work/out:/out --entrypoint /scan-offline cgr.dev/chainguard/openscap@sha256:abc /in/fixture.tar xccdf eval --profile xccdf_basic_profile_.check --results /out/results.xml /src/gpos/xml/scap/ssg/content/ssg-chainguard-gpos-ds.xml
}

// ExampleConfigFromEnv shows defaults applied when no environment overrides are
// present.
func ExampleConfigFromEnv() {
	cfg := scan.ConfigFromEnv("/repo", "/cache/scan-offline", func(string) string { return "" })
	fmt.Println(cfg.Runtime, cfg.Platform, cfg.Profile)
	// Output:
	// docker linux/amd64 xccdf_basic_profile_.check
}
