package scan_test

import (
	"errors"
	"testing"

	"github.com/chainguard-dev/stigs/tests/oscap-offline/internal/scan"
	"github.com/google/go-cmp/cmp"
)

// baseConfig returns a fully populated Config for argv tests so each case only
// overrides the field under test.
func baseConfig() scan.Config {
	return scan.Config{
		Runtime:           "docker",
		Image:             "cgr.dev/chainguard/openscap@sha256:abc",
		Platform:          "linux/amd64",
		BinaryPath:        "/cache/scan-offline",
		RepoRoot:          "/repo",
		DatastreamRelPath: "gpos/xml/scap/ssg/content/ssg-chainguard-gpos-ds.xml",
		Profile:           "xccdf_basic_profile_.check",
	}
}

func TestBuildArgs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		mutate     func(*scan.Config)
		fixtureTar string
		resultsDir string
		want       []string
	}{
		{
			name:       "default docker argv",
			fixtureTar: "/work/fixture.tar",
			resultsDir: "/work/out",
			want: []string{
				"docker", "run", "--rm", "-u", "0:0", "--platform", "linux/amd64",
				"-v", "/cache/scan-offline:/scan-offline:ro",
				"-v", "/work/fixture.tar:/in/fixture.tar:ro",
				"-v", "/repo:/src:ro",
				"-v", "/work/out:/out",
				"--entrypoint", "/scan-offline",
				"cgr.dev/chainguard/openscap@sha256:abc",
				"/in/fixture.tar",
				"xccdf", "eval",
				"--profile", "xccdf_basic_profile_.check",
				"--results", "/out/results.xml",
				"/src/gpos/xml/scap/ssg/content/ssg-chainguard-gpos-ds.xml",
			},
		},
		{
			name:       "podman runtime",
			mutate:     func(c *scan.Config) { c.Runtime = "podman" },
			fixtureTar: "/work/fixture.tar",
			resultsDir: "/work/out",
			want: []string{
				"podman", "run", "--rm", "-u", "0:0", "--platform", "linux/amd64",
				"-v", "/cache/scan-offline:/scan-offline:ro",
				"-v", "/work/fixture.tar:/in/fixture.tar:ro",
				"-v", "/repo:/src:ro",
				"-v", "/work/out:/out",
				"--entrypoint", "/scan-offline",
				"cgr.dev/chainguard/openscap@sha256:abc",
				"/in/fixture.tar",
				"xccdf", "eval",
				"--profile", "xccdf_basic_profile_.check",
				"--results", "/out/results.xml",
				"/src/gpos/xml/scap/ssg/content/ssg-chainguard-gpos-ds.xml",
			},
		},
		{
			name: "custom image and profile",
			mutate: func(c *scan.Config) {
				c.Image = "example.com/scap@sha256:deadbeef"
				c.Profile = "xccdf_custom_profile"
			},
			fixtureTar: "/work/fixture.tar",
			resultsDir: "/work/out",
			want: []string{
				"docker", "run", "--rm", "-u", "0:0", "--platform", "linux/amd64",
				"-v", "/cache/scan-offline:/scan-offline:ro",
				"-v", "/work/fixture.tar:/in/fixture.tar:ro",
				"-v", "/repo:/src:ro",
				"-v", "/work/out:/out",
				"--entrypoint", "/scan-offline",
				"example.com/scap@sha256:deadbeef",
				"/in/fixture.tar",
				"xccdf", "eval",
				"--profile", "xccdf_custom_profile",
				"--results", "/out/results.xml",
				"/src/gpos/xml/scap/ssg/content/ssg-chainguard-gpos-ds.xml",
			},
		},
		{
			name:       "unclean host paths are normalized",
			fixtureTar: "/work/./sub/../fixture.tar",
			resultsDir: "/work/out/",
			want: []string{
				"docker", "run", "--rm", "-u", "0:0", "--platform", "linux/amd64",
				"-v", "/cache/scan-offline:/scan-offline:ro",
				"-v", "/work/fixture.tar:/in/fixture.tar:ro",
				"-v", "/repo:/src:ro",
				"-v", "/work/out:/out",
				"--entrypoint", "/scan-offline",
				"cgr.dev/chainguard/openscap@sha256:abc",
				"/in/fixture.tar",
				"xccdf", "eval",
				"--profile", "xccdf_basic_profile_.check",
				"--results", "/out/results.xml",
				"/src/gpos/xml/scap/ssg/content/ssg-chainguard-gpos-ds.xml",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg := baseConfig()
			if tc.mutate != nil {
				tc.mutate(&cfg)
			}
			got, err := cfg.BuildArgs(tc.fixtureTar, tc.resultsDir)
			if err != nil {
				t.Fatalf("BuildArgs: %v", err)
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("BuildArgs argv mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestBuildArgsRejectsInvalid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		mutate     func(*scan.Config)
		fixtureTar string
		resultsDir string
	}{
		{name: "empty runtime", mutate: func(c *scan.Config) { c.Runtime = "" }, fixtureTar: "/f.tar", resultsDir: "/o"},
		{name: "empty image", mutate: func(c *scan.Config) { c.Image = "" }, fixtureTar: "/f.tar", resultsDir: "/o"},
		{name: "empty binary", mutate: func(c *scan.Config) { c.BinaryPath = "" }, fixtureTar: "/f.tar", resultsDir: "/o"},
		{name: "empty repo root", mutate: func(c *scan.Config) { c.RepoRoot = "" }, fixtureTar: "/f.tar", resultsDir: "/o"},
		{name: "empty datastream", mutate: func(c *scan.Config) { c.DatastreamRelPath = "" }, fixtureTar: "/f.tar", resultsDir: "/o"},
		{name: "empty profile", mutate: func(c *scan.Config) { c.Profile = "" }, fixtureTar: "/f.tar", resultsDir: "/o"},
		{name: "empty platform", mutate: func(c *scan.Config) { c.Platform = "" }, fixtureTar: "/f.tar", resultsDir: "/o"},
		{name: "empty fixture tar", fixtureTar: "", resultsDir: "/o"},
		{name: "empty results dir", fixtureTar: "/f.tar", resultsDir: ""},
		{name: "absolute datastream rejected", mutate: func(c *scan.Config) { c.DatastreamRelPath = "/etc/passwd" }, fixtureTar: "/f.tar", resultsDir: "/o"},
		{name: "datastream escapes repo", mutate: func(c *scan.Config) { c.DatastreamRelPath = "../secrets" }, fixtureTar: "/f.tar", resultsDir: "/o"},
		{name: "runtime leading dash", mutate: func(c *scan.Config) { c.Runtime = "-privileged" }, fixtureTar: "/f.tar", resultsDir: "/o"},
		{name: "runtime with path separator", mutate: func(c *scan.Config) { c.Runtime = "/usr/bin/docker" }, fixtureTar: "/f.tar", resultsDir: "/o"},
		{name: "runtime with embedded space", mutate: func(c *scan.Config) { c.Runtime = "docker run" }, fixtureTar: "/f.tar", resultsDir: "/o"},
		{name: "runtime with tab", mutate: func(c *scan.Config) { c.Runtime = "docker\trun" }, fixtureTar: "/f.tar", resultsDir: "/o"},
		{name: "image leading dash", mutate: func(c *scan.Config) { c.Image = "--privileged" }, fixtureTar: "/f.tar", resultsDir: "/o"},
		{name: "image with embedded space", mutate: func(c *scan.Config) { c.Image = "cgr.dev/img -v /:/host" }, fixtureTar: "/f.tar", resultsDir: "/o"},
		{name: "image with shell metachar", mutate: func(c *scan.Config) { c.Image = "img;rm -rf /" }, fixtureTar: "/f.tar", resultsDir: "/o"},
		{name: "image with newline", mutate: func(c *scan.Config) { c.Image = "img\nmalicious" }, fixtureTar: "/f.tar", resultsDir: "/o"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg := baseConfig()
			if tc.mutate != nil {
				tc.mutate(&cfg)
			}
			if _, err := cfg.BuildArgs(tc.fixtureTar, tc.resultsDir); !errors.Is(err, scan.ErrInvalidConfig) {
				t.Errorf("BuildArgs(%q, %q) err = %v, want ErrInvalidConfig", tc.fixtureTar, tc.resultsDir, err)
			}
		})
	}
}

// TestBuildArgsAcceptsValidOverrides proves the legit runtime and image shapes
// that flow in from the env overrides all pass validation.
func TestBuildArgsAcceptsValidOverrides(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*scan.Config)
	}{
		{name: "default runtime and floating tag", mutate: func(c *scan.Config) {
			c.Runtime = scan.DefaultRuntime
			c.Image = scan.DefaultImage
		}},
		{name: "podman runtime", mutate: func(c *scan.Config) { c.Runtime = "podman" }},
		{name: "digest-pinned image", mutate: func(c *scan.Config) {
			c.Image = "cgr.dev/chainguard/openscap@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
		}},
		{name: "registry repo tag", mutate: func(c *scan.Config) { c.Image = "example.com:5000/scap/openscap:latest-dev" }},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg := baseConfig()
			tc.mutate(&cfg)
			if _, err := cfg.BuildArgs("/work/fixture.tar", "/work/out"); err != nil {
				t.Errorf("BuildArgs rejected valid override: %v", err)
			}
		})
	}
}

// TestDefaultConfigFromEnv proves the env-driven defaults resolve the documented
// knobs and fall back to constants when unset.
func TestDefaultConfigFromEnv(t *testing.T) {
	t.Parallel()

	t.Run("defaults when env unset", func(t *testing.T) {
		t.Parallel()
		cfg := scan.ConfigFromEnv("/repo", "/cache/scan-offline", func(string) string { return "" })
		if cfg.Runtime != "docker" {
			t.Errorf("Runtime = %q, want docker", cfg.Runtime)
		}
		if cfg.Platform != "linux/amd64" {
			t.Errorf("Platform = %q, want linux/amd64", cfg.Platform)
		}
		if cfg.Image == "" {
			t.Error("Image default is empty")
		}
		if cfg.Profile != scan.DefaultProfile {
			t.Errorf("Profile = %q, want %q", cfg.Profile, scan.DefaultProfile)
		}
		if cfg.DatastreamRelPath != scan.DefaultDatastreamRelPath {
			t.Errorf("DatastreamRelPath = %q, want %q", cfg.DatastreamRelPath, scan.DefaultDatastreamRelPath)
		}
		if cfg.RepoRoot != "/repo" {
			t.Errorf("RepoRoot = %q, want /repo", cfg.RepoRoot)
		}
		if cfg.BinaryPath != "/cache/scan-offline" {
			t.Errorf("BinaryPath = %q, want /cache/scan-offline", cfg.BinaryPath)
		}
	})

	t.Run("env overrides", func(t *testing.T) {
		t.Parallel()
		env := map[string]string{
			"OSCAP_CONTAINER_RUNTIME": "podman",
			"SCAP_IMAGE":              "example.com/scap@sha256:abc",
		}
		cfg := scan.ConfigFromEnv("/repo", "/bin", func(k string) string { return env[k] })
		if cfg.Runtime != "podman" {
			t.Errorf("Runtime = %q, want podman", cfg.Runtime)
		}
		if cfg.Image != "example.com/scap@sha256:abc" {
			t.Errorf("Image = %q, want override", cfg.Image)
		}
	})
}
