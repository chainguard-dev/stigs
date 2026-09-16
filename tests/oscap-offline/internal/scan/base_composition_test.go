package scan_test

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"os"
	"testing"

	"github.com/chainguard-dev/stigs/tests/oscap-offline/internal/rootfs"
	"github.com/chainguard-dev/stigs/tests/oscap-offline/internal/scan"
)

// Every fixture in the offline matrix rests on premises about what the pinned
// wolfi-base ships: a fixture that appends to etc/shadow needs it to exist, and
// a fixture asserting "an unmodified image fails this rule" needs the base to
// lack the pieces that would make it pass. Nothing used to check those premises
// directly -- they were only implied by the ops a fixture declared, so a
// re-pinned base could change one and either break the matrix with an error far
// from the cause, or, worse, quietly leave a fixture asserting less than its
// name claims.
//
// overlay.PutFile made the second failure mode the more likely one. It absorbs
// the presence or absence of a path by design, which is what stops a re-pin from
// erroring, but it also means a fixture can no longer be relied on to notice
// drift on its own. This file is where that drift is caught instead: it asserts
// base composition directly, so a re-pin that moves the ground under the matrix
// fails here, naming the path and the fixture that depended on it, rather than
// surfacing as a mystery verdict flip.
//
// It needs only a registry pull, not a container runtime or the datastream, so
// it runs in more environments than the matrix itself.

// basePathExpectation is one premise about the base image, paired with the
// reason it matters so a failure explains itself.
type basePathExpectation struct {
	path string
	why  string
}

// basePresent lists paths the fixtures require the base to ship, because an op
// with an existence precondition targets them (AppendFile, ReplaceFile,
// RemoveFile, Chown, or CopyFile's source). A re-pin dropping one of these
// breaks the matrix with a wrapped ErrNotFound.
var basePresent = []basePathExpectation{
	{"etc/ssl/certs/ca-certificates.crt", "caBundlePath: AppendFile tampers it; CopyFile reads it for the /kaniko fixtures"},
	{"etc/ssl/certs/.ca-certificates.crt.sha256", "caStampPath: ReplaceFile writes wrong/malformed stamps, RemoveFile drops it"},
	{"usr/lib/apk/db/installed", "AppendFile records apk package stanzas for the FIPS, remote-access and permissions fixtures"},
	{"etc/apk/repositories", "AppendFile adds the plain-HTTP and commented-repo lines for PackageSignature"},
	{"etc/shadow", "AppendFile adds the active, empty and locked password entries for UserPasswordConfigured and NoUsers"},
	{"var/log", "Chown makes it non-root for the VarLogPermissions fail fixture"},
}

// baseAbsent lists paths whose ABSENCE gives a fixture its discriminating
// power. These are the assertions that would otherwise degrade silently: if the
// base gained one, the fixture depending on its absence would keep passing while
// testing less, because PutFile absorbs the difference instead of erroring.
var baseAbsent = []basePathExpectation{
	{"etc/ssl/fipsmodule.cnf", "detect_openssl/fail_clean_no_fips declares no ops: an unmodified base must fail DetectOpenSsl, whose tst:1 is at_least_one_exists on this path"},
	{"etc/ssh/ssh_config", "the ssh_config drop-in sourcing check (tst:21) must not be satisfiable by an unmodified base"},
	{"etc/ssh/sshd_config", "the sshd_config drop-in sourcing check (tst:22) must not be satisfiable by an unmodified base"},
	{"etc/ssh/ssh_config.d/10-ssh-fips.conf", "the client FIPS drop-in criteria (tst:9-12) must not be satisfiable by an unmodified base"},
	{"etc/ssh/sshd_config.d/10-sshd-fips.conf", "the server FIPS drop-in criteria (tst:13-20) must not be satisfiable by an unmodified base"},
	{"etc/ssl/certs/java/cacerts", "CertificateAudit tst:5 is none_exist on the Java truststore; certificate_audit/pass_java_truststore is the only fixture exercising the present-and-matching branch, so it must synthesize the pair rather than inherit one"},
	{"etc/ssl/certs/java/.cacerts.sha256", "javaStampPath: as above, the truststore stamp must come from the fixture"},
	{"kaniko/ssl/certs/ca-certificates.crt", "kanikoCABundlePath is a CopyFile destination, which requires the path to be absent"},
	{"kaniko/ssl/certs/.ca-certificates.crt.sha256", "kanikoCAStampPath: as above, and CertificateAudit tst:13 is none_exist on it"},
}

// basePutFileTargets lists every path the matrix reaches with overlay.PutFile.
// PutFile tolerates the path being absent or a regular file, but NOT a
// directory or symlink: those fail with a wrapped ErrNotRegular, which is the
// same re-pin breakage shape PutFile was introduced to eliminate. That is a real
// risk for these paths rather than a theoretical one, because the base ships
// etc/ssl/cert.pem and etc/ssl/certs/ca-bundle.crt as symlinks to
// ca-certificates.crt, so the etc/ssl tree demonstrably does contain aliases.
//
// etc/ssl/openssl.cnf is deliberately in this list and in neither of the two
// above: it is the path that drifted (absent before 2026-09-02, shipped after),
// so pinning it either way would just re-create the bet PutFile removed. What
// must hold is that it never becomes a non-regular entry.
var basePutFileTargets = []string{
	"etc/ssl/openssl.cnf",
	"etc/ssl/fipsmodule.cnf",
	"etc/ssh/ssh_config",
	"etc/ssh/sshd_config",
	"etc/ssh/ssh_config.d/10-ssh-fips.conf",
	"etc/ssh/sshd_config.d/10-sshd-fips.conf",
	"etc/ssl/certs/java/cacerts",
	"etc/ssl/certs/java/.cacerts.sha256",
}

// baseFIPSPackages are the apk package names DetectOpenSsl requires (tst:3 and
// tst:4). The base must have neither, or detect_openssl/fail_clean_no_fips stops
// being a control.
var baseFIPSPackages = []string{
	"openssl-config-fipshardened",
	"openssl-provider-fips",
}

// baseMembers exports the pinned base image and indexes its members by name.
// Only the registry is required, so a prerequisite gap skips in local dev and
// fails under OSCAP_OFFLINE_REQUIRE, matching the matrix's policy.
func baseMembers(t *testing.T) (map[string]tar.Header, []byte) {
	t.Helper()

	require := requireScans()

	repoRoot, ok := findUp(t, scan.DefaultDatastreamRelPath)
	if !ok {
		skipOrFatal(t, require, "datastream %q not found above working dir", scan.DefaultDatastreamRelPath)
		return nil, nil
	}

	basePath, err := rootfs.New().EnsureBaseTar(t.Context(), baseRef(t, repoRoot), t.TempDir())
	if err != nil {
		skipOrFatal(t, require, "cannot export pinned wolfi-base (offline?): %v", err)
		return nil, nil
	}
	baseBytes, err := os.ReadFile(basePath)
	if err != nil {
		t.Fatalf("reading exported base tar %q: %v", basePath, err)
	}

	members := make(map[string]tar.Header)
	var apkDB []byte
	tr := tar.NewReader(bytes.NewReader(baseBytes))
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("reading base tar %q: %v", basePath, err)
		}
		members[hdr.Name] = *hdr
		if hdr.Name == "usr/lib/apk/db/installed" {
			if apkDB, err = io.ReadAll(tr); err != nil {
				t.Fatalf("reading apk db from base tar: %v", err)
			}
		}
	}
	if len(members) == 0 {
		t.Fatalf("base tar %q has no members; the assertions below would be vacuous", basePath)
	}
	return members, apkDB
}

// typeName renders a tar typeflag for failure messages.
func typeName(flag byte) string {
	switch flag {
	case tar.TypeReg:
		return "regular file"
	case tar.TypeDir:
		return "directory"
	case tar.TypeSymlink:
		return "symlink"
	case tar.TypeLink:
		return "hard link"
	default:
		return "typeflag " + string(rune(flag))
	}
}

// TestBaseImageComposition asserts the premises the offline fixture matrix rests
// on, directly against the pinned base image. A failure here means a re-pin
// changed the ground under a fixture: the message names the path, what changed,
// and which fixture or OVAL test depended on it.
func TestBaseImageComposition(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip("skipping base image composition check in -short mode")
	}

	members, apkDB := baseMembers(t)
	if members == nil {
		// baseMembers skips or fatals on a prerequisite gap; defensive only.
		t.Skip("base image unavailable; skipping composition check")
	}

	t.Run("paths the fixtures require", func(t *testing.T) {
		t.Parallel()
		for _, want := range basePresent {
			hdr, ok := members[want.path]
			if !ok {
				t.Errorf("base no longer ships %q, which the matrix depends on.\n  needed because: %s\n  a fixture op targeting it will now fail with overlay.ErrNotFound", want.path, want.why)
				continue
			}
			// Content-mutating ops need a regular file; var/log is only chowned,
			// so a directory is correct there.
			if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeDir {
				t.Errorf("base ships %q as a %s, not a regular file or directory.\n  needed because: %s", want.path, typeName(hdr.Typeflag), want.why)
			}
		}
	})

	t.Run("paths whose absence the fixtures rely on", func(t *testing.T) {
		t.Parallel()
		for _, want := range baseAbsent {
			hdr, ok := members[want.path]
			if !ok {
				continue
			}
			t.Errorf("base now ships %q (%s), which a fixture assumed absent.\n  relied on because: %s\n  the fixture will still pass, but it is no longer testing what its name claims -- re-check it rather than deleting this row", want.path, typeName(hdr.Typeflag), want.why)
		}
	})

	t.Run("PutFile targets are absent or regular files", func(t *testing.T) {
		t.Parallel()
		for _, path := range basePutFileTargets {
			hdr, ok := members[path]
			if !ok {
				continue // absent is fine: PutFile creates it
			}
			if hdr.Typeflag != tar.TypeReg {
				t.Errorf("base ships %q as a %s; overlay.PutFile can only create or replace a regular file, so every fixture touching it now fails with overlay.ErrNotRegular.\n  fix the fixture (RemoveFile then PutFile, or target the link's destination) rather than relaxing this check", path, typeName(hdr.Typeflag))
			}
		}
	})

	t.Run("no FIPS packages installed", func(t *testing.T) {
		t.Parallel()
		if apkDB == nil {
			t.Fatal("apk db absent from base tar; the FIPS-package assertion would be vacuous")
		}
		for _, pkg := range baseFIPSPackages {
			if bytes.Contains(apkDB, []byte("\nP:"+pkg+"\n")) {
				t.Errorf("base now records apk package %q as installed.\n  detect_openssl/fail_clean_no_fips declares no ops and asserts an unmodified base FAILS DetectOpenSsl; with the FIPS packages present that control weakens or flips", pkg)
			}
		}
	})
}
