package scan_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/chainguard-dev/stigs/tests/oscap-offline/internal/overlay"
	"github.com/chainguard-dev/stigs/tests/oscap-offline/internal/results"
	"github.com/chainguard-dev/stigs/tests/oscap-offline/internal/rootfs"
	"github.com/chainguard-dev/stigs/tests/oscap-offline/internal/scan"
)

// Representative XCCDF rule IDs, one per offline-capable OVAL definition. Each
// id was confirmed against the Rule -> check-content-ref mapping in
// gpos/.../ssg-chainguard-gpos-ds.xml: it is the first Rule whose check
// references the named OVAL document. Every rule backed by the same definition
// resolves identically, so asserting the first is sufficient and keeps the
// matrix one row per definition.
const (
	ruleRemoteAccessServices   = "xccdf_mil.disa.stig_rule_SV-263652r982557_rule" // RemoteAccessServicesTest.xml
	rulePackageSignature       = "xccdf_mil.disa.stig_rule_SV-203720r982212_rule" // PackageSignatureTest.xml
	ruleCertificateAudit       = "xccdf_mil.disa.stig_rule_SV-263659r982563_rule" // CertificateAuditTest.xml
	ruleUserPasswordConfigured = "xccdf_mil.disa.stig_rule_SV-203629r982199_rule" // UserPasswordConfiguredTest.xml
	ruleDetectOpenSsl          = "xccdf_mil.disa.stig_rule_SV-203739r987791_rule" // DetectOpenSslTest.xml
	ruleNoUsers                = "xccdf_mil.disa.stig_rule_SV-263650r982553_rule" // NoUsersCheck.xml
	ruleVarLogPermissions      = "xccdf_mil.disa.stig_rule_SV-203664r958566_rule" // VarLogPermissionsTest.xml
	ruleLibraryPermissions     = "xccdf_mil.disa.stig_rule_SV-203675r991560_rule" // LibraryPermissionsTest.xml
)

// SCE rules excluded from the offline matrix. AslrCheck.sh reads the *live*
// host kernel (sysctl kernel.randomize_va_space) via the SCE engine, not the
// extracted OSCAP_PROBE_ROOT tree, so its verdict reflects the CI runner's
// kernel rather than the fixture. Asserting it offline would couple the test to
// the host and produce a meaningless result; TestSCERulesExcludedFromMatrix
// documents and enforces the exclusion below.
const (
	ruleAslrRandomizeVASpace = "xccdf_mil.disa.stig_rule_SV-203753r958928_rule"
	ruleAslrSysctlConfig     = "xccdf_mil.disa.stig_rule_SV-203754r958928_rule"
)

// sceRuleSet is the set of SCE-backed rule ids that must never appear in any
// matrix case's want map. It is built from named constants so a regression that
// adds an SCE rule via its constant (not just a string literal) is still caught.
func sceRuleSet() map[string]struct{} {
	return map[string]struct{}{
		ruleAslrRandomizeVASpace: {},
		ruleAslrSysctlConfig:     {},
	}
}

// envRequireScans, when set to any non-empty value, turns prerequisite gaps
// (missing datastream, runtime, registry, or a scan that does not run) into hard
// failures instead of skips. CI sets it so a run that executes no scan fails the
// job rather than reporting a vacuous pass.
const envRequireScans = "OSCAP_OFFLINE_REQUIRE"

// overlaySlack preallocates headroom in the fixture buffer above the base tar
// size so appending overlay members rarely forces a reallocation.
const overlaySlack = 64 << 10

// wolfiBaseRepo is the repository portion of the base image the offline harness
// scans. baseRef selects the FROM line referencing it specifically so a
// multi-stage Dockerfile cannot cause the wrong image to be picked.
const wolfiBaseRepo = "cgr.dev/chainguard/wolfi-base"

// errNoWolfiBaseRef is returned by parseWolfiBaseRef when no digest-pinned
// wolfi-base FROM line is present.
var errNoWolfiBaseRef = errors.New("no digest-pinned " + wolfiBaseRepo + " FROM line found")

// fromRefRe captures the image reference token from a Dockerfile FROM line,
// e.g. `FROM cgr.dev/chainguard/wolfi-base:latest@sha256:<hex>` -> the ref.
var fromRefRe = regexp.MustCompile(`^\s*FROM\s+(\S+)`)

// digestPinRe matches a digest-pinned reference suffix.
var digestPinRe = regexp.MustCompile(`@sha256:[0-9a-f]{64}$`)

// parseWolfiBaseRef returns the digest-pinned wolfi-base reference from
// Dockerfile content. It scans every FROM line and selects the one whose ref
// names the wolfi-base repository and carries a sha256 digest, so a multi-stage
// Dockerfile with other FROM lines (e.g. a builder stage) cannot mislead it. It
// returns errNoWolfiBaseRef when no such line exists.
func parseWolfiBaseRef(content []byte) (string, error) {
	for line := range bytes.Lines(content) {
		m := fromRefRe.FindSubmatch(line)
		if m == nil {
			continue
		}
		ref := string(m[1])
		if !strings.Contains(ref, wolfiBaseRepo) {
			continue
		}
		if !digestPinRe.MatchString(ref) {
			continue
		}
		return ref, nil
	}
	return "", errNoWolfiBaseRef
}

// baseRef returns the single pinned wolfi-base reference the offline harness
// scans, read from an existing e2e fixture Dockerfile. That Dockerfile's FROM
// digest is the project's single source of truth for the base image: the
// update-ca-cert workflow re-pins it in lockstep with the datastream's CA
// bundle hash, so reading it here keeps the offline CertificateAudit pass
// fixture deterministic without a second pin to maintain. The path is repo
// content, not external input, and is cleaned before reading.
func baseRef(t *testing.T, repoRoot string) string {
	t.Helper()
	dockerfile := filepath.Clean(filepath.Join(repoRoot, "tests", "e2e", "fixtures", "baseline-clean", "Dockerfile"))
	content, err := os.ReadFile(dockerfile) //nolint:gosec // path derived from the located repo root + a constant, not external input
	if err != nil {
		t.Fatalf("reading base-image pin %q: %v", dockerfile, err)
	}
	ref, err := parseWolfiBaseRef(content)
	if err != nil {
		t.Fatalf("base-image pin %q: %v", dockerfile, err)
	}
	return ref
}

// skipFataler is the subset of *testing.T that skipOrFatal needs, letting the
// skip-vs-fatal decision be unit-tested with a fake.
type skipFataler interface {
	Helper()
	Skipf(format string, args ...any)
	Fatalf(format string, args ...any)
}

// skipOrFatal halts the current test: it fails when requireScans is set
// (prerequisite gaps must not pass silently in CI) and skips otherwise (local
// dev without docker). Both Skipf and Fatalf end the goroutine, so nothing after
// a call to skipOrFatal executes.
func skipOrFatal(t skipFataler, requireScans bool, format string, args ...any) {
	t.Helper()
	if requireScans {
		t.Fatalf(format, args...)
		return
	}
	t.Skipf(format, args...)
}

// requireScans reports whether the strict mode env is set.
func requireScans() bool { return os.Getenv(envRequireScans) != "" }

// harness holds the immutable artifacts shared read-only across every subtest:
// the cached base.tar bytes read once from the pinned wolfi-base, the runner
// bound to the in-repo datastream, and the strict-mode flag. Building these once
// (not per subtest) is what lets the matrix run subtests in parallel.
type harness struct {
	baseBytes    []byte
	runner       scan.Runner
	requireScans bool
}

// findUp walks up from the test's working directory until marker exists at the
// candidate directory, returning that directory. It is used to locate two
// distinct roots: the git repo root that holds the in-repo datastream, and the
// Go module root that holds cmd/scan-offline.
func findUp(t *testing.T, marker string) (string, bool) {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, marker)); err == nil {
			return dir, true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", false
		}
		dir = parent
	}
}

// buildHarness exports the base tar and builds the entrypoint binary exactly
// once. A prerequisite gap (no datastream, no runtime, offline registry) skips
// in local dev and fails when OSCAP_OFFLINE_REQUIRE is set; a genuine setup
// error that is not an availability problem is always a hard failure.
func buildHarness(t *testing.T) (harness, bool) {
	t.Helper()

	require := requireScans()

	repoRoot, ok := findUp(t, scan.DefaultDatastreamRelPath)
	if !ok {
		skipOrFatal(t, require, "datastream %q not found above working dir", scan.DefaultDatastreamRelPath)
		return harness{}, false
	}
	moduleDir, ok := findUp(t, "go.mod")
	if !ok {
		t.Fatal("go.mod not found above working dir")
	}

	runtime := scan.ConfigFromEnv(repoRoot, "", os.Getenv).Runtime
	if _, err := exec.LookPath(runtime); err != nil {
		skipOrFatal(t, require, "container runtime %q not on PATH: %v", runtime, err)
		return harness{}, false
	}

	cacheDir := t.TempDir()
	basePath, err := rootfs.New().EnsureBaseTar(t.Context(), baseRef(t, repoRoot), cacheDir)
	if err != nil {
		skipOrFatal(t, require, "cannot export pinned wolfi-base (offline?): %v", err)
		return harness{}, false
	}

	// Read the exported base tar into memory once so the parallel subtests each
	// overlay it from a fresh reader without re-reading from disk. A read failure
	// of a tar we just exported is a real error, never an availability skip.
	baseBytes, err := os.ReadFile(basePath)
	if err != nil {
		t.Fatalf("reading exported base tar %q: %v", basePath, err)
	}

	binPath, err := scan.EnsureBinary(t.Context(), moduleDir, t.TempDir())
	if err != nil {
		t.Fatalf("EnsureBinary: %v", err)
	}

	return harness{
		baseBytes:    baseBytes,
		runner:       scan.NewRunner(scan.ConfigFromEnv(repoRoot, binPath, os.Getenv)),
		requireScans: require,
	}, true
}

// scanFixture applies ops to the shared base bytes, runs a scan, and returns the
// parsed report. Each call overlays from a fresh reader over the shared
// immutable base bytes, so parallel subtests never contend on the source.
// containerVars are the fixture's OSCAP_CONTAINER_VARS entries, the offline
// source for the environmentvariable58 probe (nil for fixtures with no env).
func (h harness) scanFixture(t *testing.T, ops []overlay.Op, containerVars []string) (results.Report, bool) {
	t.Helper()

	fixture := bytes.NewBuffer(make([]byte, 0, len(h.baseBytes)+overlaySlack))
	if err := overlay.Apply(bytes.NewReader(h.baseBytes), ops, fixture); err != nil {
		t.Fatalf("overlay apply: %v", err)
	}
	fixturePath := filepath.Join(t.TempDir(), "fixture.tar")
	if err := os.WriteFile(fixturePath, fixture.Bytes(), 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}

	resultsPath, err := h.runner.Run(t.Context(), fixturePath, t.TempDir(), containerVars)
	if err != nil {
		// A scan that could not run at all (e.g. scanner image pull failure) is an
		// availability gap: a skip in local dev, a failure under strict mode.
		if errors.Is(err, scan.ErrScanFailed) {
			skipOrFatal(t, h.requireScans, "scan could not run (offline scanner image?): %v", err)
			return results.Report{}, false
		}
		t.Fatalf("runner.Run: %v", err)
	}

	f, err := os.Open(resultsPath)
	if err != nil {
		t.Fatalf("opening results: %v", err)
	}
	defer func() { _ = f.Close() }()

	report, err := results.Parse(f)
	if err != nil {
		t.Fatalf("parsing results: %v", err)
	}
	return report, true
}

// Synthetic mutation content. Each blob is the minimal change that flips one
// OVAL definition's verdict; the comment cites the pattern/state it satisfies.

// apkOpenSSHClientStanza / apkOpenSSHServerStanza are apk installed-db records
// for the openssh client and server packages, and two rules read them:
//   - RemoteAccessServices bans openssh and openssh-server (the server ships a
//     listening sshd) but NOT openssh-client, so recording openssh-server makes
//     that rule FAIL while recording only openssh-client keeps it PASSING.
//   - DetectOpenSsl gates its SSH criteria on these: the client checks apply
//     only when openssh-client is recorded and the server checks only when
//     openssh-server is recorded.
//
// apkOpenSSHSftpServerStanza records openssh-sftp-server, which ships the
// sftp-server subsystem binary sshd serves and is banned alongside the server.
// It is listed separately from openssh-server in the pattern, so it needs its
// own row: the "-sftp-server" spelling is not reached by the openssh-server
// alternative, which is anchored against a version suffix rather than a word
// one. This package was added to the ban list without the datastream copy
// following, so the shipped rule missed it entirely — see the fail row below.
var (
	apkOpenSSHClientStanza     = []byte("\nP:openssh-client\nV:9.9_p2-r0\nA:x86_64\n")
	apkOpenSSHServerStanza     = []byte("\nP:openssh-server\nV:9.9_p2-r0\nA:x86_64\n")
	apkOpenSSHSftpServerStanza = []byte("\nP:openssh-sftp-server\nV:9.9_p2-r0\nA:x86_64\n")
)

// apkDropbearStanza is an apk installed-db record whose P: line matches the
// RemoteAccessServices pattern (dropbear remains a banned remote-access
// package), so the none_exist test fails.
var apkDropbearStanza = []byte("\nP:dropbear\nV:2022.83-r3\nA:x86_64\n")

// apkDropbearConvertStanza records dropbear-convert, whose "-convert" word suffix
// the RemoteAccessServices pattern `^P:(dropbear|...)(-\d[\d.]*(-[a-z][a-z0-9-]*)?)?$`
// must NOT match: the optional version suffix requires a leading digit, so a
// word-suffixed sibling of a banned package falls through and the rule PASSES.
// Guards the boundary against a regex regression that drops the `$` anchor or the
// digit class and starts flagging legitimate packages.
var apkDropbearConvertStanza = []byte("\nP:dropbear-convert\nV:2022.83-r3\nA:x86_64\n")

// plainHTTPRepo is a non-https, non-comment repository line, which the
// PackageSignature none_exist pattern `^(?!\s*#)(?!.*https://).+$` matches.
var plainHTTPRepo = []byte("http://insecure.example.com/alpine\n")

// commentedAndHTTPSRepos are two repository lines the PackageSignature pattern
// `^(?!\s*#)(?!.*https://).+$` must NOT match: a comment line is exempt via the
// `(?!\s*#)` branch and an https line via the `(?!.*https://)` branch. Appending
// both to a clean base must keep the rule PASSING — guarding the two exemption
// branches that the single plain-http fail fixture never exercises.
var commentedAndHTTPSRepos = []byte("# http://insecure.example.com/alpine\nhttps://packages.example.com/alpine\n")

// caTamper appends content to the CA bundle so its SHA-256 diverges from the
// digest recorded in the stamp file, failing the filehash58 state.
var caTamper = []byte("\n# tamper\n-----BEGIN CERTIFICATE-----\nTAMPERED\n-----END CERTIFICATE-----\n")

// caStampPath is the sha256sum-format stamp file the ca-certificates package
// ships next to the bundle. CertificateAudit reads the expected digest out of
// it instead of pinning one in the datastream.
const caStampPath = "etc/ssl/certs/.ca-certificates.crt.sha256"

// caBundlePath and kanikoCABundlePath are the two locations CertificateAudit
// accepts SSL_CERT_FILE pointing at, as tar member paths (rootfs-relative, no
// leading slash). kanikoCAStampPath is the stamp file the /kaniko copy is
// checked against where one is shipped beside it; cgr.dev/chainguard/kaniko
// ships none today, so the copy falls back to the stamp at caStampPath.
const (
	caBundlePath       = "etc/ssl/certs/ca-certificates.crt"
	kanikoCABundlePath = "kaniko/ssl/certs/ca-certificates.crt"
	kanikoCAStampPath  = "kaniko/ssl/certs/.ca-certificates.crt.sha256"
)

// caStampWrongDigest is a well-formed stamp naming a digest the untouched
// bundle cannot have (all zeroes), isolating the comparison from the stamp
// side: the bundle is clean, the expected value is not.
var caStampWrongDigest = []byte(strings.Repeat("0", 64) + "  ca-certificates.crt\n")

// caStampMalformed has no line matching the object's
// `^([0-9a-fA-F]{64})[ \t]+\*?ca-certificates\.crt$` pattern, so the digest
// variable collects nothing and the stamp-file existence test fails.
var caStampMalformed = []byte("not a checksum line\n")

// The Java truststore half of CertificateAudit is conditional: it only applies
// to images that ship /etc/ssl/certs/java/cacerts. The offline base is
// wolfi-base, which has no Java, so these fixtures synthesize the pair. The
// truststore's real format is irrelevant here — the check is a SHA-256
// comparison, so opaque bytes exercise it exactly as a real JKS would.
const (
	javaTrustStorePath = "etc/ssl/certs/java/cacerts"
	javaStampPath      = "etc/ssl/certs/java/.cacerts.sha256"
)

var javaTrustStore = []byte("synthetic truststore bytes, not a real JKS")

// javaStamp returns a sha256sum-format stamp naming content's digest, matching
// what the package ships next to the truststore: "<digest>  cacerts".
func javaStamp(content []byte) []byte {
	sum := sha256.Sum256(content)
	return []byte(hex.EncodeToString(sum[:]) + "  cacerts\n")
}

// activeShadowEntry is an /etc/shadow line whose password field is a
// traditional DES crypt hash (not "!" or "*"), which the UserPasswordConfigured
// pattern `^[^:]+:(?![!*])[^:\n]*:` matches, failing the none_exist test.
var activeShadowEntry = []byte("compliance-test:ZZx/p0vU8jVbA:19000:0:99999:7:::\n")

// emptyShadowPassword is an /etc/shadow line whose password field is EMPTY
// (passwordless login), distinct from a hashed or a locked ("!"/"*") field. The
// UserPasswordConfigured pattern `^[^:]+:(?![!*])[^:\n]*:` still matches it — the
// field neither starts with "!"/"*" nor is otherwise exempt — so the none_exist
// test must FAIL. This guards the negative-lookahead's handling of the empty
// field, the case a hashed-password fixture never exercises.
var emptyShadowPassword = []byte("emptyacct::19000:0:99999:7:::\n")

// lockedShadowUser is a locked ("!") entry appended after the trailing
// `nobody:` line, mirroring what apko writes for image run-as users. The
// NoUsers pattern `^[^:]+:(?![!*])[^:\n]*:` must NOT match it — locked
// service accounts cannot log in and are permitted.
var lockedShadowUser = []byte("nonroot:!::0:::::\n")

// fipsModuleCnf, opensslCnf, and apkFIPSPackages together satisfy all seven
// DetectOpenSsl criteria: the two config files must exist, both FIPS packages
// must be recorded in the apk db, and openssl.cnf must contain the include line,
// the provider_sect fips line, and the default_properties fips=yes line.
var (
	fipsModuleCnf   = []byte("[fips_sect]\nactivate = 1\n")
	opensslCnf      = []byte(".include fipsmodule.cnf\n[provider_sect]\nfips = fips_sect\ndefault = default_sect\n[algorithm_sect]\ndefault_properties = fips=yes\n")
	apkFIPSPackages = []byte("\nP:openssl-config-fipshardened\nV:3.5.1-r0\nA:x86_64\n\nP:openssl-provider-fips\nV:3.5.1-r0\nA:x86_64\n")
)

// apkFIPSPackagesDocSubpkg records only the doc subpackages
// (openssl-config-fipshardened-doc / openssl-provider-fips-doc). The DetectOpenSsl
// package patterns `^P:openssl-...(-\d+\.\d+\.\d+)?$` exclude word suffixes, so
// these must NOT satisfy the package criterion. Paired with the config files
// present, the rule must stay FAIL — isolating the package-pattern branch so a
// regex that accepts word-suffixed subpackages would be caught.
var apkFIPSPackagesDocSubpkg = []byte("\nP:openssl-config-fipshardened-doc\nV:3.5.1-r0\nA:x86_64\n\nP:openssl-provider-fips-doc\nV:3.5.1-r0\nA:x86_64\n")

// sshFipsClientConf and sshFipsServerConf are the OpenSSH client and server FIPS
// policy drop-ins shipped by openssl-config-fipshardened. DetectOpenSsl's twelve
// ssh criteria require both files to exist and to pin exactly these
// FIPS-approved algorithm lists (the client file's directives are indented under
// a "Host *" stanza, which the `^\s*<keyword>` patterns tolerate).
var (
	sshFipsClientConf = []byte("Host *\n" +
		"    Ciphers aes128-gcm@openssh.com,aes256-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\n" +
		"    KexAlgorithms ecdh-sha2-nistp256,ecdh-sha2-nistp384\n" +
		"    MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512\n" +
		"    RequiredRSASize 2048\n")
	sshFipsServerConf = []byte(
		"Ciphers aes128-gcm@openssh.com,aes256-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\n" +
			"KexAlgorithms ecdh-sha2-nistp256,ecdh-sha2-nistp384\n" +
			"MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512\n" +
			"RequiredRSASize 2048\n" +
			"HostKeyAlgorithms ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384-cert-v01@openssh.com,sk-ecdsa-sha2-nistp256-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,sk-ecdsa-sha2-nistp256@openssh.com,rsa-sha2-512,rsa-sha2-256\n" +
			"CASignatureAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,sk-ecdsa-sha2-nistp256@openssh.com,rsa-sha2-512,rsa-sha2-256\n" +
			"HostBasedAcceptedAlgorithms ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384-cert-v01@openssh.com,sk-ecdsa-sha2-nistp256-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,sk-ecdsa-sha2-nistp256@openssh.com,rsa-sha2-512,rsa-sha2-256\n" +
			"PubkeyAcceptedAlgorithms ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384-cert-v01@openssh.com,sk-ecdsa-sha2-nistp256-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,sk-ecdsa-sha2-nistp256@openssh.com,rsa-sha2-512,rsa-sha2-256\n")
)

// sshFipsServerConfWrongCipher is sshFipsServerConf with only the Ciphers line
// downgraded to a non-FIPS cipher (aes256-cbc). Every other directive stays
// valid, so the sole failing criterion is the sshd Ciphers content match —
// isolating the content-match dimension of the ssh checks from the
// file-existence dimension.
var sshFipsServerConfWrongCipher = bytes.Replace(sshFipsServerConf,
	[]byte("Ciphers aes128-gcm@openssh.com,aes256-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\n"),
	[]byte("Ciphers aes256-cbc\n"), 1)

// sshConfigMain and sshdConfigMain are the OpenSSH client/server top-level
// configs (shipped by openssh-client / openssh-server). DetectOpenSsl requires
// each to source its drop-in directory via an Include line so the FIPS policy
// files above are actually applied — a drop-in that is never Include'd is inert.
var (
	sshConfigMain  = []byte("Include /etc/ssh/ssh_config.d/*.conf\n")
	sshdConfigMain = []byte("Include /etc/ssh/sshd_config.d/*.conf\n")
)

// fipsCoreOps returns the ops that satisfy the OpenSSL (non-SSH) DetectOpenSsl
// criteria — FIPS module config, hardened openssl.cnf, both FIPS apk packages —
// plus apk records for openssh-client and openssh-server so DetectOpenSsl's
// package-gated SSH branches both engage. It deliberately lays down NO ssh
// config files, so callers exercise the SSH dimensions by adding (or omitting)
// them. Returned fresh each call so callers may append without aliasing.
func fipsCoreOps() []overlay.Op {
	return []overlay.Op{
		overlay.PutFile("etc/ssl/fipsmodule.cnf", fipsModuleCnf, 0o644, 0, 0),
		overlay.PutFile("etc/ssl/openssl.cnf", opensslCnf, 0o644, 0, 0),
		overlay.AppendFile("usr/lib/apk/db/installed", apkFIPSPackages),
		overlay.AppendFile("usr/lib/apk/db/installed", apkOpenSSHClientStanza),
		overlay.AppendFile("usr/lib/apk/db/installed", apkOpenSSHServerStanza),
	}
}

// fipsPresentOps returns the ops that satisfy every DetectOpenSsl criterion:
// fipsCoreOps (OpenSSL config/packages + both openssh packages installed) plus
// the OpenSSH client and server FIPS policy drop-ins and the top-level
// ssh_config/sshd_config that Include those drop-in directories. Returned fresh
// each call so callers may append without aliasing.
func fipsPresentOps() []overlay.Op {
	return append(fipsCoreOps(),
		overlay.PutFile("etc/ssh/ssh_config", sshConfigMain, 0o644, 0, 0),
		overlay.PutFile("etc/ssh/sshd_config", sshdConfigMain, 0o644, 0, 0),
		overlay.PutFile("etc/ssh/ssh_config.d/10-ssh-fips.conf", sshFipsClientConf, 0o644, 0, 0),
		overlay.PutFile("etc/ssh/sshd_config.d/10-sshd-fips.conf", sshFipsServerConf, 0o644, 0, 0),
	)
}

// nonRootUID/nonRootGID is the unprivileged "nobody" identity used to make the
// file-ownership checks fail; the in-container extractor preserves these via a
// confined chown so the OVAL uid/gid state no longer matches root:root.
const (
	nonRootUID = 65534
	nonRootGID = 65534
)

// matrixCase is one definition's pass or fail fixture. want maps a rule id to
// the verdict the fixture must produce.
type matrixCase struct {
	name string
	ops  []overlay.Op
	// containerVars are the OSCAP_CONTAINER_VARS entries ("NAME=value") the scan
	// exposes to oscap's environmentvariable58 offline probe. nil for fixtures
	// whose asserted rules do not read the container environment.
	containerVars []string
	want          map[string]results.Result
}

// matrixCases returns the offline scan matrix. Each row is one OVAL
// definition's pass or fail fixture. Verdicts were derived from each OVAL
// document and confirmed live against the pinned base; note where clean is FAIL
// (see DetectOpenSsl) because the rule asserts presence of content absent from a
// vanilla wolfi-base. Both TestOfflineFixtureMatrix and the structural SCE
// exclusion test read this single source so the exclusion is enforced against
// the same data the matrix runs.
func matrixCases() []matrixCase {
	return []matrixCase{
		// RemoteAccessServices: clean base has no banned remote-access package.
		{
			name: "remote_access/pass_clean",
			want: map[string]results.Result{ruleRemoteAccessServices: results.Pass},
		},
		{
			name: "remote_access/fail_dropbear_installed",
			ops:  []overlay.Op{overlay.AppendFile("usr/lib/apk/db/installed", apkDropbearStanza)},
			want: map[string]results.Result{ruleRemoteAccessServices: results.Fail},
		},
		{
			// openssh-server ships a listening sshd and is banned, so recording it
			// must trip the rule. (The openssh metapackage pulls openssh-server in,
			// so an `apk add openssh` image fails here too.)
			name: "remote_access/fail_openssh_server_installed",
			ops:  []overlay.Op{overlay.AppendFile("usr/lib/apk/db/installed", apkOpenSSHServerStanza)},
			want: map[string]results.Result{ruleRemoteAccessServices: results.Fail},
		},
		{
			// openssh-sftp-server ships the sftp-server subsystem and is banned in
			// its own right. It is a distinct alternative in the pattern rather than
			// a suffix of openssh-server, so nothing else covers it: before this row
			// the datastream had lost the package while the standalone OVAL kept it,
			// and no test noticed.
			name: "remote_access/fail_openssh_sftp_server_installed",
			ops:  []overlay.Op{overlay.AppendFile("usr/lib/apk/db/installed", apkOpenSSHSftpServerStanza)},
			want: map[string]results.Result{ruleRemoteAccessServices: results.Fail},
		},
		{
			// openssh-client is deliberately NOT banned: a client-only image such as
			// go-fips must PASS the remote-access rule. Guards against a regression
			// that widens the pattern to match openssh-client (or the `openssh`
			// alternative bleeding into the "-client" suffix).
			name: "remote_access/pass_openssh_client_allowed",
			ops:  []overlay.Op{overlay.AppendFile("usr/lib/apk/db/installed", apkOpenSSHClientStanza)},
			want: map[string]results.Result{ruleRemoteAccessServices: results.Pass},
		},
		{
			// dropbear-convert shares a banned prefix but its "-convert" word suffix
			// must not match the anchored version-suffix pattern, so the rule passes.
			name: "remote_access/pass_word_suffix_not_banned",
			ops:  []overlay.Op{overlay.AppendFile("usr/lib/apk/db/installed", apkDropbearConvertStanza)},
			want: map[string]results.Result{ruleRemoteAccessServices: results.Pass},
		},

		// PackageSignature: clean base ships only https apk repositories.
		{
			name: "package_signature/pass_clean",
			want: map[string]results.Result{rulePackageSignature: results.Pass},
		},
		{
			name: "package_signature/fail_plain_http_repo",
			ops:  []overlay.Op{overlay.AppendFile("etc/apk/repositories", plainHTTPRepo)},
			want: map[string]results.Result{rulePackageSignature: results.Fail},
		},
		{
			// A comment line and an https line are both exempt from the pattern, so
			// appending them to the clean https-only base keeps the rule passing.
			name: "package_signature/pass_comment_and_https",
			ops:  []overlay.Op{overlay.AppendFile("etc/apk/repositories", commentedAndHTTPSRepos)},
			want: map[string]results.Result{rulePackageSignature: results.Pass},
		},

		// CertificateAudit is an AND of five criteria: the CA bundle exists, the
		// ca-certificates stamp file exists and yields one SHA-256 digest, the
		// bundle's SHA-256 equals that digest, SSL_CERT_FILE names a copy of the
		// bundle carrying that same digest, and — only where
		// /etc/ssl/certs/java/cacerts exists — the Java truststore likewise
		// matches its own stamp file. Nothing here depends on a hash pinned in
		// the datastream, so no fixture needs to move when an upstream bundle
		// rolls. The pass fixtures also set SSL_CERT_FILE; the fail fixtures each
		// isolate one failing dimension while holding the others valid.
		{
			name:          "certificate_audit/pass_clean",
			containerVars: []string{"SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt"},
			want:          map[string]results.Result{ruleCertificateAudit: results.Pass},
		},
		{
			// Hash dimension: tampered bundle, SSL_CERT_FILE still valid.
			name:          "certificate_audit/fail_tampered_bundle",
			ops:           []overlay.Op{overlay.AppendFile(caBundlePath, caTamper)},
			containerVars: []string{"SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt"},
			want:          map[string]results.Result{ruleCertificateAudit: results.Fail},
		},
		{
			// Hash dimension from the stamp side: clean bundle, stamp claims a
			// digest it cannot have.
			name:          "certificate_audit/fail_wrong_stamp_digest",
			ops:           []overlay.Op{overlay.ReplaceFile(caStampPath, caStampWrongDigest)},
			containerVars: []string{"SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt"},
			want:          map[string]results.Result{ruleCertificateAudit: results.Fail},
		},
		{
			// Stamp dimension: stamp present but unparseable, so there is no
			// expected digest to compare against.
			name:          "certificate_audit/fail_malformed_stamp",
			ops:           []overlay.Op{overlay.ReplaceFile(caStampPath, caStampMalformed)},
			containerVars: []string{"SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt"},
			want:          map[string]results.Result{ruleCertificateAudit: results.Fail},
		},
		{
			// Stamp dimension: image ships no stamp file at all (e.g. a base
			// image whose ca-certificates predates it). The rule must not pass
			// vacuously.
			name:          "certificate_audit/fail_missing_stamp",
			ops:           []overlay.Op{overlay.RemoveFile(caStampPath)},
			containerVars: []string{"SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt"},
			want:          map[string]results.Result{ruleCertificateAudit: results.Fail},
		},
		{
			// Java dimension: a synthesized truststore agreeing with its stamp
			// must keep the rule passing. The base has no Java, so this is the
			// only fixture exercising the "present and matching" OR branch.
			name: "certificate_audit/pass_java_truststore",
			ops: []overlay.Op{
				overlay.PutFile(javaTrustStorePath, javaTrustStore, 0o444, 0, 0),
				overlay.PutFile(javaStampPath, javaStamp(javaTrustStore), 0o444, 0, 0),
			},
			containerVars: []string{"SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt"},
			want:          map[string]results.Result{ruleCertificateAudit: results.Pass},
		},
		{
			// Java dimension: truststore present but its stamp names a digest
			// for different content, i.e. a truststore modified in place.
			name: "certificate_audit/fail_java_wrong_stamp",
			ops: []overlay.Op{
				overlay.PutFile(javaTrustStorePath, javaTrustStore, 0o444, 0, 0),
				overlay.PutFile(javaStampPath, javaStamp([]byte("other content")), 0o444, 0, 0),
			},
			containerVars: []string{"SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt"},
			want:          map[string]results.Result{ruleCertificateAudit: results.Fail},
		},
		{
			// Java dimension: truststore present with no stamp beside it. The
			// absent-truststore OR branch must not rescue this — there is a
			// truststore, it just cannot be verified.
			name: "certificate_audit/fail_java_missing_stamp",
			ops: []overlay.Op{
				overlay.PutFile(javaTrustStorePath, javaTrustStore, 0o444, 0, 0),
			},
			containerVars: []string{"SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt"},
			want:          map[string]results.Result{ruleCertificateAudit: results.Fail},
		},
		{
			// Kaniko fallback branch: the bundle is copied to the /kaniko location
			// and SSL_CERT_FILE names that copy, the layout
			// cgr.dev/chainguard/kaniko ships. No stamp file sits beside the copy,
			// so it is held to the digest in the system stamp at /etc/ssl/certs,
			// which it matches.
			name:          "certificate_audit/pass_kaniko_bundle",
			ops:           []overlay.Op{overlay.CopyFile(caBundlePath, kanikoCABundlePath)},
			containerVars: []string{"SSL_CERT_FILE=/kaniko/ssl/certs/ca-certificates.crt"},
			want:          map[string]results.Result{ruleCertificateAudit: results.Pass},
		},
		{
			// Kaniko own-stamp branch: a stamp shipped beside the copy is what the
			// copy is checked against. The system stamp records the same digest
			// here, so this case proves the branch is reachable, not merely that
			// the fallback still fires — fail_kaniko_own_stamp_wrong_digest below
			// separates the two.
			name: "certificate_audit/pass_kaniko_own_stamp",
			ops: []overlay.Op{
				overlay.CopyFile(caBundlePath, kanikoCABundlePath),
				overlay.CopyFile(caStampPath, kanikoCAStampPath),
			},
			containerVars: []string{"SSL_CERT_FILE=/kaniko/ssl/certs/ca-certificates.crt"},
			want:          map[string]results.Result{ruleCertificateAudit: results.Pass},
		},
		{
			// Precedence: an untouched copy beside a stamp naming a digest it
			// cannot have. The system stamp would match, so the rule may only fail
			// if the stamp beside the copy takes priority over it rather than the
			// two being OR'd.
			name: "certificate_audit/fail_kaniko_own_stamp_wrong_digest",
			ops: []overlay.Op{
				overlay.CopyFile(caBundlePath, kanikoCABundlePath),
				overlay.CopyFile(caStampPath, kanikoCAStampPath),
				overlay.ReplaceFile(kanikoCAStampPath, caStampWrongDigest),
			},
			containerVars: []string{"SSL_CERT_FILE=/kaniko/ssl/certs/ca-certificates.crt"},
			want:          map[string]results.Result{ruleCertificateAudit: results.Fail},
		},
		{
			// Precedence, unparseable variant: a stamp beside the copy that yields
			// no digest is a present stamp, not an absent one, so the fallback must
			// not rescue it. This is the case a "no digest collected" test would
			// conflate with the file being missing.
			name: "certificate_audit/fail_kaniko_malformed_own_stamp",
			ops: []overlay.Op{
				overlay.CopyFile(caBundlePath, kanikoCABundlePath),
				overlay.CopyFile(caStampPath, kanikoCAStampPath),
				overlay.ReplaceFile(kanikoCAStampPath, caStampMalformed),
			},
			containerVars: []string{"SSL_CERT_FILE=/kaniko/ssl/certs/ca-certificates.crt"},
			want:          map[string]results.Result{ruleCertificateAudit: results.Fail},
		},
		{
			// Hash dimension on the /kaniko copy: the copy diverges from the digest
			// the system stamp records while the /etc bundle stays clean. Accepting
			// the alternative location must not mean accepting it unverified.
			name: "certificate_audit/fail_kaniko_tampered_bundle",
			ops: []overlay.Op{
				overlay.CopyFile(caBundlePath, kanikoCABundlePath),
				overlay.AppendFile(kanikoCABundlePath, caTamper),
			},
			containerVars: []string{"SSL_CERT_FILE=/kaniko/ssl/certs/ca-certificates.crt"},
			want:          map[string]results.Result{ruleCertificateAudit: results.Fail},
		},
		{
			// Existence dimension on the /kaniko copy: SSL_CERT_FILE names it but no
			// such file was laid down, so naming an accepted path is not on its own
			// enough to pass.
			name:          "certificate_audit/fail_kaniko_env_without_bundle",
			containerVars: []string{"SSL_CERT_FILE=/kaniko/ssl/certs/ca-certificates.crt"},
			want:          map[string]results.Result{ruleCertificateAudit: results.Fail},
		},
		{
			// Env dimension: bundle valid, SSL_CERT_FILE points elsewhere.
			name:          "certificate_audit/fail_wrong_ssl_cert_file",
			containerVars: []string{"SSL_CERT_FILE=/wrong/path.crt"},
			want:          map[string]results.Result{ruleCertificateAudit: results.Fail},
		},
		{
			// Env dimension: bundle valid, SSL_CERT_FILE unset entirely.
			name: "certificate_audit/fail_unset_ssl_cert_file",
			want: map[string]results.Result{ruleCertificateAudit: results.Fail},
		},

		// UserPasswordConfigured: clean base has only locked ("!"/"*") accounts.
		{
			name: "user_password/pass_clean",
			want: map[string]results.Result{ruleUserPasswordConfigured: results.Pass},
		},
		{
			name: "user_password/fail_active_password",
			ops:  []overlay.Op{overlay.AppendFile("etc/shadow", activeShadowEntry)},
			want: map[string]results.Result{ruleUserPasswordConfigured: results.Fail},
		},
		{
			// An empty password field is passwordless login; the negative-lookahead
			// still matches it, so the rule must fail.
			name: "user_password/fail_empty_password",
			ops:  []overlay.Op{overlay.AppendFile("etc/shadow", emptyShadowPassword)},
			want: map[string]results.Result{ruleUserPasswordConfigured: results.Fail},
		},

		// NoUsers: clean base has only locked entries in /etc/shadow.
		{
			name: "no_users/pass_clean",
			want: map[string]results.Result{ruleNoUsers: results.Pass},
		},
		// A locked entry after `nobody` is what apko writes for run-as
		// users; it cannot log in and must not fail the check.
		{
			name: "no_users/pass_locked_extra_user",
			ops:  []overlay.Op{overlay.AppendFile("etc/shadow", lockedShadowUser)},
			want: map[string]results.Result{ruleNoUsers: results.Pass},
		},
		{
			name: "no_users/fail_unlocked_user",
			ops:  []overlay.Op{overlay.AppendFile("etc/shadow", activeShadowEntry)},
			want: map[string]results.Result{ruleNoUsers: results.Fail},
		},
		{
			name: "no_users/fail_empty_password_user",
			ops:  []overlay.Op{overlay.AppendFile("etc/shadow", emptyShadowPassword)},
			want: map[string]results.Result{ruleNoUsers: results.Fail},
		},

		// VarLogPermissions: clean base /var/log is root:root.
		{
			name: "var_log/pass_clean",
			want: map[string]results.Result{ruleVarLogPermissions: results.Pass},
		},
		{
			name: "var_log/fail_non_root_owner",
			ops:  []overlay.Op{overlay.Chown("var/log", nonRootUID, nonRootGID)},
			want: map[string]results.Result{ruleVarLogPermissions: results.Fail},
		},

		// LibraryPermissions: clean base /usr/lib tree is root:root.
		{
			name: "library_permissions/pass_clean",
			want: map[string]results.Result{ruleLibraryPermissions: results.Pass},
		},
		{
			name: "library_permissions/fail_non_root_owner",
			ops:  []overlay.Op{overlay.Chown("usr/lib/apk/db/installed", nonRootUID, nonRootGID)},
			want: map[string]results.Result{ruleLibraryPermissions: results.Fail},
		},

		// DetectOpenSsl is inverted: a vanilla wolfi-base lacks the OpenSSL FIPS
		// module config, the FIPS apk packages, and the OpenSSH FIPS drop-ins this
		// rule requires, so the CLEAN tree FAILS. The "pass" fixtures synthesize
		// every required file and package record via fipsPresentOps.
		//
		// The base does now ship /etc/ssl/openssl.cnf, which it did not when these
		// fixtures were written, so that file's absence is no longer part of why
		// the clean tree fails. fail_clean_no_fips is deliberately op-free: it
		// asserts that an *unmodified* image fails, which is what a real scan of
		// wolfi-base yields. That means its discriminating power tracks whatever
		// the base ships — but it degrades loudly, not silently: if the base ever
		// gained the FIPS module config and packages, this row would flip to pass
		// and fail the suite rather than quietly assert less.
		{
			name: "detect_openssl/fail_clean_no_fips",
			want: map[string]results.Result{ruleDetectOpenSsl: results.Fail},
		},
		{
			// All FIPS files/packages and SSH drop-ins present and OPENSSL_CONF
			// unset: the OPENSSL_CONF criterion (any_exist + check=all) is vacuously
			// satisfied when the variable is absent, so the rule passes.
			name: "detect_openssl/pass_fips_present",
			ops:  fipsPresentOps(),
			want: map[string]results.Result{ruleDetectOpenSsl: results.Pass},
		},
		{
			// FIPS present and OPENSSL_CONF explicitly set to the sanctioned path:
			// the OPENSSL_CONF criterion is satisfied, so the rule passes.
			name:          "detect_openssl/pass_openssl_conf_correct",
			ops:           fipsPresentOps(),
			containerVars: []string{"OPENSSL_CONF=/etc/ssl/openssl.cnf"},
			want:          map[string]results.Result{ruleDetectOpenSsl: results.Pass},
		},
		{
			// FIPS otherwise valid but OPENSSL_CONF points elsewhere: the
			// OPENSSL_CONF criterion fails, so the AND'd rule fails.
			name:          "detect_openssl/fail_openssl_conf_wrong",
			ops:           fipsPresentOps(),
			containerVars: []string{"OPENSSL_CONF=/wrong/openssl.cnf"},
			want:          map[string]results.Result{ruleDetectOpenSsl: results.Fail},
		},
		{
			// The *doc* subpackages are installed instead of the real FIPS packages:
			// the package patterns reject word suffixes, so tst:3/tst:4 fail. No
			// openssh packages are installed, so the SSH branches are gated off and
			// irrelevant — the rule fails purely on the OpenSSL package dimension.
			name: "detect_openssl/fail_doc_subpackage_only",
			ops: []overlay.Op{
				overlay.PutFile("etc/ssl/fipsmodule.cnf", fipsModuleCnf, 0o644, 0, 0),
				overlay.PutFile("etc/ssl/openssl.cnf", opensslCnf, 0o644, 0, 0),
				overlay.AppendFile("usr/lib/apk/db/installed", apkFIPSPackagesDocSubpkg),
			},
			want: map[string]results.Result{ruleDetectOpenSsl: results.Fail},
		},
		{
			// Both openssh packages installed and the main configs Include their
			// drop-in dirs, but the SSH FIPS drop-ins are absent: both gated branches
			// engage and their drop-in content criteria collect nothing, so the rule
			// fails. Isolates the SSH drop-in file-existence dimension.
			name: "detect_openssl/fail_missing_ssh_fips_conf",
			ops: append(fipsCoreOps(),
				overlay.PutFile("etc/ssh/ssh_config", sshConfigMain, 0o644, 0, 0),
				overlay.PutFile("etc/ssh/sshd_config", sshdConfigMain, 0o644, 0, 0),
			),
			want: map[string]results.Result{ruleDetectOpenSsl: results.Fail},
		},
		{
			// Both openssh packages installed, client drop-in valid, but the sshd
			// Ciphers line is downgraded to a non-FIPS cipher: the server branch's
			// Ciphers content criterion fails. Isolates the SSH content-match
			// dimension (and proves the server branch is enforced when installed).
			name: "detect_openssl/fail_wrong_ssh_fips_value",
			ops: append(fipsCoreOps(),
				overlay.PutFile("etc/ssh/ssh_config", sshConfigMain, 0o644, 0, 0),
				overlay.PutFile("etc/ssh/sshd_config", sshdConfigMain, 0o644, 0, 0),
				overlay.PutFile("etc/ssh/ssh_config.d/10-ssh-fips.conf", sshFipsClientConf, 0o644, 0, 0),
				overlay.PutFile("etc/ssh/sshd_config.d/10-sshd-fips.conf", sshFipsServerConfWrongCipher, 0o644, 0, 0),
			),
			want: map[string]results.Result{ruleDetectOpenSsl: results.Fail},
		},
		{
			// Both openssh packages installed and drop-ins present, but the top-level
			// ssh_config/sshd_config are absent so nothing Include's the drop-in dirs:
			// the two Include criteria collect nothing and fail. Isolates the
			// drop-in-wiring dimension — a drop-in that is never sourced is inert.
			name: "detect_openssl/fail_ssh_config_missing_include",
			ops: append(fipsCoreOps(),
				overlay.PutFile("etc/ssh/ssh_config.d/10-ssh-fips.conf", sshFipsClientConf, 0o644, 0, 0),
				overlay.PutFile("etc/ssh/sshd_config.d/10-sshd-fips.conf", sshFipsServerConf, 0o644, 0, 0),
			),
			want: map[string]results.Result{ruleDetectOpenSsl: results.Fail},
		},
		{
			// Client-only image (openssh-client installed, openssh-server NOT): the
			// server branch is gated off, and the correct client config + drop-in
			// satisfy the client branch, so the rule PASSES even with no sshd_config
			// and no server drop-in. This mirrors the cgr.dev go-fips image.
			name: "detect_openssl/pass_client_only_no_server",
			ops: []overlay.Op{
				overlay.PutFile("etc/ssl/fipsmodule.cnf", fipsModuleCnf, 0o644, 0, 0),
				overlay.PutFile("etc/ssl/openssl.cnf", opensslCnf, 0o644, 0, 0),
				overlay.AppendFile("usr/lib/apk/db/installed", apkFIPSPackages),
				overlay.AppendFile("usr/lib/apk/db/installed", apkOpenSSHClientStanza),
				overlay.PutFile("etc/ssh/ssh_config", sshConfigMain, 0o644, 0, 0),
				overlay.PutFile("etc/ssh/ssh_config.d/10-ssh-fips.conf", sshFipsClientConf, 0o644, 0, 0),
			},
			want: map[string]results.Result{ruleDetectOpenSsl: results.Pass},
		},
		{
			// Neither openssh package installed: both SSH branches are gated off, so
			// the rule PASSES on the OpenSSL criteria alone with no ssh files present.
			name: "detect_openssl/pass_no_openssh_installed",
			ops: []overlay.Op{
				overlay.PutFile("etc/ssl/fipsmodule.cnf", fipsModuleCnf, 0o644, 0, 0),
				overlay.PutFile("etc/ssl/openssl.cnf", opensslCnf, 0o644, 0, 0),
				overlay.AppendFile("usr/lib/apk/db/installed", apkFIPSPackages),
			},
			want: map[string]results.Result{ruleDetectOpenSsl: results.Pass},
		},
		{
			// Server-only image (openssh-server installed, openssh-client NOT) with no
			// sshd_config or server drop-in: the client branch is gated off, but the
			// engaged server branch fails on the absent config/drop-in, so the rule
			// FAILS — proving the server gate enforces when openssh-server is present.
			name: "detect_openssl/fail_server_installed_missing_config",
			ops: []overlay.Op{
				overlay.PutFile("etc/ssl/fipsmodule.cnf", fipsModuleCnf, 0o644, 0, 0),
				overlay.PutFile("etc/ssl/openssl.cnf", opensslCnf, 0o644, 0, 0),
				overlay.AppendFile("usr/lib/apk/db/installed", apkFIPSPackages),
				overlay.AppendFile("usr/lib/apk/db/installed", apkOpenSSHServerStanza),
			},
			want: map[string]results.Result{ruleDetectOpenSsl: results.Fail},
		},
	}
}

// TestOfflineFixtureMatrix asserts, for each offline-capable OVAL definition, a
// pass fixture and a fail fixture against the real openscap scanner. Without
// OSCAP_OFFLINE_REQUIRE it skips (never fails) when docker, the datastream, or
// the registry is unavailable; with it set, a prerequisite gap fails the job.
// Once the harness is built every subtest runs in parallel against the shared,
// immutable base tar bytes and entrypoint binary. A verdict that disagrees with
// the derived expectation is a hard failure.
func TestOfflineFixtureMatrix(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip("skipping offline scan matrix in -short mode")
	}

	h, ok := buildHarness(t)
	if !ok {
		// buildHarness skips or fatals on a prerequisite gap, so this is only
		// reached defensively.
		t.Skip("offline scan prerequisites unavailable; skipping matrix")
	}

	for _, tc := range matrixCases() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			report, ran := h.scanFixture(t, tc.ops, tc.containerVars)
			if !ran {
				// scanFixture skips or fatals when a scan cannot run, so this is
				// only reached defensively.
				skipOrFatal(t, h.requireScans, "scan could not run; skipping assertion")
				return
			}

			got := make(map[string]results.Result, len(tc.want))
			for id := range tc.want {
				v, ok := report.RuleResult(id)
				if !ok {
					t.Fatalf("rule %q absent from results", id)
				}
				got[id] = v
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("rule verdicts mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestSCERulesExcludedFromMatrix enforces structurally that no SCE-backed rule
// is asserted by the offline matrix. SCE rules run AslrCheck.sh against the live
// host kernel (not the OSCAP_PROBE_ROOT tree), so their verdict is a property of
// the runner, not the fixture; pinning one here would be host-coupled or
// meaningless. The check iterates the actual matrix cases (the same data the
// matrix runs) rather than the source text, so an SCE rule added via its named
// constant is still caught.
func TestSCERulesExcludedFromMatrix(t *testing.T) {
	t.Parallel()

	sce := sceRuleSet()
	if len(sce) == 0 {
		t.Fatal("SCE rule set is empty; the exclusion guard would be meaningless")
	}

	for _, tc := range matrixCases() {
		for id := range tc.want {
			if _, banned := sce[id]; banned {
				t.Errorf("matrix case %q asserts SCE rule %q; SCE rules must be excluded from the offline matrix", tc.name, id)
			}
		}
	}
}

// TestParseWolfiBaseRef proves baseRef selects the digest-pinned wolfi-base FROM
// line even amid other stages, and fails closed when no such line exists.
func TestParseWolfiBaseRef(t *testing.T) {
	t.Parallel()

	const pinned = wolfiBaseRepo + ":latest@sha256:7e62cecd3c5712dba6e52c5260afb8f9d7a23b9bbcdd26ad7508a811e74b766d"

	realDockerfile, err := os.ReadFile(filepath.Clean(filepath.Join("..", "..", "..", "e2e", "fixtures", "baseline-clean", "Dockerfile")))
	if err != nil {
		t.Fatalf("reading real baseline-clean Dockerfile: %v", err)
	}

	tests := []struct {
		name    string
		content []byte
		want    string
		wantErr error
	}{
		{
			name:    "multi_stage_selects_wolfi_base",
			content: []byte("FROM golang:1.26@sha256:0000000000000000000000000000000000000000000000000000000000000000 AS build\nRUN go build\n" + "FROM " + pinned + "\nLABEL x=y\n"),
			want:    pinned,
		},
		{
			name:    "unpinned_wolfi_base_fails",
			content: []byte("FROM " + wolfiBaseRepo + ":latest\n"),
			wantErr: errNoWolfiBaseRef,
		},
		{
			name:    "no_wolfi_base_fails",
			content: []byte("FROM golang:1.26@sha256:1111111111111111111111111111111111111111111111111111111111111111\n"),
			wantErr: errNoWolfiBaseRef,
		},
		{
			name:    "real_baseline_clean_dockerfile",
			content: realDockerfile,
			want:    pinned,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := parseWolfiBaseRef(tc.content)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("parseWolfiBaseRef err = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseWolfiBaseRef: %v", err)
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("parseWolfiBaseRef ref mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// recordingFataler captures whether Skipf or Fatalf was invoked without ending
// the goroutine, so skipOrFatal's branch can be asserted directly.
type recordingFataler struct {
	skipped bool
	fatal   bool
	msg     string
}

func (r *recordingFataler) Helper() {}

func (r *recordingFataler) Skipf(format string, args ...any) {
	r.skipped = true
	r.msg = fmt.Sprintf(format, args...)
}

func (r *recordingFataler) Fatalf(format string, args ...any) {
	r.fatal = true
	r.msg = fmt.Sprintf(format, args...)
}

// TestSkipOrFatal proves the strict-mode gate: required => Fatalf, not required
// => Skipf, with the message threaded through in both cases.
func TestSkipOrFatal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		require     bool
		wantSkipped bool
		wantFatal   bool
	}{
		{name: "required_fatals", require: true, wantFatal: true},
		{name: "not_required_skips", require: false, wantSkipped: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rec := &recordingFataler{}
			skipOrFatal(rec, tc.require, "reason %d", 42)
			if rec.skipped != tc.wantSkipped {
				t.Errorf("skipped = %v, want %v", rec.skipped, tc.wantSkipped)
			}
			if rec.fatal != tc.wantFatal {
				t.Errorf("fatal = %v, want %v", rec.fatal, tc.wantFatal)
			}
			if rec.msg != "reason 42" {
				t.Errorf("msg = %q, want %q", rec.msg, "reason 42")
			}
		})
	}
}
