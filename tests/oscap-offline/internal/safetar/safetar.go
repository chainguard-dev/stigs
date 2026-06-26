package safetar

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// Sentinel errors returned by Extract. Callers should match with errors.Is.
var (
	// ErrUnsafePath is returned when a member name is not a clean, local,
	// relative path (absolute, contains "..", embeds NUL, or has an overlong
	// component).
	ErrUnsafePath = errors.New("unsafe member path")
	// ErrUnsafeLink is returned when a symlink or hardlink target is absolute,
	// escapes the root, or (for hardlinks) does not already exist within root.
	ErrUnsafeLink = errors.New("unsafe link target")
	// ErrUnsupportedEntry is returned for entry types that are skipped by
	// policy when Options.RejectUnsupported is set (e.g. device nodes).
	ErrUnsupportedEntry = errors.New("unsupported entry type")
	// ErrLimitExceeded is returned when an extraction breaches one of the
	// configured Limits (entries, total bytes, or single-file bytes).
	ErrLimitExceeded = errors.New("extraction limit exceeded")
)

// maxComponentLen bounds the length of any single path component. POSIX NAME_MAX
// is typically 255; rejecting longer components avoids pathological names.
const maxComponentLen = 255

// Unix permission special bits as they appear in a raw tar header Mode. These
// are distinct from the high os.FileMode bits (os.ModeSetuid etc.), so they
// must be mapped explicitly rather than via a plain os.FileMode conversion.
const (
	tarSetuid = 0o4000
	tarSetgid = 0o2000
	tarSticky = 0o1000
)

// dirPerm is the mode used for directories the extractor must synthesize for an
// entry whose parents were never explicitly declared.
const dirPerm os.FileMode = 0o755

// Limits caps resource consumption during extraction. A zero value in any
// field disables that particular limit.
type Limits struct {
	// MaxEntries caps the number of tar members processed.
	MaxEntries int
	// MaxTotalBytes caps the sum of bytes written across all regular files.
	MaxTotalBytes int64
	// MaxFileBytes caps the bytes written for any single regular file.
	MaxFileBytes int64
}

// DefaultLimits returns conservative limits sized for container-rootfs
// fixtures: generous enough for a real wolfi-base tree, small enough to stop a
// runaway stream long before it exhausts the disk.
func DefaultLimits() Limits {
	return Limits{
		MaxEntries:    1 << 18,   // 262144 entries
		MaxTotalBytes: 2 << 30,   // 2 GiB total
		MaxFileBytes:  512 << 20, // 512 MiB per file
	}
}

// Options configures Extract.
type Options struct {
	// Limits caps resource consumption; see Limits.
	Limits Limits
	// AllowSymlinks controls whether symlink members are materialized. When
	// false, symlinks are skipped. When true (the default), symlink targets are
	// validated to remain within the root. The os.Root boundary refuses to
	// follow any symlink out of root regardless of this setting.
	AllowSymlinks bool
	// AllowAbsoluteSymlinks permits symlink members whose target is an absolute
	// path (e.g. a container rootfs busybox applet usr/bin/[ -> /bin/busybox).
	// When false (the default) absolute targets are rejected as ErrUnsafeLink.
	// Enabling this only affects link creation, which merely stores the target
	// string; the os.Root boundary still refuses to *follow* any symlink out of
	// root on every subsequent operation, and ".." escapes remain rejected.
	AllowAbsoluteSymlinks bool
	// RejectUnsupported turns the silent skipping of entry types that are never
	// materialized (character/block/fifo/socket device nodes and any unknown
	// typeflag) into a wrapped ErrUnsupportedEntry instead. Device nodes are
	// never created regardless of this setting, since os.Root exposes no mknod
	// and a fixture has no need for them.
	RejectUnsupported bool
	// PreserveSetID keeps setuid/setgid mode bits from the header. When false
	// (the default) those bits are masked off; fixtures do not need them, so
	// stripping them avoids materializing setuid/setgid files.
	PreserveSetID bool
	// PreserveOwnership applies each member's header uid/gid to the materialized
	// entry via a root-confined chown (lchown for symlinks). When false (the
	// default) the extractor leaves ownership at whatever the creating process
	// yields, which on a root extraction is root:root. The offline SCAP
	// entrypoint enables this so the file-ownership OVAL checks read the fixture
	// header's uid/gid rather than a flattened root:root. Chown requires the
	// process to own the target uid/gid mapping (it runs as root in the scanner
	// container); when it lacks the privilege the chown error surfaces rather
	// than being silently dropped.
	PreserveOwnership bool
}

// DefaultOptions returns the recommended secure defaults: symlinks allowed but
// confined, device nodes skipped, setuid/setgid masked, and DefaultLimits
// applied.
func DefaultOptions() Options {
	return Options{
		Limits:        DefaultLimits(),
		AllowSymlinks: true,
	}
}

// counters tracks consumption against the configured limits.
type counters struct {
	entries int
	total   int64
}

// Extract reads a tar stream from r and materializes its members under dest,
// using os.Root as the confinement boundary so that no operation can escape
// dest by any path, symlink, or hardlink. dest must already exist.
//
// Member handling: traversal and absolute names are rejected or confined,
// symlink and hardlink targets are validated, device nodes are skipped by
// policy, total and per-file byte counts are bounded by Limits, extended and
// global headers are ignored, and setuid/setgid bits are masked unless
// explicitly preserved. Context cancellation is honored between members.
func Extract(ctx context.Context, r io.Reader, dest string, opts Options) error {
	root, err := os.OpenRoot(dest)
	if err != nil {
		return fmt.Errorf("opening root %q: %w", dest, err)
	}
	defer func() { _ = root.Close() }()

	var c counters
	// One copy buffer is reused across every regular-file member for the whole
	// Extract call, avoiding a fresh allocation per file.
	buf := make([]byte, 32*1024)
	tr := tar.NewReader(r)
	for {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("extraction cancelled: %w", err)
		}

		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("reading tar entry: %w", err)
		}

		if err := handleEntry(root, tr, hdr, opts, &c, buf); err != nil {
			return err
		}
	}
}

// handleEntry processes a single tar member. It returns a non-nil error when
// the member is unsafe or a limit is breached; benign members that policy
// ignores (extended headers, disabled or unsupported types) return nil so the
// caller advances to the next member.
func handleEntry(root *os.Root, tr io.Reader, hdr *tar.Header, opts Options, c *counters, buf []byte) error {
	// Extended and global headers carry metadata only; the reader already folds
	// them into the following member, so never materialize them.
	switch hdr.Typeflag {
	case tar.TypeXHeader, tar.TypeXGlobalHeader:
		return nil
	}

	c.entries++
	if opts.Limits.MaxEntries > 0 && c.entries > opts.Limits.MaxEntries {
		return fmt.Errorf("entry count %d exceeds max %d: %w", c.entries, opts.Limits.MaxEntries, ErrLimitExceeded)
	}

	name, dec := cleanName(hdr.Name)
	switch dec {
	case decisionSkip:
		// Empty/dot names refer to the root itself; advance to the next member.
		return nil
	case decisionReject:
		return fmt.Errorf("member %q: %w", hdr.Name, ErrUnsafePath)
	}

	switch hdr.Typeflag {
	case tar.TypeDir:
		if err := writeDir(root, name, headerMode(hdr, opts)); err != nil {
			return err
		}
		return applyOwnership(root, name, hdr, opts, false)
	case tar.TypeReg:
		// tar.Reader normalizes the deprecated TypeRegA to TypeReg, so a single
		// case covers both.
		return writeReg(root, tr, name, hdr, opts, c, buf)
	case tar.TypeSymlink:
		if !opts.AllowSymlinks {
			return nil
		}
		if err := writeSymlink(root, name, hdr.Linkname, opts.AllowAbsoluteSymlinks); err != nil {
			return err
		}
		// Lchown the link itself so ownership lands on the symlink, never the
		// (possibly out-of-root) target.
		return applyOwnership(root, name, hdr, opts, true)
	case tar.TypeLink:
		return writeHardlink(root, name, hdr.Linkname)
	default:
		// Character/block/fifo/socket nodes and any unknown typeflag are never
		// materialized: os.Root exposes no mknod and a fixture has no need for
		// real device nodes. Skip silently, or reject when configured.
		if opts.RejectUnsupported {
			return fmt.Errorf("typeflag %q for %q: %w", hdr.Typeflag, name, ErrUnsupportedEntry)
		}
		return nil
	}
}

// decision is cleanName's verdict on a tar member name, distinguishing a usable
// clean name from a benign skip and an unsafe-path rejection without overloading
// the returned string.
type decision int

const (
	// decisionWrite means the returned name is clean, local and may be used.
	decisionWrite decision = iota
	// decisionSkip means the name refers to the root itself (empty or "."); the
	// caller advances to the next member without error.
	decisionSkip
	// decisionReject means the name is unsafe; the caller surfaces ErrUnsafePath.
	decisionReject
)

// cleanName validates and normalizes a tar member name into a clean, local,
// relative path. The returned decision states whether the name may be written,
// is a benign skip, or must be rejected; the returned string is meaningful only
// for decisionWrite.
func cleanName(raw string) (clean string, dec decision) {
	if raw == "" {
		return "", decisionSkip
	}
	if strings.ContainsRune(raw, 0) {
		// Embedded NUL: unsafe.
		return "", decisionReject
	}
	// Tar names use forward slashes; reject backslashes rather than silently
	// reinterpreting them.
	if strings.ContainsRune(raw, '\\') {
		return "", decisionReject
	}

	// Drop a leading slash so absolute names are confined under root rather than
	// reaching the real filesystem root; os.Root would reject the absolute form.
	cleaned := path.Clean(strings.TrimPrefix(raw, "/"))

	if cleaned == "." || cleaned == "/" {
		return "", decisionSkip // benign: refers to the root itself
	}
	// filepath.IsLocal is a lexical pre-check; os.Root is the enforced boundary.
	// It rejects absolute paths and any path that escapes the base via "..".
	if !filepath.IsLocal(cleaned) {
		return "", decisionReject
	}
	for comp := range strings.SplitSeq(cleaned, "/") {
		if len(comp) > maxComponentLen {
			return "", decisionReject
		}
	}
	return cleaned, decisionWrite
}

// headerMode derives the FileMode to apply, masking setuid/setgid unless the
// caller opted to preserve them. The sticky bit is preserved as it is harmless.
// The raw tar header Mode uses Unix octal special bits, which are mapped to the
// corresponding high os.FileMode bits explicitly.
func headerMode(hdr *tar.Header, opts Options) os.FileMode {
	mode := os.FileMode(hdr.Mode).Perm()
	if hdr.Mode&tarSticky != 0 {
		mode |= os.ModeSticky
	}
	if opts.PreserveSetID {
		if hdr.Mode&tarSetuid != 0 {
			mode |= os.ModeSetuid
		}
		if hdr.Mode&tarSetgid != 0 {
			mode |= os.ModeSetgid
		}
	}
	return mode
}

// applyOwnership chowns name to the header's uid/gid when opts.PreserveOwnership
// is set, using lchown for symlinks so the link itself is retargeted rather than
// whatever it points at. It is a no-op when preservation is disabled. The chown
// is confined to root, so it can never touch a path outside the extraction tree.
func applyOwnership(root *os.Root, name string, hdr *tar.Header, opts Options, isSymlink bool) error {
	if !opts.PreserveOwnership {
		return nil
	}
	chown := root.Chown
	if isSymlink {
		chown = root.Lchown
	}
	if err := chown(name, hdr.Uid, hdr.Gid); err != nil {
		return fmt.Errorf("setting ownership %d:%d on %q: %w", hdr.Uid, hdr.Gid, name, err)
	}
	return nil
}

// writeDir creates a directory (and any missing parents) confined to root.
func writeDir(root *os.Root, name string, mode os.FileMode) error {
	if err := root.MkdirAll(name, dirPerm); err != nil {
		return fmt.Errorf("creating dir %q: %w", name, err)
	}
	if err := root.Chmod(name, mode); err != nil {
		return fmt.Errorf("setting mode on dir %q: %w", name, err)
	}
	return nil
}

// writeReg materializes a regular file, enforcing per-file and total byte
// limits while streaming so the write stops as soon as a cap is reached. It
// applies ownership before the final mode so a chown cannot strip preserved
// setuid/setgid bits, and replaces any existing in-root symlink at name with a
// fresh regular file rather than writing through the link's target.
func writeReg(root *os.Root, tr io.Reader, name string, hdr *tar.Header, opts Options, c *counters, buf []byte) error {
	if err := ensureParent(root, name); err != nil {
		return err
	}
	// Remove any existing member at name first so a regular-file entry replaces an
	// in-root symlink instead of following it and clobbering its target. The
	// remove is confined to root; a missing target is the common case and ignored.
	if err := root.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("replacing %q: %w", name, err)
	}
	mode := headerMode(hdr, opts)
	// O_EXCL pairs with the prior Remove so the open neither follows a symlink nor
	// races a concurrent create: the path is known absent, so a fresh regular file
	// is created. OpenFile accepts only permission bits in perm, so special bits
	// (setuid, setgid, sticky) are applied by the explicit Chmod below.
	f, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode.Perm())
	if err != nil {
		return fmt.Errorf("creating file %q: %w", name, err)
	}
	copyErr := copyLimited(f, tr, name, opts, c, buf)
	closeErr := f.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return fmt.Errorf("closing file %q: %w", name, closeErr)
	}
	// Apply ownership before the final chmod: chown(2) clears setuid/setgid on a
	// regular file, so chowning first then chmodding guarantees preserved set-id
	// bits survive.
	if err := applyOwnership(root, name, hdr, opts, false); err != nil {
		return err
	}
	// Re-apply the mode: OpenFile's perm is subject to the umask, so an explicit
	// chmod guarantees the recorded permission bits land.
	if err := root.Chmod(name, mode); err != nil {
		return fmt.Errorf("setting mode on file %q: %w", name, err)
	}
	return nil
}

// copyLimited streams from tr to dst, stopping with ErrLimitExceeded if the
// member exceeds MaxFileBytes or the run exceeds MaxTotalBytes. It avoids
// loading the whole entry into memory, reusing the caller-provided buffer.
func copyLimited(dst io.Writer, tr io.Reader, name string, opts Options, c *counters, buf []byte) error {
	var fileBytes int64
	for {
		n, err := tr.Read(buf)
		if n > 0 {
			fileBytes += int64(n)
			c.total += int64(n)
			if opts.Limits.MaxFileBytes > 0 && fileBytes > opts.Limits.MaxFileBytes {
				return fmt.Errorf("file %q exceeds max %d bytes: %w", name, opts.Limits.MaxFileBytes, ErrLimitExceeded)
			}
			if opts.Limits.MaxTotalBytes > 0 && c.total > opts.Limits.MaxTotalBytes {
				return fmt.Errorf("total bytes exceed max %d: %w", opts.Limits.MaxTotalBytes, ErrLimitExceeded)
			}
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return fmt.Errorf("writing file %q: %w", name, werr)
			}
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("reading file %q: %w", name, err)
		}
	}
}

// writeSymlink validates the link target stays within root, then creates the
// symlink confined to root. Absolute targets are rejected unless allowAbs is
// set; the explicit pre-check rejects ".." escapes lexically and yields a
// precise sentinel error. os.Root still refuses to follow any symlink out of
// root on later operations regardless of allowAbs.
func writeSymlink(root *os.Root, name, target string, allowAbs bool) error {
	if !safeLinkTarget(name, target, allowAbs) {
		return fmt.Errorf("symlink %q -> %q: %w", name, target, ErrUnsafeLink)
	}
	if err := ensureParent(root, name); err != nil {
		return err
	}
	if err := root.Symlink(target, name); err != nil {
		return fmt.Errorf("creating symlink %q -> %q: %w", name, target, ErrUnsafeLink)
	}
	return nil
}

// writeHardlink validates the target is a local path that already exists within
// root, then creates the hard link confined to root.
func writeHardlink(root *os.Root, name, target string) error {
	cleanTarget, dec := cleanName(target)
	if dec != decisionWrite {
		return fmt.Errorf("hardlink %q -> %q: %w", name, target, ErrUnsafeLink)
	}
	// The target must already exist inside root; otherwise reject rather than
	// risk dangling or out-of-root linkage. Lstat is confined by os.Root.
	if _, err := root.Lstat(cleanTarget); err != nil {
		return fmt.Errorf("hardlink %q target %q absent in root: %w", name, target, ErrUnsafeLink)
	}
	if err := ensureParent(root, name); err != nil {
		return err
	}
	if err := root.Link(cleanTarget, name); err != nil {
		return fmt.Errorf("creating hardlink %q -> %q: %w", name, cleanTarget, ErrUnsafeLink)
	}
	return nil
}

// safeLinkTarget reports whether a symlink at name pointing to target resolves
// to a location lexically within root. Absolute targets are rejected unless
// allowAbs is set; relative targets are resolved against the link's own
// directory and must not escape via "..". When allowAbs permits an absolute
// target, the os.Root boundary still prevents following it out of root on any
// subsequent operation.
func safeLinkTarget(name, target string, allowAbs bool) bool {
	if target == "" || strings.ContainsRune(target, 0) {
		return false
	}
	// path.IsAbs uses slash semantics, so a leading "/" is exactly absoluteness.
	if path.IsAbs(target) {
		return allowAbs
	}
	// Resolve target relative to the directory containing the link, then verify
	// the result remains local to root.
	resolved := path.Join(path.Dir(name), target)
	return filepath.IsLocal(filepath.FromSlash(resolved))
}

// ensureParent creates any missing parent directories for name, confined to
// root. It is a no-op when name lives at the root. Parents synthesized here have
// no tar header, so even under PreserveOwnership they are owned by the extracting
// process: there is no header uid/gid to apply. A fixture that needs a specific
// directory ownership must include an explicit directory member for it.
func ensureParent(root *os.Root, name string) error {
	parent := path.Dir(name)
	if parent == "." || parent == "/" || parent == "" {
		return nil
	}
	if err := root.MkdirAll(parent, dirPerm); err != nil {
		return fmt.Errorf("creating parent of %q: %w", name, err)
	}
	return nil
}
