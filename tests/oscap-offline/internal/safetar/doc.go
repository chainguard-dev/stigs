// Package safetar extracts a tar stream into a destination directory using
// os.Root as a hard confinement boundary, so that no member can ever read or
// write a path outside that directory.
//
// All filesystem operations go through the *os.Root returned by os.OpenRoot.
// On Linux this resolves every path with openat2/RESOLVE_BENEATH, which confines
// path traversal and symlink resolution at the syscall layer rather than relying
// on string-prefix checks. A lexical filepath.IsLocal pre-check rejects non-local
// names early and yields precise sentinel errors; os.Root is the enforced
// boundary.
//
// Extract handles the range of tar member forms as follows:
//   - ".." traversal and absolute member names are rejected or confined.
//   - Symlink targets are validated to stay within the root; os.Root refuses to
//     follow any symlink out of the root regardless.
//   - Hardlink targets must be local and already exist within the root.
//   - Character, block, fifo and socket nodes are skipped (and can be rejected
//     via RejectUnsupported); real device nodes are never created.
//   - Resource use is bounded by Limits (entry count, total bytes, per-file bytes).
//   - Name forms (empty, ".", embedded NUL, backslashes, overlong components)
//     are cleaned or rejected deterministically.
//   - setuid and setgid bits are masked off by default; ordinary mode bits are
//     preserved.
//   - PAX/GNU extended and global headers are ignored, never materialized.
//   - Context cancellation is honored between members.
//
// Options and Limits carry secure defaults via DefaultOptions and DefaultLimits.
// Errors are wrapped and matchable with errors.Is against ErrUnsafePath,
// ErrUnsafeLink, ErrUnsupportedEntry, and ErrLimitExceeded.
//
// Ownership of synthesized parents: directories the extractor must create for a
// member whose parents were never declared in the tar carry no header, so under
// PreserveOwnership they are owned by the extracting process rather than any
// header uid/gid. A fixture that needs a specific directory ownership must
// include an explicit directory member for that path.
//
// Concurrency and destination contract: extraction is single-threaded into a
// freshly created, private (0700) directory with no concurrent writers, so the
// os.Root Chown/Chmod TOCTOU window the Go docs note is unreachable here.
package safetar
