// Package overlay applies a declarative set of transforms to a base
// filesystem tar, producing a deterministic fixture tar.
//
// Each transform is an Op constructed by one of the exported helpers
// (AppendFile, AddFile, Chown). Apply reads a base tar, applies the ops in
// declaration order, and writes a PAX-format tar containing the surviving base
// entries in their original order followed by any added entries in
// op-declaration order.
//
// Ownership and permissions are written directly into the tar headers, so the
// resulting uid, gid and mode of every entry are determined entirely by the
// declared ops and base headers, independent of the OS user running the
// process. Declaring root ownership (uid 0, gid 0) yields a root-owned header
// even when the harness runs unprivileged.
//
// Ops that target a missing path (AppendFile, Chown) or that add an
// already-present path (AddFile) cause Apply to return a wrapped ErrNotFound or
// ErrExists; AppendFile additionally returns a wrapped ErrNotRegular when its
// target is not a regular file. Callers should match with errors.Is.
//
// Every base member and every added path must be a clean, local, relative path
// with no NUL byte; a member that is absolute or contains ".." causes Apply to
// return a wrapped ErrUnsafePath. The produced fixture tar therefore contains
// no absolute or traversing member names. Relative symlink targets (the
// symlink's link name) are not constrained here; confining link targets is the
// extractor's responsibility.
package overlay
