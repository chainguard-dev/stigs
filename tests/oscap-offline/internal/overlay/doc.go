// Package overlay applies a declarative set of transforms to a base
// filesystem tar, producing a deterministic fixture tar.
//
// Each transform is an Op constructed by one of the exported helpers
// (PutFile, AddFile, ReplaceFile, AppendFile, RemoveFile, CopyFile, Chown).
// Apply reads a base tar, applies the ops in declaration order, and writes a
// PAX-format tar containing the surviving base entries in their original order
// followed by any added entries in op-declaration order.
//
// PutFile is the default choice for "this file holds this content": it replaces
// an existing entry's content or creates the entry if absent, so a fixture using
// it does not depend on whether the base image happens to ship the path. AddFile
// and ReplaceFile assert the opposite preconditions and are for fixtures that
// specifically mean to fail when the base gains or loses a path. Because PutFile
// absorbs that drift, what the base ships is asserted directly against the base
// tar rather than inferred from a fixture's verdict.
//
// Ownership and permissions are written directly into the tar headers, so the
// resulting uid, gid and mode of every entry are determined entirely by the
// declared ops and base headers, independent of the OS user running the
// process. Declaring root ownership (uid 0, gid 0) yields a root-owned header
// even when the harness runs unprivileged.
//
// Ops that target a missing path (AppendFile, ReplaceFile, RemoveFile,
// CopyFile's source, Chown) or that add an already-present path (AddFile,
// CopyFile's destination) cause Apply to return a wrapped ErrNotFound or
// ErrExists; AppendFile, ReplaceFile and CopyFile additionally return a wrapped
// ErrNotRegular when the entry whose content they read or rewrite is not a
// regular file. PutFile has no existence precondition, but it reaches
// ReplaceFile's ErrNotRegular when the base holds a directory or symlink at the
// path, and AddFile's ErrUnsafePath when the path is not clean, local and
// relative. Callers should match with errors.Is.
//
// Every base member and every added path must be a clean, local, relative path
// with no NUL byte; a member that is absolute or contains ".." causes Apply to
// return a wrapped ErrUnsafePath. The produced fixture tar therefore contains
// no absolute or traversing member names. Relative symlink targets (the
// symlink's link name) are not constrained here; confining link targets is the
// extractor's responsibility.
package overlay
