package overlay

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
)

// Sentinel errors returned by Apply. Callers should match with errors.Is.
var (
	// ErrNotFound is returned when an op targets a path that is absent from
	// the base tar and not added by an earlier op.
	ErrNotFound = errors.New("path not found in base")
	// ErrExists is returned when AddFile targets a path that already exists.
	ErrExists = errors.New("path already exists")
	// ErrUnsafePath is returned when a base member or an added path is not a
	// clean, local, relative path (absolute, contains "..", or embeds NUL).
	// Rejecting these keeps every produced fixture tar free of absolute or
	// traversing member names.
	ErrUnsafePath = errors.New("unsafe member path")
	// ErrNotRegular is returned when an op that mutates file content targets a
	// base member that is not a regular file (e.g. a directory or symlink).
	// Mutating such an entry's content cannot produce a valid tar.
	ErrNotRegular = errors.New("target is not a regular file")
)

// safePath reports whether name is a clean, local, relative path with no NUL.
// Every base member and added path passes through it, so the produced fixture
// holds no traversal or absolute member name. It intentionally differs from
// safetar.cleanName: this validates names destined for a produced fixture tar
// rather than names being materialized onto a real filesystem.
func safePath(name string) bool {
	if name == "" || strings.ContainsRune(name, 0) {
		return false
	}
	return filepath.IsLocal(name)
}

// entry is a single in-memory tar entry: its header plus content.
type entry struct {
	hdr  tar.Header
	data []byte
}

// plan holds the mutable state an Op acts on while Apply walks the base tar.
// order preserves base entry order; added lists new entries in op-declaration
// order; err records the first failure so Apply can report it deterministically.
type plan struct {
	byName map[string]*entry
	order  []string
	added  []string
	err    error
}

// fail records the first error encountered; subsequent failures are ignored so
// the earliest, most actionable error surfaces.
func (p *plan) fail(err error) {
	if p.err == nil {
		p.err = err
	}
}

// Op is a declarative transform applied to a base tar by Apply. Ops execute in
// declaration order; the first failing op aborts the run.
type Op func(*plan)

// AppendFile appends extra to an existing entry's content and updates its size.
// The path must already exist, otherwise Apply returns a wrapped ErrNotFound.
// The target must be a regular file; appending to a directory or symlink yields
// a wrapped ErrNotRegular rather than a later tar write failure.
func AppendFile(path string, extra []byte) Op {
	return func(p *plan) {
		e := p.requireReg(path)
		if e == nil {
			return
		}
		combined := make([]byte, 0, len(e.data)+len(extra))
		combined = append(combined, e.data...)
		combined = append(combined, extra...)
		e.data = combined
		e.hdr.Size = int64(len(e.data))
	}
}

// AddFile adds a new regular-file entry after the base entries. The path must
// not already exist, otherwise Apply returns a wrapped ErrExists.
func AddFile(path string, content []byte, mode int64, uid, gid int) Op {
	return func(p *plan) {
		if !safePath(path) {
			p.fail(fmt.Errorf("adding %q: %w", path, ErrUnsafePath))
			return
		}
		if _, ok := p.byName[path]; ok {
			p.fail(fmt.Errorf("adding %q: %w", path, ErrExists))
			return
		}
		data := bytes.Clone(content)
		p.byName[path] = &entry{
			hdr: tar.Header{
				Name:     path,
				Typeflag: tar.TypeReg,
				Mode:     mode,
				Uid:      uid,
				Gid:      gid,
				Size:     int64(len(data)),
				Format:   tar.FormatPAX,
			},
			data: data,
		}
		p.added = append(p.added, path)
	}
}

// Chown changes only the uid and gid of an existing entry. The path must exist,
// otherwise Apply returns a wrapped ErrNotFound.
func Chown(path string, uid, gid int) Op {
	return func(p *plan) {
		if e := p.require(path); e != nil {
			e.hdr.Uid = uid
			e.hdr.Gid = gid
		}
	}
}

// require returns the entry for path or records ErrNotFound and returns nil.
func (p *plan) require(path string) *entry {
	e, ok := p.byName[path]
	if !ok {
		p.fail(fmt.Errorf("modifying %q: %w", path, ErrNotFound))
		return nil
	}
	return e
}

// requireReg returns the entry for path only when it is a regular file. It
// records ErrNotFound for an absent path or ErrNotRegular for a non-regular
// target, returning nil in either case.
func (p *plan) requireReg(path string) *entry {
	e := p.require(path)
	if e == nil {
		return nil
	}
	if e.hdr.Typeflag != tar.TypeReg {
		p.fail(fmt.Errorf("modifying %q: %w", path, ErrNotRegular))
		return nil
	}
	return e
}

// Apply reads the base tar from base, applies ops in declaration order, and
// writes a deterministic PAX-format tar to out: surviving base entries in their
// original order, followed by added entries in op-declaration order. A
// malformed base tar or any op targeting a missing/conflicting path yields a
// wrapped error.
func Apply(base io.Reader, ops []Op, out io.Writer) error {
	p := &plan{byName: make(map[string]*entry)}

	tr := tar.NewReader(base)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("reading base tar: %w", err)
		}
		if !safePath(hdr.Name) {
			return fmt.Errorf("base member %q: %w", hdr.Name, ErrUnsafePath)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			return fmt.Errorf("reading base entry %q: %w", hdr.Name, err)
		}
		cp := *hdr
		cp.Format = tar.FormatPAX
		p.byName[hdr.Name] = &entry{hdr: cp, data: data}
		p.order = append(p.order, hdr.Name)
	}

	for _, op := range ops {
		op(p)
		if p.err != nil {
			return p.err
		}
	}

	tw := tar.NewWriter(out)
	write := func(name string) error {
		e, ok := p.byName[name]
		if !ok {
			return nil // removed
		}
		e.hdr.Size = int64(len(e.data))
		if err := tw.WriteHeader(&e.hdr); err != nil {
			return fmt.Errorf("writing header %q: %w", name, err)
		}
		if _, err := tw.Write(e.data); err != nil {
			return fmt.Errorf("writing content %q: %w", name, err)
		}
		return nil
	}

	for _, name := range p.order {
		if err := write(name); err != nil {
			return err
		}
	}
	for _, name := range p.added {
		if err := write(name); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return fmt.Errorf("closing output tar: %w", err)
	}
	return nil
}
