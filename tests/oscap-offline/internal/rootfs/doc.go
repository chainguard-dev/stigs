// Package rootfs exports a pinned container image to a flattened filesystem
// tar using go-containerregistry, without a running container runtime.
//
// An Exporter pulls an image via an injectable Fetcher (defaulting to a crane
// registry pull with the ambient keychain) and writes its flattened filesystem
// as a tar. EnsureBaseTar caches the result on disk keyed by the image manifest
// digest: it first resolves the digest via an injectable Digester (a cheap
// crane lookup that does not pull layers), so a cache hit returns the cached tar
// without pulling layers or re-exporting; only a cache miss pulls and exports.
//
// The injectable Fetcher and Digester let tests build deterministic in-memory
// images with crane.Image and exercise caching without network access, and let
// tests assert that a warm cache performs no layer pull.
package rootfs
