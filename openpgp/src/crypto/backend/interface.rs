//! The crypto-backend abstraction.

/// Abstracts over the cryptographic backends.
pub trait Backend {
    /// Returns a short, human-readable description of the backend.
    ///
    /// This starts with the name of the backend, possibly a version,
    /// and any optional features that are available.  This is meant
    /// for inclusion in version strings to improve bug reports.
    fn backend() -> String;
}
