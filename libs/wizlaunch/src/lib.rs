#[cfg(windows)]
pub mod credential_store;
#[cfg(windows)]
pub mod credui;
pub mod errors;
#[cfg(windows)]
pub mod launcher;
#[cfg(windows)]
pub mod login;
#[cfg(windows)]
pub mod metadata;

#[cfg(all(feature = "pyo3", windows))]
mod python;
#[cfg(all(feature = "pyo3", not(windows)))]
mod python_portable;

#[cfg(all(feature = "pyo3", windows))]
pub use python::*;
#[cfg(all(feature = "pyo3", not(windows)))]
pub use python_portable::*;
