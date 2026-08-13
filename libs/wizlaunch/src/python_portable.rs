use pyo3::prelude::*;

#[pymodule]
pub fn _native(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add("__version__", "0.2.0")?;
    module.add("WINDOWS_ACCOUNT_BACKEND", false)?;
    Ok(())
}
