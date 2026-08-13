use pyo3::prelude::*;

#[pymodule]
pub fn _native(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add("__version__", "0.3.1")?;
    module.add("WINDOWS_ACCOUNT_BACKEND", false)?;
    Ok(())
}
