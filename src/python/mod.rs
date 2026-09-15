//! PyO3 bindings for keylock.

use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

#[pyfunction]
fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[pyfunction]
fn random_bytes<'py>(py: Python<'py>, len: usize) -> PyResult<Bound<'py, PyBytes>> {
    let mut out = vec![0u8; len];
    crate::crypto::rng::randombytes_buf(&mut out).map_err(PyRuntimeError::new_err)?;
    Ok(PyBytes::new(py, &out))
}

#[pyfunction]
fn random_uniform(upper_bound: u32) -> u32 {
    crate::crypto::rng::randombytes_uniform(upper_bound)
}

#[pyfunction]
fn sha256<'py>(py: Python<'py>, data: &[u8]) -> Bound<'py, PyBytes> {
    let digest = crate::hash::sha256::hash(data);
    PyBytes::new(py, &digest)
}

#[pyfunction]
fn keccak256<'py>(py: Python<'py>, data: &[u8]) -> Bound<'py, PyBytes> {
    let digest = crate::keccak256(data);
    PyBytes::new(py, &digest)
}

#[pyfunction]
fn bytes_equal(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && crate::crypto::constant_time::secure_compare(a, b)
}

pub fn register_python_module(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(version, m)?)?;
    m.add_function(wrap_pyfunction!(random_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(random_uniform, m)?)?;
    m.add_function(wrap_pyfunction!(sha256, m)?)?;
    m.add_function(wrap_pyfunction!(keccak256, m)?)?;
    m.add_function(wrap_pyfunction!(bytes_equal, m)?)?;
    Ok(())
}

#[pymodule]
fn keylock(m: &Bound<'_, PyModule>) -> PyResult<()> {
    register_python_module(m)
}
