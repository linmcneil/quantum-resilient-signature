# Optional SageMath-compatibility layer used by the lattice-estimator
# cross-check.  Place this directory on sys.path only when a real SageMath
# installation is unavailable; see scripts/crosscheck_lattice_estimator.py.

## Reproduce on Windows

The estimator logs Unicode glyphs (≈, δ, ↻).  On a GBK console the run dies with
`UnicodeEncodeError`, so force UTF-8 stdout first:

```powershell
$env:PYTHONIOENCODING="utf-8"
$env:LATTICE_ESTIMATOR_DIR="C:/path/to/lattice-estimator"
python scripts/crosscheck_lattice_estimator.py
```

The estimator code itself is never modified; this layer only supplies the ~28 `sage.all` symbols
the estimator imports, backed by mpmath high-precision reals.
