# Quantum-Resilient Signature — Lightweight Lattice-Based Authentication and Signatures for Blockchain Transactions

**Paper (sole-author preprint).** Zhiqian Lin. *Reproducible Design-Space Study of Lightweight
Lattice-Based Authentication and Signatures for Blockchain Transactions*. Cryptology ePrint
Archive, Paper 2026/1925, Sep 2026 — https://eprint.iacr.org/2026/1925

Repository: https://github.com/linmcneil/quantum-resilient-signature
Code and data archive (Zenodo): https://doi.org/10.5281/zenodo.22659733

Quantum computers break the public-key primitives that most blockchains use today, so the
migration to lattice-based signatures is already being mandated (ML-DSA / FIPS 204, FN-DSA).
What engineering teams lack is not a list of secure algorithms but comparable, reproducible
numbers: how large these signatures are on chain, how long they take, and when a parameter
choice is actually defensible. This repository is a teaching-level but fully reproducible study
of exactly that design space.

Two designs are studied side by side:

- **Track A — symmetric LWE authentication tag.** The matrix `A` is derived per transaction from
  `SHA-256(tx)` (one transaction, one matrix), so no seed is transmitted and no matrix is reused
  across transactions. The credential is `b = A·s + e`, and the verifier checks the residual
  against a threshold. Semantically this is a MAC: verification requires the shared key, which
  suits consortium chains and custodial settings.
- **Track B — publicly verifiable lattice signature prototype.** Public key `(A, T = A·S)`;
  signing is Fiat-Shamir with Aborts, where rejection sampling keeps the output `z` from leaking
  the private key. Anyone can verify, and no shared secret is needed.

Two supporting pieces: **I1**, a parameter-instantiation workflow that fixes parameters with a
root-Hermite / core-SVP estimator and then cross-checks the estimate against scaled-down LLL
embedding attacks; and **I2**, the message-derived matrix described above.

## Results

All experiments run on one machine (Windows 11, CPU) and are reproducible with a single script.

**Correctness.** Track A: legitimate-credential acceptance, tamper detection and blind-guess
rejection (1500 / 1500 / 300 trials) all return 1.0000. Track B: acceptance of valid signatures,
rejection of tampered transactions, rejection of random forgeries and rejection of single-byte
signature tampering (1000 trials each) all return 1.0000. In the threshold sweep both error rates
are zero for V in [6, 16].

**Performance (same machine).**

| Scheme | Sign (median) | Sign (p99) | Verify (median) | Size |
| --- | --- | --- | --- | --- |
| Track A (LWE tag) | 2.34 ms | 4.99 ms | 0.098 ms | 288 B |
| Track B (lattice signature) | 1.36 ms | 9.66 ms | 0.160 ms | 544 B |
| RSA-3072-PSS (OpenSSL 3.5.7) | 7.39 ms | — | 0.135 ms | 384 B |

Track B signing has a long tail because rejection sampling is part of the algorithm, not noise:
the retry count has median 6, p99 35 and maximum 61, consistent with the geometric distribution
implied by the designed acceptance probability of 12.5% (observed mean 8.09 against a
theoretical 8). Reporting the mean gives "3.7x faster than RSA"; reporting the worst case gives
"3.3x slower". Both describe the same scheme, so the distribution is reported instead of a single
figure.

**Scaled-down attacks (q = 257).** Recovery success falls from about 0.9 to about 0.1 as the
dimension grows, and from all-success to about 0.1 as the noise grows — the same direction as the
estimator's security-level prediction. More samples make the attack easier, which is precisely
the argument for the per-transaction matrix.

**Blockchain workload (1000 transactions per block, 64 B payload each).** Track A costs 288 B per
transaction (4.5x inflation) and Track B 544 B (8.5x), against 37.8x for ML-DSA-44; verification
throughput stays in the thousands of TPS. Signature size, not verification cost, dominates block
inflation.

**Independent cross-check with `lattice-estimator`.** The community estimator was run as-is
(with `scripts/sage_shim/` supplying the roughly 28 `sage.all` numerical symbols it imports),
after validating that shim against the official Kyber512 and Dilithium2 doctest numbers. For the
Track A n = 144 prototype the reference values are uSVP about 41.3 bits, BDD about 41.1 bits,
ADPS16 core-SVP about 12.0 bits and dual-hybrid about 17.7 bits — the teaching estimator's
84.4 bits is a dimensional-saturation artefact, not a security estimate. For a conservative
80-bit claim the recommendation is n = m = 480. Data in `data/lattice_estimator_crosscheck.json`,
figure v2_fig7.

Full per-experiment tables are in `docs/REPORT_v2.md`; the paper source is in `paper/`.

## Reproduce

```
pip install numpy matplotlib      # the core implementation uses the standard library only
python scripts/run_v2_all.py      # runs E1, E1b, E2, E3, E4 and produces all figures
```

Individual experiments: `scripts/run_v2_e1.py`, `run_v2_e1b.py`, `run_v2_e2.py`, `run_v2_e3.py`,
`run_v2_e4.py`, `make_figures_v2.py`.

The `lattice-estimator` cross-check is optional and its results ship with the repository: clone
https://github.com/malb/lattice-estimator, set `LATTICE_ESTIMATOR_DIR`, then run
`python scripts/crosscheck_lattice_estimator.py`. On Windows set
`$env:PYTHONIOENCODING="utf-8"` first, since the estimator logs Unicode symbols.

Tests: `python tests/test_v2_core.py`.

## Layout

```
qrsv2/    core implementation: parameters, security estimates, tag/signature, LLL, RSA-PSS, matrix derivation
scripts/  E1-E4, lattice-estimator cross-check and plotting (sage_shim/ is the optional numeric shim)
tests/    unit tests
data/     evaluation JSON
docs/     methodology, experiment design, result report, literature review, figures
paper/    LaTeX source of the preprint
qrs/      v1, frozen
```

## Scope and limits

This is a research prototype, not a deployable cryptographic library:

- Security conclusions rest on parameter estimates, scaled-down experiments and an independent
  reference tool; there are no formal proofs.
- Track B's ringless public key is about 224 KB, far larger than ML-DSA's 1312 B. This is not a
  detail to gloss over: it is the concrete argument for module/ring structure plus NTT in any real
  implementation, and it is the main direction for further work.
- The message-derived matrix lets an adversary choose the message, which needs an additional
  reduction argument; it is presented here as a design motivation only.
- Track B's infinity-norm MSIS instantiation requires 2(kappa - h) < (q - 1) / 2, which the
  current parameters do not yet satisfy.

## v1 (archived)

`qrs/` and `docs/EXPERIMENT.md` are the first version. v1 compared "LWE 100% vs RSA 0%" defence
rates, which is not a fair comparison: the attack semantics and success criteria are not
equivalent. v2 was rebuilt for that reason; v1 is kept for traceability, and its conclusions are
no longer cited anywhere.

## Citation

```bibtex
@misc{cryptoeprint:2026/1925,
  author       = {Zhiqian Lin},
  title        = {Reproducible Design-Space Study of Lightweight Lattice-Based Authentication and Signatures for Blockchain Transactions},
  howpublished = {Cryptology {ePrint} Archive, Paper 2026/1925},
  year         = {2026},
  url          = {https://eprint.iacr.org/2026/1925}
}
```

The code and data archive has its own DOI: 10.5281/zenodo.22659733.

## AI-assisted development

AI-assisted coding and writing tools (OpenAI Codex) were used while building this repository.
All code, experimental data and conclusions were reviewed and verified by the author; the
repository and the paper represent the author's own work.