# -*- coding: utf-8 -*-
"""Cross-check the teaching-level security estimates (I1) against the
reference lattice-estimator (https://github.com/malb/lattice-estimator).

The reference tool normally runs under SageMath.  To keep this artifact
reproducible on machines without Sage, we ship a *minimal* pure-Python
numerical compatibility layer (``sage_shim/sage/all.py``) that implements the
~28 ``sage.all`` symbols the estimator imports.  The estimator code itself is
executed unmodified.  Before using the shim, the script tries to import a real
``sage`` installation.

Two layers of output are produced:

1. ``validation`` - the same estimator calls documented in the estimator's own
   doctests (Kyber512 LWE attacks, Dilithium2 MSIS lattice attack).  These rows
   must reproduce the reference values printed in the estimator docstrings,
   which are used as a golden check of the numerical layer.
2. ``track_a`` / ``track_b`` - reference-estimator costs for the parameter sets
   of this report (Track A: LWE tag; Track B: SIS regime).

Usage:
    # Windows: force UTF-8 stdout, otherwise the estimator's Unicode log glyphs crash on the GBK console.
    $env:PYTHONIOENCODING="utf-8"
    $env:LATTICE_ESTIMATOR_DIR="C:/.../lattice-estimator"; python scripts/crosscheck_lattice_estimator.py
"""
from __future__ import annotations

import json
import math
import os
import platform
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SHIM = ROOT / "scripts" / "sage_shim"
SYSINFO = {
    "platform": platform.platform(),
    "python": platform.python_version(),
}

# ---------------------------------------------------------------------------
# Locate lattice-estimator
# ---------------------------------------------------------------------------
def find_estimator() -> Path:
    env_dir = os.environ.get("LATTICE_ESTIMATOR_DIR")
    candidates = []
    if env_dir:
        candidates.append(Path(env_dir))
    candidates.append(Path(__file__).resolve().parents[2] / "lattice-estimator")
    candidates.append(Path.home() / "codex_work" / "lattice-estimator")
    for cand in candidates:
        if (cand / "estimator" / "__init__.py").exists():
            return cand
    raise SystemExit(
        "lattice-estimator not found.\n"
        "Clone it once, e.g.\n"
        "    git clone https://github.com/malb/lattice-estimator <dir>\n"
        "then set $env:LATTICE_ESTIMATOR_DIR=<dir> and rerun."
    )


def git_commit_of(path: Path) -> str:
    import subprocess

    try:
        return (
            subprocess.run(
                ["git", "-C", str(path), "rev-parse", "HEAD"],
                capture_output=True,
                text=True,
                check=True,
                timeout=10,
            )
            .stdout.strip()[:40]
            or "unknown-local"
        )
    except Exception:
        return "unknown-local"


def activate() -> Path:
    estimator_dir = find_estimator()
    sys.path.insert(0, str(estimator_dir))
    try:
        import sage.all  # noqa: F401  (real SageMath)

        print(f"using SageMath with lattice-estimator from {estimator_dir}")
    except ImportError:
        sys.path.insert(0, str(SHIM))
        import sage.all  # noqa: F401

        print(f"using bundled sage_shim with lattice-estimator from {estimator_dir}")
    sys.path.insert(0, str(estimator_dir))

    return estimator_dir


def log2_rop(cost) -> float:
    rop = float(cost["rop"])
    if rop == float("inf"):
        return float("inf")
    return math.log(rop, 2)


# ---------------------------------------------------------------------------
# Attack wrappers
# ---------------------------------------------------------------------------
def track_a_params(n: int, q: int = 12289, sigma: float = 2.0, m: int | None = None):
    from estimator import ND
    from estimator.lwe_parameters import LWEParameters

    return LWEParameters(
        n=n,
        q=q,
        Xs=ND.Ternary,  # independent ternary secret, variance 2/3
        Xe=ND.DiscreteGaussian(stddev=float(sigma)),
        m=int(m if m is not None else n),
        tag=f"Track A LWE tag (n={n}, m={m or n}, q={q}, sigma={sigma})",
    )


def _int_or_none(v):
    return int(v) if v is not None else None


def attack_cost(call):
    cost = call()
    return {
        "rop_log2": round(log2_rop(cost), 1),
        "beta": _int_or_none(cost.get("beta")),
        "d": _int_or_none(cost.get("d")),
        "delta": float(cost["delta"]) if "delta" in cost else None,
    }


def main() -> dict:
    estimator_dir = activate()
    from estimator import LWE, SIS, ND, schemes  # noqa
    from estimator.lwe_parameters import LWEParameters
    from estimator.sis_parameters import SISParameters
    from estimator.reduction import RC

    # ---------------------------------------------------------------
    # 1. Golden validation against the estimator's own doctest output
    # ---------------------------------------------------------------
    def sis_cost_parse(cost):
        return {
            "rop_log2": round(log2_rop(cost), 1),
            "beta": int(cost["beta"]),
            "d": int(cost.get("d") or cost.get("eta")),
        }

    kyber512 = schemes.Kyber512
    validation = {
        "lwe_kyber512_usvp_default": {
            "params": "Kyber512, LWE.primal_usvp (default RC)",
            "expected": {"rop_log2": 143.8, "beta": 406, "d": 998},
            "obtained": attack_cost(lambda: LWE.primal_usvp(kyber512)),
        },
        "lwe_kyber512_bdd_default": {
            "params": "Kyber512, LWE.primal_bdd (default RC)",
            "expected": {"rop_log2": 140.2, "beta": 389, "d": 1005},
            "obtained": attack_cost(lambda: LWE.primal_bdd(kyber512)),
        },
        "lwe_kyber512_rough_usvp": {
            "params": "Kyber512, LWE.estimate.rough usvp (ADPS16/GSA)",
            "expected": {"rop_log2": 118.6, "beta": 406, "d": 998},
            "obtained": attack_cost(
                lambda: LWE.estimate.rough(kyber512)["usvp"]
            ),
        },
        "sis_dilithium2_rough_lattice": {
            "params": "Dilithium2 MSIS, SIS.estimate.rough lattice",
            "expected": {"rop_log2": 123.5, "beta": 423, "d": 2303},
            "obtained": sis_cost_parse(
                SIS.estimate.rough(schemes.Dilithium2_MSIS_WkUnf)["lattice"]
            ),
        },
    }
    # tag every validation row with pass/fail on the printed fields
    for key, row in validation.items():
        exp, got = row["expected"], row["obtained"]
        row["match"] = bool(
            got["rop_log2"] == exp["rop_log2"]
            and got["beta"] == exp["beta"]
            and got["d"] == exp["d"]
        )

    # ---------------------------------------------------------------
    # 2. Track A  (LWE tag; ternary secret; q=12289, sigma=2, m=n)
    # ---------------------------------------------------------------
    track_a = {"q": 12289, "sigma": 2.0, "secret": "independent ternary, variance 2/3"}
    track_a["n144_prototype"] = {
        "usvp_default": attack_cost(lambda: LWE.primal_usvp(track_a_params(144))),
        "bdd_default": attack_cost(lambda: LWE.primal_bdd(track_a_params(144))),
        "rough_usvp": attack_cost(lambda: LWE.estimate.rough(track_a_params(144))["usvp"]),
        "rough_dual_hybrid": attack_cost(
            lambda: LWE.estimate.rough(track_a_params(144))["dual_hybrid"]
        ),
    }
    # scan for a size that reaches ~80 bits under both cost models
    def _usvp_default(p):
        return LWE.primal_usvp(p)

    def _usvp_adps16(p):
        return LWE.primal_usvp(p, red_cost_model=RC.ADPS16, red_shape_model="gsa")

    n_vals_default = list(range(144, 481, 16))
    scan_default = [attack_cost(lambda p=p: _usvp_default(p)) for p in map(track_a_params, n_vals_default)]
    n_vals_rough = list(range(320, 1041, 80))
    scan_rough = [attack_cost(lambda p=p: _usvp_adps16(p)) for p in map(track_a_params, n_vals_rough)]
    # NOTE: the two scans use different lattices of n values on purpose
    track_a["scan_usvp_default"] = {"n_values": n_vals_default, "rows": scan_default}
    track_a["scan_usvp_rough_adps16"] = {"n_values": n_vals_rough, "rows": scan_rough}
    track_a["recommended_n480"] = {
        "usvp_default": attack_cost(lambda: LWE.primal_usvp(track_a_params(480))),
        "bdd_default": attack_cost(lambda: LWE.primal_bdd(track_a_params(480))),
        "rough_usvp": attack_cost(lambda: LWE.estimate.rough(track_a_params(480))["usvp"]),
        "rough_dual_hybrid": attack_cost(
            lambda: LWE.estimate.rough(track_a_params(480))["dual_hybrid"]
        ),
    }

    # ---------------------------------------------------------------
    # 3. Track B  (SIS regime; ringless signature, n=256, m=224)
    # ---------------------------------------------------------------
    bound = round(math.sqrt(256 * 2.0 / 3.0), 4)  # planted ternary column norm
    sis_homog = SISParameters(
        n=256, m=224, q=12289, length_bound=bound, norm=2,
        tag="Track B homogeneous kernel of A (n=256, m=224, q=12289)",
    )
    homog_lattice = SIS.estimate.rough(sis_homog)["lattice"]
    track_b = {
        "instance": (
            "homogeneous kernel of the public matrix A in Z_q^{224 x 256}; "
            "length bound = sqrt(256*2/3) ~ 13.06 (Euclidean norm of a ternary column)"
        ),
        "homog_kernel_lattice": {
            "rop_log2": log2_rop(homog_lattice),
            "beta": int(homog_lattice["beta"]),
            "d": int(homog_lattice["d"]),
            "raw": repr(homog_lattice),
        },
        "two_signature_relation_bound": {
            "value": 2 * 3956,  # 2*(kappa-h)
            "comment": (
                "infinity-norm MSIS estimator requires length_bound < (q-1)/2 = 6144; "
                "the two-signature collision vector may have coordinates up to 2*(kappa-h)=7848, "
                "above that bound, so the reference tool cannot model this instance directly."
            ),
        },
    }

    return {
        "tool": {
            "name": "malb/lattice-estimator",
            "repo": "https://github.com/malb/lattice-estimator",
            "commit": os.environ.get("LATTICE_ESTIMATOR_COMMIT", git_commit_of(estimator_dir)),
            "usage_note": "estimator code executed unmodified; numeric Sage layer: real Sage or bundled sage_shim",
        },
        "cost_models": {
            "default": "default reduction cost/shape models of lattice-estimator",
            "rough": "ADPS16 core-SVP + GSA/LGSA, the literature-comparable model of estimate.rough",
        },
        "validation": validation,
        "track_a": track_a,
        "track_b": track_b,
        "sysinfo": SYSINFO,
        "note": (
            "All rop_log2 rounded to 0.1 bit.  Default-model full 'dual' rows are not reported: "
            "that routine exercises success probabilities below the double range where only Sage's "
            "MPFR semantics apply; the conservative ADPS16 'rough' dual-hybrid row is reported instead."
        ),
    }


if __name__ == "__main__":
    payload = main()
    out = ROOT / "data" / "lattice_estimator_crosscheck.json"
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
    print(f"\nwrote {out}")
