"""English figure set for the arXiv manuscript (reproduced from data/*.json).

Same layout/content as make_figures_v2.py, with English annotations.
Output: docs/figures_en/*.png
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
DATA = ROOT / "data"
import os as _os
FIG = Path(_os.environ.get("QRS_FIG_DIR", str(ROOT / "docs" / "figures_en")))

C_TAG, C_SIG, C_RSA, C_REF, C_GRAY = "#2b6cb0", "#c05621", "#718096", "#9f7aea", "#a0aec0"


def load(name: str):
    with open(DATA / name, "r", encoding="utf-8") as fh:
        return json.load(fh)


def savefig(fig, name: str):
    FIG.mkdir(parents=True, exist_ok=True)
    fig.savefig(FIG / name, dpi=160, bbox_inches="tight")
    plt.close(fig)
    print("saved", FIG / name)


def ecdf(values):
    arr = np.sort(np.asarray(values, dtype=np.float64))
    return arr, np.arange(1, len(arr) + 1) / len(arr)


def fig0():
    fig, axes = plt.subplots(1, 2, figsize=(13, 4.8))

    ax = axes[0]
    ax.set_title("Track A · LWE authentication tag (symmetric MAC)")
    steps = [
        ("1. Transaction tx", "domain-separated seed = SHA-256(tx)"),
        ("2. Derive matrix A (n x n)", "one transaction, one matrix"),
        ("3. Tag b = A*s + e mod q", "secret s in {-1,0,1}^n"),
        ("4. Key-holder verifies", "||b - A*s||_inf <= V"),
    ]
    for i, (head, sub) in enumerate(steps):
        y = 0.88 - i * 0.24
        ax.add_patch(plt.Rectangle((0.06, y - 0.085), 0.88, 0.17,
                                   facecolor=C_TAG, alpha=0.12, edgecolor=C_TAG))
        ax.text(0.5, y, head, ha="center", va="center", fontsize=11,
                fontweight="bold", color="#1a365d")
        ax.text(0.5, y - 0.04, sub, ha="center", va="center", fontsize=8.5)
        if i < len(steps) - 1:
            ax.annotate("", xy=(0.5, y - 0.135), xytext=(0.5, y - 0.09),
                        arrowprops=dict(arrowstyle="-|>", color="gray"))
    ax.text(0.5, -0.06, "Semantics: key-holder verification; attack = search LWE",
            ha="center", fontsize=9, color="#4a5568")
    ax.set_xlim(0, 1); ax.set_ylim(-0.18, 1.05); ax.axis("off")

    ax = axes[1]
    ax.set_title("Track B · Publicly verifiable lattice signature (FS with Aborts)")
    steps = [
        ("1. Public key pk = (A, T = A*S)", "secret S is a short ternary matrix"),
        ("2. y <- U([-kappa,kappa]^n)", "w = A*y"),
        ("3. c = H(tx || w)", "sparse challenge c in {-1,0,1}"),
        ("4. z = y + S*c", "retry until ||z||_inf <= kappa - h"),
        ("5. Verify: c' = H(tx || A*z - T*c)", "z short and c' == c"),
    ]
    for i, (head, sub) in enumerate(steps):
        y = 0.94 - i * 0.21
        color = C_SIG if i % 2 == 0 else "#dd6b20"
        ax.add_patch(plt.Rectangle((0.06, y - 0.07), 0.88, 0.14,
                                   facecolor=color, alpha=0.12, edgecolor=color))
        ax.text(0.5, y, head, ha="center", va="center", fontsize=9.5,
                fontweight="bold", color="#7b341e")
        ax.text(0.5, y - 0.035, sub, ha="center", va="center", fontsize=8)
        if i < len(steps) - 1:
            ax.annotate("", xy=(0.5, y - 0.095), xytext=(0.5, y - 0.072),
                        arrowprops=dict(arrowstyle="-|>", color="gray"))
    ax.text(0.5, -0.1, "Forgery -> find short S' with A*S' = T (inhomogeneous SIS)",
            ha="center", fontsize=9, color="#4a5568")
    ax.set_xlim(0, 1); ax.set_ylim(-0.2, 1.1); ax.axis("off")
    fig.tight_layout()
    savefig(fig, "fig0_scheme.png")


def fig1():
    data = load("eval_v2_e1.json")
    fig, axes = plt.subplots(1, 2, figsize=(12.5, 4.4))
    vf = np.asarray(data["valid_residual_hist"], dtype=float)
    tf = np.asarray(data["tamper_residual_hist"], dtype=float)
    common = min(len(vf), len(tf))
    xs = np.arange(common)
    ax = axes[0]
    ax.bar(xs - 0.2, vf[:common] / vf.sum(), width=0.4,
           label="Valid tags", color=C_TAG)
    ax.bar(xs + 0.2, tf[:common] / tf.sum(), width=0.4,
           label="Tampered transactions", color=C_SIG, alpha=0.7)
    ax.axvline(data["params"]["V"], color="red", ls="--", lw=1.5,
               label=f"Threshold V={data['params']['V']}")
    ax.set_yscale("log")
    ax.set_xlabel(r"$\max\|b-A\cdot s\|_\infty$")
    ax.set_ylabel("Share (log)")
    ax.legend(fontsize=9); ax.grid(alpha=0.3)
    ax.set_title("Verification residuals: valid vs. tampered")

    ax = axes[1]
    ax.plot(data["sweep_v"], data["false_reject_by_v"], "o-", color=C_TAG,
            label="False reject (valid)")
    ax.plot(data["sweep_v"], data["tamper_pass_by_v"], "s-", color=C_SIG,
            label="Tamper accepted")
    ax.axvline(data["params"]["V"], color="red", ls="--", lw=1.2)
    ax.set_xlabel("Tolerance V"); ax.set_ylabel("Rate")
    ax.set_ylim(-0.03, 1.03)
    ax.legend(fontsize=9); ax.grid(alpha=0.3)
    ax.set_title("Threshold trade-off vs. V")
    fig.tight_layout()
    savefig(fig, "fig1_correctness.png")


def fig2():
    data = load("eval_v2_e3.json")
    pts = data["sweep_a_n"]
    ns = [p["n"] for p in pts]
    rate = [p["success_rate"] for p in pts]
    lo = [p["success_rate"] - p["ci_low"] for p in pts]
    hi = [p["ci_high"] - p["success_rate"] for p in pts]
    est = [p["est_bits"] for p in pts]
    fig, ax = plt.subplots(figsize=(8.0, 4.5))
    ax.errorbar(ns, rate, yerr=[lo, hi], fmt="o-", color=C_TAG, lw=2, ms=5,
                capsize=3, label="Empirical recovery rate (95% CI)")
    ax.set_xlabel("Secret dimension n (scaled, q=257, sigma=5)")
    ax.set_ylabel("Empirical recovery rate", color=C_TAG)
    ax.set_ylim(-0.05, 1.05); ax.grid(alpha=0.3)
    ax2 = ax.twinx()
    ax2.plot(ns, est, "s--", color=C_RSA, lw=1.8, ms=5,
             label="Estimated security (bits, core-SVP)")
    ax2.set_ylabel("Estimated security (bits)", color=C_RSA)
    h1, l1 = ax.get_legend_handles_labels()
    h2, l2 = ax2.get_legend_handles_labels()
    ax.legend(h1 + h2, l1 + l2, fontsize=9, loc="center left")
    ax.set_title("I1 cross-validation: harder instances as n grows")
    fig.tight_layout()
    savefig(fig, "fig2_nsweep.png")


def fig3():
    data = load("eval_v2_e3.json")
    fig, axes = plt.subplots(1, 2, figsize=(12.2, 4.3))
    pts = data["sweep_b_samples"]
    xs = [p["m_transactions"] for p in pts]
    rate = [p["success_rate"] for p in pts]
    lo = [p["success_rate"] - p["ci_low"] for p in pts]
    hi = [p["ci_high"] - p["success_rate"] for p in pts]
    ax = axes[0]
    ax.errorbar(xs, rate, yerr=[lo, hi], fmt="o-", color=C_SIG, lw=2, ms=6,
                capsize=3)
    ax.set_xlabel("Historical samples M (n=6, sigma=5)")
    ax.set_ylabel("Empirical recovery rate")
    ax.set_ylim(-0.05, 1.05); ax.grid(alpha=0.3)
    ax.set_title("More samples help the attacker (95% CI)")

    pts = data["sweep_c_sigma"]
    xs = [p["sigma"] for p in pts]
    rate = [p["success_rate"] for p in pts]
    lo = [p["success_rate"] - p["ci_low"] for p in pts]
    hi = [p["ci_high"] - p["success_rate"] for p in pts]
    ax = axes[1]
    ax.errorbar(xs, rate, yerr=[lo, hi], fmt="o-", color=C_TAG, lw=2, ms=6,
                capsize=3)
    ax.set_xlabel("Noise std dev sigma (n=12, q=257)")
    ax.set_ylabel("Empirical recovery rate")
    ax.set_ylim(-0.05, 1.05); ax.grid(alpha=0.3)
    ax.set_title("Larger noise makes recovery harder (95% CI)")
    ax.text(0.98, 0.03,
            "Teaching estimator degenerates to a dimensional upper bound here;\nonly measured rates shown",
            transform=ax.transAxes, ha="right", fontsize=8, color=C_RSA)
    fig.tight_layout()
    savefig(fig, "fig3_msigma.png")


def fig4():
    data = load("eval_v2_e2.json")
    schemes = data["schemes"]
    labels, pks, sks, sigs, measured = [], [], [], [], []
    mapping = {
        "track_a_lwe_tag": "Track A\ntag (sym.)",
        "track_b_lwe_sig": "Track B\nsig.",
        "rsa3072_pss": "RSA-3072\n+PSS",
    }
    for key, item in schemes.items():
        if key == "reference_nist":
            continue
        labels.append(mapping[key])
        pks.append(item.get("pk_bytes") or 0)
        sks.append(item.get("sk_bytes") or 0)
        sigs.append(item.get("signature_bytes", item.get("credential_bytes")) or 0)
        measured.append(True)
    ref = schemes["reference_nist"]
    for key in ("ml_dsa_44", "fn_dsa_512", "ecdsa_p256"):
        labels.append({"ml_dsa_44": "ML-DSA-44\n(FIPS 204)",
                       "fn_dsa_512": "FN-DSA-512\n(FALCON draft)",
                       "ecdsa_p256": "ECDSA\nP-256"}[key])
        pks.append(ref[key]["pk_bytes"]); sks.append(ref[key]["sk_bytes"])
        sigs.append(ref[key]["signature_bytes"]); measured.append(False)
    x = np.arange(len(labels)); width = 0.26
    fig, ax = plt.subplots(figsize=(10.4, 4.8))
    ax.bar(x - width, pks, width, label="Public key", color="#3182ce")
    ax.bar(x, sks, width, label="Secret key", color="#38a169")
    ax.bar(x + width, sigs, width, label="Signature / credential", color="#dd6b20")
    ax.set_xticks(x); ax.set_xticklabels(labels, fontsize=9)
    ax.set_yscale("log"); ax.set_ylabel("Bytes (log scale)")
    ax.legend(fontsize=9); ax.grid(alpha=0.3, which="both")
    for i, m in enumerate(measured):
        if not m:
            ax.text(i, pks[i] * 1.2, "spec", ha="center", fontsize=8,
                    color=C_RSA)
    ax.set_title("Sizes: Track A/B and RSA measured here; spec rows are official values")
    ax.text(0, -0.22,
            "Track A (symmetric): shared key 144 B + credential 288 B. "
            "Track B ringless public key ~224 KB\nmotivates module/ring structure "
            "(ML-DSA pk = 1312 B).",
            transform=ax.transAxes, fontsize=8.5, color="#4a5568")
    fig.tight_layout()
    savefig(fig, "fig4_sizes.png")


def fig5():
    data = load("eval_v2_e2.json")
    schemes = data["schemes"]
    fig, axes = plt.subplots(1, 2, figsize=(12.4, 4.4))
    ax = axes[0]
    for key, color, label in [
            ("track_a_lwe_tag", C_TAG, "Track A issue"),
            ("track_b_lwe_sig", C_SIG, "Track B sign")]:
        samples = schemes[key]["sign_ms"]["samples_ms"]
        xs, ys = ecdf(samples)
        ax.plot(xs, ys, "o-", color=color, lw=1.5, ms=2.5,
                label=f"{label} (ECDF, n={len(samples)})")
    rsa = schemes["rsa3072_pss"]["sign_ms"]
    ax.axvline(rsa["median_ms"], color=C_RSA, ls="--", lw=2,
               label=f"RSA-3072 (OpenSSL) {rsa['median_ms']:.2f} ms")
    ax.set_xscale("log")
    ax.set_xlabel("Signing time (ms, log)"); ax.set_ylabel("Cumulative probability")
    ax.legend(fontsize=9); ax.grid(alpha=0.3, which="both")
    ax.set_title("ECDF: heavy right tail for Track B "
                 "(median=1.3 ms, p99=9 ms)")

    ax = axes[1]
    rejects = schemes["track_b_lwe_sig"]["reject_tries"]
    hist = rejects["hist"]
    xs = np.arange(len(hist))
    ax.bar(xs, hist, color=C_SIG)
    ax.set_xlabel("Rejection (retry) count per signature")
    ax.set_ylabel("Occurrences")
    ax.text(0.98, 0.9,
            f"median={rejects['median']}  p99={rejects['p99']}  max={rejects['max']}",
            transform=ax.transAxes, ha="right", fontsize=10, color="#7b341e")
    ax.set_title("Track B rejection-sampling retry distribution")
    fig.tight_layout()
    savefig(fig, "fig5_timing.png")


def fig6():
    data = load("eval_v2_e4.json")
    rows = data["rows"]
    _en = ["Track A tag (LWE, sym.)", "Track B sig (LWE)", "RSA-3072-PSS",
           "ML-DSA-44 (FIPS 204)", "FN-DSA-512 (FALCON draft)", "ECDSA P-256"]
    labels = [_en[i] for i in range(len(rows))]
    fig, axes = plt.subplots(1, 2, figsize=(12.8, 4.6))
    colors = [C_TAG, C_SIG, C_RSA, C_REF, C_REF, C_GRAY]
    ax = axes[0]
    ax.bar(np.arange(len(labels)), [r["inflation_vs_payload"] for r in rows],
           color=colors)
    ax.set_yscale("log")
    ax.set_xticks(np.arange(len(labels)))
    ax.set_xticklabels(labels, rotation=18, fontsize=8)
    ax.set_ylabel("Ledger overhead / payload (x, log)")
    ax.grid(alpha=0.3, which="both")
    ax.set_title("Block overhead (N=1000 tx, 64 B each)")
    ax = axes[1]
    ax.bar(np.arange(len(labels)), [r["verify_tps_median"] for r in rows],
           color=colors)
    ax.set_yscale("log")
    ax.set_xticks(np.arange(len(labels)))
    ax.set_xticklabels(labels, rotation=18, fontsize=8)
    ax.set_ylabel("Verify throughput (TPS, log)")
    ax.grid(alpha=0.3, which="both")
    ax.set_title("Single-node verify throughput (measured rows use E2 medians)")
    ax.text(0, -0.25,
            "Purple/gray bars = official spec sizes (FN-DSA-512: FALCON v1.2 draft) with literature-order timing refs; "
            "others measured on this machine.",
            transform=ax.transAxes, fontsize=8.5, color="#4a5568")
    fig.tight_layout()
    savefig(fig, "fig6_blockchain.png")


def fig7():
    cross = ROOT / "data" / "lattice_estimator_crosscheck.json"
    if not cross.exists():
        print("fig7 skipped: run scripts/crosscheck_lattice_estimator.py first")
        return
    ref = json.load(open(cross, encoding="utf-8"))
    ns = np.arange(144, 1041, 8)
    from qrsv2.estimator import estimate_lwe_search
    teaching = [estimate_lwe_search(int(n), int(n), 12289, 2.0).bits for n in ns]

    fig, ax = plt.subplots(figsize=(10.4, 5.2))
    ax.plot(ns, teaching, color=C_TAG, lw=2.2,
            label="Teaching estimator (root-Hermite + core-SVP, I1)")
    d = ref["track_a"]["scan_usvp_default"]
    ax.plot(d["n_values"], [r["rop_log2"] for r in d["rows"]], "s-",
            color="#2f855a", lw=2, ms=4,
            label="lattice-estimator uSVP (default cost model)")
    r = ref["track_a"]["scan_usvp_rough_adps16"]
    ax.plot(r["n_values"], [x["rop_log2"] for x in r["rows"]], "o-",
            color=C_SIG, lw=2, ms=4,
            label="lattice-estimator uSVP (ADPS16 core-SVP, literature-comparable)")
    ax.axhline(80, color=C_GRAY, ls=":", lw=1.5)
    ax.text(1030, 81, "80 bits", ha="right", va="bottom", fontsize=9, color=C_GRAY)
    for xn, lab in [(144, "prototype n=144"), (480, "recommended n=480")]:
        ax.axvline(xn, color=C_GRAY, ls="--", lw=1)
        ax.text(xn, 3, lab, rotation=90, ha="right", va="bottom",
                fontsize=8.5, color="#4a5568")
    ax.set_xlabel("Secret dimension n (m = n, q = 12289, sigma = 2, ternary secret)")
    ax.set_ylabel("Estimated attack cost (log2 bits)")
    ax.set_ylim(0, 260)
    ax.set_title("Reference cross-check: lattice-estimator vs. teaching estimator (Track A family)")
    ax.legend(fontsize=9.5, loc="upper left")
    ax.grid(alpha=0.3)
    fig.tight_layout()
    savefig(fig, "fig7_reference_bits.png")

def main():
    for fn in (fig0, fig1, fig2, fig3, fig4, fig5, fig6, fig7):
        fn()
    print("all english figures done in", FIG)


if __name__ == "__main__":
    main()


