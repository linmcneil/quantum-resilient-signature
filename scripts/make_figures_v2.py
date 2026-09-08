"""v2 全套图表（专业版）：CI 误差棒 + 真 ECDF + 中文 YaHei。"""
from __future__ import annotations

import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
from matplotlib import font_manager
import matplotlib.pyplot as plt
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
FIG = ROOT / "docs" / "figures_v2"

for fp in [r"C:\Windows\Fonts\msyh.ttc", r"C:\Windows\Fonts\msyh.ttf",
           r"C:\Windows\Fonts\simhei.ttf", r"C:\Windows\Fonts\Deng.ttf"]:
    if Path(fp).exists():
        font_manager.fontManager.addfont(fp)
plt.rcParams["font.sans-serif"] = ["Microsoft YaHei", "SimHei", "DejaVu Sans"]
plt.rcParams["axes.unicode_minus"] = False

C_TAG, C_SIG, C_RSA, C_REF = "#2b6cb0", "#c05621", "#718096", "#9f7aea"


def load(name):
    with open(DATA / name, "r", encoding="utf-8") as fh:
        return json.load(fh)


def savefig(fig, name):
    out = FIG / name
    fig.savefig(out, dpi=160, bbox_inches="tight")
    plt.close(fig)
    print("saved", out)


def ecdf(values: list) -> tuple:
    arr = np.sort(np.asarray(values, dtype=np.float64))
    y = np.arange(1, len(arr) + 1) / len(arr)
    return arr, y


def fig0():
    fig, axes = plt.subplots(1, 2, figsize=(13, 4.8))
    ax = axes[0]
    ax.set_title("Track A · LWE 认证标签（对称 MAC）")
    for i, (head, sub) in enumerate([
            ("1. 交易 tx", "SHA-256(tx)"),
            ("2. 派生矩阵 A (n×n)", "一事一密"),
            ("3. 标签 b = A·s + e", "私钥 s ∈ {-1,0,1}^n"),
            ("4. 持钥方校验", "‖b − A·s‖_∞ ≤ V")]):
        y = 0.88 - i * 0.24
        ax.add_patch(plt.Rectangle((0.06, y - 0.085), 0.88, 0.17,
                                   facecolor=C_TAG, alpha=0.12, edgecolor=C_TAG))
        ax.text(0.5, y, head, ha="center", va="center", fontsize=11,
                fontweight="bold", color="#1a365d")
        ax.text(0.5, y - 0.04, sub, ha="center", va="center", fontsize=8.5)
        if i < 3:
            ax.annotate("", xy=(0.5, y - 0.135), xytext=(0.5, y - 0.09),
                        arrowprops=dict(arrowstyle="-|>", color="gray"))
    ax.text(0.5, -0.06, "语义：持钥校验；攻击 = 搜索 LWE", ha="center",
            fontsize=9, color="#4a5568")
    ax.set_xlim(0, 1); ax.set_ylim(-0.18, 1.05); ax.axis("off")

    ax = axes[1]
    ax.set_title("Track B · 公开可验证格签名（FS-with-Aborts）")
    for i, (head, sub) in enumerate([
            ("1. 公钥 pk = (A, T=A·S)", "私钥 S 短矩阵（三元）"),
            ("2. y ← U([-κ,κ]^n)", "w = A·y"),
            ("3. c = H(tx ‖ w)", "挑战 c 稀疏 {±1}"),
            ("4. z = y + S·c", "重试直到 ‖z‖_∞ ≤ κ−h"),
            ("5. 验签：c′ = H(tx ‖ A·z − T·c)", "z 短 且 c′ == c")]):
        y = 0.94 - i * 0.21
        color = C_SIG if i % 2 == 0 else "#dd6b20"
        ax.add_patch(plt.Rectangle((0.06, y - 0.07), 0.88, 0.14,
                                   facecolor=color, alpha=0.12, edgecolor=color))
        ax.text(0.5, y, head, ha="center", va="center", fontsize=9.5,
                fontweight="bold", color="#7b341e")
        ax.text(0.5, y - 0.035, sub, ha="center", va="center", fontsize=8)
        if i < 4:
            ax.annotate("", xy=(0.5, y - 0.095), xytext=(0.5, y - 0.072),
                        arrowprops=dict(arrowstyle="-|>", color="gray"))
    ax.text(0.5, -0.1, "伪造 → 求短 S′：A·S′ = T（非齐次 SIS）", ha="center",
            fontsize=9, color="#4a5568")
    ax.set_xlim(0, 1); ax.set_ylim(-0.2, 1.1); ax.axis("off")
    fig.tight_layout()
    savefig(fig, "v2_fig0_scheme.png")


def fig1():
    data = load("eval_v2_e1.json")
    fig, axes = plt.subplots(1, 2, figsize=(12.5, 4.4))
    ax = axes[0]
    vf = np.asarray(data["valid_residual_hist"], dtype=float)
    tf = np.asarray(data["tamper_residual_hist"], dtype=float)
    common = min(len(vf), len(tf))
    vh, th = vf[:common] / vf.sum(), tf[:common] / tf.sum()
    xs = np.arange(common)
    ax.bar(xs - 0.2, vh, width=0.4, label="合法标签残差", color=C_TAG)
    ax.bar(xs + 0.2, th, width=0.4, label="篡改交易残差", color=C_SIG, alpha=0.7)
    ax.axvline(data["params"]["V"], color="red", ls="--", lw=1.5,
               label=f"验证阈值 V={data['params']['V']}")
    ax.set_yscale("log")
    ax.set_xlabel("max|b − A·s|_∞"); ax.set_ylabel("占比（log）")
    ax.legend(fontsize=9); ax.grid(alpha=0.3)
    ax.set_title("校验残差分布（合法 vs 篡改）")

    ax = axes[1]
    ax.plot(data["sweep_v"], data["false_reject_by_v"], "o-", color=C_TAG,
            label="合法误拒率")
    ax.plot(data["sweep_v"], data["tamper_pass_by_v"], "s-", color=C_SIG,
            label="篡改放行率")
    ax.axvline(data["params"]["V"], color="red", ls="--", lw=1.2)
    ax.set_xlabel("验证容差 V"); ax.set_ylabel("比例")
    ax.set_ylim(-0.03, 1.03); ax.legend(fontsize=9); ax.grid(alpha=0.3)
    ax.set_title("误拒率 / 篡改放行率 随 V")
    fig.tight_layout()
    savefig(fig, "v2_fig1_correctness.png")


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
                capsize=3, label="实测恢复成功率（95% CI）")
    ax.set_xlabel("私钥维度 n（q=257, σ=5，缩尺）")
    ax.set_ylabel("实测恢复成功率", color=C_TAG)
    ax.set_ylim(-0.05, 1.05); ax.grid(alpha=0.3)
    ax2 = ax.twinx()
    ax2.plot(ns, est, "s--", color=C_RSA, lw=1.8, ms=5, label="估计 bit 安全级")
    ax2.set_ylabel("估计 bit 安全级（core-SVP）", color=C_RSA)
    h1, l1 = ax.get_legend_handles_labels(); h2, l2 = ax2.get_legend_handles_labels()
    ax.legend(h1 + h2, l1 + l2, fontsize=9, loc="center left")
    ax.set_title("I1：n↑ → 估计安全↑ 且 实测恢复↓（Wilson 95% CI）")
    fig.tight_layout()
    savefig(fig, "v2_fig2_e3_nsweep.png")


def fig3():
    data = load("eval_v2_e3.json")
    fig, axes = plt.subplots(1, 2, figsize=(12.2, 4.3))
    ax = axes[0]
    pts = data["sweep_b_samples"]
    xs = [p["m_transactions"] for p in pts]
    rate = [p["success_rate"] for p in pts]
    lo = [p["success_rate"] - p["ci_low"] for p in pts]
    hi = [p["ci_high"] - p["success_rate"] for p in pts]
    ax.errorbar(xs, rate, yerr=[lo, hi], fmt="o-", color=C_SIG, lw=2, ms=6,
                capsize=3)
    ax.set_xlabel("历史交易样本数 M（n=6, σ=5）"); ax.set_ylabel("实测恢复成功率")
    ax.set_ylim(-0.05, 1.05); ax.grid(alpha=0.3)
    ax.set_title("样本越多攻击越有利（95% CI）")

    ax = axes[1]
    pts = data["sweep_c_sigma"]
    xs = [p["sigma"] for p in pts]
    rate = [p["success_rate"] for p in pts]
    lo = [p["success_rate"] - p["ci_low"] for p in pts]
    hi = [p["ci_high"] - p["success_rate"] for p in pts]
    ax.errorbar(xs, rate, yerr=[lo, hi], fmt="o-", color=C_TAG, lw=2, ms=6,
                capsize=3)
    ax.set_xlabel("噪声标准差 σ（n=12, q=257）"); ax.set_ylabel("实测恢复成功率")
    ax.set_ylim(-0.05, 1.05); ax.grid(alpha=0.3)
    ax.set_title("噪声越大恢复越难（95% CI）")
    ax.text(0.98, 0.03, "教学级估计器在该区退化为维度上界（见 METHODOLOGY）\n"
                        "故本图只放实测 + CI", transform=ax.transAxes, ha="right",
            fontsize=8, color="#718096")
    fig.tight_layout()
    savefig(fig, "v2_fig3_e3_msigma.png")


def fig4():
    data = load("eval_v2_e2.json")
    schemes = data["schemes"]
    labels, pks, sks, sigs, measured = [], [], [], [], []
    for key, item in schemes.items():
        if key == "reference_nist":
            continue
        labels.append({"track_a_lwe_tag": "Track A\nLWE 标签(对称)",
                       "track_b_lwe_sig": "Track B\n格签名",
                       "rsa3072_pss": "RSA-3072\n+PSS"}[key])
        pks.append(item.get("pk_bytes") or 0)
        sks.append(item.get("sk_bytes") or 0)
        sigs.append(item.get("signature_bytes", item.get("credential_bytes")) or 0)
        measured.append(True)
    ref = schemes["reference_nist"]
    for key in ("ml_dsa_44", "fn_dsa_512", "ecdsa_p256"):
        labels.append({"ml_dsa_44": "ML-DSA-44\n(FIPS 204)",
                       "fn_dsa_512": "FN-DSA-512\n(FIPS 206)",
                       "ecdsa_p256": "ECDSA\nP-256"}[key])
        pks.append(ref[key]["pk_bytes"]); sks.append(ref[key]["sk_bytes"])
        sigs.append(ref[key]["signature_bytes"]); measured.append(False)
    x = np.arange(len(labels)); width = 0.26
    fig, ax = plt.subplots(figsize=(10.4, 4.8))
    ax.bar(x - width, pks, width, label="公钥 pk", color="#3182ce")
    ax.bar(x, sks, width, label="私钥 sk", color="#38a169")
    ax.bar(x + width, sigs, width, label="签名/凭证", color="#dd6b20")
    ax.set_xticks(x); ax.set_xticklabels(labels, fontsize=9)
    ax.set_yscale("log"); ax.set_ylabel("字节数（log 轴）")
    ax.legend(fontsize=9); ax.grid(alpha=0.3, which="both")
    for i, m in enumerate(measured):
        if not m:
            ax.text(i, pks[i] * 1.2, "官方值", ha="center", fontsize=8,
                    color="#718096")
    ax.set_title("尺寸对照（Track A/B、RSA-OpenSSL 为本机实测；NIST 项官方值）")
    ax.text(0, -0.22,
            "Track A 对称：共享私钥 144 B + 凭证 288 B；Track B ringless 公钥 ~224 KB\n"
            "→ 需要 module/ring 结构（ML-DSA pk 1312 B）的工程证据",
            transform=ax.transAxes, fontsize=8.5, color="#4a5568")
    fig.tight_layout()
    savefig(fig, "v2_fig4_sizes.png")


def fig5():
    data = load("eval_v2_e2.json")
    schemes = data["schemes"]
    fig, axes = plt.subplots(1, 2, figsize=(12.4, 4.4))
    ax = axes[0]
    drawn = False
    for key, color, label in [("track_a_lwe_tag", C_TAG, "Track A 签发"),
                              ("track_b_lwe_sig", C_SIG, "Track B 签名")]:
        samples = schemes[key]["sign_ms"]["samples_ms"]
        xs, ys = ecdf(samples)
        ax.plot(xs, ys, "o-", color=color, lw=1.5, ms=2.5, label=f"{label}（ECDF, n={len(samples)}）")
        drawn = True
    rsa = schemes["rsa3072_pss"]["sign_ms"]
    ax.axvline(rsa["median_ms"], color=C_RSA, ls="--", lw=2,
               label=f"RSA-3072 (OpenSSL) {rsa['median_ms']:.2f}ms")
    ax.set_xscale("log")
    ax.set_xlabel("签发耗时（ms，log）"); ax.set_ylabel("累计概率")
    ax.legend(fontsize=9); ax.grid(alpha=0.3, which="both")
    ax.set_title("真实 ECDF：Track B 长尾清晰（median=1.3ms, p99=9ms）")

    ax = axes[1]
    rejects = schemes["track_b_lwe_sig"]["reject_tries"]
    hist = rejects["hist"]
    xs = np.arange(len(hist))
    ax.bar(xs, hist, color=C_SIG)
    ax.set_xlabel("单次签名拒绝（重试）次数"); ax.set_ylabel("出现次数")
    ax.text(0.98, 0.9, f"median={rejects['median']}  p99={rejects['p99']}  "
                       f"max={rejects['max']}", transform=ax.transAxes, ha="right",
            fontsize=10, color="#7b341e")
    ax.set_title("Track B 拒绝采样重试分布（WCET 视角）")
    fig.tight_layout()
    savefig(fig, "v2_fig5_timing.png")


def fig6():
    data = load("eval_v2_e4.json")
    rows = data["rows"]
    labels = [r["scheme"] for r in rows]
    fig, axes = plt.subplots(1, 2, figsize=(12.8, 4.6))
    colors = [C_TAG, C_SIG, C_RSA, C_REF, C_REF, "#a0aec0"]
    ax = axes[0]
    ax.bar(np.arange(len(labels)), [r["inflation_vs_payload"] for r in rows],
           color=colors)
    ax.set_yscale("log")
    ax.set_xticks(np.arange(len(labels)))
    ax.set_xticklabels(labels, rotation=18, fontsize=8)
    ax.set_ylabel("记账开销 / 交易负载（倍数，log）")
    ax.grid(alpha=0.3, which="both")
    ax.set_title("区块记账膨胀（N=1000 笔，64 B/笔）")
    ax = axes[1]
    ax.bar(np.arange(len(labels)), [r["verify_tps_median"] for r in rows],
           color=colors)
    ax.set_yscale("log")
    ax.set_xticks(np.arange(len(labels)))
    ax.set_xticklabels(labels, rotation=18, fontsize=8)
    ax.set_ylabel("验签吞吐 TPS（log）")
    ax.grid(alpha=0.3, which="both")
    ax.set_title("单节点验签吞吐（实测方案用 E2 中位数）")
    ax.text(0, -0.25, "紫/灰柱 = NIST 官方尺寸 + 文献耗时参考；其余 = 本机实测。",
            transform=ax.transAxes, fontsize=8.5, color="#4a5568")
    fig.tight_layout()
    savefig(fig, "v2_fig6_blockchain.png")


def main():
    FIG.mkdir(parents=True, exist_ok=True)
    for fn in (fig0, fig1, fig2, fig3, fig4, fig5, fig6):
        fn()
    print("all figures done in", FIG)


if __name__ == "__main__":
    main()