"""生成全套“数形结合”图表（保存到 docs/figures/）。

图 0  scheme 流程图：TX -> SHA-256 -> A，b = A·s + e (mod q)，验证 ‖b-A·s‖_∞<=V
图 1  三种方案的防御成功率柱状图（含伪造计数标注）
图 2  合法 vs 被篡改/盲猜凭证的 ‖b-A·s‖_∞ 分布 + 阈值 V 与检出率
图 3  防御成功率随尝试次数累计的稳定性曲线
图 4  LWE 攻击预算（历史样本数 M）vs 伪造成功率曲线
图 5  签名/验签延迟对比（LWE vs RSA-1024/2048，log 轴）
"""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

import numpy as np

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib import font_manager

_CJK_FONTS = [r"C:\Windows\Fonts\msyh.ttc", r"C:\Windows\Fonts\msyhbd.ttc",
              r"C:\Windows\Fonts\simhei.ttf", r"C:\Windows\Fonts\simsun.ttc"]
for _fp in _CJK_FONTS:
    if Path(_fp).exists():
        font_manager.fontManager.addfont(_fp)
plt.rcParams["font.sans-serif"] = ["Microsoft YaHei", "SimHei", "DejaVu Sans"]
plt.rcParams["axes.unicode_minus"] = False

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT.parent))

from qrs import attacks                       # noqa: E402
from qrs.bench import bench_latencies         # noqa: E402
from qrs.lwe import LweIdentity               # noqa: E402
from qrs.params import LweParams              # noqa: E402

DATA = ROOT / "data"
FIG = ROOT / "docs" / "figures"

BLUE = "#1f77b4"
RED = "#d62728"
GREEN = "#2ca02c"
GREY = "#7f7f7f"


def savefig(fig, name):
    FIG.mkdir(parents=True, exist_ok=True)
    path = FIG / name
    fig.tight_layout()
    fig.savefig(path, dpi=200, bbox_inches="tight")
    plt.close(fig)
    print("saved", path)


# ---------- 图 0：方案流程图 ----------
def plot_overview():
    fig, ax = plt.subplots(figsize=(9.2, 3.6))
    ax.axis("off")

    def box(x, y, w, h, text, fc="#eef4fb", ec=BLUE, fs=10, style="round,pad=0.25"):
        ax.add_patch(matplotlib.patches.FancyBboxPatch(
            (x, y), w, h, boxstyle=style, linewidth=1.4, edgecolor=ec,
            facecolor=fc, zorder=2))
        ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=fs, zorder=3)

    def arrow(x1, y1, x2, y2, label=None, dy=0.0):
        ax.annotate("", xy=(x2, y2), xytext=(x1, y1),
                    arrowprops=dict(arrowstyle="-|>", color="#333333", lw=1.5), zorder=1)
        if label:
            ax.text((x1 + x2) / 2, (y1 + y2) / 2 + dy, label, ha="center", va="bottom",
                    fontsize=8.5, color="#333333")

    # 签名侧
    box(0.02, 0.62, 0.24, 0.20, "交易 TX", fc="#fef7e0", ec="#e6b800")
    box(0.02, 0.14, 0.24, 0.20, "私钥 s ∈ {-1,0,1}^n", fc="#e8f7e8", ec=GREEN)
    box(0.34, 0.38, 0.28, 0.30, "SHA-256(TX)\n→ 种子 → 矩阵 A", fc="#eef4fb", ec=BLUE)
    box(0.70, 0.38, 0.26, 0.30, "b = A·s + e (mod q)", fc="#eef4fb", ec=BLUE)
    box(0.70, 0.02, 0.26, 0.18, "e ~ 离散高斯(σ=2)", fc="#e8f7e8", ec=GREEN)
    arrow(0.26, 0.72, 0.34, 0.58)
    arrow(0.26, 0.24, 0.60, 0.5, label=None) if False else arrow(0.26, 0.30, 0.36, 0.52)
    arrow(0.62, 0.53, 0.70, 0.53)
    arrow(0.83, 0.38, 0.83, 0.20)

    ax.text(0.5, -0.06, "图 0  LWE 认证凭证：矩阵 A 由交易哈希逐笔生成（一事一密），噪声 e 掩盖短向量 s",
            ha="center", va="top", fontsize=9, color="#333333")
    savefig(fig, "fig0_scheme_overview.png")


# ---------- 图 1：防御成功率柱状图 ----------
def plot_defense_bars(summary_path=None):
    sp = summary_path or DATA / "blockchain_defense_summary.json"
    if not Path(sp).exists():
        print("[skip fig1] summary json not found:", sp)
        return None
    s = json.loads(Path(sp).read_text(encoding="utf-8"))
    names = {"lwe": "LWE scheme", "rsa_raw": "RSA raw", "rsa_hash": "RSA + SHA-256"}
    colors = [BLUE, RED, GREEN]
    schemes = list(names)
    vals = [s["schemes"][k]["defense_rate"] * 100 for k in schemes]
    forged = [s["schemes"][k]["forged"] for k in schemes]
    n = s["attempts"]
    fig, ax = plt.subplots(figsize=(7.6, 4.4))
    bars = ax.bar([names[k] for k in schemes], vals, color=colors, alpha=0.9, width=0.6)
    ax.set_ylim(0, 115)
    ax.set_ylabel("Defense success rate (%)")
    ax.set_title(f"Anti-forgery defense rate  (N = {n} attacks per scheme)")
    for b, v, f in zip(bars, vals, forged):
        ax.text(b.get_x() + b.get_width() / 2, v + 3, f"{v:.2f}%\nforged {f}/{n}",
                ha="center", va="bottom", fontsize=10)
    ax.grid(axis="y", ls="--", alpha=0.35)
    ax.spines[["top", "right"]].set_visible(False)
    savefig(fig, "fig1_defense_rate.png")
    return s


# ---------- 图 2：验证残差分布与阈值 ----------
def plot_verify_residuals(n_trials=2000, seed=7):
    ident = LweIdentity(LweParams(), seed=seed)
    p = ident.params
    legit, tampered, blind = [], [], []
    rng = np.random.default_rng(seed + 1)

    def residual(tx, b):
        diff = (b - (ident.derive_a(tx) @ ident.s) % p.q) % p.q
        diff = np.where(diff > p.q // 2, diff - p.q, diff)
        return int(np.max(np.abs(diff)))

    for i in range(n_trials):
        tx = f"tx-{i}:{rng.integers(0, 2 ** 40)}"
        b = ident.sign_transaction(tx)
        legit.append(residual(tx, b))
        tampered.append(residual(tx + "&tampered=1", b))
        blind.append(residual(attacks.gen_tx(rng, "blind"), rng.integers(0, p.q, size=p.n)))

    V = p.verify_bound
    det_tamper = np.mean(np.array(tampered) > V) * 100
    det_blind = np.mean(np.array(blind) > V) * 100
    false_reject = np.mean(np.array(legit) > V) * 100

    fig, ax = plt.subplots(figsize=(8.4, 4.6))
    bins = np.linspace(0, p.q // 2, 90)
    ax.hist(legit, bins=bins, alpha=0.75, label=f"Legit credential (max |b-A·s|_inf)", color=GREEN, density=True)
    ax.hist(tampered, bins=bins, alpha=0.55, label="Tampered transaction", color=RED, density=True)
    ax.hist(blind, bins=bins, alpha=0.4, label="Blind guess (no s)", color=GREY, density=True)
    ax.axvline(V, color="black", ls="--", lw=1.6)
    ax.text(V, ax.get_ylim()[1] * 0.92, f"  V={V}", color="black", fontsize=10)
    ax.set_xlabel(r"$\|b - A\cdot s\|_\infty$  (centered mod $q$)")
    ax.set_ylabel("Density")
    ax.set_title(f"Tamper & blind-forgery detection  (n={p.n}, q={p.q});  "
                 f"tamper detect={det_tamper:.2f}%  false-reject={false_reject:.3f}%")
    ax.legend(frameon=False)
    ax.grid(alpha=0.25, ls="--")
    ax.spines[["top", "right"]].set_visible(False)
    savefig(fig, "fig2_verify_residuals.png")
    return {"tamper_detect_pct": det_tamper, "blind_detect_pct": det_blind,
            "false_reject_pct": false_reject}


# ---------- 图 3：累计稳定性曲线 ----------
def plot_running_defense(csv_path=None):
    cp = csv_path or DATA / "blockchain_defense_data.csv"
    if not Path(cp).exists():
        print("[skip fig3] csv not found:", cp)
        return None
    data = {}
    with open(cp, encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            data.setdefault(row["scheme"], []).append(int(row["forged"]))
    fig, ax = plt.subplots(figsize=(7.6, 4.4))
    style = {"lwe": (BLUE, "LWE scheme"), "rsa_raw": (RED, "RSA raw"),
             "rsa_hash": (GREEN, "RSA + SHA-256")}
    for scheme, (color, label) in style.items():
        arr = np.cumsum(data.get(scheme, []))
        idx = np.arange(1, len(arr) + 1)
        running = 1.0 - arr / idx
        ax.plot(idx, running * 100, color=color, lw=1.8, label=label)
    ax.set_xlabel("Number of attack attempts so far")
    ax.set_ylabel("Running defense rate (%)")
    ax.set_ylim(-3, 103)
    ax.set_title("Stability of defense rate over accumulated attempts")
    ax.legend(frameon=False, loc="center right")
    ax.grid(alpha=0.25, ls="--")
    ax.spines[["top", "right"]].set_visible(False)
    savefig(fig, "fig3_running_defense.png")


# ---------- 图 4：攻击预算（样本数 M）扫描 ----------
def collect_sweep(queries_list, attempts_per_point=60, seed=11):
    out = []
    for m in queries_list:
        ident = LweIdentity(LweParams(), seed=seed)
        rng = np.random.default_rng(seed + m)
        forged = 0
        for _ in range(attempts_per_point):
            tx = attacks.gen_tx(rng, "target")
            forged += int(attacks.lwe_statistical_forge(ident, tx, rng, m))
        out.append({"queries": m, "forged": forged, "attempts": attempts_per_point,
                    "forgery_rate": forged / attempts_per_point})
    return out


def plot_attack_budget_sweep(attempts_per_point=60, seed=11, cache=True):
    cache_path = DATA / "attack_sweep.csv"
    if cache and cache_path.exists():
        rows = list(csv.DictReader(open(cache_path, encoding="utf-8")))
    else:
        queries_list = [1, 2, 4, 8, 16, 32, 64, 96]
        rows = collect_sweep(queries_list, attempts_per_point, seed)
        with open(cache_path, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=["queries", "forged", "attempts", "forgery_rate"])
            w.writeheader()
            w.writerows(rows)
    xs = [int(r["queries"]) for r in rows]
    ys = [float(r["forgery_rate"]) * 100 for r in rows]
    fig, ax = plt.subplots(figsize=(7.6, 4.4))
    ax.plot(xs, ys, marker="o", color=BLUE, lw=1.8, markersize=5)
    for x, y in zip(xs, ys):
        ax.annotate(f"{y:.1f}%", (x, y), textcoords="offset points", xytext=(0, 8),
                    ha="center", fontsize=9)
    ax.set_xscale("log", base=2)
    ax.set_xticks(xs)
    ax.set_xticklabels(xs)
    ax.set_xlabel("Attacker history samples M (chosen-message oracle queries)")
    ax.set_ylabel("Forgery success rate (%)")
    ax.set_ylim(-5, 105)
    ax.set_title(f"LWE: forgery rate vs attacker budget  (n=128, least-squares+rounding attack, "
                 f"{int(rows[0]['attempts'])} attempts/point)")
    ax.grid(alpha=0.3, ls="--")
    ax.spines[["top", "right"]].set_visible(False)
    savefig(fig, "fig4_attack_budget_sweep.png")


# ---------- 图 5：延迟对比 ----------
def plot_latency(n_trials=200, seed=42):
    bench = bench_latencies(n_trials=n_trials, seed=seed)
    groups = ["lwe128", "rsa1024", "rsa2048"]
    labels = ["LWE (n=128)", "RSA-1024", "RSA-2048"]
    sign = [bench[g]["sign_ms"] for g in groups]
    verify = [bench[g]["verify_ms"] for g in groups]
    x = np.arange(len(groups))
    w = 0.38
    fig, ax = plt.subplots(figsize=(7.6, 4.6))
    b1 = ax.bar(x - w / 2, sign, w, label="Sign / issue", color=BLUE, alpha=0.9)
    b2 = ax.bar(x + w / 2, verify, w, label="Verify", color=GREEN, alpha=0.9)
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.set_ylabel("Time per operation (ms, log scale)")
    ax.set_yscale("log")
    ax.set_title(f"Latency comparison (avg of {n_trials} ops)")
    for bars in (b1, b2):
        for b in bars:
            ax.annotate(f"{b.get_height():.3g}", (b.get_x() + b.get_width() / 2, b.get_height()),
                        textcoords="offset points", xytext=(0, 3), ha="center", fontsize=8)
    ax.legend(frameon=False)
    ax.grid(axis="y", alpha=0.3, ls="--")
    ax.spines[["top", "right"]].set_visible(False)
    savefig(fig, "fig5_latency.png")


def main():
    print("=== make figures ===")
    plot_overview()
    plot_defense_bars()
    plot_verify_residuals()
    plot_running_defense()
    plot_attack_budget_sweep(attempts_per_point=40)
    plot_latency()


if __name__ == "__main__":
    main()
