"""安全参数估计器（I1 核心）。

方法学口径（与 lattice-estimator / 文献一致的教学级简化）：
- 攻击模型：对格问题的“最短向量/最近向量”求解，用 BKZ 理想化根 Hermite 因子
    delta(beta) = ( beta/(2*pi*e) * (pi*beta)^(1/beta) )^(1/(2*(beta-1)))
  逼近；BKZ-β 的经典 core-SVP 成本取 2^(0.292*beta)（Alkim-Ducas-Pöppelmann-
  Schwabe / NewHope 口径）。量子 core-SVP 取 2^(0.265*beta)。
- Track A (LWE)：Kannan 嵌入 uSVP：d = m + n + 1，体积 V = q^m * t_embed，
  目标短向量长度 ~ sqrt(||e||^2 + ||s||^2 + t_embed^2)。
- Track B (SIS)：核格 Lambda = {x : A x ≡ 0 (mod q)}，维数 n_dim、余体积 q^n_rows；
  GH 界 lambda1 ~ sqrt(dim/(2*pi*e)) * q^(n_rows/n_dim)。攻击者找到长度 R 的
  核向量需 root-Hermite delta 使 delta^d * GH >= R（理想化）。
- 免责声明：这是教学级估计，用于“参数相对强弱”排序与缩尺实验对照；
  不替代 lattice-estimator 的完整 primal/dual 分析。数值结果保留到整数。
"""
from __future__ import annotations

import json
import math
from dataclasses import dataclass

import numpy as np


def root_hermite_factor(beta: int) -> float:
    """BKZ-β 可达到的根 Hermite 因子 δ(β)（近似公式，β>=10）。"""
    beta = max(beta, 2)
    x = (beta / (2.0 * math.pi * math.e)) * (math.pi * beta) ** (1.0 / beta)
    return x ** (1.0 / (2.0 * (beta - 1.0)))


def core_svp_cost(beta: int, quantum: bool = False) -> float:
    """BKZ-β 的 core-SVP 成本（log2）。"""
    if beta <= 0:
        return float("inf")
    coeff = 0.265 if quantum else 0.292
    return coeff * beta


def _smallest_beta_for_delta(delta_target: float, dim: int,
                             quantum: bool = False) -> tuple:
    """找最小 beta（<=dim）使得 δ(beta) <= delta_target；返回 (beta, cost_bits)。"""
    if delta_target >= 1.0 or delta_target <= root_hermite_factor(dim):
        return dim, core_svp_cost(dim, quantum=quantum)
    # delta 随 beta 单调下降：对 beta 二分
    lo, hi = 10, dim
    if root_hermite_factor(lo) <= delta_target:
        return lo, core_svp_cost(lo, quantum=quantum)
    if root_hermite_factor(hi) > delta_target:
        return None, float("inf")
    while hi - lo > 1:
        mid = (lo + hi) // 2
        if root_hermite_factor(mid) <= delta_target:
            hi = mid
        else:
            lo = mid
    return hi, core_svp_cost(hi, quantum=quantum)


@dataclass(frozen=True)
class LweSecurityEstimate:
    dim: int          # 嵌入格维数 d = m + n + 1
    volume_log: float # log2(vol)
    target_log: float # log2(短向量长度)
    gh_log: float     # log2(高斯启发式 λ1)
    delta_required: float
    beta: int
    bits: float


def estimate_lwe_search(n: int, m: int, q: int, sigma: float,
                        secret_var: float = 2.0 / 3.0, t_embed: float = 1.0,
                        quantum: bool = False) -> LweSecurityEstimate:
    """Track A：搜索 LWE 的 Kannan 嵌入估计（教学级，对数域）。

    secret_var: 私钥分量二阶矩（均匀 {-1,0,1} 时 = 2/3）
    """
    dim = m + n + 1
    target = math.sqrt(m * sigma * sigma + n * secret_var + t_embed * t_embed)
    # log2(volume) = m*log2(q) + log2(t_embed)
    volume_log = m * math.log2(q) + math.log2(t_embed)
    vol_root = 2.0 ** (volume_log / dim)  # vol^(1/dim)
    gh = math.sqrt(dim / (2.0 * math.pi * math.e)) * vol_root
    delta_required = (target / vol_root) ** (1.0 / dim)
    beta, bits = _smallest_beta_for_delta(delta_required, dim, quantum=quantum)
    return LweSecurityEstimate(
        dim=dim,
        volume_log=volume_log,
        target_log=math.log2(target),
        gh_log=math.log2(gh),
        delta_required=delta_required,
        beta=beta,
        bits=bits,
    )


@dataclass(frozen=True)
class SisSecurityReport:
    dim: int
    gh_log: float
    target_log: float
    gap_db: float      # 10*log10(target/GH)
    note: str


def report_sis_regime(n_dim: int, n_rows: int, q: int,
                      target_norm: float) -> SisSecurityReport:
    """Track B：SIS 核格参数与 GH 界的相对位置（对数域）。

    gap_db > 0 表示目标向量比 GH 界还长 → 格上存在大量短解 → 更偏“易”；
    gap_db < 0 表示目标比 GH 短 → 落在 SIS 困难区（求短解需格基约化）。
    """
    volume_log = n_rows * math.log2(q)
    gh = math.sqrt(n_dim / (2.0 * math.pi * math.e)) * (2.0 ** (volume_log / n_dim))
    gap_db = 10.0 * math.log10(target_norm / gh)
    note = ("gap_db<0: 目标比 GH 短，落在 SIS 困难区（需格基约化）"
            if gap_db < 0 else
            "gap_db>=0: 目标接近/超过 GH，教学原型可能偏弱，需加大 n 或 m")
    return SisSecurityReport(
        dim=n_dim, gh_log=math.log2(gh), target_log=math.log2(target_norm),
        gap_db=gap_db, note=note,
    )


def recommend_tag_params(target_bits: float, q: int = 12289, sigma: float = 2.0,
                         m_factor: float = 1.0) -> dict:
    """扫描 n（A 行=列=m=n）到估计安全级 >= target_bits。"""
    best = None
    for n in range(96, 641, 8):
        m = int(n * m_factor)
        est = estimate_lwe_search(n, m, q, sigma)
        if est.bits >= target_bits:
            best = {"n": n, "m": m, "q": q, "sigma": sigma,
                    "tail": max(6, int(round(3 * sigma))), "V": max(8, int(round(3 * sigma)) + 2),
                    "est_bits": round(est.bits, 1), "beta": est.beta}
            break
    if best is None:
        raise ValueError(f"target {target_bits} bits unreachable in scan range")
    return best


def recommend_sig_params(target_bits: float, q: int = 12289,
                         n_dim: int = 256, n_rows: int = 224,
                         h: int = 32, m_ch: int = 256,
                         accept_p: float = 0.125) -> dict:
    """Track B：先给定 n/n_rows 骨架，报告 SIS 困难区与挑战空间，并反推 kappa。

    拒绝采样接受率 P = ((kappa - h)/kappa)^n_dim 约等于 accept_p
    => kappa ~ h / (1 - accept_p^(1/n_dim))
    """
    kappa = math.ceil(h / (1.0 - accept_p ** (1.0 / n_dim)))
    target_norm = math.sqrt(n_dim * (2.0 / 3.0))  # 三元私钥列向量的期望范数
    rep = report_sis_regime(n_dim, n_rows, q, target_norm)
    challenge_log2 = math.log2(math.comb(m_ch, h)) + h
    return {
        "n_rows": n_rows, "n_dim": n_dim, "q": q, "h": h, "m_ch": m_ch,
        "kappa": kappa, "accept_bound": kappa - h,
        "secret_p": 2.0 / 3.0,
        "sis_gap_db": round(rep.gap_db, 1), "sis_note": rep.note,
        "challenge_log2": round(challenge_log2, 1),
        "accept_p_design": accept_p,
        "note": "教学级估计；正式发布前需用 lattice-estimator 复核 primal/dual",
    }


def dump_params_json(tag: dict, sig: dict, path: str) -> None:
    payload = {
        "methodology": "I1: root-Hermite/core-SVP 教学级估计 + 缩尺实验交叉验证",
        "quantum": False,
        "tag_track_A": tag,
        "sig_track_B": sig,
        "disclaimer": ("教学级估计，非形式化证明；引用请标注方法学口径"),
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    tag_rec = recommend_tag_params(80.0)
    sig_rec = recommend_sig_params(80.0)
    print(json.dumps({"tag_A": tag_rec, "sig_B": sig_rec},
                     ensure_ascii=False, indent=2))