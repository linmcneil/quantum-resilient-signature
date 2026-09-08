"""E3：缩尺格攻击（I1 交叉验证）。

(a) n 扫描 σ=5；(b) M 扫描 n=6；(c) σ 扫描 n=12。
成功率带 Wilson 95% 置信区间；每点时间上限保护。
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from qrsv2.estimator import estimate_lwe_search
from qrsv2.expand import new_rng, sample_truncated_gaussian
from qrsv2.lattices import lwe_kannan_embedding
from qrsv2.stats import wilson_ci

POINT_TIME_LIMIT_S = 120.0


def sample_instance(rng, n: int, rows: int, q: int, sigma: float, tail: int):
    secret = rng.choice(np.array([-1, 0, 1], dtype=np.int64), size=n)
    a_mat = rng.integers(0, q, size=(rows, n), dtype=np.int64)
    noise = np.array([sample_truncated_gaussian(rng, sigma, tail)
                      for _ in range(rows)], dtype=np.int64)
    b_vec = (a_mat @ secret + noise) % q
    return secret, a_mat, b_vec


def attack_once(rng, n: int, rows: int, q: int, sigma: float, tail: int) -> bool:
    secret, a_mat, b_vec = sample_instance(rng, n, rows, q, sigma, tail)
    return lwe_kannan_embedding(a_mat, b_vec, q, sigma=sigma, s_true=secret)["success"]


def run_point(rng, n: int, rows: int, q: int, sigma: float, tail: int,
              trials: int) -> tuple:
    succ = 0
    done = 0
    t0 = time.perf_counter()
    for _ in range(trials):
        if time.perf_counter() - t0 > POINT_TIME_LIMIT_S:
            break
        if attack_once(rng, n, rows, q, sigma, tail):
            succ += 1
        done += 1
    return succ, done


def make_point(name: str, succ: int, done: int, est) -> dict:
    low, high = wilson_ci(succ, done)
    point = {"success_rate": round(succ / max(done, 1), 4),
             "ci_low": round(low, 4), "ci_high": round(high, 4),
             "trials": done, "est_bits": round(est.bits, 1),
             "est_beta": est.beta, "dim": est.dim}
    print(f"[{name}] {point}", flush=True)
    return point


def main() -> None:
    q = 257
    sigma_a = 5.0
    tail = 16
    rng = new_rng(20260908)

    # (a) n 扫描
    sweep_a = []
    for n in range(5, 21):
        trials = 10 if n >= 14 else 12
        succ, done = run_point(rng, n, n, q, sigma_a, tail, trials)
        point = make_point("a", succ, done, estimate_lwe_search(n, n, q, sigma_a))
        point.update({"n": n, "rows": n, "q": q, "sigma": sigma_a})
        sweep_a.append(point)

    # (b) M 扫描：n=6
    sweep_b = []
    for m in range(1, 7):
        rows = 6 * m
        succ, done = run_point(rng, 6, rows, q, sigma_a, tail, 8)
        point = make_point("b", succ, done, estimate_lwe_search(6, rows, q, sigma_a))
        point.update({"n": 6, "rows": rows, "m_transactions": m, "q": q,
                      "sigma": sigma_a})
        sweep_b.append(point)

    # (c) σ 扫描：n=12
    sweep_c = []
    for s_val in [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0]:
        tail_c = max(1, int(round(3 * s_val + 0.5)))
        succ, done = run_point(rng, 12, 12, q, s_val, tail_c, 10)
        point = make_point("c", succ, done, estimate_lwe_search(12, 12, q, s_val))
        point.update({"sigma": s_val, "tail": tail_c, "n": 12, "rows": 12, "q": q})
        sweep_c.append(point)

    payload = {
        "q": q, "sigma_default": sigma_a, "seed": 20260908,
        "ci_method": "Wilson 95%（1.96σ）",
        "note": ("缩尺小维度 LLL 嵌入攻击；q=257、σ≈5 使目标/GH 比接近 1，"
                 "在小维度观察到相变；教学级估计器仅用于趋势对照"),
        "sweep_a_n": sweep_a, "sweep_b_samples": sweep_b, "sweep_c_sigma": sweep_c,
    }
    out = Path(__file__).resolve().parents[1] / "data" / "eval_v2_e3.json"
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
    print("E3 done ->", out)


if __name__ == "__main__":
    main()