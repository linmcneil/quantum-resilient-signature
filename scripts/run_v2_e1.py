"""E1：Track A（LWE 认证标签）正确性与误拒/漏检阈值曲线。

输出 data/eval_v2_e1.json：
- valid_residuals：合法标签校验残差分布（max|e| 的直方图数据）
- tamper_residuals：篡改交易后的校验残差分布
- sweep：V ∈ {0..16} 下的合法误拒率与篡改放行率
- rates：默认 V 下的合法接受率 / 篡改检出率 / 盲猜拒绝率
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from qrsv2.tag import LweTag
from qrsv2.params import TagParams
from qrsv2.estimator import recommend_tag_params


def synthetic_tx(index: int, seed: int = 0) -> bytes:
    rng = np.random.default_rng(seed * 10 ** 6 + index)
    dept = ["内分泌", "心血管", "消化", "神经", "肝病"][int(rng.integers(0, 5))]
    content = "".join(chr(97 + int(rng.integers(0, 26))) for _ in range(48))
    return f"{dept}|{index}|{content}".encode("utf-8")


def main() -> None:
    params_rec = recommend_tag_params(80.0)          # I1：按目标 80 bits 定参
    params = TagParams(n=params_rec["n"], q=params_rec["q"],
                       sigma=params_rec["sigma"], tail=params_rec["tail"],
                       V=params_rec["V"])
    tagger = LweTag(params=params, seed=12345)

    n_valid = 1500
    n_tamper = 1500
    valid_res = []
    tamper_res = []
    rng = np.random.default_rng(99)

    for i in range(n_valid):
        tx = synthetic_tx(i)
        b = tagger.issue(tx, seed=1000 + i)
        valid_res.append(tagger.residual(tx, b))
    for i in range(n_tamper):
        tx = synthetic_tx(i)
        b = tagger.issue(tx, seed=2000 + i)
        raw = bytearray(tx)
        pos = int(rng.integers(0, len(raw)))
        raw[pos] ^= 0x01 | rng.integers(0, 255)
        tampered = bytes(raw)
        if tampered == tx:  # 确保真的改了
            raw[pos] ^= 2
            tampered = bytes(raw)
        tamper_res.append(tagger.residual(tampered, b))

    valid_res = np.asarray(valid_res, dtype=np.int64)
    tamper_res = np.asarray(tamper_res, dtype=np.int64)

    # 盲猜凭证（随机 b）：应被 V 拒绝
    n_blind = 300
    blind_ok = 0
    for i in range(n_blind):
        tx = synthetic_tx(i)
        rnd = np.random.default_rng(3000 + i)
        fake = rnd.integers(0, params.q, size=params.n, dtype=np.int64)
        if tagger.verify(tx, fake):
            blind_ok += 1

    sweep_v = list(range(0, 17))
    false_reject = []
    tamper_pass = []
    for v in sweep_v:
        false_reject.append(float(np.mean(valid_res > v)))
        tamper_pass.append(float(np.mean(tamper_res <= v)))

    default_v = params.V
    payload = {
        "params": params_rec,
        "n_valid": int(n_valid),
        "n_tamper": int(n_tamper),
        "valid_accept_rate": float(np.mean(valid_res <= default_v)),
        "tamper_detect_rate": float(np.mean(tamper_res > default_v)),
        "blind_reject_rate": 1.0 - blind_ok / n_blind,
        "valid_residual_mean": float(valid_res.mean()),
        "valid_residual_max": int(valid_res.max()),
        "valid_residual_hist": np.histogram(valid_res, bins=range(0, 15))[0].tolist(),
        "tamper_residual_hist": np.histogram(np.clip(tamper_res, 0, 14),
                                             bins=range(0, 16))[0].tolist(),
        "sweep_v": sweep_v,
        "false_reject_by_v": false_reject,
        "tamper_pass_by_v": tamper_pass,
        "note": "残差为 max|b - A·s|_inf（中心化模 q）",
    }
    out = Path(__file__).resolve().parents[1] / "data" / "eval_v2_e1.json"
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
    print(f"E1 done -> {out}")
    print(f"  合法接受率={payload['valid_accept_rate']:.4f} "
          f"篡改检出率={payload['tamper_detect_rate']:.4f} "
          f"盲猜拒绝率={payload['blind_reject_rate']:.4f}")


if __name__ == "__main__":
    main()