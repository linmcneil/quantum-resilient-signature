"""防御成功率模拟实验（run_blockchain_defense_test）。

对每个方案重复 N 次“攻击者尝试伪造一笔新交易”：
- lwe     ：每轮给攻击者 M 个选择消息签名样本，做线性/舍入恢复攻击；
- rsa_raw ：教科书 RSA，2 次选择消息签名即完成存在性伪造；
- rsa_hash：SHA-256 后再签（类 FDH），乘法伪造被哈希破坏（对照组）。
结果实时写入 blockchain_defense_data.csv，聚合写入 summary JSON。
"""
from __future__ import annotations

import csv
import json
import time
from pathlib import Path

import numpy as np

from . import attacks
from .lwe import LweIdentity
from .params import LweParams, RsaParams
from .rsa_baseline import RsaIdentity


def run_blockchain_defense_test(
    attempts: int = 10000,
    seed: int = 42,
    lwe_queries: int = 8,
    rsa_bits: int = 1024,
    out_dir: str = "data",
) -> dict:
    rng = np.random.default_rng(seed)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    csv_path = out_dir / "blockchain_defense_data.csv"

    lwe = LweIdentity(LweParams(), seed=seed)
    rsa_raw = RsaIdentity(RsaParams(bits=rsa_bits), mode="raw")
    rsa_hash = RsaIdentity(RsaParams(bits=rsa_bits), mode="hash")

    stats = {
        "lwe": {"forged": 0, "attempts": attempts},
        "rsa_raw": {"forged": 0, "attempts": attempts},
        "rsa_hash": {"forged": 0, "attempts": attempts},
    }

    t_start = time.perf_counter()
    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["attempt_id", "scheme", "attack", "target", "oracle_queries", "forged"])
        for i in range(attempts):
            tx_target = attacks.gen_tx(rng, "target")
            # LWE 攻击
            forged_lwe = attacks.lwe_statistical_forge(lwe, tx_target, rng, lwe_queries)
            stats["lwe"]["forged"] += int(forged_lwe)
            writer.writerow([i, "lwe", "least-squares+rounding", i, lwe_queries, int(forged_lwe)])
            # RSA raw 攻击
            m_target = attacks.rand_below(rng, rsa_raw.n)
            forged_raw = attacks.rsa_raw_multiplicative_forge(rsa_raw, m_target, rng)
            stats["rsa_raw"]["forged"] += int(forged_raw)
            writer.writerow([i, "rsa_raw", "multiplicative-existential", i, 2, int(forged_raw)])
            # RSA hash 攻击（对照组）
            forged_hash = attacks.rsa_hash_forge_attempt(rsa_hash, tx_target)
            stats["rsa_hash"]["forged"] += int(forged_hash)
            writer.writerow([i, "rsa_hash", "multiplicative-existential", i, 0, int(forged_hash)])
    elapsed = time.perf_counter() - t_start

    summary = {
        "attempts": attempts,
        "seed": seed,
        "attack_params": {
            "lwe_queries": lwe_queries,
            "rsa_bits": rsa_bits,
            "lwe": {"n": lwe.params.n, "q": lwe.params.q, "sigma": lwe.params.sigma},
        },
        "elapsed_sec": round(elapsed, 2),
        "schemes": {},
    }
    for name, st in stats.items():
        defense = 1.0 - st["forged"] / max(1, st["attempts"])
        summary["schemes"][name] = {
            "forged": st["forged"],
            "attempts": st["attempts"],
            "defense_rate": round(defense, 6),
        }

    json_path = out_dir / "blockchain_defense_summary.json"
    json_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"elapsed={elapsed:.1f}s csv={csv_path} summary={json_path}")
    for name, st in summary["schemes"].items():
        print(
            f"  {name:9s} forged={st['forged']:6d}/{st['attempts']}  "
            f"defense_rate={st['defense_rate']*100:.2f}%"
        )
    return summary
