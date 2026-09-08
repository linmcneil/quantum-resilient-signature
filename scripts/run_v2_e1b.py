"""E1b：Track B（公开可验证格签名）正确性实验。

输出 data/eval_v2_e1b.json：
- valid_accept_rate: 1000 条合法签名验证通过率
- tamper_detect_rate: 1000 条被篡改交易被拒绝率
- forgery_reject_rate: 1000 条随机伪造签名（合法界内的 z + 随机 digest）被拒绝率
- mutation_reject_rate: 1000 条对合法签名做单字节篡改后被拒绝率
签名内部采样与 E2 保持一致（实例种子固定、逐次签名使用内部 RNG）。
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from qrsv2.estimator import recommend_sig_params
from qrsv2.params import SigParams
from qrsv2.signature import LweSignatureScheme, Sig


def synthetic_tx(index: int) -> bytes:
    return f"tx|{index}|medical-record-{index}-{'ab' * 40}".encode("utf-8")


def main() -> None:
    sig_rec = recommend_sig_params(80.0)          # 与 E2/E4 同一套教学级参数
    params = SigParams(n_rows=sig_rec["n_rows"], n_dim=sig_rec["n_dim"],
                       q=sig_rec["q"], h=sig_rec["h"], m_ch=sig_rec["m_ch"],
                       kappa=sig_rec["kappa"], secret_p=sig_rec["secret_p"])
    scheme = LweSignatureScheme(params=params, seed=20260908)

    n = 1000
    txs = [synthetic_tx(i) for i in range(n)]
    sigs = []
    for i in range(n):
        sig, _tries = scheme.sign(txs[i])
        sigs.append(sig)

    valid_ok = sum(1 for i in range(n) if scheme.verify(txs[i], sigs[i]))

    rng = np.random.default_rng(20260908)
    tamper_ok = 0
    for i in range(n):
        raw = bytearray(txs[i])
        pos = int(rng.integers(0, len(raw)))
        raw[pos] ^= (0x01 | int(rng.integers(0, 255))) & 0xFF
        tampered = bytes(raw)
        if tampered == txs[i]:
            raw[pos] ^= 2
            tampered = bytes(raw)
        if not scheme.verify(tampered, sigs[i]):
            tamper_ok += 1

    bound = params.accept_bound
    forgery_reject = 0
    for i in range(n):
        z = rng.integers(-bound, bound + 1, size=params.n_dim, dtype=np.int64)
        digest = rng.bytes(32)
        if not scheme.verify(txs[i], Sig(digest=digest, z=z)):
            forgery_reject += 1

    mutation_reject = 0
    for i in range(n):
        raw = bytearray(sigs[i].to_bytes())
        pos = int(rng.integers(0, len(raw)))
        raw[pos] ^= 1
        mutated = Sig.from_bytes(bytes(raw), params.n_dim)
        if not scheme.verify(txs[i], mutated):
            mutation_reject += 1

    payload = {
        "params": {k: sig_rec[k] for k in ("n_rows", "n_dim", "q", "h", "m_ch",
                                           "kappa", "accept_p_design", "challenge_log2",
                                           "sis_gap_db")},
        "seed": 20260908,
        "n": int(n),
        "valid_accept_rate": round(valid_ok / n, 6),
        "tamper_detect_rate": round(tamper_ok / n, 6),
        "forgery_reject_rate": round(forgery_reject / n, 6),
        "mutation_reject_rate": round(mutation_reject / n, 6),
        "note": "Track B correctness: valid round-trip, tampered message, random forgery "
                "(uniform z within bound + random 32-byte digest), single-byte signature mutation",
    }
    out = Path(__file__).resolve().parents[1] / "data" / "eval_v2_e1b.json"
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
    print(f"E1b done -> {out}")
    print(f"  valid={payload['valid_accept_rate']:.4f} "
          f"tamper={payload['tamper_detect_rate']:.4f} "
          f"forgery_reject={payload['forgery_reject_rate']:.4f} "
          f"mutation_reject={payload['mutation_reject_rate']:.4f}")


if __name__ == "__main__":
    main()
