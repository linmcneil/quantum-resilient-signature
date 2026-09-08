"""E4：区块链交易场景（区块膨胀 + 验签吞吐）。

模拟“单节点收块 → 逐笔验签”的流水线：
- 区块负载 = N 笔交易；记账开销 = N × 凭证/签名尺寸；
- 区块膨胀系数 = 记账开销 / 交易原始负载（ECDSA-64B 为基线 1.0）；
- 验签 TPS = N / Σverify 耗时（使用 E2 实测中位数换算，避免重复测量）。

输出 data/eval_v2_e4.json。
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from qrsv2.params import estimated_sig_size, estimated_tag_size

N_TX = 1000
TX_PAYLOAD = 64  # 每笔交易原始负载（近似字节）


def load_e2() -> dict:
    path = Path(__file__).resolve().parents[1] / "data" / "eval_v2_e2.json"
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def scheme_row(name: str, sig_bytes: int, verify_median_ms: float,
               sign_median_ms: float, verify_p99_ms: float | None = None) -> dict:
    block_overhead = sig_bytes * N_TX
    payload_bytes = TX_PAYLOAD * N_TX
    inflation = block_overhead / payload_bytes
    verify_tps = 1000.0 / max(verify_median_ms, 1e-6)
    return {
        "scheme": name,
        "per_tx_signature_bytes": sig_bytes,
        "block_signature_overhead_bytes": block_overhead,
        "block_payload_bytes": payload_bytes,
        "inflation_vs_payload": round(inflation, 1),
        "verify_tps_median": round(verify_tps, 0),
        "sign_tps_median": round(1000.0 / max(sign_median_ms, 1e-6), 0),
        "block_verify_ms_median": round(verify_median_ms * N_TX, 1),
    }


def main() -> None:
    e2 = load_e2()
    schemes = e2["schemes"]

    rows = []
    # Track A / Track B / RSA 用 E2 实测中位数
    for key, label in [("track_a_lwe_tag", "LWE 认证标签 A"),
                       ("track_b_lwe_sig", "LWE 格签名 B"),
                       ("rsa3072_pss", "RSA-3072-PSS")]:
        item = schemes[key]
        sig_bytes = item.get("signature_bytes") or item.get("credential_bytes")
        rows.append(scheme_row(label, sig_bytes,
                               item["verify_ms"]["median_ms"],
                               item["sign_ms"]["median_ms"]))
    # 官方参考尺寸 + 文献验签耗时（数量级，标注非本机）
    ref_verify_ms = {"ml_dsa_44": 0.05, "fn_dsa_512": 0.08, "ecdsa_p256": 0.01}
    for key, label in [("ml_dsa_44", "ML-DSA-44 (FIPS 204)"),
                       ("fn_dsa_512", "FN-DSA-512 (FN-DSA draft/FALCON)"),
                       ("ecdsa_p256", "ECDSA P-256")]:
        item = schemes["reference_nist"][key]
        row = scheme_row(label, item["signature_bytes"], ref_verify_ms[key], 0.02)
        row["measured_on_this_machine"] = False
        row["note"] = "尺寸为规格值（FN-DSA-512 按 FALCON v1.2/FN-DSA 草案）；验签耗时取文献数量级参考"
        rows.append(row)

    payload = {
        "n_tx": N_TX,
        "tx_payload_bytes": TX_PAYLOAD,
        "scenario": "单节点收块逐笔验签（教学模拟）",
        "rows": rows,
    }
    out = Path(__file__).resolve().parents[1] / "data" / "eval_v2_e4.json"
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
    print("E4 done ->", out)
    header = f"{'scheme':<22}{'sigB':>8}{'块膨胀':>8}{'验签TPS':>10}"
    print(header)
    for row in rows:
        print(f"{row['scheme']:<22}{row['per_tx_signature_bytes']:>8}"
              f"{row['inflation_vs_payload']:>8}x{row['verify_tps_median']:>10.0f}")


if __name__ == "__main__":
    main()