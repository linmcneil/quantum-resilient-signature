"""E2：同安全级性能对照（专业版）。

协议（对齐 ePrint 2026/1333）：
- 固定消息集（同一条 600+ 字节负载，逐条变化）；同机、单进程、无并行负载；
- Track A/B 逐样本计时（perf_counter），报告 mean/median/p90/p99/max，原始样本
  一并入 JSON（samples_ms），供真 ECDF；
- RSA-3072-PSS 采用系统 OpenSSL 3.5 的 in-process speed 基准（行业标准实现，
  逐样本分布不可得，标记 constant）；
- 机器/依赖元数据入库：CPU、平台、Python/numpy/matplotlib/openssl 版本、
  perf_counter 分辨率。
"""
from __future__ import annotations

import json
import platform
import re
import subprocess
import sys
import time
from importlib.metadata import version as pkg_version
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from qrsv2.estimator import recommend_sig_params, recommend_tag_params
from qrsv2.params import SigParams, TagParams, estimated_sig_size, estimated_tag_size
from qrsv2.signature import LweSignatureScheme
from qrsv2.tag import LweTag

OPENSSL = r"C:\Program Files\Git\usr\bin\openssl.exe"


def timing_summary(times_ms) -> dict:
    arr = np.asarray(times_ms, dtype=np.float64)
    return {
        "n": int(len(arr)),
        "mean_ms": round(float(arr.mean()), 4),
        "median_ms": round(float(np.median(arr)), 4),
        "p90_ms": round(float(np.percentile(arr, 90)), 4),
        "p99_ms": round(float(np.percentile(arr, 99)), 4),
        "max_ms": round(float(arr.max()), 4),
        "min_ms": round(float(arr.min()), 4),
        "samples_ms": [round(float(x), 4) for x in arr],
    }


def openssl_version() -> str:
    try:
        proc = subprocess.run([OPENSSL, "version"], capture_output=True, text=True)
        return proc.stdout.strip() or proc.stderr.strip()
    except Exception as exc:  # pragma: no cover
        return f"unavailable ({exc})"


def openssl_rsa3072(seconds: int = 3) -> dict:
    """返回 OpenSSL speed 的 keygen/sign/verify 秒数。"""
    proc = subprocess.run([OPENSSL, "speed", "-seconds", str(seconds), "rsa3072"],
                          capture_output=True, text=True)
    text = proc.stdout + proc.stderr
    lines = text.splitlines()
    sig_idx = None
    for idx, line in enumerate(lines):
        if "sign/s" in line and "verify/s" in line and "keygen" in line:
            sig_idx = idx + 1
            break
    if sig_idx is None:
        raise RuntimeError("cannot locate signature speed table in openssl output")
    m = re.match(r"^\s*rsa3072\s+([0-9.]+)s\s+([0-9.]+)s\s+([0-9.]+)s",
                 lines[sig_idx])
    if not m:
        raise RuntimeError(f"cannot parse openssl row: {lines[sig_idx]!r}")
    return {"keygen_s": float(m.group(1)), "sign_s": float(m.group(2)),
            "verify_s": float(m.group(3))}


def machine_info() -> dict:
    return {
        "platform": platform.platform(),
        "processor": platform.processor(),
        "release": platform.release(),
        "python": platform.python_version(),
        "numpy": pkg_version("numpy"),
        "matplotlib": pkg_version("matplotlib"),
        "openssl": openssl_version(),
        "perf_counter_resolution_s": time.get_clock_info("perf_counter").resolution,
        "note": "单线程；计时包含 Python/调用开销，跨语言对比请以 openssl/官方基准为准",
    }


def synthetic_tx(i: int) -> bytes:
    return f"tx|{i}|medical-record-{i}-{'ab' * 40}".encode("utf-8")


def main() -> None:
    results = {}
    n_tx = 1600
    txs = [synthetic_tx(i) for i in range(n_tx)]

    # ---------- Track A ----------
    tag_rec = recommend_tag_params(80.0)
    tag_params = TagParams(n=tag_rec["n"], q=tag_rec["q"], sigma=tag_rec["sigma"],
                           tail=tag_rec["tail"], V=tag_rec["V"])
    tagger = LweTag(params=tag_params, seed=11)
    tags = [tagger.issue(txs[i], seed=i) for i in range(n_tx)]
    issue_ms, verify_ms = [], []
    for _ in range(15):
        tagger.issue(txs[0], seed=1)
    t0 = time.perf_counter()
    for idx in range(1000):
        t1 = time.perf_counter()
        tagger.issue(txs[idx], seed=6000 + idx)
        issue_ms.append((time.perf_counter() - t1) * 1000.0)
    issue_total = (time.perf_counter() - t0) * 1000.0
    verify_ms = []
    for idx in range(1000):
        t1 = time.perf_counter()
        assert tagger.verify(txs[idx], tags[idx])
        verify_ms.append((time.perf_counter() - t1) * 1000.0)
    results["track_a_lwe_tag"] = {
        "semantics": "对称 LWE 认证标签（MAC）",
        "params": tag_rec,
        "sk_bytes": tag_params.n,
        "credential_bytes": estimated_tag_size(tag_params),
        "keygen_once_ms": round(issue_total, 3),
        "sign_ms": timing_summary(issue_ms),
        "verify_ms": timing_summary(verify_ms),
        "reject_tries": None,
    }

    # ---------- Track B ----------
    sig_rec = recommend_sig_params(80.0)
    sig_params = SigParams(n_rows=sig_rec["n_rows"], n_dim=sig_rec["n_dim"],
                           q=sig_rec["q"], h=sig_rec["h"], m_ch=sig_rec["m_ch"],
                           kappa=sig_rec["kappa"], secret_p=sig_rec["secret_p"])
    scheme = LweSignatureScheme(params=sig_params, seed=22)
    sign_ms, verify_ms, reject_counts = [], [], []
    sigs = []
    t0 = time.perf_counter()
    for i in range(1000):
        t1 = time.perf_counter()
        sig, tries = scheme.sign(txs[i])
        sign_ms.append((time.perf_counter() - t1) * 1000.0)
        reject_counts.append(tries)
        sigs.append(sig)
    keygen_ms = (time.perf_counter() - t0) * 1000.0 - sum(sign_ms)
    for i in range(1000):
        t1 = time.perf_counter()
        assert scheme.verify(txs[i], sigs[i])
        verify_ms.append((time.perf_counter() - t1) * 1000.0)
    results["track_b_lwe_sig"] = {
        "semantics": "Lyubashevsky FS-with-Aborts 格签名（ringless，SIS）",
        "params": sig_rec,
        "pk_bytes": scheme.public_key_bytes().__len__(),
        "sk_bytes": scheme.private_key_bytes().__len__(),
        "signature_bytes": estimated_sig_size(sig_params),
        "keygen_once_ms": round(keygen_ms, 3),
        "sign_ms": timing_summary(sign_ms),
        "verify_ms": timing_summary(verify_ms),
        "reject_tries": {
            "mean": round(float(np.mean(reject_counts)), 3),
            "median": int(np.median(reject_counts)),
            "p90": int(np.percentile(reject_counts, 90)),
            "p99": int(np.percentile(reject_counts, 99)),
            "max": int(np.max(reject_counts)),
            "hist": np.bincount(reject_counts, minlength=1).tolist(),
        },
    }

    # ---------- RSA-3072（OpenSSL 专业基准） ----------
    ossl = openssl_rsa3072()
    sign_ms_const = [ossl["sign_s"] * 1000.0]
    verify_ms_const = [ossl["verify_s"] * 1000.0]
    results["rsa3072_pss"] = {
        "semantics": "RSA-3072 + PSS（OpenSSL 3.5 in-process speed，行业标准实现）",
        "pk_bytes": 384, "sk_bytes": 384, "signature_bytes": 384,
        "keygen_once_ms": ossl["keygen_s"] * 1000.0,
        "sign_ms": timing_summary(sign_ms_const),
        "verify_ms": timing_summary(verify_ms_const),
        "reject_tries": None,
        "distribution": "constant（openssl speed 聚合值）",
        "note": "纯 Python 实现的同方案仅作功能自检，不用于基准（避免误导）",
    }

    # ---------- 官方参考（非本机实测） ----------
    results["reference_nist"] = {
        "ml_dsa_44": {"semantics": "FIPS 204 ML-DSA-44（NIST Ⅰ 级）",
                      "pk_bytes": 1312, "sk_bytes": 2560, "signature_bytes": 2420,
                      "note": "尺寸为 FIPS 204 官方值"},
        "fn_dsa_512": {"semantics": "FIPS 206 FN-DSA-512 / Falcon-512（NIST Ⅰ 级）",
                       "pk_bytes": 897, "sk_bytes": 1281, "signature_bytes": 666,
                       "note": "尺寸为 FIPS 206 官方值"},
        "ecdsa_p256": {"semantics": "经典 ECDSA P-256（基线）",
                       "pk_bytes": 65, "sk_bytes": 32, "signature_bytes": 64,
                       "note": "经典 ~128-bit，不抗量子"},
    }

    payload = {
        "machine": machine_info(),
        "seed": 20260908,
        "methodology": ("固定消息集/逐样本计时/报分布；Track B 拒绝次数分布；"
                        "RSA 用 OpenSSL speed；对齐 ePrint 2026/1333"),
        "schemes": results,
    }
    out = Path(__file__).resolve().parents[1] / "data" / "eval_v2_e2.json"
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
    print("E2 done ->", out)
    for key, item in results.items():
        if key == "reference_nist":
            continue
        sig = item.get("signature_bytes", item.get("credential_bytes"))
        print(f"  {key}: sig={sig}B pk={item.get('pk_bytes')}B | "
              f"sign med={item['sign_ms']['median_ms']}ms "
              f"(p99 {item['sign_ms']['p99_ms']}) | "
              f"verify med={item['verify_ms']['median_ms']}ms")


if __name__ == "__main__":
    main()