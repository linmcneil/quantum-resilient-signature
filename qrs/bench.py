"""签名/验签延迟基准：LWE 矩阵乘 vs RSA 模幂。"""
from __future__ import annotations

import time

import numpy as np

from .lwe import LweIdentity
from .params import LweParams, RsaParams
from .rsa_baseline import RsaIdentity
from .attacks import rand_below


def bench_latencies(n_trials: int = 200, seed: int = 42):
    rng = np.random.default_rng(seed)

    out = {}
    for bits in (1024, 2048):
        rsa = RsaIdentity(RsaParams(bits=bits), mode="raw")
        msgs = [rand_below(rng, rsa.n) for _ in range(n_trials)]
        t0 = time.perf_counter()
        sigs = [rsa.sign_int(m) for m in msgs]
        t1 = time.perf_counter()
        for m, s in zip(msgs, sigs):
            rsa.verify_int(m, s)
        t2 = time.perf_counter()
        out[f"rsa{bits}"] = {
            "sign_ms": (t1 - t0) / n_trials * 1000.0,
            "verify_ms": (t2 - t1) / n_trials * 1000.0,
        }

    lwe = LweIdentity(LweParams(), seed=seed)
    txs = [f"bench:{i}" for i in range(n_trials)]
    t0 = time.perf_counter()
    creds = [lwe.sign_transaction(tx) for tx in txs]
    t1 = time.perf_counter()
    for tx, b in zip(txs, creds):
        lwe.verify_transaction(tx, b)
    t2 = time.perf_counter()
    out["lwe128"] = {
        "sign_ms": (t1 - t0) / n_trials * 1000.0,
        "verify_ms": (t2 - t1) / n_trials * 1000.0,
    }
    return out
