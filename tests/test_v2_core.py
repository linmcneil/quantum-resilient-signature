"""v2 核心单测：功能正确性 + 攻击模块 + 估计器烟雾。"""
from __future__ import annotations

import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from qrsv2.estimator import (core_svp_cost, estimate_lwe_search,
                             recommend_sig_params, recommend_tag_params,
                             root_hermite_factor)
from qrsv2.params import SigParams, TagParams
from qrsv2.rsa_pss import RsaKey, generate_rsa
from qrsv2.signature import LweSignatureScheme, Sig
from qrsv2.tag import LweTag


def test_estimator_smoke():
    assert root_hermite_factor(100) < root_hermite_factor(50)
    assert core_svp_cost(50) > 0
    est = estimate_lwe_search(32, 32, 257, 1.0)
    assert est.dim == 32 + 32 + 1
    rec = recommend_tag_params(40.0)
    assert rec["est_bits"] >= 40
    sig_rec = recommend_sig_params(60.0)
    assert sig_rec["kappa"] > sig_rec["h"]
    assert sig_rec["challenge_log2"] >= 60


def test_track_a_roundtrip_and_tamper():
    tagger = LweTag(params=TagParams(n=48, q=12289, sigma=2.0, tail=6, V=8), seed=3)
    tx = b"medical-record-1"
    tag = tagger.issue(tx, seed=1)
    assert tagger.verify(tx, tag)
    assert tagger.residual(tx, tag) <= 8
    tampered = tx[:-1] + bytes([tx[-1] ^ 1])
    assert not tagger.verify(tampered, tag)


def test_track_b_roundtrip_and_tamper():
    params = SigParams(n_rows=48, n_dim=64, q=12289, h=8, m_ch=64, kappa=2000)
    scheme = LweSignatureScheme(params=params, seed=42)
    for i in range(30):
        tx = f"tx-{i}".encode()
        sig, tries = scheme.sign(tx)
        assert scheme.verify(tx, sig)
        assert tries >= 1
        bad = tx[:-1] + bytes([tx[-1] ^ 1])
        assert not scheme.verify(bad, sig)
        assert np.max(np.abs(sig.z)) <= params.accept_bound


def test_track_b_serialization():
    params = SigParams(n_rows=48, n_dim=64, q=12289, h=8, m_ch=64, kappa=2000)
    scheme = LweSignatureScheme(params=params, seed=5)
    tx = b"roundtrip"
    sig, _ = scheme.sign(tx)
    sig2 = Sig.from_bytes(sig.to_bytes(), params.n_dim)
    assert scheme.verify(tx, sig2)


def test_rsa_pss_functional():
    n, e, d, _p, _q = generate_rsa(1024)
    key = RsaKey(bits=1024, n=n, e=e, d=d)
    message = b"rsa pss message"
    sig = key.sign(message)
    assert key.verify(message, sig)
    assert not key.verify(message + b"x", sig)


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"PASS {name}")
    print("all v2 core tests passed")