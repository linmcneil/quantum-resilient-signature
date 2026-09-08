"""核心逻辑单测：确定性、验签、篡改检测、两类攻击行为。"""
from __future__ import annotations

import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from qrs import attacks                               # noqa: E402
from qrs.lwe import LweIdentity, matrix_from_seed     # noqa: E402
from qrs.params import LweParams, RsaParams           # noqa: E402
from qrs.rsa_baseline import RsaIdentity              # noqa: E402


def test_matrix_from_seed_deterministic():
    m1 = matrix_from_seed(b"tx-1", 32, 12289)
    m2 = matrix_from_seed(b"tx-1", 32, 12289)
    m3 = matrix_from_seed(b"tx-2", 32, 12289)
    assert np.array_equal(m1, m2)
    assert not np.array_equal(m1, m3)


def test_lwe_sign_verify_and_tamper():
    params = LweParams(n=32, verify_bound=8)
    ident = LweIdentity(params, seed=1)
    tx = "tx:hello:world"
    b = ident.sign_transaction(tx, noise_seed=2)
    assert ident.verify_transaction(tx, b)
    assert not ident.verify_transaction(tx + "x", b)
    blind = np.random.default_rng(0).integers(0, params.q, size=32)
    assert not ident.verify_transaction(tx, blind)


def test_noise_within_tail():
    rng = np.random.default_rng(0)
    from qrs.lwe import sample_discrete_gaussian
    vals = [sample_discrete_gaussian(rng, 2.0, 6) for _ in range(2000)]
    assert min(vals) >= -6 and max(vals) <= 6
    assert abs(float(np.mean(vals))) < 0.6


def test_lwe_statistical_attack_fails():
    params = LweParams(n=64, verify_bound=8)
    ident = LweIdentity(params, seed=3)
    rng = np.random.default_rng(4)
    tx = "target:attack:1"
    forged = attacks.lwe_statistical_forge(ident, tx, rng, queries=8)
    assert not forged


def test_rsa_raw_existential_forgery_succeeds():
    rsa = RsaIdentity(RsaParams(bits=512), mode="raw")
    rng = np.random.default_rng(5)
    target = attacks.rand_below(rng, rsa.n)
    assert attacks.rsa_raw_multiplicative_forge(rsa, target, rng)


def test_rsa_hash_mode_basics():
    rsa = RsaIdentity(RsaParams(bits=512), mode="hash")
    tx = "transfer:alice:bob:100"
    sig = rsa.sign_transaction(tx)
    assert rsa.verify_transaction(tx, sig)
    assert not rsa.verify_transaction(tx + "x", sig)
    assert attacks.rsa_hash_forge_attempt(rsa, tx) is False

