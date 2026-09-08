"""攻击实现：统一在“自适应选择消息预言机 + 有界查询预算”下建模。

- lwe_statistical_forge：攻击者收集 M 个历史样本 (A_i, b_i)（b_i=A_i·s+e_i），
  用最小二乘+就近舍入到 {-1,0,1} 估计私钥 s；估计成功则对目标交易伪造凭证。
- rsa_raw_multiplicative_forge：教科书 RSA（raw，无哈希/填充）存在乘法同态性，
  攻击者用 2 次选择消息签名即可伪造任意目标载荷。
- rsa_hash_forge_attempt：对 SHA-256 后再签的类 FDH 版本，乘法伪造被哈希破坏，
  本函数不做全盘搜索，直接返回未伪造成功（用于对照组讨论）。
"""
from __future__ import annotations

import math

import numpy as np

from .lwe import LweIdentity
from .rsa_baseline import RsaIdentity


def gen_tx(rng: np.random.Generator, tag: str) -> str:
    a = int(rng.integers(0, 2 ** 63))
    b = int(rng.integers(0, 2 ** 63))
    return f"{tag}:{a:016x}:{b:016x}"


def rand_below(rng: np.random.Generator, bound: int, lo: int = 2) -> int:
    """在 [lo, bound-1] 内均匀生成可超出 int64 的大随机整数。"""
    width = (bound.bit_length() + 7) // 8
    while True:
        x = int.from_bytes(rng.bytes(width), "big") % (bound - lo) + lo
        if lo <= x < bound:
            return x


def lwe_statistical_forge(
    identity: LweIdentity, target_tx: str, rng: np.random.Generator, queries: int
) -> bool:
    """有界历史样本 + 线性回归/舍入攻击，返回是否伪造成功。"""
    p = identity.params
    rows, bs = [], []
    for _ in range(queries):
        tx = gen_tx(rng, "lwe-obs")
        A = identity.derive_a(tx)
        b = identity.sign_transaction(tx)
        rows.append(A.reshape(-1, p.n))
        bs.append(b)
    A_stack = np.vstack(rows).astype(np.float64)          # (queries*n, n)
    b_vec = np.concatenate(bs).astype(np.float64)
    sol, *_ = np.linalg.lstsq(A_stack, b_vec, rcond=None)
    cand = np.where(sol >= 0.5, 1.0, np.where(sol <= -0.5, -1.0, 0.0)).astype(np.int64)
    forged = (identity.derive_a(target_tx) @ cand) % p.q
    return identity.verify_transaction(target_tx, forged)


def rsa_raw_multiplicative_forge(
    identity: RsaIdentity, target_m: int, rng: np.random.Generator
) -> bool:
    """2 次选择消息签名构造目标载荷的合法签名（教科书 RSA 存在性伪造）。"""
    n = identity.n
    k = rand_below(rng, n)
    while math.gcd(k, n) != 1:
        k = rand_below(rng, n)
    m1 = k
    m2 = (target_m * pow(k, -1, n)) % n
    if m2 < 2:  # 理论概率可忽略，防御性重试
        return rsa_raw_multiplicative_forge(identity, target_m, rng)
    s1 = identity.sign_int(m1)
    s2 = identity.sign_int(m2)
    sig = (s1 * s2) % n
    return identity.verify_int(target_m, sig)


def rsa_hash_forge_attempt(identity: RsaIdentity, target_tx: str) -> bool:
    """类 FDH 版本：无全盘搜索时，乘法伪造不可行（对照组，返回 False）。"""
    _ = identity, target_tx
    return False
