"""LWE 认证凭证方案。

对应《技术交底书》：
- 系统初始化 __init__：维度 n、模数 q，私钥 s ∈ {-1,0,1}^n（短向量）；
- sign_transaction：SHA-256(tx) -> 随机种子 -> 生成矩阵 A（一事一密），
  b = A·s + e (mod q)，e 为截断离散高斯噪声（sigma=2）；
- verify_transaction：持钥方验证 ‖b - A·s‖_∞ <= V。

设计说明：本实现是“持钥方验证”的认证凭证原型（凭证值 b 由持有 s 的
验证节点校验），不是公钥签名方案；其安全性建立在搜索 LWE 困难假设之上。
攻击者在无 s 时无法直接构造通过验证的新凭证，只能尝试从历史样本恢复 s。
"""
from __future__ import annotations

import hashlib
from typing import Optional

import numpy as np

from .params import LweParams


def _seed_int(seed: bytes) -> int:
    return int.from_bytes(hashlib.sha256(seed).digest(), "big") % (2 ** 128)


def matrix_from_seed(seed: bytes, n: int, q: int) -> np.ndarray:
    """由种子确定性生成 n x n 的 Z_q 矩阵（实现“一事一密”）。"""
    rng = np.random.default_rng(_seed_int(seed))
    return rng.integers(0, q, size=(n, n), dtype=np.int64)


def sample_discrete_gaussian(rng: np.random.Generator, sigma: float, tail: int) -> int:
    """在 [-tail, tail] 上按截断离散高斯分布采样一个整数。"""
    xs = np.arange(-tail, tail + 1, dtype=np.float64)
    w = np.exp(-(xs ** 2) / (2.0 * sigma * sigma))
    w /= w.sum()
    return int(rng.choice(xs, p=w))


class LweIdentity:
    """持钥方认证凭证：私钥 s 为短向量，凭证 b = A·s + e (mod q)。"""

    def __init__(self, params: Optional[LweParams] = None, seed: Optional[int] = None):
        self.params = params or LweParams()
        rng = np.random.default_rng(seed)
        vals = np.asarray(self.params.secret_set, dtype=np.int64)
        self.s = rng.choice(vals, size=self.params.n).astype(np.int64)

    def derive_a(self, tx: str) -> np.ndarray:
        p = self.params
        return matrix_from_seed(tx.encode("utf-8"), p.n, p.q)

    def sign_transaction(self, tx: str, noise_seed: Optional[int] = None) -> np.ndarray:
        """生成凭证 b = (A·s + e) mod q。"""
        p = self.params
        rng = np.random.default_rng(noise_seed)
        e = np.array(
            [sample_discrete_gaussian(rng, p.sigma, p.tail) for _ in range(p.n)],
            dtype=np.int64,
        )
        b = (self.derive_a(tx) @ self.s + e) % p.q
        return b

    def verify_transaction(self, tx: str, b: np.ndarray) -> bool:
        """持钥方验证：‖b - A·s‖_∞ <= V。"""
        p = self.params
        diff = (b - (self.derive_a(tx) @ self.s) % p.q) % p.q
        diff = np.where(diff > p.q // 2, diff - p.q, diff)
        return bool(np.max(np.abs(diff)) <= p.verify_bound)
