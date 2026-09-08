"""Track A：LWE 认证标签（对称语义，对应《技术交底书》）。

架构与 v1 相同但语义更清晰：这**不是数字签名**，而是“指定持钥方校验”的
认证标签 / MAC 型凭证。每笔交易 tx 用 SHA-256 派生独立矩阵 A（一事一密），
标签 b = A·s + e (mod q)。持钥方用私钥 s 校验 ‖b − A·s‖_∞ ≤ V。
"""
from __future__ import annotations

from typing import Optional

import numpy as np

from .expand import (matrix_from_seed, new_rng, sample_truncated_gaussian,
                     seed_from_tx)
from .params import TagParams


class LweTag:
    DOMAIN = b"qrs-v2/tag/v1"

    def __init__(self, params: Optional[TagParams] = None, seed: Optional[int] = None):
        self.params = params or TagParams(n=144)
        rng = new_rng(seed)
        self.secret = rng.choice(np.array([-1, 0, 1], dtype=np.int64),
                                 size=self.params.n)

    def derive_a(self, tx: bytes) -> np.ndarray:
        p = self.params
        seed = seed_from_tx(tx, self.DOMAIN)
        return matrix_from_seed(seed, p.n, p.n, p.q)

    def issue(self, tx: bytes, seed: Optional[int] = None) -> np.ndarray:
        """生成标签 b = A·s + e (mod q)。"""
        p = self.params
        rng = new_rng(seed)
        noise = np.array(
            [sample_truncated_gaussian(rng, p.sigma, p.tail)
             for _ in range(p.n)],
            dtype=np.int64,
        )
        b = (self.derive_a(tx) @ self.secret + noise) % p.q
        return b

    def residual(self, tx: bytes, b: np.ndarray) -> int:
        """校验残差 max|b − A·s|_inf（按中心化余数计）。"""
        p = self.params
        recompute = (self.derive_a(tx) @ self.secret) % p.q
        diff = (np.asarray(b, dtype=np.int64) - recompute) % p.q
        diff = np.where(diff > p.q // 2, diff - p.q, diff)
        return int(np.max(np.abs(diff)))

    def verify(self, tx: bytes, b: np.ndarray) -> bool:
        return self.residual(tx, b) <= self.params.V