"""确定性展开（PRG）：把种子/摘要展开成矩阵、均匀整数、稀疏三元挑战。

全部只用标准库 hashlib，保证可复现；A 由 SHA-256(seed) 逐块派生，
对应“一事一密”。教学原型说明：随机性来源为 os.urandom / 固定 seed，
正式部署需用密码学安全随机源。
"""
from __future__ import annotations

import hashlib
import os
from typing import Optional

import numpy as np


class Prg:
    """基于 SHA-256 计数器的确定性伪随机源。"""

    def __init__(self, seed: bytes):
        self._seed = bytes(seed)
        self._counter = 0

    def _next_block(self) -> bytes:
        block = self._seed + self._counter.to_bytes(8, "big")
        self._counter += 1
        return hashlib.sha256(block).digest()

    def uniform_int(self, bound: int) -> int:
        """均匀整数 [0, bound)。bound 需 <= 2**32。"""
        if bound <= 0:
            raise ValueError("bound must be positive")
        if bound >= 2 ** 32:
            raise ValueError("bound too large")
        span = 2 ** 32
        excess = span % bound
        max_valid = span - excess
        while True:
            value = int.from_bytes(self._next_block()[:4], "big")
            if value < max_valid:
                return value % bound


def seed_from_tx(tx: bytes, domain: bytes) -> bytes:
    return hashlib.sha256(domain + tx).digest()


def matrix_from_seed(seed: bytes, rows: int, cols: int, q: int) -> np.ndarray:
    """确定性生成 rows x cols 的 Z_q 矩阵。

    实现：SHA-256(seed) -> numpy 确定性 RNG（PCG64）。A 是公开对象，
    只要求“由种子唯一确定 + 统计均匀”，不需要密码学级 PRG；
    正式实现可换成 CTR-DRBG，语义一致。
    """
    seed_int = int.from_bytes(hashlib.sha256(seed).digest(), "big")
    rng = np.random.default_rng(seed_int)
    return rng.integers(0, q, size=(rows, cols), dtype=np.int64)


def uniform_box_vector(rng: np.random.Generator, size: int, kappa: int) -> np.ndarray:
    """从 [-kappa, kappa]^size 均匀采样整数向量。"""
    return rng.integers(-kappa, kappa + 1, size=size, dtype=np.int64)


def sparse_ternary(rng: np.random.Generator, length: int, h: int) -> np.ndarray:
    """长度 length、恰有 h 个非零分量的 {-1,0,1} 挑战向量。"""
    out = np.zeros(length, dtype=np.int64)
    idx = rng.choice(length, size=h, replace=False)
    out[idx] = rng.choice(np.array([-1, 1], dtype=np.int64), size=h)
    return out


def sample_ternary_matrix(rng: np.random.Generator, rows: int, cols: int,
                          p_active: float) -> np.ndarray:
    """每个分量以概率 p_active 均匀取 ±1，否则为 0。"""
    r = rng.random((rows, cols))
    out = np.zeros((rows, cols), dtype=np.int64)
    active = r < p_active
    signs = rng.choice(np.array([-1, 1], dtype=np.int64), size=(rows, cols))
    out[active] = signs[active]
    return out


def sample_truncated_gaussian(rng: np.random.Generator, sigma: float, tail: int) -> int:
    xs = np.arange(-tail, tail + 1, dtype=np.float64)
    w = np.exp(-(xs ** 2) / (2.0 * sigma * sigma))
    w = w / w.sum()
    return int(rng.choice(xs, p=w))


def centering_mod(x: np.ndarray, q: int) -> np.ndarray:
    """把余数映射到对称区间 (-q/2, q/2]。"""
    x = np.asarray(x) % q
    return np.where(x > q // 2, x - q, x)


def vector_to_bytes(v: np.ndarray, q: int) -> bytes:
    """编码向量为固定宽度字节（每坐标 2 字节小端），用于哈希输入。"""
    raw = np.asarray(v, dtype=np.int64).astype(object) % q
    out = bytearray()
    for value in raw:
        out += int(value).to_bytes(2, "little")
    return bytes(out)


def bytes_to_digest(message: bytes, w_bytes: bytes) -> bytes:
    return hashlib.sha256(message + w_bytes).digest()


def challenge_from_digest(digest: bytes, m_ch: int, h: int) -> np.ndarray:
    """由摘要确定性派生稀疏三元挑战（verifier 可重复计算）。"""
    seed_int = int.from_bytes(hashlib.sha256(digest).digest(), "big")
    rng = np.random.default_rng(seed_int)
    out = np.zeros(m_ch, dtype=np.int64)
    idx = rng.choice(m_ch, size=h, replace=False)
    out[idx] = rng.choice(np.array([-1, 1], dtype=np.int64), size=h)
    return out


def new_rng(seed: Optional[int] = None) -> np.random.Generator:
    if seed is None:
        seed = int.from_bytes(os.urandom(8), "big")
    return np.random.default_rng(seed)