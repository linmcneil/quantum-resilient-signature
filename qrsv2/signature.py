"""Track B：公开可验证格签名（Lyubashevsky Fiat-Shamir with Aborts，ringless 原型）。

构造（教学实现，自洽且验证严格成立）：
- 公钥：A (n_rows × n_dim) 均匀随机 + T = A·S (mod q)；
  私钥：S (n_dim × m_ch)，每个分量 ∈ {-1,0,1}（短矩阵）。
- 签名：采样 y ← U([-kappa,kappa]^n_dim)；w = A·y；
  digest = H(tx ‖ encode(w))；挑战 c = ExpandTernary(digest, m_ch, h)；
  z = y + S·c；若 ‖z‖_∞ > kappa − h 则重试（拒绝采样）。
- 验证：c 由 digest 确定性重算；w' = A·z − T·c；检查
  H(tx ‖ encode(w')) == digest 且 ‖z‖_∞ <= kappa − h。

安全说明：
- 接受域内 z 的条件分布是 [-kappa+h, kappa-h]^n 上的均匀分布，与 S 无关
  （统计零知识 → 传输不泄露 S）；
- 伪造需找短矩阵 S' 使 A·S' = T（非齐次 SIS）→ 归约到格困难假设。
- 免责声明：ringless 教学原型，参数与安全论证为教学级，正式使用前需
  module/ring 结构化 + lattice-estimator 复核。
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import numpy as np

from .expand import (bytes_to_digest, challenge_from_digest, matrix_from_seed,
                     new_rng, sample_ternary_matrix, seed_from_tx,
                     uniform_box_vector, vector_to_bytes)
from .params import SigParams


@dataclass(frozen=True)
class Sig:
    digest: bytes
    z: np.ndarray

    def to_bytes(self) -> bytes:
        """z 每坐标 2 字节（偏移 32768）+ digest。"""
        head = bytearray()
        for value in np.asarray(self.z, dtype=np.int64):
            head += int(value + 32768).to_bytes(2, "little")
        return bytes(head) + self.digest

    @staticmethod
    def from_bytes(raw: bytes, n_dim: int) -> "Sig":
        if len(raw) != 2 * n_dim + 32:
            raise ValueError("bad signature length")
        # 每坐标 2 字节（存储时做了 +32768 偏移）
        z = np.asarray(
            [int.from_bytes(raw[i:i + 2], "little") - 32768
             for i in range(0, 2 * n_dim, 2)],
            dtype=np.int64,
        )
        return Sig(digest=bytes(raw[2 * n_dim:]), z=z)


class LweSignatureScheme:
    DOMAIN_A = b"qrs-v2/sig/v1/a"
    DOMAIN_MSG = b"qrs-v2/sig/v1/m"

    def __init__(self, params: Optional[SigParams] = None, seed: Optional[int] = None):
        self.params = params or SigParams()
        rng = new_rng(seed)
        a_seed = int(rng.integers(0, 2 ** 63)).to_bytes(8, "big")
        self.A = matrix_from_seed(a_seed, self.params.n_rows,
                                  self.params.n_dim, self.params.q)
        self.S = sample_ternary_matrix(rng, self.params.n_dim,
                                       self.params.m_ch, self.params.secret_p)
        self.T = (self.A @ self.S) % self.params.q

    # ---- 序列化公钥/私钥（教学用，明文本地演示） ----
    def public_key_bytes(self) -> bytes:
        p = self.params
        raw = bytearray()
        for matrix in (self.A, self.T):
            for value in np.asarray(matrix, dtype=np.int64).ravel() % p.q:
                raw += int(value).to_bytes(2, "little")
        return bytes(raw)

    def private_key_bytes(self) -> bytes:
        raw = bytearray()
        for value in np.asarray(self.S, dtype=np.int64).ravel():
            raw += int(value + 1).to_bytes(1, "little")
        return bytes(raw)

    def _commit(self, tx: bytes) -> np.ndarray:
        w = (self.A @ uniform_box_vector(new_rng(), self.params.n_dim,
                                         self.params.kappa)) % self.params.q
        return w

    def sign(self, tx: bytes, max_tries: int = 4096) -> tuple:
        """返回 (Sig, 拒绝次数)。拒绝次数用于长尾/WCET 分析（E2）。"""
        p = self.params
        bound = p.accept_bound
        for tries in range(1, max_tries + 1):
            rng = new_rng()
            y = uniform_box_vector(rng, p.n_dim, p.kappa)
            w = (self.A @ y) % p.q
            digest = bytes_to_digest(tx, vector_to_bytes(w, p.q))
            c = challenge_from_digest(digest, p.m_ch, p.h)
            z = y + self.S @ c
            if np.max(np.abs(z)) <= bound:
                return Sig(digest=digest, z=z), tries
        raise RuntimeError(f"rejection sampling exceeded max_tries={max_tries}")

    def verify(self, tx: bytes, sig: Sig) -> bool:
        p = self.params
        if np.max(np.abs(sig.z)) > p.accept_bound:
            return False
        c = challenge_from_digest(sig.digest, p.m_ch, p.h)
        w_prime = (self.A @ sig.z - self.T @ c) % p.q
        digest_prime = bytes_to_digest(tx, vector_to_bytes(w_prime, p.q))
        return digest_prime == sig.digest