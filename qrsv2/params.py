"""v2 参数结构。与 v1 分离：v2 的安全参数由 estimator 方法学产生（I1），
默认值仅作为“教学原型”，正式参数见 data/v2_params.json。"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class TagParams:
    """Track A：LWE 认证标签（对称语义，对应《技术交底书》b = A·s + e）。

    n    : 私钥维度（同时是 A 的行/列数，m = n）
    q    : 素数模数
    sigma: 离散高斯噪声标准差
    tail : 噪声截断半径（±3*sigma 左右）
    V    : 验证容差 ‖b - A·s‖_∞ <= V
    """
    n: int = 128
    q: int = 12289
    sigma: float = 2.0
    tail: int = 6
    V: int = 8


@dataclass(frozen=True)
class SigParams:
    """Track B：公开可验证格签名（Lyubashevsky Fiat-Shamir with Aborts，
    ringless 矩阵原型，安全性基于 SIS，拒绝采样保证传输统计零知识）。

    n_rows  : 公开矩阵 A 的行数 m_a（A: m_a x n_dim）
    n_dim   : 秘密维度（y / z / 私钥列向量维度）
    q       : 素数模数
    h       : 挑战向量 c 的非零分量个数（稀疏，{0,+-1}）
    m_ch    : 挑战向量 c 的长度
    kappa   : 掩码 y 的均匀盒半径 [-kappa, kappa]
    secret_p : 私钥矩阵 S 的每个分量取 {-1,0,1} 的概率
    accept_bound = kappa - h  （z 需落入该盒）
    """
    n_rows: int = 96
    n_dim: int = 128
    q: int = 12289
    h: int = 32
    m_ch: int = 256
    kappa: int = 2000
    secret_p: float = 2.0 / 3.0  # 每个分量在 {-1,0,1} 等概率

    @property
    def accept_bound(self) -> int:
        return self.kappa - self.h

    @property
    def challenge_log2(self) -> float:
        import math
        return math.log2(math.comb(self.m_ch, self.h)) + self.h


def estimated_sig_size(p: SigParams) -> int:
    """z 坐标（2 字节）+ SHA-256 摘要 32 字节。"""
    return 2 * p.n_dim + 32


def estimated_tag_size(p: TagParams) -> int:
    """b 共 n 个坐标，每坐标 2 字节。"""
    return 2 * p.n