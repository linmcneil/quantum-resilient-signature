"""格基约化与攻击（I1 的“缩尺实验”部分）。

实现（自包含，无 fpylll 依赖）：
- lll_reduce：浮点 LLL（delta=0.75）。GSO 用 numpy 的 QR 计算（C 速度），
  规模约化按经典过程做整数回代；
- babai_cvp：Babai 最近平面算法（基于约化基的 CVP 近似）；
- lwe_kannan_embedding：搜索 LWE 的 Kannan 嵌入攻击——在
  d = m + n + 1 维格中找短向量 (-e, s, -t)，从而恢复私钥 s。

用途：小维度参数下实测“密钥恢复成功率 vs n / M / σ”，与估计器交叉验证。
数值说明：双精度 LLL 在 dim <= ~48、条目 <= 2^15 量级稳定；更大时应使用
fpylll/fplll 精确实现。
"""
from __future__ import annotations

from typing import Optional

import numpy as np


def _gso_qr(rows):
    """QR 加速 GSO：mu[i,j]=R[j,i]/R[j,j]，||b*_i||^2 = R[i,i]^2。

    rows 为 (n, dim) 行基向量；令 M = rows^T（dim x n），M = Q·R，R 上三角。
    返回 (mu, norms)。
    """
    mat = np.asarray(rows, dtype=np.float64).T
    r_mat = np.linalg.qr(mat, mode="r")
    diag = np.diag(r_mat)
    n = r_mat.shape[0]
    mu = np.zeros((n, n))
    for i in range(n):
        col = r_mat[:, i]
        for j in range(i):
            if diag[j] != 0:
                mu[i, j] = col[j] / diag[j]
    norms = diag * diag
    return mu, norms


def lll_reduce(rows, delta: float = 0.75, max_loops: int = 20000):
    """经典 LLL（QR 加速版）。rows: (n, dim) int 数组（每行一个基向量）。"""
    basis = [np.asarray(row, dtype=np.int64).copy() for row in rows]
    n = len(basis)
    if n <= 1:
        return np.array(basis)
    k = 1
    guard = 0
    while k < n:
        guard += 1
        if guard > max_loops:
            break
        mu, norms = _gso_qr(basis)
        # 规模约化：从大到小（每次减法后刷新 GSO，保证稳定性）
        for j in range(k - 1, -1, -1):
            if abs(mu[k, j]) > 0.5 and norms[j] > 0:
                c_round = int(round(mu[k, j]))
                basis[k] = basis[k] - c_round * basis[j]
                mu, norms = _gso_qr(basis)
        if norms[k] >= (delta - mu[k, k - 1] ** 2) * norms[k - 1]:
            k += 1
        else:
            basis[k], basis[k - 1] = basis[k - 1], basis[k]
            k = max(k - 1, 1)
    return np.array(basis, dtype=np.int64)


def babai_cvp(basis, target: np.ndarray) -> np.ndarray:
    """Babai 最近平面：返回格中近似最近点（浮点实现）。"""
    basis = np.asarray(basis, dtype=np.float64)
    n = basis.shape[0]
    mu, norms = _gso_qr(basis)
    gs = []
    for i in range(n):
        v = basis[i].copy()
        for j in range(i):
            if norms[j] > 0:
                v = v - float(np.dot(v, gs[j]) / norms[j]) * gs[j]
        gs.append(v)
    x = np.asarray(target, dtype=np.float64).copy()
    for i in range(n - 1, -1, -1):
        if norms[i] > 0:
            c_coef = int(round(float(np.dot(x, gs[i]) / norms[i])))
            x = x - c_coef * basis[i]
    point = np.asarray(target, dtype=np.float64) - x
    return np.round(point).astype(np.int64)


def lwe_kannan_embedding(a_mat, b_vec, q: int, sigma: float,
                         s_true: Optional[np.ndarray] = None,
                         t_embed: float = 1.0,
                         noise_margin: float = 5.0) -> dict:
    """搜索 LWE：给定 (A, b = A·s + e mod q)，用嵌入攻击尝试恢复 s。

    返回 {"success", "recovered", "residual_inf"}。
    success 判定：提供 s_true 时按完全相等；否则按残差落在噪声界内判定。
    """
    a_mat = np.asarray(a_mat, dtype=np.int64)
    b_vec = np.asarray(b_vec, dtype=np.int64)
    m_rows, n_cols = a_mat.shape
    dim = m_rows + n_cols + 1
    basis = np.zeros((dim, dim), dtype=np.int64)
    for i in range(m_rows):
        basis[i, i] = q
    basis[m_rows:m_rows + n_cols, 0:m_rows] = a_mat.T
    for j in range(n_cols):
        basis[m_rows + j, m_rows + j] = 1
    basis[dim - 1, 0:m_rows] = b_vec
    basis[dim - 1, dim - 1] = int(t_embed)

    reduced = lll_reduce(basis)
    order = np.argsort(np.linalg.norm(reduced.astype(np.float64), axis=1))
    best = {"success": False, "recovered": None, "residual_inf": None}
    for idx in order:
        row = reduced[idx]
        cand = row[m_rows:m_rows + n_cols]
        s_cand = np.round(cand).astype(np.int64)
        for candidate in (s_cand, -s_cand):
            if not np.all(np.abs(candidate) <= 1):
                continue
            residual = (b_vec - a_mat @ candidate) % q
            residual = np.where(residual > q // 2, residual - q, residual)
            res_inf = int(np.max(np.abs(residual)))
            ok = False
            if s_true is not None:
                ok = bool(np.array_equal(candidate, np.asarray(s_true)))
            else:
                ok = res_inf <= max(4.0, noise_margin * sigma)
            if ok:
                return {"success": True, "recovered": candidate,
                        "residual_inf": res_inf}
            best = {"success": False, "recovered": None, "residual_inf": res_inf}
    return best