"""统计工具：Wilson 分数区间（小样本成功率的不确定度）。"""
from __future__ import annotations

import math


def wilson_ci(k: int, n: int, z: float = 1.96) -> tuple:
    """二项比例 p=k/n 的 Wilson 95% 置信区间 (low, high)。"""
    if n <= 0:
        return (0.0, 0.0)
    p = k / n
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    half = (z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))) / denom
    low = max(0.0, center - half)
    high = min(1.0, center + half)
    return (low, high)