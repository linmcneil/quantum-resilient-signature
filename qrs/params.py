"""参数配置。默认值与《技术交底书》口径一致，可通过构造参数覆盖。"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class LweParams:
    n: int = 128              # 格维度
    q: int = 12289            # 素数模数
    sigma: float = 2.0        # 离散高斯噪声标准差
    tail: int = 6             # 噪声截断半径（±3*sigma）
    verify_bound: int = 8     # 验证容差 V：满足 ‖b-A·s‖_∞ <= V
    secret_set: tuple = field(default_factory=lambda: (-1, 0, 1))


@dataclass(frozen=True)
class RsaParams:
    bits: int = 1024          # 模数位数（演示/对照用）
    e: int = 65537            # 公钥指数


@dataclass(frozen=True)
class AttackParams:
    """攻击者单轮预算：向签名预言机发起的查询次数上限。"""
    lwe_queries: int = 8      # LWE 攻击：最多收集 M 个历史样本
    rsa_queries: int = 2      # RSA(raw) 攻击：最多 2 次选择消息签名
