"""RSA 认证凭证基线（无填充实现，用于展示代数结构弱点）。

mode="raw"  ：签名直接作用于整数载荷 m（sig = m^d mod N），保留乘法同态性，
              攻击者可借“选择消息签名预言机”做存在性伪造（m* = m1·m2 mod N）；
mode="hash" ：签名作用于 SHA-256(tx)（类 FDH），乘法伪造被哈希破坏，
              用于对照说明“填充/哈希为什么必要”。
"""
from __future__ import annotations

import hashlib
import secrets
from typing import Optional

from .params import RsaParams


def _miller_rabin(n: int, rounds: int = 40) -> bool:
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def _rand_prime(bits: int) -> int:
    while True:
        cand = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if _miller_rabin(cand):
            return cand


class RsaIdentity:
    def __init__(self, params: Optional[RsaParams] = None, mode: str = "raw"):
        if mode not in ("raw", "hash"):
            raise ValueError("mode must be 'raw' or 'hash'")
        self.mode = mode
        self.params = params or RsaParams()
        bits = self.params.bits
        while True:
            p = _rand_prime(bits // 2)
            q = _rand_prime(bits // 2)
            if p == q:
                continue
            n = p * q
            phi = (p - 1) * (q - 1)
            e = self.params.e
            try:
                d = pow(e, -1, phi)
            except ValueError:
                continue
            break
        self.p, self.q, self.n, self.phi, self.e, self.d = p, q, n, phi, e, d

    def _payload_int(self, payload) -> int:
        """把载荷规约为 [2, N-1) 内的整数 m。"""
        if isinstance(payload, int):
            m = payload % self.n
        else:
            digest = hashlib.sha256(str(payload).encode("utf-8")).digest()
            m = int.from_bytes(digest, "big") % self.n
        if m < 2:
            m += 2
        return m

    def sign_int(self, m: int) -> int:
        """（raw 模式用）对整数载荷 m 直接签名，供攻击预言机调用。"""
        m = self._payload_int(m)
        return pow(m, self.d, self.n)

    def sign_transaction(self, tx) -> int:
        """对外 API：对交易载荷签名。

        raw 模式直接签 SHA-256(tx) 的整数值；hash 模式先哈希再做“全域”签名。
        """
        m = self._payload_int(tx)
        return pow(m, self.d, self.n)

    def verify_int(self, m: int, sig: int) -> bool:
        m = self._payload_int(m)
        return pow(sig, self.e, self.n) == m

    def verify_transaction(self, tx, sig: int) -> bool:
        return self.verify_int(self._payload_int(tx), sig)
