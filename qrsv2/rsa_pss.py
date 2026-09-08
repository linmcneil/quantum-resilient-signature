"""纯标准库 RSA-PSS（对照基线，无 pycryptodome 依赖）。

按 RFC 8017 EMSA-PSS / RSASSA-PSS 实现：SHA-256 + 32 字节盐。
RSA 密钥用 Miller-Rabin 概率素性测试生成；密钥可缓存到本地文件避免重复生成。
教学用途：用于同安全级性能对照（RSA-3072 常与 NIST Ⅰ/Ⅱ 级对照使用），
不用于生产。量子威胁背景下 RSA 仍是“将被替换”的基线——这正是项目意义。
"""
from __future__ import annotations

import hashlib
import json
import os
import random
from dataclasses import dataclass

_SMALL_PRIMES = None


def _sieve(n: int):
    flags = bytearray([1]) * (n + 1)
    flags[0] = flags[1] = 0
    for i in range(2, int(n ** 0.5) + 1):
        if flags[i]:
            flags[i * i: n + 1: i] = bytearray(len(flags[i * i: n + 1: i]))
    return [i for i in range(n + 1) if flags[i]]


def _small_primes():
    global _SMALL_PRIMES
    if _SMALL_PRIMES is None:
        _SMALL_PRIMES = _sieve(50000)
    return _SMALL_PRIMES


def is_probable_prime(n: int, rounds: int = 16) -> bool:
    if n < 2:
        return False
    for p in _small_primes():
        if n % p == 0:
            return n == p
    d = n - 1
    r2 = 0
    while d % 2 == 0:
        d //= 2
        r2 += 1
    for _ in range(rounds):
        a = random.randrange(2, n - 2)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r2 - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def random_prime(bits: int) -> int:
    while True:
        candidate = random.getrandbits(bits)
        candidate |= (1 << (bits - 1)) | 1
        if is_probable_prime(candidate):
            return candidate


def generate_rsa(bits: int = 3072, exponent: int = 65537):
    """生成 RSA 密钥，返回 (n, e, d, p, q)。"""
    half = bits // 2
    while True:
        p = random_prime(half)
        q = random_prime(bits - half)
        if p == q:
            continue
        phi = (p - 1) * (q - 1)
        if __import__("math").gcd(exponent, phi) != 1:
            continue
        d = pow(exponent, -1, phi)
        return exponent * 0 or (p * q, exponent, d, p, q)


def _mgf1(seed: bytes, out_len: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < out_len:
        out += hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return bytes(out[:out_len])


def pss_encode(message: bytes, em_bits: int, salt: bytes, h_len: int = 32) -> bytes:
    """EMSA-PSS-ENCODE (RFC 8017 9.1.1)，返回长度 emLen = ceil(em_bits/8)。"""
    em_len = (em_bits + 7) // 8
    s_len = len(salt)
    m_hash = hashlib.sha256(message).digest()
    m_prime = b"\x00" * 8 + m_hash + salt
    h = hashlib.sha256(m_prime).digest()
    ps_len = em_len - s_len - h_len - 2
    if ps_len < 0:
        raise ValueError("em_bits too small for salt")
    db = b"\x00" * ps_len + b"\x01" + salt
    db_mask = _mgf1(h, em_len - h_len - 1)
    masked_db = bytes(x ^ y for x, y in zip(db, db_mask))
    # 清掉最左边多余比特：8*em_len - em_bits
    excess = 8 * em_len - em_bits
    if excess:
        head = bytearray(masked_db)
        head[0] &= 0xFF >> excess
        masked_db = bytes(head)
    return masked_db + h + b"\xbc"


def pss_verify(em: bytes, message: bytes, em_bits: int, salt_len: int = 32,
               h_len: int = 32) -> bool:
    """EMSA-PSS-VERIFY (RFC 8017 9.1.2)。"""
    em_len = (em_bits + 7) // 8
    if len(em) != em_len or em[-1] != 0xBC:
        return False
    excess = 8 * em_len - em_bits
    if excess and (em[0] >> (8 - excess)) != 0:
        return False
    masked_db = em[: em_len - h_len - 1]
    h = em[em_len - h_len - 1: -1]
    db_mask = _mgf1(h, em_len - h_len - 1)
    db = bytes(x ^ y for x, y in zip(masked_db, db_mask))
    if excess:
        head = bytearray(db)
        head[0] &= 0xFF >> excess
        db = bytes(head)
    if db[-salt_len - 1] != 0x01:
        return False
    salt = db[-salt_len:]
    m_hash = hashlib.sha256(message).digest()
    m_prime = b"\x00" * 8 + m_hash + salt
    return h == hashlib.sha256(m_prime).digest()


@dataclass
class RsaKey:
    bits: int
    n: int
    e: int
    d: int

    def public_bytes(self) -> bytes:
        return self.n.to_bytes((self.bits + 7) // 8, "big")

    def private_bytes(self) -> bytes:
        return self.d.to_bytes((self.bits + 7) // 8, "big")

    def sign(self, message: bytes) -> bytes:
        salt = os.urandom(32)
        em = pss_encode(message, self.bits - 1, salt)
        m_int = int.from_bytes(em, "big")
        s_int = pow(m_int, self.d, self.n)
        return s_int.to_bytes((self.bits + 7) // 8, "big")

    def verify(self, message: bytes, signature: bytes) -> bool:
        s_int = int.from_bytes(signature, "big")
        m_int = pow(s_int, self.e, self.n)
        em = m_int.to_bytes((self.bits + 7) // 8, "big")
        return pss_verify(em, message, self.bits - 1)


def cache_path(bits: int) -> str:
    base = os.path.join(os.environ.get("TEMP", "/tmp"), "qrs_v2_rsa_cache")
    os.makedirs(base, exist_ok=True)
    return os.path.join(base, f"rsa_{bits}.json")


def load_or_generate_rsa(bits: int = 3072) -> RsaKey:
    path = cache_path(bits)
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return RsaKey(bits=bits, n=data["n"], e=data["e"], d=data["d"])
    print(f"[rsa] generating RSA-{bits} key (one-time, may take a while)...")
    n, e, d, _p, _q = generate_rsa(bits)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"n": n, "e": e, "d": d}, fh)
    print("[rsa] key cached.")
    return RsaKey(bits=bits, n=n, e=e, d=d)