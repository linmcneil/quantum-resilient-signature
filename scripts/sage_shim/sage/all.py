# -*- coding: utf-8 -*-
"""
Minimal numerical compatibility layer exposing the small subset of SageMath
("sage.all") that the lattice-estimator package uses.  The goal is *not* to
reimplement Sage: every estimator function still runs the original estimator
code; this module only supplies plain-Python stand-ins for the handful of
numeric objects/functions those functions import from ``sage.all``.

Reals are represented by mpmath numbers whose working precision tracks the
Sage ``RealField(prec)`` ring they belong to (default 53 bits).  This preserves
the wide dynamic range of Sage's MPFR reals that IEEE-754 doubles would lose
(e.g. probabilities of order 1e-600 that the dual-attack amplification logic
encounters), while keeping ordinary values bit-comparable to double arithmetic.
"""
from __future__ import annotations

import math as _math
import builtins
from fractions import Fraction

import mpmath as _mp

# silence mpmath default behaviour
mp = _mp.mp



def _as_mpf(x):
    """Robustly turn int/float/RealElement/mpmath numbers into an mpmath mpf."""
    if isinstance(x, RealElement):
        return x._v
    if isinstance(x, (int, float)):
        return _mp.mpf(x)
    try:
        return _mp.mpf(x)
    except (TypeError, ValueError):
        return _mp.mpf(float(x))


class RealElement:
    """A Sage-RR-like real carrying an mpmath value and a precision."""

    __slots__ = ("_v", "_prec")

    def __init__(self, value=0.0, prec=None):
        if isinstance(value, RealElement):
            self._prec = value._prec if prec is None else prec
            self._v = _mp.mpf(value._v)
        else:
            self._prec = 53 if prec is None else int(prec)
            try:
                self._v = _mp.mpf(value)
            except (TypeError, ValueError):
                self._v = _mp.mpf(float(value))

    # -- basic protocol -----------------------------------------------------
    def __float__(self):
        return float(self._v)

    def __int__(self):
        return int(self._v)

    def __index__(self):
        return int(self._v)

    def __bool__(self):
        return bool(self._v)

    def prec(self):
        return self._prec

    def n(self, digits=None):
        if digits is None:
            return RealElement(self._v, self._prec)
        return RealElement(_mp.nstr(self._v, int(digits), strip_zeros=False), self._prec)

    def __round__(self, ndigits=None):
        if ndigits is None:
            return int(_mp.nint(self._v))
        return RealElement(_mp.nint(self._v * _mp.mpf(10) ** ndigits) / (_mp.mpf(10) ** ndigits), self._prec)

    def is_NaN(self):
        return _mp.isnan(self._v)

    def is_infinity(self):
        return _mp.isinf(self._v)

    def is_positive_infinity(self):
        return self._v == _mp.inf

    def is_negative_infinity(self):
        return self._v == -_mp.inf

    def round(self, mode="round"):
        v = self._v
        if mode in ("down", "floor"):
            return int(_mp.floor(v))
        if mode in ("up", "ceil"):
            return int(_mp.ceil(v))
        return int(_mp.nint(v))

    def __repr__(self):
        return _mp.nstr(self._v, 8, strip_zeros=False)

    # -- arithmetic (kept in the element's precision) ------------------------
    def _bin(self, other, op):
        prec = self._prec
        if isinstance(other, RealElement):
            prec = max(prec, other._prec)
            o = other._v
        else:
            try:
                o = _as_mpf(other)
            except (TypeError, ValueError, OverflowError):
                return NotImplemented
        return RealElement(op(self._v, o), prec)

    def __add__(self, other):
        return self._bin(other, lambda a, b: a + b)

    def __radd__(self, other):
        return RealElement(_as_mpf(other), self._prec).__add__(self)

    def __sub__(self, other):
        return self._bin(other, lambda a, b: a - b)

    def __rsub__(self, other):
        return RealElement(_as_mpf(other), self._prec).__sub__(self)

    def __mul__(self, other):
        return self._bin(other, lambda a, b: a * b)

    def __rmul__(self, other):
        return RealElement(_as_mpf(other), self._prec).__mul__(self)

    def __truediv__(self, other):
        ov = other._v if isinstance(other, RealElement) else _as_mpf(other)
        if ov == 0:
            nv = self._v
            if nv == 0:
                return RealElement(_mp.nan, self._prec)
            sign = 1 if (nv > 0) == (ov > 0) else -1
            return RealElement(sign * _mp.inf, max(self._prec, getattr(other, "_prec", 53)))
        return self._bin(other, lambda a, b: a / b)

    def __rtruediv__(self, other):
        return RealElement(_as_mpf(other), self._prec).__truediv__(self)

    def __floordiv__(self, other):
        r = self._bin(other, lambda a, b: a // b)
        return int(r._v) if isinstance(r, RealElement) else r

    def __rfloordiv__(self, other):
        return RealElement(_as_mpf(other), self._prec).__floordiv__(self)

    def __mod__(self, other):
        return self._bin(other, lambda a, b: a % b)

    def __rmod__(self, other):
        return RealElement(_as_mpf(other), self._prec).__mod__(self)

    def __pow__(self, other):
        return self._bin(other, lambda a, b: a ** b)

    def __rpow__(self, other):
        return RealElement(_as_mpf(other), self._prec).__pow__(self)

    def __neg__(self):
        return RealElement(-self._v, self._prec)

    def __pos__(self):
        return RealElement(self._v, self._prec)

    def __abs__(self):
        return RealElement(abs(self._v), self._prec)

    # -- comparisons ---------------------------------------------------------
    def _cmp(self, other, op):
        if isinstance(other, RealElement):
            o = other._v
        else:
            try:
                o = _as_mpf(other)
            except (TypeError, ValueError, OverflowError):
                return NotImplemented
        return op(self._v, o)

    def __lt__(self, other):
        return self._cmp(other, lambda a, b: a < b)

    def __le__(self, other):
        return self._cmp(other, lambda a, b: a <= b)

    def __gt__(self, other):
        return self._cmp(other, lambda a, b: a > b)

    def __ge__(self, other):
        return self._cmp(other, lambda a, b: a >= b)

    def __eq__(self, other):
        if other is None:
            return False
        try:
            return self._cmp(other, lambda a, b: a == b)
        except (TypeError, ValueError):
            return NotImplemented

    def __hash__(self):
        return hash(float(self._v))

    # -- sage-ish convenience methods ---------------------------------------
    def sqrt(self):
        with mp.extraprec(max(0, self._prec - 53)):
            return RealElement(_mp.sqrt(self._v), self._prec)

    def log(self, base=None):
        return log(self, base)

    def exp(self):
        return exp(self)

    def abs(self):
        return abs(self)


def _mpf(x):
    if isinstance(x, RealElement):
        return x._v, x._prec
    return _mp.mpf(x), 53


def ceil(x):
    v = _element_or_float(x)
    if _mp.isinf(v):
        return float(v)  # Sage: ceil(+/-infinity) stays infinite
    return int(_mp.ceil(v))


def floor(x):
    v = _element_or_float(x)
    if _mp.isinf(v):
        return float(v)
    return int(_mp.floor(v))


def sqrt(x):
    if isinstance(x, RealElement):
        return RealElement(_mp.sqrt(x._v), x._prec)
    return RealElement(_mp.sqrt(x), 53)


def log(x, base=None):
    if isinstance(x, RealElement):
        prec = x._prec
        with mp.extraprec(max(0, prec - 53)):
            val = _mp.log(x._v) if base is None else _mp.log(x._v) / _mp.log(_mp.mpf(base))
        return RealElement(val, prec)
    if base is None:
        return RealElement(_mp.log(x), 53)
    return RealElement(_mp.log(x) / _mp.log(_mp.mpf(base)), 53)


def exp(x):
    if isinstance(x, RealElement):
        with mp.extraprec(max(0, x._prec - 53)):
            return RealElement(_mp.exp(x._v), x._prec)
    return RealElement(_mp.exp(x), 53)


def erf(x):
    if isinstance(x, RealElement):
        return RealElement(_mp.erf(x._v), x._prec)
    return RealElement(_mp.erf(x), 53)


def coth(x):
    if isinstance(x, RealElement):
        return RealElement(_mp.coth(x._v), x._prec)
    return RealElement(_mp.coth(x), 53)


def tanh(x):
    if isinstance(x, RealElement):
        return RealElement(_mp.tanh(x._v), x._prec)
    return RealElement(_mp.tanh(x), 53)


def zeta(x):
    if isinstance(x, RealElement):
        return RealElement(_mp.zeta(x._v), x._prec)
    return RealElement(_mp.zeta(x), 53)


def binomial(n, k):
    n = int(n)
    k = int(k)
    if k < 0 or n < 0:
        return 0
    return _math.comb(n, k)


def prod(iterable):
    items = list(iterable)
    if not items:
        return 1
    out = items[0]
    for it in items[1:]:
        out = out * it
    return out


def _element_or_float(x):
    if isinstance(x, RealElement):
        return x._v
    if isinstance(x, (Fraction, _Rational)):
        return _mp.mpf(float(x))
    return _mp.mpf(x)


class RealRing:
    """Stand-in for Sage's ``RealField(prec)`` (a callable ring)."""

    def __init__(self, prec=53):
        self._prec = int(prec)

    def prec(self):
        return self._prec

    def __call__(self, value=0.0):
        if isinstance(value, RealElement):
            if value._prec >= self._prec:
                return RealElement(value._v, self._prec)
            with mp.extraprec(max(0, self._prec - 53)):
                return RealElement(_mp.mpf(value._v), self._prec)
        return RealElement(value, self._prec)

    def pi(self):
        return RealElement(_mp.pi, self._prec)

    def e(self):
        return RealElement(_mp.e, self._prec)

    def one(self):
        return RealElement(1, self._prec)

    def zero(self):
        return RealElement(0, self._prec)

    def __repr__(self):
        return f"Real Field with {self._prec} bits of precision"

    def __eq__(self, other):
        return isinstance(other, RealRing) and other._prec == self._prec

    def __hash__(self):
        return hash(("RealRing", self._prec))


class IntegerRing:
    """Stand-in for Sage's ``ZZ``."""

    def __call__(self, value=0):
        if isinstance(value, RealElement):
            return int(value._v)
        return int(value)

    def __repr__(self):
        return "Integer Ring"


class _Rational(Fraction):
    def round(self, mode="round"):
        v = float(self)
        if mode in ("down", "floor"):
            return int(_math.floor(v))
        if mode in ("up", "ceil"):
            return int(_math.ceil(v))
        return int(round(v))

    def n(self, digits=None):
        return RealElement(float(self))


class RationalField:
    """Stand-in for Sage's ``QQ``."""

    def __call__(self, value=0):
        if isinstance(value, _Rational):
            return value
        if isinstance(value, RealElement):
            return _Rational(Fraction(float(value._v)).limit_denominator(10**9))
        if isinstance(value, float):
            return _Rational(Fraction(value).limit_denominator(10**9))
        return _Rational(value)

    def __repr__(self):
        return "Rational Field"


class _RealDistribution:
    """Small subset of Sage's RealDistribution needed by estimator."""

    def __init__(self, name, params):
        self.name = name
        self.params = params
        from scipy import stats as _stats
        if name == "normal":
            self._dist = _stats.norm(loc=float(params[0]), scale=float(params[1]))
        elif name == "chisquared":
            self._dist = _stats.chi2(df=float(params))
        elif name == "beta":
            self._dist = _stats.beta(a=float(params[0]), b=float(params[1]))
        elif name == "uniform":
            self._dist = _stats.uniform(loc=float(params[0]), scale=float(params[1]) - float(params[0]))
        else:
            raise NotImplementedError(f"RealDistribution {name} not supported by shim")

    def cum_distribution_function(self, x):
        return RealElement(float(self._dist.cdf(float(x))))

    def density(self, x):
        return RealElement(float(self._dist.pdf(float(x))))

    def get_random_element(self):
        return RealElement(float(self._dist.rvs()))

    def __repr__(self):
        return f"{self.name} distribution {self.params}"


def parent(x):
    if isinstance(x, RealElement):
        return RealRing(x._prec)
    if isinstance(x, (int, float)) and not isinstance(x, bool):
        return RealRing(53)
    if isinstance(x, Fraction):
        return RationalField()
    return type(x)


def find_root(f, a, b, max_iterations=100, rtol=None, atol=None, **kwargs):
    from scipy.optimize import brentq as _brentq

    def _f(x):
        return float(f(_mp.mpf(x)))

    lo, hi = float(_mp.mpf(a)), float(_mp.mpf(b))
    xtol = 1e-12 if rtol is None else float(rtol)
    return RealElement(_brentq(_f, lo, hi, xtol=xtol, maxiter=int(max_iterations)))


def cached_function(f):
    """Deterministic memoizer; bypasses the cache for unhashable keys."""
    cache = {}

    def wrapper(*args, **kwargs):
        try:
            key = (args, tuple(sorted(kwargs.items())))
            hash(key)
        except TypeError:
            return f(*args, **kwargs)
        if key not in cache:
            cache[key] = f(*args, **kwargs)
        return cache[key]

    wrapper.__name__ = getattr(f, "__name__", "cached")
    wrapper.__doc__ = getattr(f, "__doc__", None)
    wrapper.__wrapped__ = f
    return wrapper


class _NotImplementedRing:
    def __init__(self, *args, **kwargs):
        pass

    def __call__(self, *args, **kwargs):
        raise NotImplementedError("PowerSeriesRing is not implemented in the sage shim")

    def __repr__(self):
        return "Power Series Ring (shim stub)"


def PowerSeriesRing(*args, **kwargs):
    return _NotImplementedRing(*args, **kwargs)


def line(points, *args, **kwargs):
    raise NotImplementedError("sage plotting is not implemented in the sage shim")


ZZ = IntegerRing()
QQ = RationalField()
RR = RealRing(53)
RDF = RealRing(53)
RealField = RealRing
RealDistribution = _RealDistribution
oo = float("inf")
pi = RealElement(_mp.pi, 53)
e = RealElement(_mp.e, 53)
euler_gamma = RealElement(_mp.euler, 53)
round = builtins.round
