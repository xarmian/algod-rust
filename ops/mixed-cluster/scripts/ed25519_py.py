#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.

"""Pure-python ed25519 so the mixed-cluster harness can produce validly signed
transactions with the standard library only (issue #1974); a pure-python
signer avoids a third-party dependency in CI. Test/harness use: not constant
time and slow (about 0.1 s per signature).

Third-party attribution: the algorithm is the public-domain reference
`ed25519.py` by D. J. Bernstein, N. Duif, T. Lange, P. Schwabe and B.-Y. Yang
(https://ed25519.cr.yp.to/python/ed25519.py), also reproduced in RFC 8032
section 6; checked against the RFC 8032 test vectors in ed25519_py_test.py."""
import hashlib

_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _inv(x):
    return pow(x, _P - 2, _P)


def _xrecover(y):
    xx = (y * y - 1) * _inv(_D * y * y + 1)
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = (x * _I) % _P
    if x % 2 != 0:
        x = _P - x
    return x


_BY = 4 * _inv(5) % _P
_B = (_xrecover(_BY) % _P, _BY % _P)


def _add(p, q):
    x1, y1 = p
    x2, y2 = q
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + _D * x1 * x2 * y1 * y2)
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - _D * x1 * x2 * y1 * y2)
    return x3 % _P, y3 % _P


def _mul(p, e):
    q = (0, 1)
    while e:
        if e & 1:
            q = _add(q, p)
        p = _add(p, p)
        e >>= 1
    return q


def _encode(p):
    x, y = p
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _h(m):
    return hashlib.sha512(m).digest()


def _clamp(h):
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    return a | (1 << 254)


def public_key(seed):
    return _encode(_mul(_B, _clamp(_h(seed))))


def sign(seed, msg):
    h = _h(seed)
    a = _clamp(h)
    pk = _encode(_mul(_B, a))
    r = int.from_bytes(_h(h[32:] + msg), "little") % _L
    big_r = _encode(_mul(_B, r))
    k = int.from_bytes(_h(big_r + pk + msg), "little") % _L
    s = (r + k * a) % _L
    return big_r + s.to_bytes(32, "little")
