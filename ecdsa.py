#!/usr/bin/env python3
"""ECDSA — Elliptic Curve Digital Signature Algorithm over secp256k1.

Pure Python implementation: point arithmetic, key generation, sign, verify.
Same curve used in Bitcoin, Ethereum, and most blockchain systems.

Usage: python ecdsa.py [--test]
"""

import sys, hashlib, secrets

# secp256k1 parameters
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
A = 0
B = 7
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (Gx, Gy)
INF = (0, 0)  # point at infinity

def mod_inv(a, m):
    if a < 0:
        a = a % m
    g, x, _ = _ext_gcd(a, m)
    if g != 1:
        raise ValueError("No inverse")
    return x % m

def _ext_gcd(a, b):
    if a == 0:
        return b, 0, 1
    g, x, y = _ext_gcd(b % a, a)
    return g, y - (b // a) * x, x

def point_add(p1, p2):
    if p1 == INF: return p2
    if p2 == INF: return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        if y1 != y2:
            return INF  # inverse points
        if y1 == 0:
            return INF
        # Point doubling
        lam = (3 * x1 * x1 + A) * mod_inv(2 * y1, P) % P
    else:
        lam = (y2 - y1) * mod_inv(x2 - x1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)

def point_mul(k, point):
    """Scalar multiplication via double-and-add."""
    result = INF
    addend = point
    k = k % N
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result

def generate_keypair():
    """Generate (private_key, public_key) pair."""
    priv = secrets.randbelow(N - 1) + 1
    pub = point_mul(priv, G)
    return priv, pub

def sign(message, private_key):
    """Sign message (bytes) with private key. Returns (r, s)."""
    z = _hash_to_int(message)
    while True:
        k = secrets.randbelow(N - 1) + 1
        R = point_mul(k, G)
        r = R[0] % N
        if r == 0:
            continue
        k_inv = mod_inv(k, N)
        s = (k_inv * (z + r * private_key)) % N
        if s == 0:
            continue
        # Normalize s (low-S convention for Bitcoin)
        if s > N // 2:
            s = N - s
        return (r, s)

def verify(message, signature, public_key):
    """Verify ECDSA signature. Returns True if valid."""
    r, s = signature
    if not (1 <= r < N and 1 <= s < N):
        return False
    z = _hash_to_int(message)
    s_inv = mod_inv(s, N)
    u1 = (z * s_inv) % N
    u2 = (r * s_inv) % N
    R = point_add(point_mul(u1, G), point_mul(u2, public_key))
    if R == INF:
        return False
    return R[0] % N == r

def _hash_to_int(message):
    if isinstance(message, str):
        message = message.encode()
    h = hashlib.sha256(message).digest()
    return int.from_bytes(h, 'big') % N

def encode_der(r, s):
    """Encode signature in DER format."""
    def int_bytes(v):
        b = v.to_bytes((v.bit_length() + 7) // 8, 'big')
        if b[0] & 0x80:
            b = b'\x00' + b
        return b
    rb = int_bytes(r)
    sb = int_bytes(s)
    inner = b'\x02' + bytes([len(rb)]) + rb + b'\x02' + bytes([len(sb)]) + sb
    return b'\x30' + bytes([len(inner)]) + inner

def decode_der(data):
    """Decode DER-encoded signature."""
    assert data[0] == 0x30
    assert data[2] == 0x02
    rlen = data[3]
    r = int.from_bytes(data[4:4+rlen], 'big')
    pos = 4 + rlen
    assert data[pos] == 0x02
    slen = data[pos+1]
    s = int.from_bytes(data[pos+2:pos+2+slen], 'big')
    return (r, s)

# --- Tests ---

def test_point_arithmetic():
    # G is on curve
    assert (Gy * Gy) % P == (Gx**3 + 7) % P
    # n*G = infinity
    assert point_mul(N, G) == INF
    # 1*G = G
    assert point_mul(1, G) == G
    # 2*G
    G2 = point_add(G, G)
    assert G2 != INF
    assert G2 == point_mul(2, G)

def test_sign_verify():
    priv, pub = generate_keypair()
    msg = b"Hello, ECDSA!"
    sig = sign(msg, priv)
    assert verify(msg, sig, pub)
    assert not verify(b"Tampered", sig, pub)

def test_different_keys():
    priv1, pub1 = generate_keypair()
    priv2, pub2 = generate_keypair()
    msg = b"test message"
    sig = sign(msg, priv1)
    assert verify(msg, sig, pub1)
    assert not verify(msg, sig, pub2)

def test_der_encoding():
    priv, pub = generate_keypair()
    sig = sign(b"DER test", priv)
    der = encode_der(*sig)
    r2, s2 = decode_der(der)
    assert (r2, s2) == sig

def test_low_s():
    priv, _ = generate_keypair()
    for _ in range(5):
        _, s = sign(b"low-s", priv)
        assert s <= N // 2

def test_mod_inv():
    for a in [1, 2, 7, 12345, N-1]:
        inv = mod_inv(a, P)
        assert (a * inv) % P == 1

if __name__ == "__main__":
    if "--test" in sys.argv or len(sys.argv) == 1:
        test_mod_inv()
        test_point_arithmetic()
        test_sign_verify()
        test_different_keys()
        test_der_encoding()
        test_low_s()
        print("All tests passed!")
    else:
        print("Generating keypair...")
        priv, pub = generate_keypair()
        print(f"Private: {priv:064x}")
        print(f"Public:  ({pub[0]:064x},\n          {pub[1]:064x})")
        msg = " ".join(sys.argv[1:]).encode()
        sig = sign(msg, priv)
        print(f"Signature: r={sig[0]:064x}\n           s={sig[1]:064x}")
        print(f"Valid: {verify(msg, sig, pub)}")
