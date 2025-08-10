# sm2_poc.py
# Simple, readable SM2 implementation + PoC for signature misuse (repeat k / known k) and forgery demo.
# Not optimized for performance. For research and PoC only.

import hashlib
import secrets

# SM2 domain parameters (recommended curve over prime field)
# Parameters from GM/T 0003.5-2012 / commonly used SM2 curve
p = int("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
a = int("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16)
b = int("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD4144D940E93", 16)
Gx = int("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16)
Gy = int("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16)
n = int("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16)

# Basic field ops mod p
def mod_inv(x, m=p):
    return pow(x, m-2, m)

def mod_sqrt(x, m=p):
    # Not used; placeholder
    return pow(x, (m+1)//4, m)

# Point representation: use affine (x, y) or None for point at infinity
O = None

def is_on_curve(P):
    if P is None:
        return True
    x, y = P
    return (y*y - (x*x*x + a*x + b)) % p == 0

def point_add(P, Q):
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    if P != Q:
        lam = ((y2 - y1) * mod_inv((x2 - x1) % p)) % p
    else:
        # point doubling
        lam = ((3 * x1 * x1 + a) * mod_inv((2 * y1) % p)) % p
    x3 = (lam*lam - x1 - x2) % p
    y3 = (lam*(x1 - x3) - y1) % p
    return (x3, y3)

def scalar_mul(k, P):
    if k % n == 0 or P is None:
        return None
    if k < 0:
        return scalar_mul(-k, (P[0], (-P[1]) % p))
    R = None
    Q = P
    while k:
        if k & 1:
            R = point_add(R, Q)
        Q = point_add(Q, Q)
        k >>= 1
    return R

# Key generation
def gen_keypair():
    d = secrets.randbelow(n-1) + 1
    P = scalar_mul(d, (Gx, Gy))
    return d, P

# SM2 signing (simplified, using e = hash(msg))
def sm2_hash(msg: bytes) -> int:
    # SM3 would be used in standard SM2; here use SHA-256 for simplicity in PoC
    h = hashlib.sha256(msg).digest()
    return int.from_bytes(h, 'big')

def sm2_sign(msg: bytes, d: int, k=None):
    e = sm2_hash(msg) % n
    while True:
        if k is None:
            k = secrets.randbelow(n-1) + 1
        P1 = scalar_mul(k, (Gx, Gy))
        if P1 is None:
            if k is not None:
                k = None
            continue
        x1 = P1[0] % n
        r = (e + x1) % n
        if r == 0 or r + k == n:
            if k is not None:
                k = None
            continue
        s = ( (pow(1 + d, -1, n) * (k - r * d)) ) % n
        if s == 0:
            if k is not None:
                k = None
            continue
        return (r, s, k)  # return k for PoC when needed

def sm2_verify(msg: bytes, sig, P_pub):
    r, s = sig
    if not (1 <= r <= n-1 and 1 <= s <= n-1):
        return False
    e = sm2_hash(msg) % n
    t = (r + s) % n
    if t == 0:
        return False
    P = point_add( scalar_mul(s, (Gx, Gy)),
                   scalar_mul(t, P_pub) )
    if P is None:
        return False
    x1 = P[0] % n
    return (r % n) == ((e + x1) % n)

# PoC 1: repeated k -> recover private key
# Derivation:
# Given two signatures (r, s1) and (r, s2) on different messages e1, e2 using same k:
# r = (e1 + x1) mod n  (x1 from kG)
# s1 = (1+d)^{-1} (k - r d) mod n
# s2 = (1+d)^{-1} (k - r d) mod n
# Subtract: s1 - s2 = 0 -> Wait identical if same r and same d and k -> actually identical signatures for same r.
# But in ECDSA-like schemes, repeated k across different messages leaks d. For SM2 formula arrangement:
# Rearranged: k = s*(1+d) + r*d  (mod n)
# For two signatures (r same, known s1,s2), subtract:
# k - k = (s1 - s2)*(1+d) + 0 => gives s1==s2 if same k
# So repeated k across two different messages yields identical (r,s) in SM2 standard. However if attacker learns k for one signature, recover d:
# from s = (1+d)^{-1}(k - r d) => (1+d)*s = k - r d => r d = k - (1+d)*s => d*(r + s) = k - s
# => d = (k - (1+d)*s) * (r)^{-1} ... not linear in d. But correct derivation:
# Let's derive properly:
# s = (1+d)^{-1} (k - r d) mod n
# Multiply both sides: (1+d)*s = k - r d (mod n)
# Expand: s + d s = k - r d
# Collect d terms: d (s + r) = k - s  => d = (k - s) * inv(s + r) mod n
# So if attacker knows k (nonce), they can compute d. Also if two signatures leak relation allowing solving for k, can recover d.
#
# Implement PoC: generate signature while returning k, then recover d from known k and signature.

def recover_priv_from_known_k(r, s, k):
    # d = (k - s) * inv(s + r) mod n
    denom = (s + r) % n
    if denom == 0:
        raise ValueError("Invalid denom")
    d_rec = ((k - s) * pow(denom, -1, n)) % n
    return d_rec

# PoC 2: forge signature under broken verification (example: if verifier mistakenly checks r == (e + x) mod n but uses
# wrong combination allowing attacker to craft r,s). More practical: if signer uses deterministic but predictable k,
# attacker can compute k and recover d. For demonstration: show forging signature when signer leaks k or uses k=1.
def demo():
    print("SM2 PoC demo")
    # generate keypair
    d, P = gen_keypair()
    print("private d:", hex(d))
    print("public P.x:", hex(P[0]))
    # sign a message and get k
    msg1 = b"Hello SM2"
    r, s, k = sm2_sign(msg1, d)
    print("signature r,s:", hex(r), hex(s))
    print("nonce k used (PoC):", hex(k))
    # verify
    assert sm2_verify(msg1, (r, s), P)
    print("verification ok")

    # recover private key from known k
    d_rec = recover_priv_from_known_k(r, s, k)
    print("recovered d:", hex(d_rec))
    assert d_rec == d
    print("Recovered private key matches original. PoC successful.")

    # Forge signature when signer uses k=1 (bad nonces)
    bad_k = 1
    r2, s2, _ = sm2_sign(b"msg2", d, k=bad_k)
    print("bad-k signature for msg2:", hex(r2), hex(s2))
    # attacker knows bad_k, can recover d similarly
    d_from_bad = recover_priv_from_known_k(r2, s2, bad_k)
    print("d_from_bad_k:", hex(d_from_bad))
    assert d_from_bad == d
    print("PoC: If signer uses a known or predictable nonce, attacker recovers d and can forge arbitrary signatures.")

if __name__ == "__main__":
    demo()