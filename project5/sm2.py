
import os
import random
import hashlib
from math import gcd

# 使用一个简单的短椭圆曲线 y^2 = x^3 + ax + b mod p
p = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
a = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
b = 0x28E9FA9E9D9F5E344D5AEF5E4D29C5D0

# 使用 y^2 = x^3 + ax + b mod p 的简单曲线
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
a = 0
b = 7

Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def inv_mod(a, m):
    # 计算 a 的模 m 乘法逆元，使用扩展欧几里得算法
    if a == 0:
        raise ZeroDivisionError("inverse of 0")
    lm, hm = 1, 0
    low, high = a % m, m
    while low > 1:
        r = high // low
        nm = hm - lm * r
        new = high - low * r
        lm, hm = nm, lm
        high, low = low, new
    return lm % m

def is_on_curve(x, y):
    return (y * y - (x * x * x + a * x + b)) % p == 0

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
        lam = ((y2 - y1) * inv_mod((x2 - x1) % p, p)) % p
    else:
        # diesel: 2*y1 / (2*x1)
        lam = ((3 * x1 * x1 + a) * inv_mod((2 * y1) % p, p)) % p
    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)

def scalar_mult(k, P):
    N = P
    Q = None
    while k > 0:
        if k & 1:
            Q = point_add(Q, N)
        N = point_add(N, N)
        k >>= 1
    return Q

def generate_keypair():
    d = random.randrange(1, n)
    Q = scalar_mult(d, (Gx, Gy))
    return d, Q

def kdf(z, klen):

    ct = 1
    Ha = b""
    while len(Ha) * 8 < klen:
        data = z + ct.to_bytes(4, 'big')
        Ha += hashlib.sha256(data).digest()
        ct += 1
    return Ha[: (klen + 7) // 8]

def sm3_hash(data: bytes) -> bytes:

    return hashlib.sha256(data).digest()

def encrypt_public_key(pubkey, data: bytes, ID=b'1234567812345678'):
    # 公钥加密
    # 1) 生成随机 k
    k = random.randrange(1, n)
    C1 = scalar_mult(k, (Gx, Gy))
    # 共享密钥 S = k * Pub
    S = scalar_mult(k, pubkey)
    x2, y2 = S
    z = ID + b":"+str(x2).encode() + b":"+str(y2).encode()
    t = kdf(z, len(data)*8)
    # 伪对称加密
    enc = bytes([_ ^ t[i % len(t)] for i, _ in enumerate(data)])

    return {'C1': C1, 'C2': enc, 'C3': sm3_hash(z + enc)}

def decrypt_private_key(d, C1, C2, C3, ID=b'1234567812345678'):
    # 使用私钥解密
    S = scalar_mult(d, C1)
    x2, y2 = S
    z = ID + b":"+str(x2).encode() + b":"+str(y2).encode()
    t = kdf(z, len(C2)*8)
    dec = bytes([_ ^ t[i % len(t)] for i, _ in enumerate(C2)])
    # 简单校验
    if C3 != sm3_hash(z + C2):
        raise ValueError("Invalid ciphertext or wrong key")
    return dec

if __name__ == "__main__":
    # 生成密钥对
    d, Q = generate_keypair()
    print("Private key d:", d)
    print("Public key Q:", Q)

    # 原始消息
    message = b"hello SM2 demo"

    # 使用公钥加密
    ciphertext = encrypt_public_key(Q, message)
    print("Ciphertext:", ciphertext)

    # 使用私钥解密
    decrypted = decrypt_private_key(d, ciphertext['C1'], ciphertext['C2'], ciphertext['C3'])
    print("Decrypted:", decrypted)