# 1
from hashlib import sha256

n = int("8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3", 16)

def modinv(a, m):
    return pow(a, m-2, m)

k = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
r = 0x1111111111111111111111111111111111111111111111111111111111111111
s = 0x2222222222222222222222222222222222222222222222222222222222222222

denom = (s + r) % n
if denom == 0:
    raise Exception("s + r == 0 (mod n), cannot invert")
d = ((k - s) * modinv(denom, n)) % n
print("Recovered d =", hex(d))


# 2
n = int("8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3", 16)

def modinv(a, m): return pow(a % m, m-2, m)

r1 = ...
s1 = ...
r2 = ...
s2 = ...

num = (s2 - s1) % n
den = (s1 - s2 + r1 - r2) % n
if den == 0:
    raise Exception("Denominator zero")
d = (num * modinv(den, n)) % n
print("Recovered d =", hex(d))



# 3
n = int("...hex n ...", 16)
def modinv(a, m): return pow(a % m, m-2, m)

r1 = ...
s1 = ...
r2 = ...
s2 = ...


denom = (s1 + r1) % n
if denom == 0:
    raise Exception("...")



# 4

n = ...
def modinv(a,m): return pow(a % m, m-2, m)
r1 = ...
s1 = ...
e1 = ...
r2 = ...
s2 = ...

num = (s1 * s2 - e1) % n
den = (r1 - s1*s2 - s1*r2) % n
d = (num * modinv(den, n)) % n
print(hex(d))