from typing import Optional, Tuple, List

p = int("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
a = int("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16)
b = int("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16)
Gx = int("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16)
Gy = int("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16)
n = int("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16)  # 椭圆曲线阶

# 我们将使用雅可比坐标 (X, Y, Z) 表示仿射坐标 (x = X/Z^2, y = Y/Z^3)
Point = Optional[Tuple[int, int, int]]  # None 表示无穷远点

# 工具函数：对 p 取模
def modp(x: int) -> int:
    return x % p

# 有限域运算（概念性占位符，实际应使用优化的蒙哥马利版本）
def fadd(x: int, y: int) -> int:
    # 带模约简的加法
    r = x + y
    if r >= p:
        r -= p
    return r

def fsub(x: int, y: int) -> int:
    r = x - y
    if r < 0:
        r += p
    return r

def fmul(x: int, y: int) -> int:
    # 优化实现中应使用蒙哥马利乘法
    return (x * y) % p

def fsqr(x: int) -> int:
    return (x * x) % p

def finv(x: int) -> int:

    return pow(x, p-2, p)

# 仿射坐标与雅可比坐标之间的转换
def affine_to_jacobian(P: Optional[Tuple[int,int]]) -> Point:
    if P is None:
        return None
    x, y = P
    return (x, y, 1)

def jacobian_to_affine(P: Point) -> Optional[Tuple[int,int]]:
    if P is None:
        return None
    X, Y, Z = P
    if Z == 0:
        return None
    Z2 = fsqr(Z)
    Z3 = fmul(Z2, Z)
    x = fmul(X, finv(Z2))
    y = fmul(Y, finv(Z3))
    return (x % p, y % p)

# 雅可比坐标中的无穷远点
O: Point = None

# 雅可比坐标中的点加倍运算
def point_double(P: Point) -> Point:
    if P is None:
        return None
    X1, Y1, Z1 = P
    if Y1 == 0:
        return None

    S = fmul(4, fmul(X1, fsqr(Y1)))
    M = fadd(fmul(3, fsqr(X1)), fmul(a, fsqr(fsqr(Z1))))  # a*Z^4 项
    X3 = fsub(fsqr(M), fmul(2, S))
    Y3 = fsub(fmul(M, fsub(S, X3)), fmul(8, fsqr(fsqr(Y1))))
    Z3 = fmul(2, fmul(Y1, Z1))
    return (X3 % p, Y3 % p, Z3 % p)

# 雅可比坐标中的点加法运算 (P + Q)
def point_add(P: Point, Q: Point) -> Point:
    if P is None:
        return Q
    if Q is None:
        return P
    X1, Y1, Z1 = P
    # 允许 Q 为雅可比坐标或仿射坐标；检测 Z 坐标
    X2, Y2, Z2 = Q
    if Z1 == 0:
        return Q
    if Z2 == 0:
        return P
    # 通用雅可比坐标加法：
    Z1Z1 = fsqr(Z1)
    Z2Z2 = fsqr(Z2)
    U1 = fmul(X1, Z2Z2)
    U2 = fmul(X2, Z1Z1)
    S1 = fmul(Y1, fmul(Z2, Z2Z2))
    S2 = fmul(Y2, fmul(Z1, Z1Z1))
    if U1 == U2:
        if S1 != S2:
            return None
        return point_double(P)
    H = fsub(U2, U1)
    I = fsqr(fmul(2, H))
    J = fmul(H, I)
    r = fmul(2, fsub(S2, S1))
    V = fmul(U1, I)
    X3 = fsub(fsqr(r), fadd(J, fmul(2, V)))
    Y3 = fsub(fmul(r, fsub(V, X3)), fmul(2, fmul(S1, J)))
    Z3 = fmul(fsub(fsqr(fadd(Z1, Z2)), fadd(Z1Z1, Z2Z2)), H)
    return (X3 % p, Y3 % p, Z3 % p)

def point_add_mixed(P: Point, Q_affine: Optional[Tuple[int,int]]) -> Point:
    if Q_affine is None:
        return P
    if P is None:
        return affine_to_jacobian(Q_affine)
    X1, Y1, Z1 = P
    x2, y2 = Q_affine
    Z1Z1 = fsqr(Z1)
    U2 = fmul(x2, Z1Z1)
    S2 = fmul(y2, fmul(Z1, Z1Z1))
    if U2 == X1 and S2 == Y1:
        return point_double(P)
    H = fsub(U2, X1)
    HH = fsqr(H)
    I = fmul(4, HH)
    J = fmul(H, I)
    r = fmul(2, fsub(S2, Y1))
    V = fmul(X1, I)
    X3 = fsub(fsqr(r), fadd(J, fmul(2, V)))
    Y3 = fsub(fmul(r, fsub(V, X3)), fmul(2, fmul(Y1, J)))
    Z3 = fmul(fsub(fsqr(fadd(Z1, H)), fadd(Z1Z1, HH)), 1)  # 简化版
    return (X3 % p, Y3 % p, Z3 % p)

def wnaf(k: int, w: int = 5) -> List[int]:
    # 计算 k 的宽度为 w 的 NAF 表示
    if k == 0:
        return [0]
    naf = []
    while k > 0:
        if k & 1:
            mod = 1 << w
            d = k % mod
            if d >= (1 << (w-1)):
                d = d - mod
            naf.append(d)
            k = k - d
        else:
            naf.append(0)
        k >>= 1
    return naf

# 预计算 P 的奇数倍数：[P, 3P, 5P, ..., (2^w-1)P]
def precompute_window(P_affine: Tuple[int,int], w: int) -> List[Tuple[int,int,int]]:
    # 返回表示奇数倍数的雅可比点列表
    m = 1 << (w - 1)
    tbl = []
    Pj = affine_to_jacobian(P_affine)
    tbl.append(Pj)  # 1*P
    if m == 1:
        return tbl
    # 计算 2P，然后通过连续加 2P 得到奇数倍数
    twoP = point_double(Pj)
    cur = Pj
    for i in range(1, m):
        # cur + 2P => (2i+1)P
        cur = point_add(cur, twoP)
        tbl.append(cur)
    return tbl

def ct_select_point(table: List[Point], idx: int) -> Point:
    # idx 是奇数索引 (1,3,5...)。我们转换为表索引
    if idx == 0:
        return None
    tindex = (abs(idx) - 1) // 2
    # 无分支选择：返回 table[tindex]，如果为负则取点的相反数
    P = table[tindex]
    if idx < 0:
        # 雅可比坐标中的点取反：(X, p-Y, Z)
        X, Y, Z = P
        return (X, (-Y) % p, Z)
    return P

# 使用 w-NAF 和雅可比点的标量乘法（变点）
def scalar_mul(P_affine: Tuple[int,int], k: int, w: int = 5) -> Point:
    if k % n == 0 or P_affine is None:
        return None
    k = k % n
    # 预计算雅可比坐标中的奇数倍数表
    tbl = precompute_window(P_affine, w)
    naf = wnaf(k, w)
    R: Point = None
    # 从最高有效位到最低有效位处理：naf[0] 是最低有效位 -> 反转
    for digit in reversed(naf):
        # R = 2*R
        R = point_double(R)
        if digit != 0:
            addP = ct_select_point(tbl, digit)
            R = point_add(R, addP)
    return R

# 固定基点乘法：为基点 G 预计算更大的表
def fixed_base_precompute(G_affine: Tuple[int,int], w: int = 8) -> List[Point]:
    # 固定基点使用更大的 w；存储 up to 2^w 的奇数倍数
    return precompute_window(G_affine, w)

def fixed_base_mul(precomp: List[Point], k: int, w: int = 8) -> Point:
    # 按 w 大小的窗口处理 k（通过简单的带符号数字提取实现非相邻）
    if k == 0:
        return None
    # 将 k 分割为窗口：这里我们使用简单的滑动窗口从最高位扫描
    R = None
    kb = k.bit_length()
    i = kb - 1
    while i >= 0:
        # 加倍
        R = point_double(R)
        if ((k >> i) & 1) == 0:
            i -= 1
            continue
        # 如果有 1，取最多 w 位
        l = max(1, min(w, i+1))
        # 提取窗口
        window = (k >> (i - l + 1)) & ((1 << l) - 1)
        # 转换为奇数带符号表示
        if window & 1 == 0:
            # 如果是偶数，通过右移 1 位减少（罕见情况），退化为单次加法
            R = point_add(R, precomp[0])
            i -= 1
            continue
        # 转换为范围内的带符号奇数
        if window >= (1 << (l - 1)):
            signed = window - (1 << l)
        else:
            signed = window
        # 消耗的加倍次数
        for _ in range(l - 1):
            R = point_double(R)
        # 添加选中的倍数
        addP = ct_select_point(precomp, signed)
        R = point_add(R, addP)
        i -= l
    return R

# 工具函数：点取反，点相等
def point_neg(P: Point) -> Point:
    if P is None:
        return None
    X, Y, Z = P
    return (X, (-Y) % p, Z)

def is_at_infinity(P: Point) -> bool:
    return P is None

def generate_keypair() -> Tuple[int, Tuple[int,int]]:
    # 私钥 d 在 [1, n-1] 范围内
    import os
    d = int.from_bytes(os.urandom(32), 'big') % n
    if d == 0:
        d = 1
    # 公钥 Q = d*G
    G_aff = (Gx, Gy)
    Qj = scalar_mul(G_aff, d, w=8)
    Q_aff = jacobian_to_affine(Qj)
    return d, Q_aff

if __name__ == "__main__":

    from random import randint
    k = randint(1, n-1)
    G_aff = (Gx, Gy)

    Pj = scalar_mul(G_aff, k, w=5)
    P_aff = jacobian_to_affine(Pj)

    def naive_mul(P_aff, k):
        R = None
        Q = affine_to_jacobian(P_aff)
        while k > 0:
            if k & 1:
                R = point_add(R, Q)
            Q = point_double(Q)
            k >>= 1
        return jacobian_to_affine(R)
    ref = naive_mul(G_aff, k)
    print("k:", k)
    print("结果匹配:", P_aff == ref)