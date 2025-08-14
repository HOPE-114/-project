# SM2算法基本实现
本代码实现了 SM2 椭圆曲线密码算法的基本功能，包括密钥对生成、加密和解密操作。SM2 是国家密码管理局发布的椭圆曲线公钥密码算法标准，基于椭圆曲线离散对数问题，提供较高的安全性和效率。

## 主要功能
密钥对生成：生成随机私钥和对应的公钥  
加密：使用公钥对数据进行加密  
解密：使用私钥对加密数据进行解密  
辅助函数：包括椭圆曲线点运算、模逆计算、密钥派生函数 (KDF) 等  
## 函数说明
核心函数
generate_keypair(): 生成 SM2 密钥对，返回私钥 d 和公钥 Q  
encrypt_public_key(pubkey, data, ID): 使用公钥加密数据  
decrypt_private_key(d, C1, C2, C3, ID): 使用私钥解密数据  
## 辅助函数
inv_mod(a, m): 计算 a 在模 m 下的乘法逆元  
is_on_curve(x, y): 检查点 (x,y) 是否在椭圆曲线上  
point_add(P, Q): 椭圆曲线上点 P 和 Q 的加法  
scalar_mult(k, P): 椭圆曲线上点 P 的 k 倍标量乘法  
kdf(z, klen): 密钥派生函数  
sm3_hash(data): 哈希函数（此处使用 SHA256 模拟 SM3）  

# SM2 椭圆曲线实现与优化 
## 项目概述
本项目目标是实现并优化基于中国国家密码算法 SM2 的椭圆曲线密码学（ECC）核心运算。
## 主要功能：
SM2 椭圆曲线点运算（加法、倍点、坐标变换）  
标量乘法（固定基与任意基）  
采样与密钥对生成示例  
集成若干算法优化思路：雅各比（Jacobian）坐标、w-NAF、固定基预计算、常数时间选择的设计等  
## 设计目标
正确性：实现与 RFC/GM/T 标准一致的 SM2 椭圆曲线算术。  
可验证性：使用 Python 实现以便快速验证和单元测试。  
可移植性：代码结构便于将核心算法迁移到更高性能的实现（C、汇编、硬件）。  
可扩展性：支持将蒙哥马利算术、优化模约、常量时间逆元等替换为更高效实现。  
安全性：设计考虑常量时间实现策略，标注需要在低层实现的防侧信道措施。  

## 关键算法与优化策略

### 坐标选择 — Jacobian 坐标
目标：尽可能减少代价昂贵的模逆。  
实现：点在内部用 (X, Y, Z) 表示，只有在需要输出 affine 坐标时做一次逆元运算。  
### 窗口法与 w-NAF
目标：减少点加操作，用更多的预计算换取更少的在线计算。  
实现：w-NAF 编码与基于奇数倍的表格预计算（只存储奇数倍点）。  
### 固定基预计算（Fixed-base）
目标：加速涉及固定基点（如 G）的频繁标量乘，如签名时的 k*G。  
实现：可配置窗口大小（w），支持离线生成预计算表。  
### 蒙哥马利乘法与快速模约
目标：用 montgomery 形式减少模约开销并便于链式乘法。  
### 模逆优化
方案：使用 FLT(pow，p-2) 在原型中实现；在高性能实现中，采用 SafeGCD 或 Partial Montgomery Inversion 等更高效/常量时间方法。  
目标：避免基于私钥或其他秘密数据的分支与内存访问模式。  
实现建议：C 层的条件掩码、无分支选择、方向访问与掩码写回；对表选择使用恒定时间查找或 Rayon-like 并行掩码合并。  
### Co-Z / CoZXY 与批量运算
目标：同时计算多个点的倍点/加法以共享代价。  
### 汇编指令级优化（x86-64）
指令：MULX, ADCX, ADOX, BMI2(LZCNT/TZCNT) 等用于多精度乘加。  
策略：实现基于 64 位字的乘加循环，重排以利用 ADOX/ADCX 的双链架构，减少中间寄存器依赖与进位处理成本。  

## 代码说明
```python
def encrypt_public_key(pubkey, data: bytes, ID=b'1234567812345678'):
    # 公钥加密
    # 1) 生成随机 k
    k = random.randrange(1, n)
    C1 = scalar_mult(k, (Gx, Gy))  # C1 = k*G
    # 共享密钥 S = k * Pub
    S = scalar_mult(k, pubkey)
    x2, y2 = S
    # 生成z值
    z = ID + b":"+str(x2).encode() + b":"+str(y2).encode()
    # 派生会话密钥
    t = kdf(z, len(data)*8)
    # 伪对称加密（异或）
    enc = bytes([_ ^ t[i % len(t)] for i, _ in enumerate(data)])
    
    return {'C1': C1, 'C2': enc, 'C3': sm3_hash(z + enc)}
```
encrypt_public_key函数实现公钥加密：生成随机数 k，计算 C1 = k*G,计算共享秘密 S = k*Q（Q 为接收方公钥）从 S 派生出会话密钥 t
用 t 加密数据得到 C2,计算 C3 作为加密数据的哈希验证,返回密文结构 {C1, C2, C3}
```python
def decrypt_private_key(d, C1, C2, C3, ID=b'1234567812345678'):
    # 使用私钥解密
    # 计算共享密钥 S = d*C1
    S = scalar_mult(d, C1)
    x2, y2 = S
    # 生成z值
    z = ID + b":"+str(x2).encode() + b":"+str(y2).encode()
    # 派生会话密钥
    t = kdf(z, len(C2)*8)
    # 解密数据
    dec = bytes([_ ^ t[i % len(t)] for i, _ in enumerate(C2)])
    # 校验哈希值
    if C3 != sm3_hash(z + C2):
        raise ValueError("Invalid ciphertext or wrong key")
    return dec
```
decrypt_private_key函数实现私钥解密：使用私钥 d 计算共享秘密 S = d*C1,从 S 派生出会话密钥 t,用 t 解密密文 C2 得到明文
验证 C3 的哈希值确保数据完整性和正确性,返回解密后的明文
```python
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
```
坐标转换与点运算部分是核心，提供了仿射坐标与雅可比坐标的双向转换函数 (affine_to_jacobian 和 jacobian_to_affine)。
点运算包括雅可比坐标下的点加倍 (point_double) 和点加法 (point_add)，以及针对一个点为仿射坐标的优化加法 (point_add_mixed)，
这些函数通过数学公式实现椭圆曲线上的点运算规则。
```python
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
```
标量乘法优化是提升性能的关键，实现了基于窗口化非相邻形式 (w-NAF) 的高效标量乘法。通过 wnaf 函数将标量转换为特殊表示，precompute_window 函数预计算点的奇数倍数表，
再结合 ct_select_point 实现无分支查表，最终在 scalar_mul 中完成高效的标量乘法。
## 主要优化点
Jacobian 坐标：减少模逆  
w-NAF：用于非固定点标量乘，实现 w-NAF 与预计算表  
固定点乘：提供固定点预计算思路（函数 fixed_base_precompute / fixed_base_mul）  
模运算/模乘：代码使用 Python 的 % 运算；  
模逆：多种模逆优化（Partial Montgomery inversion, SafeGCD, FLT exponentiation chains 等）。  
表访问常量化：ct_select_point 函数示意常量时间选择；  
Co-Z / CoZXY 方法：此处没有完整实现 Co-Z 路径，但点加/点倍函数和预计算框架便于集成 Co-Z 算法  
## 实现结果
![image](/project5/sm2.png)
![image](/project5/优化.png)
