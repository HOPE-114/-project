# 基于 DDH 的私有交集和协议

<img width="1281" height="1025" alt="image" src="https://github.com/user-attachments/assets/fc4cd5af-b43b-4acd-a154-cced621309c7" />

### 该协议按如下流程执行：
首先是初始化，\(P_1\)和\(P_2\) 各自选群 \(\mathcal{G}\) 中随机私钥指数 \(k_1\)、\(k_2\) ，\(P_2\) 生成加法同态加密密钥对 \((pk, sk)\) 并把公钥 pk 发 \(P_1\) ；  
接着第一轮，\(P_1\) 处理自身集合 V 里的元素 \(v_i\) ，先哈希再用私钥指数 \(k_1\) 做指数运算，将结果打乱发给 \(P_2\) ；  
然后第二轮，\(P_2\) 先对收到的 \(P_1\) 结果用私钥指数 \(k_2\) 再次指数运算并打乱回发 \(P_1\) ，同时处理自身集合 W 里的 \((w_j, t_j)\) ，对 \(w_j\) 哈希后用 \(k_2\) 指数运算，对 \(t_j\) 用公钥 pk 加密，将这组结果打乱发给 \(P_1\) ；  
之后第三轮，\(P_1\) 对收到的 \(P_2\) 结果，用私钥指数 \(k_1\) 再次处理 \(w_j\) 相关运算结果，接着找交集集合 J ，利用同态加密特性对交集对应的加密数值做加法，经刷新操作后发 \(P_2\) ；最后输出阶段，\(P_2\) 用私钥 sk 解密密文得到交集和，完成整个私有交集和计算流程 。  
代码中，P1 有 {"alice", "bob", "charlie", "david"} 这些标识符，P2 有 {"bob": 100, "charlie": 200, "david": 300, "eve": 400} 这些带值的标识符。它们的交集是 {"bob", "charlie", "david"}，对应的和应该是 600，协议会计算出这个结果而不泄露非交集的信息。  

## 代码说明
1. Party1 类（参与方 1）负责提供标识符集合，不包含数值信息
```python
class Party1:
    def __init__(self, identifiers: Set[Identifier]):
        self.identifiers = identifiers  # P1的标识符集合
        self.private_key = random.randint(1, 10**6)  # 随机私钥
        self.z_values = None  # 存储从P2收到的Z集合
```
round1()：  
对每个标识符进行哈希处理（SHA256）  
用自己的私钥对哈希结果进行指数运算（模幂）  
打乱顺序后返回给 P2，避免泄露原始顺序  
round3(data_from_p2)：  
接收 P2 发送的处理后数据（标识符哈希 + 加密数值）  
用自己的私钥再次处理标识符哈希  
找出与 Z 集合匹配的交集元素  
对交集元素的加密数值求和（利用同态加密特性）  
返回加密的总和  
receive_z_values(z_values)：存储 P2 返回的 Z 集合，用于后续交集判断  

2. Party2 类（参与方 2）负责提供带数值的标识符集合，需要计算交集和 
```python
class Party2:
    def __init__(self, identifiers_with_values: Dict[Identifier, Value]):
        self.identifiers = identifiers_with_values  # 带数值的标识符
        self.private_key = random.randint(1, 10**6)  # 随机私钥
        # 同态加密密钥对
        self.he_public_key = random.randint(10**6, 10**7)
        self.he_private_key = random.randint(1, 10**6)
```
round2(data_from_p1)：  
接收 P1 的处理结果，用自己的私钥再次处理生成 Z 集合  
对自己的标识符进行哈希和私钥处理  
用同态加密公钥加密数值  
返回 Z 集合和处理后的（标识符 + 加密数值）对  
_homomorphic_encrypt(value)：简化的同态加密实现  
基于 Paillier 加密思想：(value * 公钥 + 私钥) % 模  
支持密文直接相加：E(a) + E(b) = E(a+b)  
decrypt(encrypted_sum)：解密加密的总和，得到最终结果  

3.协议执行流程（run_protocol 函数）
初始化 P1 和 P2，分别传入各自的数据  
第一轮：P1 处理自己的标识符并发送给 P2  
第二轮：P2 处理 P1 的数据生成 Z 集合，同时处理自己的数据并返回  
第三轮：P1 计算加密的交集和并发送给 P2  
P2 解密得到最终结果  
```python
# P1的标识符集合
p1_ids = {"alice", "bob", "charlie", "david"}

# P2的标识符及其对应的值
p2_ids = {
    "bob": 100,
    "charlie": 200,
    "david": 300,
    "eve": 400
}
```
协议执行过程中：
P1 不会知道 P2 的 "eve" 标识符及其值 400  
P2 不会知道 P1 的 "alice" 标识符  
双方仅能通过计算得知交集元素的总和  

### 安全特性说明
隐私保护：通过打乱顺序和加密处理，双方无法获取对方的非交集数据  
离散对数模拟：使用模幂运算模拟群操作，确保无法从中间结果反推原始数据  
同态加密：允许在加密状态下计算总和，避免泄露中间计算结果  
   

## 运行结果
<img width="1079" height="252" alt="image" src="https://github.com/user-attachments/assets/d7f0167d-a8c8-4e42-9cbf-3bcbde668003" />

<img width="1132" height="276" alt="image" src="https://github.com/user-attachments/assets/c881d8af-1712-4b2b-8196-ec60d3291f98" />



