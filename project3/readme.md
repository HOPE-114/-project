# 用circom实现poseidon2哈希算法的电路

## 实验要求

1) poseidon2哈希算法参数参考参考文档1的Table1，用(n,t,d)=(256,3,5)或(256,2,5)  
2）电路的公开输入用poseidon2哈希值，隐私输入为哈希原象，哈希算法的输入只考虑一个block即可。  
3) 用Groth16算法生成证明  
   
   <img width="953" height="326" alt="image" src="https://github.com/user-attachments/assets/1cae0b5e-7467-4bed-98cc-452705e95b7c" />

### 编写circom电路
```circom
// 引入 Poseidon 哈希相关组件
include "poseidon.circom"; 

template Poseidon2Hash() {
    // 定义输入输出信号
    signal input privateInput[3]; // 隐私输入，对应 t=3 的原象
    signal output hashOutput;     // 公开输出，哈希结果

    // 实例化 Poseidon 哈希，根据 (n,t,d)=(256,3,5) 设置参数
    component poseidon = Poseidon(3, 5, 256); // 输入长度 t=3，s-box 指数 d=5，n=256 
    for (var i = 0; i < 3; i++) {
        poseidon.inputs[i] <== privateInput[i];
    }
    hashOutput <== poseidon.out;
}

component main = Poseidon2Hash();
```
### 编译电路
```
circom poseidon2.circom --r1cs --wasm --sym
```
生成：  
.r1cs 文件：电路的约束系统表示，后续用于 Groth16 密钥生成。  
.wasm 文件：用于辅助生成 witness（见证数据 ）。  
.sym 文件：符号信息。  

###  生成 Witness（见证数据）

###  Groth16 密钥生成
```
snarkjs groth16 setup poseidon2.r1cs powersOfTau28_hez_final_10.ptau circuit_0000.zkey
snarkjs groth16 contribute circuit_0000.zkey circuit_0001.zkey --name "First contribution" -v
snarkjs groth16 export verificationkey circuit_final.zkey verification_key.json
snarkjs groth16 prove circuit_final.zkey witness.wtns proof.json public.json
```
circuit_final.zkey 是前面生成的包含密钥信息的文件。  
witness.wtns 是见证数据。  
proof.json 是生成的证明文件，包含证明相关的多项式承诺等信息。  
public.json 是公开输入输出信息（这里主要是哈希结果等 ），用于验证。  
### 验证证明
```
snarkjs groth16 verify verification_key.json public.json proof.json
```
如果证明有效，会输出 OK，表示验证通过，即可以证明在满足电路约束（也就是正确执行了 Poseidon2 哈希计算 ）的情况下，存在对应的隐私输入（哈希原象 ）得到公开的哈希输出。
