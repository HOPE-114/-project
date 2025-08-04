import struct

# 循环左移函数
def left_rotate(x, n):
    return ((x << n) & 0xFFFFFFFF) | (x >> (32 - n))

# 布尔函数FF和GG，分阶段不同实现
def FF_j(x, y, z, j):
    if 0 <= j <= 15:
        return x ^ y ^ z
    else:
        return (x & y) | (x & z) | (y & z)

def GG_j(x, y, z, j):
    if 0 <= j <= 15:
        return x ^ y ^ z
    else:
        return (x & y) | (~x & z)

# 置换函数P0和P1
def P0(x):
    return x ^ left_rotate(x, 9) ^ left_rotate(x, 17)

def P1(x):
    return x ^ left_rotate(x, 15) ^ left_rotate(x, 23)

# T常量
T_j = [0x79CC4519] * 16 + [0x7A879D8A] * 48

class SM3:
    def __init__(self):
        # 初始值IV，8个32bit值
        self.IV = [
            0x7380166F,
            0x4914B2B9,
            0x172442D7,
            0xDA8A0600,
            0xA96F30BC,
            0x163138AA,
            0xE38DEE4D,
            0xB0FB0E4E,
        ]

    def padding(self, message: bytes) -> bytes:
        # 消息填充，消息长度以bit计
        bit_len = len(message) * 8
        message += b'\x80'  # 加1 bit
        padding_len = (56 - (len(message) % 64)) % 64
        message += b'\x00' * padding_len
        message += struct.pack('>Q', bit_len)  # 64bit长度，大端序
        return message

    def message_extension(self, block: bytes):
        # W拓展：
        W = list(struct.unpack('>16I', block))
        for j in range(16, 68):
            tmp = P1(W[j-16] ^ W[j-9] ^ left_rotate(W[j-3], 15)) ^ left_rotate(W[j-13], 7) ^ W[j-6]
            W.append(tmp & 0xFFFFFFFF)
        W_1 = [W[j] ^ W[j+4] for j in range(64)]
        return W, W_1

    def compress(self, V: list, block: bytes) -> list:
        A, B, C, D, E, F, G, H = V
        W, W_1 = self.message_extension(block)

        for j in range(64):
            SS1 = left_rotate((left_rotate(A, 12) + E + left_rotate(T_j[j], j)) & 0xFFFFFFFF, 7)
            SS2 = SS1 ^ left_rotate(A, 12)
            TT1 = (FF_j(A, B, C, j) + D + SS2 + W_1[j]) & 0xFFFFFFFF
            TT2 = (GG_j(E, F, G, j) + H + SS1 + W[j]) & 0xFFFFFFFF
            D = C
            C = left_rotate(B, 9)
            B = A
            A = TT1
            H = G
            G = left_rotate(F, 19)
            F = E
            E = P0(TT2)

        return [
            A ^ V[0], B ^ V[1], C ^ V[2], D ^ V[3],
            E ^ V[4], F ^ V[5], G ^ V[6], H ^ V[7]
        ]

    def hash(self, message: bytes) -> bytes:
        msg_padded = self.padding(message)
        V = self.IV[:]
        for i in range(0, len(msg_padded), 64):
            block = msg_padded[i:i+64]
            V = self.compress(V, block)
        return b''.join(struct.pack('>I', i) for i in V)

    def hexdigest(self, message: bytes) -> str:
        return self.hash(message).hex()

# 使用示例
if __name__ == "__main__":
    sm3 = SM3()
    msg = b"abc"
    print("SM3 Hash of 'abc':", sm3.hexdigest(msg))