import hashlib
import hmac
import os
import random
from typing import List, Tuple, Dict

# 定义一些常量
SALT_LENGTH = 16
HASH_LENGTH = 32
BLOOM_FILTER_SIZE = 2 ** 20  # 1MB的布隆过滤器
NUM_HASH_FUNCTIONS = 3


def generate_salt() -> bytes:
    """生成随机盐值"""
    return os.urandom(SALT_LENGTH)


def hkdf(key: bytes, salt: bytes, info: bytes, length: int) -> bytes:

    prk = hmac.new(salt, key, hashlib.sha256).digest()
    t = b""
    okm = b""
    i = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:length]


def password_hash(password: str, salt: bytes) -> bytes:
    """计算密码的哈希值"""
    return hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        100000  # 迭代次数
    )


class BloomFilter:
    """布隆过滤器实现"""

    def __init__(self, size: int, num_hash: int):
        self.size = size
        self.num_hash = num_hash
        self.bit_array = [0] * size

    def _hash_functions(self, item: bytes) -> List[int]:
        """生成多个哈希值索引"""
        hashes = []
        for i in range(self.num_hash):
            # 使用不同的信息生成不同的哈希函数
            h = hkdf(item, b"bloom_filter", bytes([i]), 4)
            idx = int.from_bytes(h, byteorder='big') % self.size
            hashes.append(idx)
        return hashes

    def add(self, item: bytes) -> None:
        """向布隆过滤器添加元素"""
        for idx in self._hash_functions(item):
            self.bit_array[idx] = 1

    def contains(self, item: bytes) -> bool:
        """检查元素是否可能在布隆过滤器中"""
        for idx in self._hash_functions(item):
            if self.bit_array[idx] == 0:
                return False
        return True


class Server:
    """服务器端实现"""

    def __init__(self):
        # 服务器私钥
        self.server_key = generate_salt()
        # 全局盐值，用于密码哈希计算，确保客户端和服务器计算一致
        self.global_salt = generate_salt()
        # 布隆过滤器，用于快速检查
        self.bloom_filter = BloomFilter(BLOOM_FILTER_SIZE, NUM_HASH_FUNCTIONS)
        # 存储H(s) -> (s, k_s)的映射
        self.hash_map = {}

    def add_leaked_password(self, password: str) -> None:
        """添加泄露的密码到服务器数据库"""
        # 使用全局盐值生成哈希，确保客户端可以生成相同的哈希
        s = password_hash(password, self.global_salt)

        # 计算H(s)
        h_s = hashlib.sha256(s).digest()

        # 生成k_s
        k_s = hkdf(self.server_key, h_s, b"server_key_derivation", HASH_LENGTH)

        # 添加到布隆过滤器
        self.bloom_filter.add(h_s)

        # 存储映射关系
        self.hash_map[h_s] = (s, k_s)

    def prepare_challenge(self, client_h_s_list: List[bytes]) -> Tuple[Dict[bytes, Tuple[bytes, bytes]], bytes]:
        """准备挑战数据"""
        # 筛选出布隆过滤器中存在的H(s)
        challenge_data = {}
        for h_s in client_h_s_list:
            if self.bloom_filter.contains(h_s) and h_s in self.hash_map:
                s, k_s = self.hash_map[h_s]
                # 生成随机数r_s
                r_s = os.urandom(HASH_LENGTH)
                # 计算t_s = HMAC(k_s, r_s)
                t_s = hmac.new(k_s, r_s, hashlib.sha256).digest()
                challenge_data[h_s] = (r_s, t_s)

        # 生成服务器随机数
        server_rand = os.urandom(HASH_LENGTH)

        return challenge_data, server_rand

    def verify_response(self, challenge_data: Dict[bytes, Tuple[bytes, bytes]],
                        client_response: Dict[bytes, bytes]) -> bool:
        """验证客户端响应"""
        # 检查每个挑战的响应是否正确
        for h_s, (r_s, expected_t_s) in challenge_data.items():
            if h_s in client_response:
                client_t_s = client_response[h_s]
                # 如果客户端计算的t_s与服务器预期的一致，则密码已泄露
                if client_t_s == expected_t_s:
                    return True
        return False


class Client:
    """客户端实现"""

    def __init__(self, server_global_salt: bytes):
        # 客户端私钥
        self.client_key = generate_salt()
        # 服务器的全局盐值，用于密码哈希计算
        self.server_global_salt = server_global_salt

    def generate_queries(self, password: str, num_decoys: int = 4) -> Tuple[List[bytes], bytes]:
        """生成查询列表，包含真实密码哈希和一些干扰项"""
        # 使用服务器的全局盐值生成真实哈希，确保与服务器计算一致
        s_real = password_hash(password, self.server_global_salt)
        h_s_real = hashlib.sha256(s_real).digest()

        # 生成干扰查询
        queries = [h_s_real]
        for _ in range(num_decoys):
            # 生成随机干扰项
            fake_salt = generate_salt()
            fake_password = os.urandom(16).hex()  # 随机字符串作为假密码
            fake_s = password_hash(fake_password, fake_salt)
            fake_h_s = hashlib.sha256(fake_s).digest()
            queries.append(fake_h_s)

        # 打乱顺序，增加隐私保护
        random.shuffle(queries)
        return queries, s_real

    def process_challenge(self, challenge_data: Dict[bytes, Tuple[bytes, bytes]], s_real: bytes, server_rand: bytes) -> \
    Dict[bytes, bytes]:
        """处理服务器挑战并生成响应"""
        response = {}

        # 为每个挑战生成响应
        for h_s, (r_s, _) in challenge_data.items():
            # 计算k_s' = HKDF(client_key, h_s, ...)
            k_s_prime = hkdf(self.client_key, h_s, b"client_key_derivation", HASH_LENGTH)

            # 计算t_s' = HMAC(k_s', r_s)
            t_s_prime = hmac.new(k_s_prime, r_s, hashlib.sha256).digest()

            response[h_s] = t_s_prime

        return response


def main():
    # 创建服务器并添加一些泄露的密码
    server = Server()
    leaked_passwords = ["password123", "qwerty", "letmein", "123456"]
    for pwd in leaked_passwords:
        server.add_leaked_password(pwd)
    print(f"服务器已加载泄露密码: {leaked_passwords}")

    # 创建客户端，传入服务器的全局盐值
    client = Client(server.global_salt)

    # 测试：检查一个未泄露的密码
    test_password = "SecureP@ssw0rd!"
    print(f"\n测试- 检查密码: {test_password}")

    queries, s_real = client.generate_queries(test_password)
    challenge_data, server_rand = server.prepare_challenge(queries)
    print(f"服务器返回 {len(challenge_data)} 个挑战")
    client_response = client.process_challenge(challenge_data, s_real, server_rand)
    is_leaked = server.verify_response(challenge_data, client_response)

    if is_leaked:
        print(f"警告: 密码 '{test_password}' 已被泄露!")
    else:
        print(f"恭喜: 密码 '{test_password}' 未在泄露列表中")


if __name__ == "__main__":
    main()
