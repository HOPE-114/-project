from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import random
import hashlib
from typing import List, Tuple, Set, Dict

# 定义协议中使用的类型
Identifier = str
Value = int


class Party1:
    def __init__(self, identifiers: Set[Identifier]):
        self.identifiers = identifiers
        # 生成私钥
        self.private_key = random.randint(1, 10 ** 6)  # 简化的私钥生成
        self.public_key = None
        self.received_from_p2 = None

    def round1(self) -> List[bytes]:
        """第一轮：处理自己的标识符并发送给P2"""
        # 使用SHA256哈希标识符，然后用私钥进行指数运算
        processed = []
        for id in self.identifiers:
            # 哈希标识符
            hashed = hashlib.sha256(id.encode()).digest()
            # 模拟指数运算：这里使用简单的模运算代替真实的群运算
            processed_id = int.from_bytes(hashed, byteorder='big')
            processed_id = pow(processed_id, self.private_key, 10 ** 18)
            processed.append(processed_id.to_bytes(24, byteorder='big'))

        # 打乱顺序
        random.shuffle(processed)
        return processed

    def round3(self, data_from_p2: List[Tuple[bytes, int]]) -> int:
        """第三轮：处理P2发送的数据，找到交集并计算加密的和"""
        self.received_from_p2 = data_from_p2

        # 处理P2发送的标识符部分
        processed = []
        for (hashed_id, encrypted_value) in data_from_p2:
            # 用自己的私钥进行指数运算
            id_num = int.from_bytes(hashed_id, byteorder='big')
            processed_id = pow(id_num, self.private_key, 10 ** 18)
            processed.append((processed_id, encrypted_value))

        # 找出交集
        intersection = []
        z_set = set(int.from_bytes(z, byteorder='big') for z in self.z_values)

        for (processed_id, encrypted_value) in processed:
            if processed_id in z_set:
                intersection.append(encrypted_value)

        # 计算加密的和（利用同态加密的加法特性）
        if not intersection:
            return 0  # 空集的和为0

        encrypted_sum = 0
        for val in intersection:
            encrypted_sum += val  # 同态加密的加法

        # 模拟刷新操作
        encrypted_sum = self._refresh_encryption(encrypted_sum)
        return encrypted_sum

    def _refresh_encryption(self, encrypted_value: int) -> int:
        """模拟同态加密的刷新操作"""
        # 简单的刷新：添加一个随机数然后减去
        random_val = random.randint(1, 10 ** 6)
        return (encrypted_value + random_val - random_val) % (10 ** 18)

    def receive_z_values(self, z_values: List[bytes]):
        """接收P2发送的Z集合"""
        self.z_values = z_values


class Party2:
    def __init__(self, identifiers_with_values: Dict[Identifier, Value]):
        self.identifiers = identifiers_with_values
        # 生成私钥
        self.private_key = random.randint(1, 10 ** 6)  # 简化的私钥生成
        # 生成同态加密密钥对
        self.he_public_key = random.randint(10 ** 6, 10 ** 7)
        self.he_private_key = random.randint(1, 10 ** 6)

    def round2(self, data_from_p1: List[bytes]) -> Tuple[List[bytes], List[Tuple[bytes, int]]]:
        """第二轮：处理P1发送的数据，并发送自己的数据给P1"""
        # 处理P1的数据生成Z集合
        z_values = []
        for item in data_from_p1:
            # 用自己的私钥进行指数运算
            item_num = int.from_bytes(item, byteorder='big')
            processed_item = pow(item_num, self.private_key, 10 ** 18)
            z_values.append(processed_item.to_bytes(24, byteorder='big'))

        # 打乱Z集合
        random.shuffle(z_values)

        # 处理自己的标识符和值
        processed_data = []
        for id, value in self.identifiers.items():
            # 哈希标识符
            hashed = hashlib.sha256(id.encode()).digest()
            # 用私钥进行指数运算
            id_num = int.from_bytes(hashed, byteorder='big')
            processed_id = pow(id_num, self.private_key, 10 ** 18)

            # 用同态加密加密值
            encrypted_value = self._homomorphic_encrypt(value)

            processed_data.append((processed_id.to_bytes(24, byteorder='big'), encrypted_value))

        # 打乱自己的数据
        random.shuffle(processed_data)

        return z_values, processed_data

    def _homomorphic_encrypt(self, value: int) -> int:
        """同态加密：简单的加法同态加密模拟"""
        # 这里使用简化的Paillier加密方案思想
        return (value * self.he_public_key + self.he_private_key) % (10 ** 18)

    def decrypt(self, encrypted_sum: int) -> int:
        """解密同态加密的结果"""
        # 简化的解密过程
        return (encrypted_sum - self.he_private_key) // self.he_public_key


def run_protocol(p1_identifiers: Set[Identifier], p2_identifiers: Dict[Identifier, Value]) -> int:
    """运行整个私有交集和协议"""
    # 初始化参与方
    p1 = Party1(p1_identifiers)
    p2 = Party2(p2_identifiers)

    # 第一轮：P1发送数据给P2
    p1_data = p1.round1()

    # 第二轮：P2处理并返回数据
    z_values, p2_data = p2.round2(p1_data)
    p1.receive_z_values(z_values)

    # 第三轮：P1计算加密的交集和并发送给P2
    encrypted_sum = p1.round3(p2_data)

    # 解密得到结果
    result = p2.decrypt(encrypted_sum)

    return result


if __name__ == "__main__":
    # P1的标识符集合
    p1_ids = {"alice", "bob", "charlie", "david"}

    # P2的标识符及其对应的值
    p2_ids = {
        "bob": 100,
        "charlie": 200,
        "david": 300,
        "eve": 400
    }

    # 计算交集和：预期结果是100 + 200 + 300 = 600
    result = run_protocol(p1_ids, p2_ids)
    print(f"私有交集和的结果: {result}")
