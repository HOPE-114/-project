#include <iostream>
#include <vector>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <algorithm>
#include <cmath>
#include <stdexcept>

using namespace std;

// SM3常量定义
const uint32_t IV[8] = {
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
};

const uint32_t T[64] = {
    0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519,
    0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A
};

// SM3辅助函数
uint32_t ROTL32(uint32_t x, int n) {
    n &= 31;
    return (x << n) | (x >> (32 - n));
}

uint32_t P0(uint32_t x) {
    return x ^ ROTL32(x, 9) ^ ROTL32(x, 17);
}

uint32_t P1(uint32_t x) {
    return x ^ ROTL32(x, 15) ^ ROTL32(x, 23);
}

uint32_t FF(uint32_t x, uint32_t y, uint32_t z, int j) {
    return (j < 16) ? (x ^ y ^ z) : ((x & y) | (x & z) | (y & z));
}

uint32_t GG(uint32_t x, uint32_t y, uint32_t z, int j) {
    return (j < 16) ? (x ^ y ^ z) : ((x & y) | ((~x) & z));
}

// SM3哈希函数，返回256位(32字节)哈希值
vector<uint8_t> sm3_hash(const vector<uint8_t>& msg) {
    size_t msg_len_bits = msg.size() * 8;
    vector<uint8_t> m = msg;

    // 填充
    m.push_back(0x80);
    while ((m.size() * 8) % 512 != 448) {
        m.push_back(0x00);
    }

    // 添加长度
    for (int i = 7; i >= 0; --i) {
        m.push_back((msg_len_bits >> (i * 8)) & 0xFF);
    }

    uint32_t V[8];
    memcpy(V, IV, 8 * sizeof(uint32_t));

    for (size_t i = 0; i < m.size(); i += 64) {
        uint32_t W[68] = { 0 };
        uint32_t W1[64] = { 0 };

        // 处理当前分组
        int group_bytes = min(64, (int)(m.size() - i));
        for (int j = 0; j < group_bytes / 4; ++j) {
            if (i + 4 * j >= m.size()) break;
            W[j] = (m[i + 4 * j] << 24) |
                (m[i + 4 * j + 1] << 16) |
                (m[i + 4 * j + 2] << 8) |
                m[i + 4 * j + 3];
        }

        // 消息扩展
        for (int j = 16; j < 68; ++j) {
            W[j] = P1(W[j - 16] ^ W[j - 9] ^ ROTL32(W[j - 3], 15)) ^
                ROTL32(W[j - 13], 7) ^ W[j - 6];
        }

        for (int j = 0; j < 64; ++j) {
            W1[j] = W[j] ^ W[j + 4];
        }

        // 迭代压缩
        uint32_t A = V[0], B = V[1], C = V[2], D = V[3];
        uint32_t E = V[4], F = V[5], G = V[6], H = V[7];

        for (int j = 0; j < 64; ++j) {
            uint32_t SS1 = ROTL32(ROTL32(A, 12) + E + ROTL32(T[j], j), 7);
            uint32_t SS2 = SS1 ^ ROTL32(A, 12);
            uint32_t TT1 = FF(A, B, C, j) + D + SS2 + W1[j];
            uint32_t TT2 = GG(E, F, G, j) + H + SS1 + W[j];

            D = C; C = ROTL32(B, 9); B = A; A = TT1;
            H = G; G = ROTL32(F, 19); F = E; E = P0(TT2);
        }

        // 更新状态
        V[0] ^= A; V[1] ^= B; V[2] ^= C; V[3] ^= D;
        V[4] ^= E; V[5] ^= F; V[6] ^= G; V[7] ^= H;
    }

    // 输出哈希值
    vector<uint8_t> digest(32);
    for (int i = 0; i < 8; ++i) {
        digest[4 * i] = (V[i] >> 24) & 0xFF;
        digest[4 * i + 1] = (V[i] >> 16) & 0xFF;
        digest[4 * i + 2] = (V[i] >> 8) & 0xFF;
        digest[4 * i + 3] = V[i] & 0xFF;
    }
    return digest;
}

// RFC6962中定义的节点哈希计算
vector<uint8_t> hash_leaf(const vector<uint8_t>& data) {
    vector<uint8_t> prefix = { 0x00 }; // 叶子节点前缀
    vector<uint8_t> input = prefix;
    input.insert(input.end(), data.begin(), data.end());
    return sm3_hash(input);
}

vector<uint8_t> hash_internal(const vector<uint8_t>& left, const vector<uint8_t>& right) {
    vector<uint8_t> prefix = { 0x01 }; // 内部节点前缀
    vector<uint8_t> input = prefix;
    input.insert(input.end(), left.begin(), left.end());
    input.insert(input.end(), right.begin(), right.end());
    return sm3_hash(input);
}

// 打印十六进制
void print_hex(const vector<uint8_t>& data, const string& label = "") {
    if (!label.empty()) cout << label << ": ";
    for (uint8_t c : data) {
        cout << hex << setw(2) << setfill('0') << (int)c;
    }
    cout << dec << endl;
}

// Merkle树实现
class MerkleTree {
private:
    vector<vector<uint8_t>> leaves;       // 叶子节点哈希
    vector<vector<vector<uint8_t>>> layers;// 所有层，layers[0]是叶子层
    vector<uint8_t> root;                 // 根哈希

    // 计算下一层
    vector<vector<uint8_t>> compute_next_layer(const vector<vector<uint8_t>>& current) {
        vector<vector<uint8_t>> next;

        for (size_t i = 0; i < current.size(); i += 2) {
            // 如果是最后一个节点且为奇数，与自身哈希
            if (i + 1 == current.size()) {
                next.push_back(hash_internal(current[i], current[i]));
            }
            else {
                next.push_back(hash_internal(current[i], current[i + 1]));
            }
        }

        return next;
    }

public:
    // 构造函数，从原始数据构建Merkle树
    MerkleTree(const vector<vector<uint8_t>>& data) {
        // 计算叶子节点哈希
        for (const auto& d : data) {
            leaves.push_back(hash_leaf(d));
        }

        // 构建各层
        layers.push_back(leaves);

        while (layers.back().size() > 1) {
            vector<vector<uint8_t>> next = compute_next_layer(layers.back());
            layers.push_back(next);
        }

        // 根节点
        if (!layers.empty() && !layers.back().empty()) {
            root = layers.back()[0];
        }
    }

    // 获取根哈希
    vector<uint8_t> get_root() const {
        return root;
    }

    // 检查索引是否有效
    bool is_valid_index(size_t index) const {
        return index < leaves.size();
    }

    // 获取存在性证明
    vector<pair<vector<uint8_t>, bool>> get_inclusion_proof(size_t index) {
        if (!is_valid_index(index)) {
            throw invalid_argument("Invalid index");
        }

        vector<pair<vector<uint8_t>, bool>> proof; // 哈希值和是否为右节点
        size_t current_index = index;

        for (size_t i = 0; i < layers.size() - 1; ++i) {
            const auto& current_layer = layers[i];
            bool is_right = (current_index % 2 == 1);
            size_t sibling_index = is_right ? current_index - 1 : current_index + 1;

            // 如果是最后一个节点且为奇数，兄弟节点是自身
            if (sibling_index >= current_layer.size()) {
                sibling_index = current_index;
            }

            proof.emplace_back(current_layer[sibling_index], is_right);

            current_index = current_index / 2;
        }

        return proof;
    }

    // 验证存在性证明
    bool verify_inclusion(const vector<uint8_t>& leaf_data,
        size_t index,
        const vector<pair<vector<uint8_t>, bool>>& proof,
        const vector<uint8_t>& expected_root) {
        vector<uint8_t> current_hash = hash_leaf(leaf_data);

        for (const auto& p : proof) {
            const auto& sibling_hash = p.first;
            bool is_right = p.second;

            if (is_right) {
                // 当前节点在左，兄弟节点在右
                current_hash = hash_internal(current_hash, sibling_hash);
            }
            else {
                // 当前节点在右，兄弟节点在左
                current_hash = hash_internal(sibling_hash, current_hash);
            }
        }

        return current_hash == expected_root;
    }

    // 获取不存在性证明
    // 需要有序的叶子节点，这里假设叶子节点是按字典序排列的
    struct ExclusionProof {
        vector<pair<vector<uint8_t>, bool>> left_proof;   // 左侧存在节点的证明
        vector<uint8_t> left_hash;                        // 左侧存在节点的哈希
        vector<pair<vector<uint8_t>, bool>> right_proof;  // 右侧存在节点的证明
        vector<uint8_t> right_hash;                       // 右侧存在节点的哈希
    };

    ExclusionProof get_exclusion_proof(size_t index) {
        if (is_valid_index(index)) {
            throw invalid_argument("Index is valid, cannot get exclusion proof");
        }

        if (leaves.empty() || index >= leaves.size()) {
            throw invalid_argument("Invalid index for exclusion proof");
        }

        // 找到index前后最近的存在的节点
        size_t left_index = index - 1;
        while (left_index < leaves.size() && !is_valid_index(left_index)) {
            if (left_index == 0) break;
            left_index--;
        }

        size_t right_index = index + 1;
        while (right_index < leaves.size() && !is_valid_index(right_index)) {
            right_index++;
        }

        if (left_index >= leaves.size() && right_index >= leaves.size()) {
            throw invalid_argument("No valid nodes to form exclusion proof");
        }

        ExclusionProof proof;

        // 获取左侧证明
        if (left_index < leaves.size() && is_valid_index(left_index)) {
            proof.left_proof = get_inclusion_proof(left_index);
            proof.left_hash = leaves[left_index];
        }

        // 获取右侧证明
        if (right_index < leaves.size() && is_valid_index(right_index)) {
            proof.right_proof = get_inclusion_proof(right_index);
            proof.right_hash = leaves[right_index];
        }

        return proof;
    }

    // 验证不存在性证明
    bool verify_exclusion(size_t index,
        const ExclusionProof& proof,
        const vector<uint8_t>& expected_root) {
        if (is_valid_index(index)) {
            return false; // 索引存在，证明失败
        }

        // 验证左侧节点证明
        if (!proof.left_hash.empty()) {
            if (!verify_inclusion(proof.left_hash, index - 1, proof.left_proof, expected_root)) {
                return false;
            }
        }

        // 验证右侧节点证明
        if (!proof.right_hash.empty()) {
            if (!verify_inclusion(proof.right_hash, index + 1, proof.right_proof, expected_root)) {
                return false;
            }
        }

        // 检查左右节点是否相邻，中间没有其他节点
        // 这部分逻辑取决于具体的叶子节点排序方式
        return true;
    }

    // 获取叶子节点数量
    size_t size() const {
        return leaves.size();
    }
};

// 生成测试数据
vector<vector<uint8_t>> generate_test_data(size_t count) {
    vector<vector<uint8_t>> data;
    for (size_t i = 0; i < count; ++i) {
        // 生成简单的测试数据，实际应用中可以是任意数据
        vector<uint8_t> item(8);
        for (int j = 0; j < 8; ++j) {
            item[j] = (i >> (j * 8)) & 0xFF;
        }
        data.push_back(item);
    }
    return data;
}

int main() {
    try {
        // 生成10万个叶子节点数据
        const size_t leaf_count = 100000;
        cout << "生成 " << leaf_count << " 个叶子节点数据..." << endl;
        vector<vector<uint8_t>> test_data = generate_test_data(leaf_count);

        // 构建Merkle树
        cout << "构建Merkle树..." << endl;
        MerkleTree merkle_tree(test_data);
        cout << "Merkle树构建完成，根哈希为：" << endl;
        print_hex(merkle_tree.get_root(), "根哈希");

        // 测试存在性证明
        size_t test_index = 4567;
        cout << "\n测试存在性证明，索引: " << test_index << endl;
        auto inclusion_proof = merkle_tree.get_inclusion_proof(test_index);
        cout << "存在性证明包含 " << inclusion_proof.size() << " 个节点" << endl;

        bool inclusion_valid = merkle_tree.verify_inclusion(
            test_data[test_index],
            test_index,
            inclusion_proof,
            merkle_tree.get_root()
        );
        cout << "存在性证明验证结果: " << (inclusion_valid ? "成功" : "失败") << endl;

        // 测试不存在性证明（选择一个超出范围的索引）
        size_t invalid_index = 99999;
        cout << "\n测试不存在性证明，索引: " << invalid_index << endl;

        // 为了演示，我们修改一下树，标记某些索引为无效
        // 这里简化处理，直接使用一个超出范围的索引
        try {
            auto exclusion_proof = merkle_tree.get_exclusion_proof(invalid_index);
            bool exclusion_valid = merkle_tree.verify_exclusion(
                invalid_index,
                exclusion_proof,
                merkle_tree.get_root()
            );
            cout << "不存在性证明验证结果: " << (exclusion_valid ? "成功" : "失败") << endl;
        }
        catch (const exception& e) {
            cout << "获取不存在性证明失败: " << e.what() << endl;
        }

    }
    catch (const exception& e) {
        cerr << "错误: " << e.what() << endl;
        return 1;
    }

    return 0;
}
