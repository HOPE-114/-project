#include <iostream>
#include <vector>
#include <cstdint>
#include <cstring>
#include <iomanip>

using namespace std;

// SM3 常量定义（与标准实现一致）
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

// 辅助函数（与标准实现一致）
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

// 标准 SM3 哈希函数（返回哈希值字节流）
vector<uint8_t> sm3_hash(const vector<uint8_t>& msg) {
    size_t msg_len_bits = msg.size() * 8;
    vector<uint8_t> m = msg;

    // 填充 0x80 和后续的 0x00
    m.push_back(0x80);
    while ((m.size() * 8) % 512 != 448) {
        m.push_back(0x00);
    }

    // 添加原始消息长度（大端，8 字节）
    for (int i = 7; i >= 0; --i) {
        m.push_back((msg_len_bits >> (i * 8)) & 0xFF);
    }

    uint32_t V[8];
    memcpy(V, IV, 8 * sizeof(uint32_t));

    for (size_t i = 0; i < m.size(); i += 64) {
        uint32_t W[68] = { 0 }; // 初始化避免未定义行为
        uint32_t W1[64] = { 0 };

        // 处理当前分组（最多 64 字节）
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

        // 更新哈希状态
        V[0] ^= A; V[1] ^= B; V[2] ^= C; V[3] ^= D;
        V[4] ^= E; V[5] ^= F; V[6] ^= G; V[7] ^= H;
    }

    // 输出最终哈希值
    vector<uint8_t> digest(32);
    for (int i = 0; i < 8; ++i) {
        digest[4 * i] = (V[i] >> 24) & 0xFF;
        digest[4 * i + 1] = (V[i] >> 16) & 0xFF;
        digest[4 * i + 2] = (V[i] >> 8) & 0xFF;
        digest[4 * i + 3] = V[i] & 0xFF;
    }
    return digest;
}

// 从哈希值恢复压缩状态（用于长度扩展攻击）
void hash_to_state(const vector<uint8_t>& hash, uint32_t* state) {
    for (int i = 0; i < 8; ++i) {
        state[i] = (hash[4 * i] << 24) |
            (hash[4 * i + 1] << 16) |
            (hash[4 * i + 2] << 8) |
            hash[4 * i + 3];
    }
}

// 基于已知状态和附加消息执行 SM3 压缩（长度扩展攻击核心）
vector<uint8_t> sm3_extend(const uint32_t* initial_state, size_t original_len_bytes, const vector<uint8_t>& append) {
    size_t original_len_bits = original_len_bytes * 8; // 原始消息的比特长度
    vector<uint8_t> padding;

    // 1. 构造填充部分（与 sm3_hash 逻辑一致）
    padding.push_back(0x80);
    while ((original_len_bytes + padding.size()) * 8 % 512 != 448) {
        padding.push_back(0x00);
    }

    // 添加原始消息长度（大端，8 字节）
    for (int i = 7; i >= 0; --i) {
        padding.push_back((original_len_bits >> (i * 8)) & 0xFF);
    }

    // 2. 拼接填充和附加消息
    vector<uint8_t> attack_msg = padding;
    attack_msg.insert(attack_msg.end(), append.begin(), append.end());

    // 3. 使用初始状态继续 SM3 压缩
    uint32_t V[8];
    memcpy(V, initial_state, 8 * sizeof(uint32_t));

    for (size_t i = 0; i < attack_msg.size(); i += 64) {
        uint32_t W[68] = { 0 };
        uint32_t W1[64] = { 0 };

        // 处理当前分组（最多 64 字节）
        int group_bytes = min(64, (int)(attack_msg.size() - i));
        for (int j = 0; j < group_bytes / 4; ++j) {
            if (i + 4 * j >= attack_msg.size()) break;
            W[j] = (attack_msg[i + 4 * j] << 24) |
                (attack_msg[i + 4 * j + 1] << 16) |
                (attack_msg[i + 4 * j + 2] << 8) |
                attack_msg[i + 4 * j + 3];
        }

        // 消息扩展（与 sm3_hash 一致）
        for (int j = 16; j < 68; ++j) {
            W[j] = P1(W[j - 16] ^ W[j - 9] ^ ROTL32(W[j - 3], 15)) ^
                ROTL32(W[j - 13], 7) ^ W[j - 6];
        }

        for (int j = 0; j < 64; ++j) {
            W1[j] = W[j] ^ W[j + 4];
        }

        // 迭代压缩（与 sm3_hash 一致）
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

    // 输出扩展后的哈希值
    vector<uint8_t> digest(32);
    for (int i = 0; i < 8; ++i) {
        digest[4 * i] = (V[i] >> 24) & 0xFF;
        digest[4 * i + 1] = (V[i] >> 16) & 0xFF;
        digest[4 * i + 2] = (V[i] >> 8) & 0xFF;
        digest[4 * i + 3] = V[i] & 0xFF;
    }
    return digest;
}

// 打印字节流为十六进制
void print_hex(const vector<uint8_t>& data, const string& label) {
    cout << label << ": ";
    for (uint8_t c : data) {
        cout << hex << setw(2) << setfill('0') << (int)c;
    }
    cout << dec << endl;
}

int main() {
    // 原始消息
    vector<uint8_t> original_msg = { 't', 'e', 's', 't', '_', 'm', 's', 'g' }; // "test_msg"
    size_t original_len_bytes = original_msg.size();

    // 计算原始消息的哈希值
    vector<uint8_t> original_hash = sm3_hash(original_msg);
    print_hex(original_hash, "原始消息哈希");

    // 攻击者已知：原始哈希和原始长度，构造扩展哈希
    uint32_t initial_state[8];
    hash_to_state(original_hash, initial_state);

    // 附加消息（攻击者添加的内容）
    vector<uint8_t> append_msg = { '_', 'e', 'x', 't', 'e', 'n', 'd' }; // "_extend"

    // 执行长度扩展攻击
    vector<uint8_t> attack_hash = sm3_extend(initial_state, original_len_bytes, append_msg);
    print_hex(attack_hash, "攻击构造的哈希");

    // 构造真实扩展消息并计算哈希（验证用）
    vector<uint8_t> real_extend_msg = original_msg;

    // 1. 执行与 sm3_extend 相同的填充
    size_t original_len_bits = original_len_bytes * 8;
    real_extend_msg.push_back(0x80);
    while ((real_extend_msg.size() * 8) % 512 != 448) {
        real_extend_msg.push_back(0x00);
    }
    for (int i = 7; i >= 0; --i) {
        real_extend_msg.push_back((original_len_bits >> (i * 8)) & 0xFF);
    }

    // 2. 添加附加消息
    real_extend_msg.insert(real_extend_msg.end(), append_msg.begin(), append_msg.end());

    // 3. 计算真实扩展消息的哈希
    vector<uint8_t> real_extend_hash = sm3_hash(real_extend_msg);
    print_hex(real_extend_hash, "真实扩展消息哈希");

    //// 对比攻击结果与真实结果
    if (attack_hash == real_extend_hash) {
        cout << "长度扩展攻击成功！" << endl;
    }
    else {
        cout << "长度扩展攻击失败！" << endl;
    }
    return 0;
}