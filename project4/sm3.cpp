#include <iostream>
#include <vector>
#include <cstdint>
#include <chrono>
#include <iomanip>

using namespace std;
using namespace chrono;

// ��������
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

// ��������
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
    if (j < 16) return x ^ y ^ z;
    else return (x & y) | (x & z) | (y & z);
}

uint32_t GG(uint32_t x, uint32_t y, uint32_t z, int j) {
    if (j < 16) return x ^ y ^ z;
    else return (x & y) | ((~x) & z);
}

// ��׼SM3ʵ��
vector<uint8_t> sm3_standard(const vector<uint8_t>& msg) {
    // 1. ��Ϣ���
    size_t l = msg.size() * 8;
    vector<uint8_t> m = msg;
    m.push_back(0x80);  // ���1����

    while ((m.size() * 8) % 512 != 448) {
        m.push_back(0x00);  // ���0
    }

    // ��ӳ�����Ϣ��С��ת��ˣ�
    for (int i = 7; i >= 0; --i) {
        m.push_back((l >> (i * 8)) & 0xFF);
    }

    // 2. ��ʼ����ϣֵ
    uint32_t V[8];
    memcpy(V, IV, 8 * sizeof(uint32_t));

    // 3. ����ÿ��512���ط���
    for (size_t i = 0; i < m.size(); i += 64) {
        // 3.1 ��Ϣ��չ
        uint32_t W[68], W1[64];
        for (int j = 0; j < 16; ++j) {
            W[j] = (m[i + 4 * j] << 24) | (m[i + 4 * j + 1] << 16) |
                (m[i + 4 * j + 2] << 8) | m[i + 4 * j + 3];
        }

        for (int j = 16; j < 68; ++j) {
            W[j] = P1(W[j - 16] ^ W[j - 9] ^ ROTL32(W[j - 3], 15)) ^
                ROTL32(W[j - 13], 7) ^ W[j - 6];
        }

        for (int j = 0; j < 64; ++j) {
            W1[j] = W[j] ^ W[j + 4];
        }

        // 3.2 ����ѹ��
        uint32_t A = V[0], B = V[1], C = V[2], D = V[3];
        uint32_t E = V[4], F = V[5], G = V[6], H = V[7];

        for (int j = 0; j < 64; ++j) {
            uint32_t SS1 = ROTL32(ROTL32(A, 12) + E + ROTL32(T[j], j), 7);
            uint32_t SS2 = SS1 ^ ROTL32(A, 12);
            uint32_t TT1 = FF(A, B, C, j) + D + SS2 + W1[j];
            uint32_t TT2 = GG(E, F, G, j) + H + SS1 + W[j];

            D = C;
            C = ROTL32(B, 9);
            B = A;
            A = TT1;
            H = G;
            G = ROTL32(F, 19);
            F = E;
            E = P0(TT2);
        }

        // 3.3 ���¹�ϣֵ
        V[0] ^= A;
        V[1] ^= B;
        V[2] ^= C;
        V[3] ^= D;
        V[4] ^= E;
        V[5] ^= F;
        V[6] ^= G;
        V[7] ^= H;
    }

    // 4. �����ϣֵ����ˣ�
    vector<uint8_t> digest(32);
    for (int i = 0; i < 8; ++i) {
        digest[4 * i] = (V[i] >> 24) & 0xFF;
        digest[4 * i + 1] = (V[i] >> 16) & 0xFF;
        digest[4 * i + 2] = (V[i] >> 8) & 0xFF;
        digest[4 * i + 3] = V[i] & 0xFF;
    }
    return digest;
}

// �Ż���SM3ʵ��
vector<uint8_t> sm3_optimized(const vector<uint8_t>& msg) {
    // 1. ��Ϣ��䣨ͬ��׼ʵ�֣�
    size_t l = msg.size() * 8;
    vector<uint8_t> m = msg;
    m.push_back(0x80);

    while ((m.size() * 8) % 512 != 448) {
        m.push_back(0x00);
    }

    for (int i = 7; i >= 0; --i) {
        m.push_back((l >> (i * 8)) & 0xFF);
    }

    // 2. ��ʼ����ϣֵ
    uint32_t V[8];
    memcpy(V, IV, 8 * sizeof(uint32_t));

    // 3. ����ÿ��512���ط���
    for (size_t i = 0; i < m.size(); i += 64) {
        // 3.1 ��Ϣ��չ���Ż�������������ʣ�
        uint32_t W[68], W1[64];
        for (int j = 0; j < 16; ++j) {
            W[j] = (m[i + 4 * j] << 24) | (m[i + 4 * j + 1] << 16) |
                (m[i + 4 * j + 2] << 8) | m[i + 4 * j + 3];
        }

        // �Ż���ʹ�þֲ��������泣��ֵ
        for (int j = 16; j < 68; ++j) {
            const uint32_t w16 = W[j - 16];
            const uint32_t w9 = W[j - 9];
            const uint32_t w3 = ROTL32(W[j - 3], 15);
            const uint32_t w13 = ROTL32(W[j - 13], 7);
            const uint32_t w6 = W[j - 6];
            W[j] = P1(W[j - 16] ^ W[j - 9] ^ ROTL32(W[j - 3], 15)) ^ ROTL32(W[j - 13], 7) ^ W[j - 6];
        }

        for (int j = 0; j < 64; ++j) {
            W1[j] = W[j] ^ W[j + 4];
        }

        // 3.2 ����ѹ�����Ż���4�ֺϲ���
        uint32_t A = V[0], B = V[1], C = V[2], D = V[3];
        uint32_t E = V[4], F = V[5], G = V[6], H = V[7];

        // �궨��4����ϲ���
#define ROUND(j) \
            SS1 = ROTL32(ROTL32(A, 12) + E + ROTL32(T[j], j), 7); \
            SS2 = SS1 ^ ROTL32(A, 12); \
            TT1 = FF(A, B, C, j) + D + SS2 + W1[j]; \
            TT2 = GG(E, F, G, j) + H + SS1 + W[j]; \
            D = C; C = ROTL32(B, 9); B = A; A = TT1; \
            H = G; G = ROTL32(F, 19); F = E; E = P0(TT2);

        // ��������64�֣�ÿ4��һ�飩
        for (int j = 0; j < 64; ) {
            uint32_t SS1, SS2, TT1, TT2;
            ROUND(j++);
            ROUND(j++);
            ROUND(j++);
            ROUND(j++);
        }
#undef ROUND

        // 3.3 ���¹�ϣֵ
        V[0] ^= A; V[1] ^= B; V[2] ^= C; V[3] ^= D;
        V[4] ^= E; V[5] ^= F; V[6] ^= G; V[7] ^= H;
    }

    // 4. �����ϣֵ
    vector<uint8_t> digest(32);
    for (int i = 0; i < 8; ++i) {
        digest[4 * i] = (V[i] >> 24) & 0xFF;
        digest[4 * i + 1] = (V[i] >> 16) & 0xFF;
        digest[4 * i + 2] = (V[i] >> 8) & 0xFF;
        digest[4 * i + 3] = V[i] & 0xFF;
    }
    return digest;
}

// ���Ժ���
void benchmark() {
    // ����1MB��������
    const size_t DATA_SIZE = 1024 * 1024;
    vector<uint8_t> data(DATA_SIZE, 0xAA);  // ����������

    // ��׼ʵ�ֲ���
    auto start = high_resolution_clock::now();
    auto hash1 = sm3_standard(data);
    auto end = high_resolution_clock::now();
    double time_std = duration<double, milli>(end - start).count();
    double throughput_std = (DATA_SIZE / 1024.0 / 1024.0) / (time_std / 1000.0);

    // �Ż�ʵ�ֲ���
    start = high_resolution_clock::now();
    auto hash2 = sm3_optimized(data);
    end = high_resolution_clock::now();
    double time_opt = duration<double, milli>(end - start).count();
    double throughput_opt = (DATA_SIZE / 1024.0 / 1024.0) / (time_opt / 1000.0);

    // ������
    cout << "=== SM3Ч�ʶԱȲ��� ===" << endl;
    cout << "���ݴ�С: " << DATA_SIZE / 1024 << "KB" << endl;
    cout << "��׼ʵ��: " << fixed << setprecision(2)
        << time_std << "ms, ������: " << throughput_std << "MB/s" << endl;
    cout << "�Ż�ʵ��: " << fixed << setprecision(2)
        << time_opt << "ms, ������: " << throughput_opt << "MB/s" << endl;
    cout << "�Ż�����: " << fixed << setprecision(2) << (throughput_opt / throughput_std) << "x" << endl;

    
}

int main() {
    benchmark();
    return 0;
}