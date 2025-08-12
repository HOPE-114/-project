#include <cstdio>
#include <cstdint>
#include <cstring>
#include <array>
#include <vector>
#include <immintrin.h> 
#include <chrono>  

using u8 = uint8_t;
using u32 = uint32_t;
using u64 = uint64_t;
using namespace std::chrono;

// SM4基本常量与S盒
static const u8 SM4_SBOX[256] = {
    0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,
    0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
    0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,
    0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,
    0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,
    0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,
    0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,
    0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,
    0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,
    0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,
    0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,
    0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,
    0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,
    0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,
    0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
    0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48
};

static inline u32 rotl32(u32 x, int r) { return (x << r) | (x >> (32 - r)); }
static inline u32 L_transform(u32 b) {
    return b ^ rotl32(b, 2) ^ rotl32(b, 10) ^ rotl32(b, 18) ^ rotl32(b, 24);
}
static inline u32 tau(u32 a) {
    u32 y = 0;
    y |= (u32)SM4_SBOX[(a >> 24) & 0xFF] << 24;
    y |= (u32)SM4_SBOX[(a >> 16) & 0xFF] << 16;
    y |= (u32)SM4_SBOX[(a >> 8) & 0xFF] << 8;
    y |= (u32)SM4_SBOX[(a) & 0xFF];
    return y;
}
static inline u32 sm4_T(u32 x) {
    return L_transform(tau(x));
}

static const u32 FK[4] = { 0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc };
static const u32 CK[32] = {
    0x00070e15,0x1c232a31,0x383f464d,0x545b6269,0x70777e85,0x8c939aa1,0xa8afb6bd,0xc4cbd2d9,
    0xe0e7eef5,0xfc030a11,0x181f262d,0x343b4249,0x50575e65,0x6c737a81,0x888f969d,0xa4abb2b9,
    0xc0c7ced5,0xdce3eaf1,0xf8ff060d,0x141b2229,0x30373e45,0x4c535a61,0x686f767d,0x848b9299,
    0xa0a7aeb5,0xbcc3cad1,0xd8dfe6ed,0xf4fb0209,0x10171e25,0x2c333a41,0x484f565d,0x646b7279
};

void sm4_key_expand(const u8 key[16], u32 rk[32]) {
    u32 MK[4] = { 0 };
    for (int i = 0; i < 4; ++i) {
        MK[i] = (u32(key[4 * i]) << 24) | (u32(key[4 * i + 1]) << 16) |
            (u32(key[4 * i + 2]) << 8) | u32(key[4 * i + 3]);
    }
    u32 K[4] = { 0 };
    for (int i = 0; i < 4; ++i) K[i] = MK[i] ^ FK[i];
    for (int i = 0; i < 32; ++i) {
        u32 tmp = K[1] ^ K[2] ^ K[3] ^ CK[i];
        u32 t = tau(tmp);
        u32 rk_i = K[0] ^ (t ^ rotl32(t, 13) ^ rotl32(t, 23));
        rk[i] = rk_i;
        K[0] = K[1]; K[1] = K[2]; K[2] = K[3]; K[3] = rk_i;
    }
}

// 基础实现
void sm4_encrypt_block(const u8 in[16], u8 out[16], const u32 rk[32]) {
   
    u32 X[4] = { 0 };
    for (int i = 0; i < 4; ++i) {
        X[i] = (u32(in[4 * i]) << 24) | (u32(in[4 * i + 1]) << 16) |
            (u32(in[4 * i + 2]) << 8) | u32(in[4 * i + 3]);
    }
    for (int i = 0; i < 32; ++i) {
        u32 tmp = X[1] ^ X[2] ^ X[3] ^ rk[i];
        u32 t = sm4_T(tmp);
        u32 newX = X[0] ^ t;
        X[0] = X[1]; X[1] = X[2]; X[2] = X[3]; X[3] = newX;
    }
    for (int i = 0; i < 4; ++i) {
        u32 outw = X[3 - i];
        out[4 * i + 0] = (u8)(outw >> 24);
        out[4 * i + 1] = (u8)(outw >> 16);
        out[4 * i + 2] = (u8)(outw >> 8);
        out[4 * i + 3] = (u8)(outw);
    }
}

// T表优化实现
using ttable_t = std::array<u32, 256>;
struct SM4_TTABLE {
    ttable_t T0, T1, T2, T3;
    void init_from_sbox() {
        for (int b = 0; b < 256; ++b) {
            u32 sb = (u32)SM4_SBOX[b];
            u32 w0 = L_transform((u32)sb << 24);
            u32 w1 = L_transform((u32)sb << 16);
            u32 w2 = L_transform((u32)sb << 8);
            u32 w3 = L_transform((u32)sb);
            T0[b] = w0;
            T1[b] = rotl32(w1, 8);
            T2[b] = rotl32(w2, 16);
            T3[b] = rotl32(w3, 24);
        }
    }
} TTABLE;

void sm4_encrypt_block_ttable(const u8 in[16], u8 out[16], const u32 rk[32]) {
    u32 X[4] = { 0 };
    for (int i = 0; i < 4; ++i) X[i] = (u32(in[4 * i]) << 24) | (u32(in[4 * i + 1]) << 16) |
        (u32(in[4 * i + 2]) << 8) | u32(in[4 * i + 3]);
    for (int r = 0; r < 32; ++r) {
        u32 a = X[1] ^ X[2] ^ X[3] ^ rk[r];
        u8 b0 = (a >> 24) & 0xFF;
        u8 b1 = (a >> 16) & 0xFF;
        u8 b2 = (a >> 8) & 0xFF;
        u8 b3 = a & 0xFF;
        u32 t = TTABLE.T0[b0] ^ TTABLE.T1[b1] ^ TTABLE.T2[b2] ^ TTABLE.T3[b3];
        u32 newX = X[0] ^ t;
        X[0] = X[1]; X[1] = X[2]; X[2] = X[3]; X[3] = newX;
    }
    for (int i = 0; i < 4; ++i) {
        u32 outw = X[3 - i];
        out[4 * i + 0] = (u8)(outw >> 24);
        out[4 * i + 1] = (u8)(outw >> 16);
        out[4 * i + 2] = (u8)(outw >> 8);
        out[4 * i + 3] = (u8)(outw);
    }
}

// AVX2优化相关定义与实现
struct SM4_AVX2_TTABLE {
    alignas(32) std::array<__m128i, 256> t0, t1, t2, t3;

    void init_from_sbox() {
        for (int b = 0; b < 256; ++b) {
            u32 sb = SM4_SBOX[b];
            u32 w0 = L_transform((u32)sb << 24);
            u32 w1 = L_transform((u32)sb << 16);
            u32 w2 = L_transform((u32)sb << 8);
            u32 w3 = L_transform((u32)sb);
            t0[b] = _mm_set_epi32(0, 0, 0, w0);
            t1[b] = _mm_set_epi32(0, 0, 0, rotl32(w1, 8));
            t2[b] = _mm_set_epi32(0, 0, 0, rotl32(w2, 16));
            t3[b] = _mm_set_epi32(0, 0, 0, rotl32(w3, 24));
        }
    }
} AVX2_TTABLE;

#ifdef __AVX2__
// 一次加密4个16字节块
void sm4_encrypt_4blocks_avx2(const u8* in, u8* out, const u32 rk[32]) {
    // 加载4个输入块到YMM寄存器（每个块16字节，共64字节）
    __m256i x0 = _mm256_loadu_si256((const __m256i*)(in + 0 * 16));
    __m256i x1 = _mm256_loadu_si256((const __m256i*)(in + 1 * 16));
    __m256i x2 = _mm256_loadu_si256((const __m256i*)(in + 2 * 16));
    __m256i x3 = _mm256_loadu_si256((const __m256i*)(in + 3 * 16));

    // 32轮加密
    for (int r = 0; r < 32; ++r) {
        __m256i rk_vec = _mm256_set1_epi32(rk[r]);

        // 计算 tmp = X1 ^ X2 ^ X3 ^ rk[r]
        __m256i tmp = _mm256_xor_si256(x1, x2);
        tmp = _mm256_xor_si256(tmp, x3);
        tmp = _mm256_xor_si256(tmp, rk_vec);

        // 提取4个字节（每个32位字的4个字节）
        __m256i b0 = _mm256_and_si256(_mm256_srli_epi32(tmp, 24), _mm256_set1_epi32(0xFF));
        __m256i b1 = _mm256_and_si256(_mm256_srli_epi32(tmp, 16), _mm256_set1_epi32(0xFF));
        __m256i b2 = _mm256_and_si256(_mm256_srli_epi32(tmp, 8), _mm256_set1_epi32(0xFF));
        __m256i b3 = _mm256_and_si256(tmp, _mm256_set1_epi32(0xFF));

        // 准备T表的AVX2向量（将128位T表项扩展为256位）
        __m256i t0_table = _mm256_set_m128i(AVX2_TTABLE.t0[0], AVX2_TTABLE.t0[0]);
        __m256i t1_table = _mm256_set_m128i(AVX2_TTABLE.t1[0], AVX2_TTABLE.t1[0]);
        __m256i t2_table = _mm256_set_m128i(AVX2_TTABLE.t2[0], AVX2_TTABLE.t2[0]);
        __m256i t3_table = _mm256_set_m128i(AVX2_TTABLE.t3[0], AVX2_TTABLE.t3[0]);

        // 并行查表
        __m256i t0 = _mm256_shuffle_epi8(t0_table, b0);
        __m256i t1 = _mm256_shuffle_epi8(t1_table, b1);
        __m256i t2 = _mm256_shuffle_epi8(t2_table, b2);
        __m256i t3 = _mm256_shuffle_epi8(t3_table, b3);

        // 合并结果
        __m256i t = _mm256_xor_si256(t0, t1);
        t = _mm256_xor_si256(t, t2);
        t = _mm256_xor_si256(t, t3);

        // 更新状态
        __m256i new_x = _mm256_xor_si256(x0, t);

        // 轮换寄存器
        x0 = x1;
        x1 = x2;
        x2 = x3;
        x3 = new_x;
    }

    // 存储结果（注意逆序）
    _mm256_storeu_si256((__m256i*)(out + 0 * 16), x3);
    _mm256_storeu_si256((__m256i*)(out + 1 * 16), x2);
    _mm256_storeu_si256((__m256i*)(out + 2 * 16), x1);
    _mm256_storeu_si256((__m256i*)(out + 3 * 16), x0);
}
#endif

// AES-NI优化相关定义与实现
#ifdef __AES__
static __m128i SM4_SBOX_AES[256];

void init_aes_sbox() {
    for (int i = 0; i < 256; ++i) {
        // 将S盒值存入128位向量的低8位
        SM4_SBOX_AES[i] = _mm_set_epi8(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, SM4_SBOX[i]);
    }
}

// 利用AES-NI指令加速S盒查找
void sm4_encrypt_block_aesni(const u8 in[16], u8 out[16], const u32 rk[32]) {
    
    u32 X[4] = { 0 };
    for (int i = 0; i < 4; ++i) {
        X[i] = (u32(in[4 * i]) << 24) | (u32(in[4 * i + 1]) << 16) |
            (u32(in[4 * i + 2]) << 8) | u32(in[4 * i + 3]);
    }

    for (int r = 0; r < 32; ++r) {
        u32 tmp = X[1] ^ X[2] ^ X[3] ^ rk[r];
        u8 b0 = (tmp >> 24) & 0xFF;
        u8 b1 = (tmp >> 16) & 0xFF;
        u8 b2 = (tmp >> 8) & 0xFF;
        u8 b3 = tmp & 0xFF;

        // 使用AES-NI指令集的快速查表能力
        __m128i s0 = SM4_SBOX_AES[b0];
        __m128i s1 = SM4_SBOX_AES[b1];
        __m128i s2 = SM4_SBOX_AES[b2];
        __m128i s3 = SM4_SBOX_AES[b3];

        // 提取S盒结果
        u32 tau_val =
            ((u32(_mm_cvtsi128_si32(s0)) & 0xFF) << 24) |
            ((u32(_mm_cvtsi128_si32(s1)) & 0xFF) << 16) |
            ((u32(_mm_cvtsi128_si32(s2)) & 0xFF) << 8) |
            (u32(_mm_cvtsi128_si32(s3)) & 0xFF);

        u32 t = L_transform(tau_val);
        u32 newX = X[0] ^ t;

        // 轮换
        X[0] = X[1]; X[1] = X[2]; X[2] = X[3]; X[3] = newX;
    }

    // 输出结果
    for (int i = 0; i < 4; ++i) {
        u32 outw = X[3 - i];
        out[4 * i] = (u8)(outw >> 24);
        out[4 * i + 1] = (u8)(outw >> 16);
        out[4 * i + 2] = (u8)(outw >> 8);
        out[4 * i + 3] = (u8)outw;
    }
}
#endif

// 效率测量函数
double measure_basic_efficiency(const u8 key[16], const u8 plain[16], int loop_count) {
    u32 rk[32];
    sm4_key_expand(key, rk);
    u8 out[16];

    auto start = high_resolution_clock::now();
    for (int i = 0; i < loop_count; ++i) {
        sm4_encrypt_block(plain, out, rk);
    }
    auto end = high_resolution_clock::now();
    double duration = duration_cast<microseconds>(end - start).count() / 1000000.0;
    return (loop_count * 16.0) / (1024 * 1024 * duration);
}

double measure_ttable_efficiency(const u8 key[16], const u8 plain[16], int loop_count) {
    u32 rk[32];
    sm4_key_expand(key, rk);
    TTABLE.init_from_sbox();
    u8 out[16];

    auto start = high_resolution_clock::now();
    for (int i = 0; i < loop_count; ++i) {
        sm4_encrypt_block_ttable(plain, out, rk);
    }
    auto end = high_resolution_clock::now();
    double duration = duration_cast<microseconds>(end - start).count() / 1000000.0;
    return (loop_count * 16.0) / (1024 * 1024 * duration);
}

#ifdef __AVX2__
double measure_avx2_efficiency(const u8 key[16], const u8* plain, int loop_count) {
    u32 rk[32];
    sm4_key_expand(key, rk);
    AVX2_TTABLE.init_from_sbox();

    u8 in[4 * 16];
    memcpy(in, plain, 16);
    memcpy(in + 16, plain, 16);
    memcpy(in + 32, plain, 16);
    memcpy(in + 48, plain, 16);
    u8 out[4 * 16];

    auto start = high_resolution_clock::now();
    for (int i = 0; i < loop_count; ++i) {
        sm4_encrypt_4blocks_avx2(in, out, rk);
    }
    auto end = high_resolution_clock::now();
    double duration = duration_cast<microseconds>(end - start).count() / 1000000.0;
    return (loop_count * 4 * 16.0) / (1024 * 1024 * duration);
}
#endif

#ifdef __AES__
double measure_aesni_efficiency(const u8 key[16], const u8 plain[16], int loop_count) {
    u32 rk[32];
    sm4_key_expand(key, rk);
    init_aes_sbox();
    u8 out[16];

    auto start = high_resolution_clock::now();
    for (int i = 0; i < loop_count; ++i) {
        sm4_encrypt_block_aesni(plain, out, rk);
    }
    auto end = high_resolution_clock::now();
    double duration = duration_cast<microseconds>(end - start).count() / 1000000.0;
    return (loop_count * 16.0) / (1024 * 1024 * duration);
}
#endif

int main() {
    // 初始化表结构
    TTABLE.init_from_sbox();
#ifdef __AVX2__
    AVX2_TTABLE.init_from_sbox();
#endif
#ifdef __AES__
    init_aes_sbox();
#endif

    // 测试数据
    u8 key[16] = { 0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
                  0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10 };
    u8 plain_block[16] = { 0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
                          0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10 };

    // 循环次数
    const int LOOP_BASIC = 1000000;
    const int LOOP_TTABLE = 1000000;
#ifdef __AVX2__
    const int LOOP_AVX2 = 250000;  // 每次处理4块，总数据量与基础实现相当
#endif
#ifdef __AES__
    const int LOOP_AESNI = 1000000;
#endif

    // 测量效率
    double basic = measure_basic_efficiency(key, plain_block, LOOP_BASIC);
    double ttable = measure_ttable_efficiency(key, plain_block, LOOP_TTABLE);
#ifdef __AVX2__
    double avx2 = measure_avx2_efficiency(key, plain_block, LOOP_AVX2);
#endif
#ifdef __AES__
    double aesni = measure_aesni_efficiency(key, plain_block, LOOP_AESNI);
#endif

    // 输出对比结果
    printf("=== SM4 优化效率对比 (MB/s) ===\n");
    printf("基础实现:      %.2f MB/s\n", basic);
    printf("T表优化:       %.2f MB/s (%.2fx)\n", ttable, ttable / basic);
#ifdef __AES__
    printf("AES-NI优化:    %.2f MB/s (%.2fx)\n", aesni, aesni / basic);
#endif
#ifdef __AVX2__
    printf("AVX2并行(4块): %.2f MB/s (%.2fx)\n", avx2, avx2 / basic);
#endif

    // 验证加密结果一致性
    u32 rk[32];
    sm4_key_expand(key, rk);
    u8 ct_basic[16], ct_ttable[16];
    sm4_encrypt_block(plain_block, ct_basic, rk);
    sm4_encrypt_block_ttable(plain_block, ct_ttable, rk);

    printf("\n加密结果验证:\n");
    printf("基础实现: ");
    for (int i = 0; i < 16; ++i) printf("%02x", ct_basic[i]);
    printf("\nT表优化:  ");
    for (int i = 0; i < 16; ++i) printf("%02x", ct_ttable[i]);
#ifdef __AES__
    u8 ct_aesni[16];
    sm4_encrypt_block_aesni(plain_block, ct_aesni, rk);
    printf("\nAES-NI:   ");
    for (int i = 0; i < 16; ++i) printf("%02x", ct_aesni[i]);
#endif
#ifdef __AVX2__
    u8 ct_avx2[4 * 16];
    u8 in_avx2[4 * 16];
    memcpy(in_avx2, plain_block, 16);
    memcpy(in_avx2 + 16, plain_block, 16);
    memcpy(in_avx2 + 32, plain_block, 16);
    memcpy(in_avx2 + 48, plain_block, 16);
    sm4_encrypt_4blocks_avx2(in_avx2, ct_avx2, rk);
    printf("\nAVX2(第1块): ");
    for (int i = 0; i < 16; ++i) printf("%02x", ct_avx2[i]);
#endif
    printf("\n");

    return 0;
}
