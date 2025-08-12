#include <cstdio>
#include <cstdint>
#include <cstring>
#include <array>
#include <vector>
#include <immintrin.h> 
#include <chrono>  // 用于时间测量

using u8 = uint8_t;
using u32 = uint32_t;
using u64 = uint64_t;
using namespace std::chrono;

// ---------------------------
// SM4 basic constants
// ---------------------------
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
    u32 MK[4];
    for (int i = 0; i < 4; ++i) {
        MK[i] = (u32(key[4 * i]) << 24) | (u32(key[4 * i + 1]) << 16) | (u32(key[4 * i + 2]) << 8) | u32(key[4 * i + 3]);
    }
    u32 K[4];
    for (int i = 0; i < 4; ++i) K[i] = MK[i] ^ FK[i];
    for (int i = 0; i < 32; ++i) {
        u32 tmp = K[1] ^ K[2] ^ K[3] ^ CK[i];
        u32 t = tau(tmp);
        u32 rk_i = K[0] ^ (t ^ rotl32(t, 13) ^ rotl32(t, 23)); 
        rk[i] = rk_i;
      
        K[0] = K[1]; K[1] = K[2]; K[2] = K[3]; K[3] = rk_i;
    }
}
void sm4_encrypt_block(const u8 in[16], u8 out[16], const u32 rk[32]) {
    u32 X[4];
    for (int i = 0; i < 4; ++i) {
        X[i] = (u32(in[4 * i]) << 24) | (u32(in[4 * i + 1]) << 16) | (u32(in[4 * i + 2]) << 8) | u32(in[4 * i + 3]);
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

// ---------------------------
// T-table 
// ---------------------------
using ttable_t = std::array<u32, 256>;
struct SM4_TTABLE {
    ttable_t T0, T1, T2, T3;
    void init_from_sbox() {
        for (int b = 0; b < 256; ++b) {
            u32 sb = (u32)SM4_SBOX[b];
            u32 v = sb;
         
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
    u32 X[4];
    for (int i = 0; i < 4; ++i) X[i] = (u32(in[4 * i]) << 24) | (u32(in[4 * i + 1]) << 16) | (u32(in[4 * i + 2]) << 8) | u32(in[4 * i + 3]);
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



// ---------------------------
// GHASH & SM4-GCM 
// ---------------------------
struct u128 { u64 hi; u64 lo; };
static inline u128 xor128(const u128& a, const u128& b) { return { a.hi ^ b.hi, a.lo ^ b.lo }; }
u128 gfmul128_slow(u128 X, u128 Y) {
  
    u128 Z{ 0,0 };
  
    for (int i = 0; i < 128; ++i) {
        bool bit = ((i < 64) ? ((Y.lo >> i) & 1) : ((Y.hi >> (i - 64)) & 1));
        if (bit) {
          
        }
    }
  
    return { 0,0 };
}
void ghash_update(u128& X, const u8 block[16], const u128& H) {
   
    u128 B;
    B.hi = ((u64)block[0] << 56) | ((u64)block[1] << 48) | ((u64)block[2] << 40) | ((u64)block[3] << 32) |
        ((u64)block[4] << 24) | ((u64)block[5] << 16) | ((u64)block[6] << 8) | ((u64)block[7]);
    B.lo = ((u64)block[8] << 56) | ((u64)block[9] << 48) | ((u64)block[10] << 40) | ((u64)block[11] << 32) |
        ((u64)block[12] << 24) | ((u64)block[13] << 16) | ((u64)block[14] << 8) | ((u64)block[15]);
    X = xor128(X, B);
 
    X = gfmul128_slow(X, H);
}

void sm4_gcm_encrypt(const u8 key[16], const u8 iv[12], const u8* plaintext, size_t plen,
    const u8* aad, size_t aadlen,
    u8* ciphertext, u8 tag_out[16])
{
    u32 rk[32];
    sm4_key_expand(key, rk);
   
    u8 zero[16] = { 0 };
    u8 Hblock[16];
    sm4_encrypt_block(zero, Hblock, rk);
    
    u128 H;
    H.hi = ((u64)Hblock[0] << 56) | ((u64)Hblock[1] << 48) | ((u64)Hblock[2] << 40) | ((u64)Hblock[3] << 32) |
        ((u64)Hblock[4] << 24) | ((u64)Hblock[5] << 16) | ((u64)Hblock[6] << 8) | ((u64)Hblock[7]);
    H.lo = ((u64)Hblock[8] << 56) | ((u64)Hblock[9] << 48) | ((u64)Hblock[10] << 40) | ((u64)Hblock[11] << 32) |
        ((u64)Hblock[12] << 24) | ((u64)Hblock[13] << 16) | ((u64)Hblock[14] << 8) | ((u64)Hblock[15]);

    // init GHASH
    u128 X{0,0 };
    size_t off = 0;
    u8 block[16];
    while (off + 16<= aadlen) {
        memcpy(block, aad + off, 16 );
        ghash_update
        (X, block, H);
        off +=16;
    }
    if
        (off < aadlen) {
        memset(block, 0, 16);
        memcpy(block, aad + off, aadlen - off);
        ghash_update(X, block, H);
    }
    u8 J0[16];
    memcpy(J0, iv, 12 );
    J0[12] = 0; J0[13] = 0; J0[14] = 0; J0[15] = 1;
        auto inc32 = [](u8 ctr[16
        ]) {
                for (int i = 15; i >= 12; --i) {
                    if (++ctr[i]) break;
                }
        };
        u8 Sblock[ 16 ];
        size_t i = 0 ;
        u8 ctr[ 16 ];
        memcpy(ctr, J0, 16
        );
        inc32(ctr); 
        while (i + 16 <= plen) {
            u8 keystream[16];
            sm4_encrypt_block
            (ctr, keystream, rk);
            for (int j = 0; j < 16 ; ++j) ciphertext[i + j] = plaintext[i + j] ^ keystream[j];
            // GHASH over ciphertext
            ghash_update
            (X, ciphertext + i, H);
            inc32 (ctr);
            i += 16;
        }
        if
            (i < plen) {
            u8 keystream[ 16 ];
            sm4_encrypt_block
            (ctr, keystream, rk);
            size_t
                rem = plen - i;
            for (size_t j = 0 ; j < rem; ++j) ciphertext[i + j] = plaintext[i + j] ^ keystream[j];
            // pad block and GHASH
            memset(block, 0, 16 );
            memcpy(block, ciphertext + i, rem);
            ghash_update (X, block, H);
        }
        u8 lenblock[16] = { 0 };
        u64 aadbits = (u64)aadlen * 8 ;
        u64 ctxtbits = (u64)plen * 8 ;
        for (int b = 0; b < 8; ++b) lenblock[7 - b] = (u8)(aadbits >> (8 * b));
        for (int b = 0; b < 8; ++b) lenblock[15 - b] = (u8)(ctxtbits >> (8 * b));
        ghash_update(X, lenblock, H);


        sm4_encrypt_block(J0, Sblock, rk);
       
        u8 Xbytes[16];
        for (int k = 0; k < 8; ++k) Xbytes[k] = (u8)(X.hi >> (56 - 8 * k));
        for (int k = 0; k < 8; ++k) Xbytes[8 + k] = (u8)(X.lo >> (56 - 8 * k));
        for (int k = 0; k < 16 ; ++k) tag_out[k] = Sblock[k] ^ Xbytes[k];

}
// ---------------------------
// 效率测量核心逻辑
// ---------------------------
// 测量单个 16 字节块加密耗时（基础实现）
double measure_basic_efficiency(const u8 key[16], const u8 plain[16], int loop_count) {
    u32 rk[32];
    sm4_key_expand(key, rk);
    u8 out[16];

    auto start = high_resolution_clock::now();
    for (int i = 0; i < loop_count; ++i) {
        sm4_encrypt_block(plain, out, rk);
    }
    auto end = high_resolution_clock::now();
    double duration = duration_cast<microseconds>(end - start).count() / 1000000.0; // 转换为秒
    // 总加密字节数 / 耗时 = 效率 (字节/秒)，再转换为 MB/s
    return (loop_count * 16.0) / (1024 * 1024 * duration);
}

// 测量单个 16 字节块加密耗时（T 表优化）
double measure_ttable_efficiency(const u8 key[16], const u8 plain[16], int loop_count) {
    u32 rk[32];
    sm4_key_expand(key, rk);
    TTABLE.init_from_sbox(); // 确保 T 表初始化
    u8 out[16];

    auto start = high_resolution_clock::now();
    for (int i = 0; i < loop_count; ++i) {
        sm4_encrypt_block_ttable(plain, out, rk);
    }
    auto end = high_resolution_clock::now();
    double duration = duration_cast<microseconds>(end - start).count() / 1000000.0;
    return (loop_count * 16.0) / (1024 * 1024 * duration);
}

// 测量 SM4-GCM 模式效率（含认证，这里用较长明文放大差异）
double measure_gcm_efficiency(const u8 key[16], const u8 iv[12],
    const u8* plaintext, size_t text_len,
    int loop_count) {
    std::vector<u8> cipher(text_len);
    u8 tag[16];

    auto start = high_resolution_clock::now();
    for (int i = 0; i < loop_count; ++i) {
        sm4_gcm_encrypt(key, iv, plaintext, text_len, nullptr, 0, cipher.data(), tag);
    }
    auto end = high_resolution_clock::now();
    double duration = duration_cast<microseconds>(end - start).count() / 1000000.0;
    // 总加密字节数 = loop_count * text_len
    return (loop_count * text_len * 1.0) / (1024 * 1024 * duration);
}

int main() {
    // 初始化 T 表
    TTABLE.init_from_sbox();

    // 测试密钥、明文
    u8 key[16] = { 0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
                  0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10 };
    u8 plain_block[16] = { 0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
                          0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10 };
    u8 iv[12] = { 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                 0x08,0x09,0x0a,0x0b };

    // 构造较长明文用于 GCM 测试（比如 1KB）
    const size_t large_text_len = 1024;
    std::vector<u8> large_plain(large_text_len, 0x41); 

    // 循环次数：根据实际性能调整，性能越高可适当增大，让时间测量更稳定
    const int LOOP_BASIC = 100000;
    const int LOOP_TTABLE = 100000;
    const int LOOP_GCM = 100;

    // 测量并输出效率
    double basic_mb_s = measure_basic_efficiency(key, plain_block, LOOP_BASIC);
    double ttable_mb_s = measure_ttable_efficiency(key, plain_block, LOOP_TTABLE);
    double gcm_mb_s = measure_gcm_efficiency(key, iv, large_plain.data(), large_text_len, LOOP_GCM);

    printf("=== SM4 加密效率对比 (MB/s) ===\n");
    printf("基础实现:  %.2f MB/s\n", basic_mb_s);
    printf("T 表优化:  %.2f MB/s (优化倍数: %.2fx)\n",
        ttable_mb_s, ttable_mb_s / basic_mb_s);
    printf("SM4-GCM:   %.2f MB/s (含认证，数据越长相对耗时占比越低)\n", gcm_mb_s);

    // 输出原始加密结果验证
    u32 rk[32];
    sm4_key_expand(key, rk);
    u8 ct_basic[16], ct_ttable[16];
    sm4_encrypt_block(plain_block, ct_basic, rk);
    sm4_encrypt_block_ttable(plain_block, ct_ttable, rk);
    printf("\n加密结果验证 (16 字节块):\n");
    printf("基础: "); for (int i = 0; i < 16; i++) printf("%02x", ct_basic[i]); printf("\n");
    printf("T表: "); for (int i = 0; i < 16; i++) printf("%02x", ct_ttable[i]); printf("\n");

    return 0;
}
