/*
 * This file is part of the BSGS distribution (https://github.com/JeanLucPons/BSGS).
 * Copyright (c) 2020 Jean Luc PONS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <cstdio>
#include <cstring>
#include "SECP256k1.h"
#include "Point.h"
#include "../util.h"
#include "../hash/sha256.h"
#include "../hash/ripemd160.h"

Secp256K1::Secp256K1()
{
}

void Secp256K1::Init()
{
    // Prime for the finite field
    P.SetBase16("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");

    // Set up field
    Int::SetupField(&P);

    // Generator point and order
    G.x.SetBase16("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798");
    G.y.SetBase16("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8");
    G.z.SetInt32(1);
    order.SetBase16("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");

    Int::InitK1(&order);

    // Compute Generator table
    Point N(G);
    for (int i = 0; i < 32; i++)
    {
        GTable[i * 256] = N;
        N = DoubleDirect(N);
        for (int j = 1; j < 255; j++)
        {
            GTable[i * 256 + j] = N;
            N = AddDirect(N, GTable[i * 256]);
        }
        GTable[i * 256 + 255] = N; // Dummy point for check function
    }
}

Secp256K1::~Secp256K1()
{
}

Point Secp256K1::ComputePublicKey(Int *privKey)
{
    int i = 0;
    uint8_t b;
    Point Q;
    Q.Clear();
    // Search first significant byte
    for (i = 0; i < 32; i++)
    {
        b = privKey->GetByte(i);
        if (b)
            break;
    }
    Q = GTable[256 * i + (b - 1)];
    i++;

    for (; i < 32; i++)
    {
        b = privKey->GetByte(i);
        if (b)
            Q = Add2(Q, GTable[256 * i + (b - 1)]);
    }
    Q.Reduce();
    return Q;
}

Point Secp256K1::NextKey(Point &key)
{
    // Input key must be reduced and different from G
    // in order to use AddDirect
    return AddDirect(key, G);
}

uint8_t Secp256K1::GetByte(char *str, int idx)
{
    char tmp[3];
    int val;
    tmp[0] = str[2 * idx];
    tmp[1] = str[2 * idx + 1];
    tmp[2] = 0;
    if (sscanf(tmp, "%X", &val) != 1)
    {
        printf("ParsePublicKeyHex: Error invalid public key specified (unexpected hexadecimal digit)\n");
        exit(-1);
    }
    return (uint8_t)val;
}

bool Secp256K1::ParsePublicKeyHex(char *str, Point &ret, bool &isCompressed)
{
    int len = strlen(str);
    ret.Clear();
    if (len < 2)
    {
        printf("ParsePublicKeyHex: Error invalid public key specified (66 or 130 character length)\n");
        return false;
    }
    uint8_t type = GetByte(str, 0);
    switch (type)
    {
    case 0x02:
        if (len != 66)
        {
            printf("ParsePublicKeyHex: Error invalid public key specified (66 character length)\n");
            return false;
        }
        for (int i = 0; i < 32; i++)
            ret.x.SetByte(31 - i, GetByte(str, i + 1));
        ret.y = GetY(ret.x, true);
        isCompressed = true;
        break;

    case 0x03:
        if (len != 66)
        {
            printf("ParsePublicKeyHex: Error invalid public key specified (66 character length)\n");
            return false;
        }
        for (int i = 0; i < 32; i++)
            ret.x.SetByte(31 - i, GetByte(str, i + 1));
        ret.y = GetY(ret.x, false);
        isCompressed = true;
        break;

    case 0x04:
        if (len != 130)
        {
            printf("ParsePublicKeyHex: Error invalid public key specified (130 character length)\n");
            exit(-1);
        }
        for (int i = 0; i < 32; i++)
            ret.x.SetByte(31 - i, GetByte(str, i + 1));
        for (int i = 0; i < 32; i++)
            ret.y.SetByte(31 - i, GetByte(str, i + 33));
        isCompressed = false;
        break;

    default:
        printf("ParsePublicKeyHex: Error invalid public key specified (Unexpected prefix (only 02,03 or 04 allowed)\n");
        return false;
    }

    ret.z.SetInt32(1);

    if (!EC(ret))
    {
        printf("ParsePublicKeyHex: Error invalid public key specified (Not lie on elliptic curve)\n");
        return false;
    }

    return true;
}

char *Secp256K1::GetPublicKeyHex(bool compressed, Point &pubKey)
{
    unsigned char publicKeyBytes[65];
    char *ret = NULL;
    if (!compressed)
    {
        // Uncompressed public key
        publicKeyBytes[0] = 0x4;
        pubKey.x.Get32Bytes(publicKeyBytes + 1);
        pubKey.y.Get32Bytes(publicKeyBytes + 33);
        ret = (char *)tohex((char *)publicKeyBytes, 65);
    }
    else
    {
        // Compressed public key
        publicKeyBytes[0] = pubKey.y.IsEven() ? 0x2 : 0x3;
        pubKey.x.Get32Bytes(publicKeyBytes + 1);
        ret = (char *)tohex((char *)publicKeyBytes, 33);
    }
    return ret;
}

void Secp256K1::GetPublicKeyHex(bool compressed, Point &pubKey, char *dst)
{
    unsigned char publicKeyBytes[65];
    if (!compressed)
    {
        // Uncompressed public key
        publicKeyBytes[0] = 0x4;
        pubKey.x.Get32Bytes(publicKeyBytes + 1);
        pubKey.y.Get32Bytes(publicKeyBytes + 33);
        tohex_dst((char *)publicKeyBytes, 65, dst);
    }
    else
    {
        // Compressed public key
        publicKeyBytes[0] = pubKey.y.IsEven() ? 0x2 : 0x3;
        pubKey.x.Get32Bytes(publicKeyBytes + 1);
        tohex_dst((char *)publicKeyBytes, 33, dst);
    }
}

char *Secp256K1::GetPublicKeyRaw(bool compressed, Point &pubKey)
{
    char *ret = (char *)malloc(65);
    if (ret == NULL)
    {
        ::fprintf(stderr, "Can't alloc memory\n");
        exit(0);
    }
    if (!compressed)
    {
        // Uncompressed public key
        ret[0] = 0x4;
        pubKey.x.Get32Bytes((unsigned char *)(ret + 1));
        pubKey.y.Get32Bytes((unsigned char *)(ret + 33));
    }
    else
    {
        // Compressed public key
        ret[0] = pubKey.y.IsEven() ? 0x2 : 0x3;
        pubKey.x.Get32Bytes((unsigned char *)(ret + 1));
    }
    return ret;
}

void Secp256K1::GetPublicKeyRaw(bool compressed, Point &pubKey, char *dst)
{
    if (!compressed)
    {
        // Uncompressed public key
        dst[0] = 0x4;
        pubKey.x.Get32Bytes((unsigned char *)(dst + 1));
        pubKey.y.Get32Bytes((unsigned char *)(dst + 33));
    }
    else
    {
        // Compressed public key
        dst[0] = pubKey.y.IsEven() ? 0x2 : 0x3;
        pubKey.x.Get32Bytes((unsigned char *)(dst + 1));
    }
}

Point Secp256K1::AddDirect(Point &p1, Point &p2)
{
    // Optimized version that assumes inputs are normalized
    Int s;
    Int dx;
    Int dy;
    Point r;
    r.z.SetInt32(1);

    // Optimized slope calculation
    dy.ModSub(&p2.y, &p1.y);
    dx.ModSub(&p2.x, &p1.x);
    dx.ModInv();
    s.ModMulK1(&dy, &dx);

    // Optimized point calculation
    Int s2;
    s2.ModSquareK1(&s);
    r.x.ModSub(&s2, &p1.x);
    r.x.ModSub(&p2.x);

    // Calculate y coordinate
    Int temp;
    temp.ModSub(&p1.x, &r.x);
    temp.ModMulK1(&s);
    r.y.ModSub(&temp, &p1.y);

    return r;
}

Point Secp256K1::Add2(Point &p1, Point &p2)
{
    // P2.z = 1
    Int u;
    Int v;
    Int u1;
    Int v1;
    Int vs2;
    Int vs3;
    Int us2;
    Int a;
    Int us2w;
    Int vs2v2;
    Int vs3u2;
    Int _2vs2v2;
    Point r;
    u1.ModMulK1(&p2.y, &p1.z);
    v1.ModMulK1(&p2.x, &p1.z);
    u.ModSub(&u1, &p1.y);
    v.ModSub(&v1, &p1.x);
    us2.ModSquareK1(&u);
    vs2.ModSquareK1(&v);
    vs3.ModMulK1(&vs2, &v);
    us2w.ModMulK1(&us2, &p1.z);
    vs2v2.ModMulK1(&vs2, &p1.x);
    _2vs2v2.ModAdd(&vs2v2, &vs2v2);
    a.ModSub(&us2w, &vs3);
    a.ModSub(&_2vs2v2);

    r.x.ModMulK1(&v, &a);

    vs3u2.ModMulK1(&vs3, &p1.y);
    r.y.ModSub(&vs2v2, &a);
    r.y.ModMulK1(&r.y, &u);
    r.y.ModSub(&vs3u2);

    r.z.ModMulK1(&vs3, &p1.z);

    return r;
}

Point Secp256K1::Add(Point &p1, Point &p2)
{
    // Handle infinity cases
    if (p1.isZero())
    {
        Point result(p2);
        return result;
    }
    if (p2.isZero())
    {
        Point result(p1);
        return result;
    }

    // Check for point and its negative
    Point neg2 = Negation(p2);
    if (p1.equals(neg2))
    {
        Point result;
        result.setInfinity(); // Return infinity point
        return result;
    }

    // Check if points are the same
    if (p1.equals(p2))
    {
        return Double(p1);
    }

    // Regular point addition
    Point result;

    // Ensure points are normalized
    Point p1n(p1);
    Point p2n(p2);
    p1n.Reduce();
    p2n.Reduce();

    // Calculate slope = (y2-y1)/(x2-x1)
    Int slope;
    Int temp;
    temp.ModSub(&p2n.y, &p1n.y);
    Int dx;
    dx.ModSub(&p2n.x, &p1n.x);
    dx.ModInv();
    slope.ModMulK1(&temp, &dx);

    // x3 = slope² - x1 - x2
    result.x.ModSquareK1(&slope);
    result.x.ModSub(&p1n.x);
    result.x.ModSub(&p2n.x);

    // y3 = slope(x1 - x3) - y1
    temp.ModSub(&p1n.x, &result.x);
    temp.ModMulK1(&slope);
    result.y.ModSub(&temp, &p1n.y);

    result.z.SetInt32(1);
    return result;
}

Point Secp256K1::Double(Point &p)
{
    if (p.isZero())
    {
        return p;
    }

    // Optimized point doubling
    Int _2y;
    Int _3x2;
    Int s;
    Point r;
    r.z.SetInt32(1);

    // Calculate 2y
    _2y.ModAdd(&p.y, &p.y);
    _2y.ModInv();

    // Calculate 3x^2
    _3x2.ModSquareK1(&p.x);
    Int temp;
    temp.Set(&_3x2);
    _3x2.ModAdd(&temp);
    _3x2.ModAdd(&temp);

    // Calculate slope
    s.ModMulK1(&_3x2, &_2y);

    // Calculate new x
    r.x.ModSquareK1(&s);
    temp.ModAdd(&p.x, &p.x);
    r.x.ModSub(&temp);

    // Calculate new y
    temp.ModSub(&p.x, &r.x);
    temp.ModMulK1(&s);
    r.y.ModSub(&temp, &p.y);

    return r;
}

Point Secp256K1::Negation(Point &p)
{
    // Optimized for normalized points (z=1)
    // Used frequently in subtraction operations
    Point result;

    // Direct coordinate copy
    result.x = p.x;
    result.y = p.y;
    result.y.ModNeg(); // Single negation operation
    result.z.SetInt32(1);

    return result;
}

Point Secp256K1::DoubleDirect(Point &p)
{
    Int _s;
    Int _p;
    Int a;
    Point r;
    r.z.SetInt32(1);
    _s.ModMulK1(&p.x, &p.x);
    _p.ModAdd(&_s, &_s);
    _p.ModAdd(&_s);

    a.ModAdd(&p.y, &p.y);
    a.ModInv();
    _s.ModMulK1(&_p, &a); // s = (3*pow2(p.x))*inverse(2*p.y);

    _p.ModMulK1(&_s, &_s);
    a.ModAdd(&p.x, &p.x);
    a.ModNeg();
    r.x.ModAdd(&a, &_p); // rx = pow2(s) + neg(2*p.x);

    a.ModSub(&r.x, &p.x);

    _p.ModMulK1(&a, &_s);
    r.y.ModAdd(&_p, &p.y);
    r.y.ModNeg(); // ry = neg(p.y + s*(ret.x+neg(p.x)));
    return r;
}

Int Secp256K1::GetY(Int x, bool isEven)
{
    Int _s;
    Int _p;
    _s.ModSquareK1(&x);
    _p.ModMulK1(&_s, &x);
    _p.ModAdd(7);
    _p.ModSqrt();
    if (!_p.IsEven() && isEven)
    {
        _p.ModNeg();
    }
    else if (_p.IsEven() && !isEven)
    {
        _p.ModNeg();
    }
    return _p;
}

bool Secp256K1::EC(Point &p)
{
    Int _s;
    Int _p;
    _s.ModSquareK1(&p.x);
    _p.ModMulK1(&_s, &p.x);
    _p.ModAdd(7);
    _s.ModMulK1(&p.y, &p.y);
    _s.ModSub(&_p);
    return _s.IsZero(); // ( ((pow2(y) - (pow3(x) + 7)) % P) == 0 );
}

Point Secp256K1::ScalarMultiplication(Point &P, Int *scalar, bool debug)
{
    // Handle zero scalar
    if (scalar->IsZero())
    {
        Point result;
        result.Clear();
        return result;
    }

    // Use precomputed table for G point multiplication
    if (P.equals(G))
    {
        return ComputePublicKey(scalar);
    }

    // Window size optimization for non-G points
    const int WINDOW_SIZE = 4;
    const int TABLE_SIZE = 1 << WINDOW_SIZE;
    Point precomp[16]; // 2^4 = 16 for window size 4

    // Build precomputation table
    precomp[0] = P;
    Point doubled = Double(P);
    for (int i = 1; i < TABLE_SIZE; i++)
    {
        precomp[i] = AddDirect(precomp[i - 1], P);
    }

    Point result;
    result.Clear();

    int bits = scalar->GetBitLength();
    int window = 0;
    int window_bits = 0;

    for (int i = bits - 1; i >= 0; i--)
    {
        if (!result.isZero())
        {
            result = Double(result);
        }

        // Collect bits for window
        window = (window << 1) | scalar->GetBit(i);
        window_bits++;

        if (window_bits == WINDOW_SIZE || i == 0)
        {
            if (window > 0)
            {
                result = window == 1 ? Add(result, P) : Add(result, precomp[window - 1]);
            }
            window = 0;
            window_bits = 0;
        }
    }

    return result;
}

#define KEYBUFFCOMP(buff, p)                                                    \
    (buff)[0] = ((p).x.bits[7] >> 8) | ((uint32_t)(0x2 + (p).y.IsOdd()) << 24); \
    (buff)[1] = ((p).x.bits[6] >> 8) | ((p).x.bits[7] << 24);                   \
    (buff)[2] = ((p).x.bits[5] >> 8) | ((p).x.bits[6] << 24);                   \
    (buff)[3] = ((p).x.bits[4] >> 8) | ((p).x.bits[5] << 24);                   \
    (buff)[4] = ((p).x.bits[3] >> 8) | ((p).x.bits[4] << 24);                   \
    (buff)[5] = ((p).x.bits[2] >> 8) | ((p).x.bits[3] << 24);                   \
    (buff)[6] = ((p).x.bits[1] >> 8) | ((p).x.bits[2] << 24);                   \
    (buff)[7] = ((p).x.bits[0] >> 8) | ((p).x.bits[1] << 24);                   \
    (buff)[8] = 0x00800000 | ((p).x.bits[0] << 24);                             \
    (buff)[9] = 0;                                                              \
    (buff)[10] = 0;                                                             \
    (buff)[11] = 0;                                                             \
    (buff)[12] = 0;                                                             \
    (buff)[13] = 0;                                                             \
    (buff)[14] = 0;                                                             \
    (buff)[15] = 0x108;

#define KEYBUFFUNCOMP(buff, p)                                 \
    (buff)[0] = ((p).x.bits[7] >> 8) | 0x04000000;             \
    (buff)[1] = ((p).x.bits[6] >> 8) | ((p).x.bits[7] << 24);  \
    (buff)[2] = ((p).x.bits[5] >> 8) | ((p).x.bits[6] << 24);  \
    (buff)[3] = ((p).x.bits[4] >> 8) | ((p).x.bits[5] << 24);  \
    (buff)[4] = ((p).x.bits[3] >> 8) | ((p).x.bits[4] << 24);  \
    (buff)[5] = ((p).x.bits[2] >> 8) | ((p).x.bits[3] << 24);  \
    (buff)[6] = ((p).x.bits[1] >> 8) | ((p).x.bits[2] << 24);  \
    (buff)[7] = ((p).x.bits[0] >> 8) | ((p).x.bits[1] << 24);  \
    (buff)[8] = ((p).y.bits[7] >> 8) | ((p).x.bits[0] << 24);  \
    (buff)[9] = ((p).y.bits[6] >> 8) | ((p).y.bits[7] << 24);  \
    (buff)[10] = ((p).y.bits[5] >> 8) | ((p).y.bits[6] << 24); \
    (buff)[11] = ((p).y.bits[4] >> 8) | ((p).y.bits[5] << 24); \
    (buff)[12] = ((p).y.bits[3] >> 8) | ((p).y.bits[4] << 24); \
    (buff)[13] = ((p).y.bits[2] >> 8) | ((p).y.bits[3] << 24); \
    (buff)[14] = ((p).y.bits[1] >> 8) | ((p).y.bits[2] << 24); \
    (buff)[15] = ((p).y.bits[0] >> 8) | ((p).y.bits[1] << 24); \
    (buff)[16] = 0x00800000 | ((p).y.bits[0] << 24);           \
    (buff)[17] = 0;                                            \
    (buff)[18] = 0;                                            \
    (buff)[19] = 0;                                            \
    (buff)[20] = 0;                                            \
    (buff)[21] = 0;                                            \
    (buff)[22] = 0;                                            \
    (buff)[23] = 0;                                            \
    (buff)[24] = 0;                                            \
    (buff)[25] = 0;                                            \
    (buff)[26] = 0;                                            \
    (buff)[27] = 0;                                            \
    (buff)[28] = 0;                                            \
    (buff)[29] = 0;                                            \
    (buff)[30] = 0;                                            \
    (buff)[31] = 0x208;

#define KEYBUFFSCRIPT(buff, h)                                                                          \
    (buff)[0] = 0x00140000 | (uint32_t)h[0] << 8 | (uint32_t)h[1];                                      \
    (buff)[1] = (uint32_t)h[2] << 24 | (uint32_t)h[3] << 16 | (uint32_t)h[4] << 8 | (uint32_t)h[5];     \
    (buff)[2] = (uint32_t)h[6] << 24 | (uint32_t)h[7] << 16 | (uint32_t)h[8] << 8 | (uint32_t)h[9];     \
    (buff)[3] = (uint32_t)h[10] << 24 | (uint32_t)h[11] << 16 | (uint32_t)h[12] << 8 | (uint32_t)h[13]; \
    (buff)[4] = (uint32_t)h[14] << 24 | (uint32_t)h[15] << 16 | (uint32_t)h[16] << 8 | (uint32_t)h[17]; \
    (buff)[5] = (uint32_t)h[18] << 24 | (uint32_t)h[19] << 16 | 0x8000;                                 \
    (buff)[6] = 0;                                                                                      \
    (buff)[7] = 0;                                                                                      \
    (buff)[8] = 0;                                                                                      \
    (buff)[9] = 0;                                                                                      \
    (buff)[10] = 0;                                                                                     \
    (buff)[11] = 0;                                                                                     \
    (buff)[12] = 0;                                                                                     \
    (buff)[13] = 0;                                                                                     \
    (buff)[14] = 0;                                                                                     \
    (buff)[15] = 0xB0;

void Secp256K1::GetHash160(int type, bool compressed,
                           Point &k0, Point &k1, Point &k2, Point &k3,
                           uint8_t *h0, uint8_t *h1, uint8_t *h2, uint8_t *h3)
{

#ifdef WIN64
    __declspec(align(16)) unsigned char sh0[64];
    __declspec(align(16)) unsigned char sh1[64];
    __declspec(align(16)) unsigned char sh2[64];
    __declspec(align(16)) unsigned char sh3[64];
#else
    unsigned char sh0[64] __attribute__((aligned(16)));
    unsigned char sh1[64] __attribute__((aligned(16)));
    unsigned char sh2[64] __attribute__((aligned(16)));
    unsigned char sh3[64] __attribute__((aligned(16)));
#endif

    switch (type)
    {

    case P2PKH:
    case BECH32:
    {

        if (!compressed)
        {

            uint32_t b0[32];
            uint32_t b1[32];
            uint32_t b2[32];
            uint32_t b3[32];

            KEYBUFFUNCOMP(b0, k0);
            KEYBUFFUNCOMP(b1, k1);
            KEYBUFFUNCOMP(b2, k2);
            KEYBUFFUNCOMP(b3, k3);

            sha256sse_2B(b0, b1, b2, b3, sh0, sh1, sh2, sh3);
            ripemd160sse_32(sh0, sh1, sh2, sh3, h0, h1, h2, h3);
        }
        else
        {

            uint32_t b0[16];
            uint32_t b1[16];
            uint32_t b2[16];
            uint32_t b3[16];

            KEYBUFFCOMP(b0, k0);
            KEYBUFFCOMP(b1, k1);
            KEYBUFFCOMP(b2, k2);
            KEYBUFFCOMP(b3, k3);

            sha256sse_1B(b0, b1, b2, b3, sh0, sh1, sh2, sh3);
            ripemd160sse_32(sh0, sh1, sh2, sh3, h0, h1, h2, h3);
        }
    }
    break;

    case P2SH:
    {

        unsigned char kh0[20];
        unsigned char kh1[20];
        unsigned char kh2[20];
        unsigned char kh3[20];

        GetHash160(P2PKH, compressed, k0, k1, k2, k3, kh0, kh1, kh2, kh3);

        // Redeem Script (1 to 1 P2SH)
        uint32_t b0[16];
        uint32_t b1[16];
        uint32_t b2[16];
        uint32_t b3[16];

        KEYBUFFSCRIPT(b0, kh0);
        KEYBUFFSCRIPT(b1, kh1);
        KEYBUFFSCRIPT(b2, kh2);
        KEYBUFFSCRIPT(b3, kh3);

        sha256sse_1B(b0, b1, b2, b3, sh0, sh1, sh2, sh3);
        ripemd160sse_32(sh0, sh1, sh2, sh3, h0, h1, h2, h3);
    }
    break;
    }
}

void Secp256K1::GetHash160(int type, bool compressed, Point &pubKey, unsigned char *hash)
{

    unsigned char shapk[64];

    switch (type)
    {

    case P2PKH:
    case BECH32:
    {
        unsigned char publicKeyBytes[128];

        if (!compressed)
        {

            // Full public key
            publicKeyBytes[0] = 0x4;
            pubKey.x.Get32Bytes(publicKeyBytes + 1);
            pubKey.y.Get32Bytes(publicKeyBytes + 33);
            sha256_65(publicKeyBytes, shapk);
        }
        else
        {

            // Compressed public key
            publicKeyBytes[0] = pubKey.y.IsEven() ? 0x2 : 0x3;
            pubKey.x.Get32Bytes(publicKeyBytes + 1);
            sha256_33(publicKeyBytes, shapk);
        }

        ripemd160_32(shapk, hash);
    }
    break;

    case P2SH:
    {

        // Redeem Script (1 to 1 P2SH)
        unsigned char script[64];

        script[0] = 0x00; // OP_0
        script[1] = 0x14; // PUSH 20 bytes
        GetHash160(P2PKH, compressed, pubKey, script + 2);

        sha256(script, 22, shapk);
        ripemd160_32(shapk, hash);
    }
    break;
    }
}

#define KEYBUFFPREFIX(buff, k, fix)                          \
    (buff)[0] = (k->bits[7] >> 8) | ((uint32_t)(fix) << 24); \
    (buff)[1] = (k->bits[6] >> 8) | (k->bits[7] << 24);      \
    (buff)[2] = (k->bits[5] >> 8) | (k->bits[6] << 24);      \
    (buff)[3] = (k->bits[4] >> 8) | (k->bits[5] << 24);      \
    (buff)[4] = (k->bits[3] >> 8) | (k->bits[4] << 24);      \
    (buff)[5] = (k->bits[2] >> 8) | (k->bits[3] << 24);      \
    (buff)[6] = (k->bits[1] >> 8) | (k->bits[2] << 24);      \
    (buff)[7] = (k->bits[0] >> 8) | (k->bits[1] << 24);      \
    (buff)[8] = 0x00800000 | (k->bits[0] << 24);             \
    (buff)[9] = 0;                                           \
    (buff)[10] = 0;                                          \
    (buff)[11] = 0;                                          \
    (buff)[12] = 0;                                          \
    (buff)[13] = 0;                                          \
    (buff)[14] = 0;                                          \
    (buff)[15] = 0x108;

void Secp256K1::GetHash160_fromX(int type, unsigned char prefix,
                                 Int *k0, Int *k1, Int *k2, Int *k3,
                                 uint8_t *h0, uint8_t *h1, uint8_t *h2, uint8_t *h3)
{

#ifdef WIN64
    __declspec(align(16)) unsigned char sh0[64];
    __declspec(align(16)) unsigned char sh1[64];
    __declspec(align(16)) unsigned char sh2[64];
    __declspec(align(16)) unsigned char sh3[64];
#else
    unsigned char sh0[64] __attribute__((aligned(16)));
    unsigned char sh1[64] __attribute__((aligned(16)));
    unsigned char sh2[64] __attribute__((aligned(16)));
    unsigned char sh3[64] __attribute__((aligned(16)));
#endif

    switch (type)
    {

    case P2PKH:
    {
        uint32_t b0[16];
        uint32_t b1[16];
        uint32_t b2[16];
        uint32_t b3[16];

        KEYBUFFPREFIX(b0, k0, prefix);
        KEYBUFFPREFIX(b1, k1, prefix);
        KEYBUFFPREFIX(b2, k2, prefix);
        KEYBUFFPREFIX(b3, k3, prefix);

        sha256sse_1B(b0, b1, b2, b3, sh0, sh1, sh2, sh3);
        ripemd160sse_32(sh0, sh1, sh2, sh3, h0, h1, h2, h3);
    }
    break;

    case P2SH:
    {
        fprintf(stderr, "[E] Fixme unsopported case");
        exit(0);
    }
    break;
    }
}

bool Secp256K1::VerifyPoint(Point &p, const char *label)
{
    printf("Verifying point %s:\n", label);
    printf("x: %s\n", p.x.GetBase16());
    printf("y: %s\n", p.y.GetBase16());
    printf("z: %s\n", p.z.GetBase16());

    // Check if point is on curve
    if (!EC(p))
    {
        printf("FAILED: Point is not on curve!\n");
        return false;
    }

    // If not identity, check coordinates are properly reduced
    if (!p.isZero())
    {
        Point reduced(p);
        reduced.Reduce();
        if (!p.equals(reduced))
        {
            printf("WARNING: Point is not in reduced form\n");
        }
    }

    return true;
}

// Define identity point correctly
Point Secp256K1::GetIdentity()
{
    Point identity;
    identity.Clear();
    identity.z.SetInt32(0); // Point at infinity has z=0
    return identity;
}

Point Secp256K1::SubtractPoints(Point &P1, Point &P2)
{
    // Since we're working with normalized points in subtraction operations,
    // we can optimize by directly modifying y-coordinate and using AddDirect

    Point negP2;
    negP2.x = P2.x;      // Copy x coordinate
    negP2.z.SetInt32(1); // Set z to 1 (normalized)

    // Compute negative y-coordinate in one step
    negP2.y = P2.y;
    negP2.y.ModNeg();

    // Use our optimized AddDirect
    return AddDirect(P1, negP2);
}
