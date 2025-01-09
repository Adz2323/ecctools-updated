#include "SECP256K1.cuh"
#include <cuda_runtime.h>
#include <device_launch_parameters.h>
#include "../hash/sha256.h"
#include "../hash/ripemd160.h"
#include "../util.h"

Secp256K1_CUDA::Secp256K1_CUDA()
{
    h_GTable = nullptr;
    d_GTable = nullptr;
    d_points = nullptr;
    d_scalars = nullptr;
}

Secp256K1_CUDA::~Secp256K1_CUDA()
{
    Cleanup();
}

void Secp256K1_CUDA::Init()
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

    // Allocate host memory for G table
    h_GTable = new Point[256 * 32];

    // Compute Generator table
    Point N(G);
    for (int i = 0; i < 32; i++)
    {
        h_GTable[i * 256] = N;
        N = DoubleDirect(N);
        for (int j = 1; j < 255; j++)
        {
            h_GTable[i * 256 + j] = N;
            N = AddDirect(N, h_GTable[i * 256]);
        }
        h_GTable[i * 256 + 255] = N;
    }

    InitCUDA();
}

void Secp256K1_CUDA::InitCUDA()
{
    cudaMalloc(&d_GTable, 256 * 32 * sizeof(Point));
    cudaMalloc(&d_points, MAX_BLOCKS * BLOCK_SIZE * sizeof(Point));
    cudaMalloc(&d_scalars, MAX_BLOCKS * BLOCK_SIZE * sizeof(Int));
    cudaMemcpy(d_GTable, h_GTable, 256 * 32 * sizeof(Point), cudaMemcpyHostToDevice);
}

void Secp256K1_CUDA::Cleanup()
{
    if (h_GTable)
        delete[] h_GTable;
    if (d_GTable)
        cudaFree(d_GTable);
    if (d_points)
        cudaFree(d_points);
    if (d_scalars)
        cudaFree(d_scalars);
}

__host__ Point Secp256K1_CUDA::ComputePublicKey(Int *privKey)
{
    Point result;
    cudaMemcpy(d_scalars, privKey, sizeof(Int), cudaMemcpyHostToDevice);
    Point *d_result;
    cudaMalloc(&d_result, sizeof(Point));

    computePublicKeysKernel<<<1, 1>>>(d_scalars, d_result, d_GTable, 1);

    cudaMemcpy(&result, d_result, sizeof(Point), cudaMemcpyDeviceToHost);
    cudaFree(d_result);
    return result;
}

__host__ Point Secp256K1_CUDA::NextKey(Point &key)
{
    return AddDirect(key, G);
}

__host__ Int Secp256K1_CUDA::GetY(Int x, bool isEven)
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

__host__ __device__ Point Secp256K1_CUDA::Add(Point &p1, Point &p2)
{
    if (p1.isZero())
        return p2;
    if (p2.isZero())
        return p1;

    Point neg2 = Negation(p2);
    if (p1.equals(neg2))
    {
        Point result;
        result.Clear();
        return result;
    }

    if (p1.equals(p2))
        return Double(p1);

    Point result;
    Point p1n(p1);
    Point p2n(p2);
    p1n.Reduce();
    p2n.Reduce();

    Int slope;
    Int temp;
    temp.ModSub(&p2n.y, &p1n.y);
    Int dx;
    dx.ModSub(&p2n.x, &p1n.x);
    dx.ModInv();
    slope.ModMulK1(&temp, &dx);

    result.x.ModSquareK1(&slope);
    result.x.ModSub(&p1n.x);
    result.x.ModSub(&p2n.x);

    temp.ModSub(&p1n.x, &result.x);
    temp.ModMulK1(&slope);
    result.y.ModSub(&temp, &p1n.y);

    result.z.SetInt32(1);
    return result;
}

__host__ __device__ Point Secp256K1_CUDA::AddDirect(Point &p1, Point &p2)
{
    Int s;
    Int dx;
    Int dy;
    Point r;
    r.z.SetInt32(1);

    dy.ModSub(&p2.y, &p1.y);
    dx.ModSub(&p2.x, &p1.x);
    dx.ModInv();
    s.ModMulK1(&dy, &dx);

    Int s2;
    s2.ModSquareK1(&s);
    r.x.ModSub(&s2, &p1.x);
    r.x.ModSub(&p2.x);

    Int temp;
    temp.ModSub(&p1.x, &r.x);
    temp.ModMulK1(&s);
    r.y.ModSub(&temp, &p1.y);

    return r;
}

__host__ __device__ Point Secp256K1_CUDA::Double(Point &p)
{
    if (p.isZero())
        return p;

    Int _2y;
    Int _3x2;
    Int s;
    Point r;
    r.z.SetInt32(1);

    _2y.ModAdd(&p.y, &p.y);
    _2y.ModInv();

    _3x2.ModSquareK1(&p.x);
    Int temp;
    temp.Set(&_3x2);
    _3x2.ModAdd(&temp);
    _3x2.ModAdd(&temp);

    s.ModMulK1(&_3x2, &_2y);

    r.x.ModSquareK1(&s);
    temp.ModAdd(&p.x, &p.x);
    r.x.ModSub(&temp);

    temp.ModSub(&p.x, &r.x);
    temp.ModMulK1(&s);
    r.y.ModSub(&temp, &p.y);

    return r;
}

__host__ __device__ Point Secp256K1_CUDA::DoubleDirect(Point &p)
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
    _s.ModMulK1(&_p, &a);

    _p.ModMulK1(&_s, &_s);
    a.ModAdd(&p.x, &p.x);
    a.ModNeg();
    r.x.ModAdd(&a, &_p);

    a.ModSub(&r.x, &p.x);

    _p.ModMulK1(&a, &_s);
    r.y.ModAdd(&_p, &p.y);
    r.y.ModNeg();

    return r;
}

__host__ __device__ Point Secp256K1_CUDA::Negation(Point &p)
{
    Point result;
    result.x = p.x;
    result.y = p.y;
    result.y.ModNeg();
    result.z.SetInt32(1);
    return result;
}

__host__ bool Secp256K1_CUDA::EC(Point &p)
{
    Int _s;
    Int _p;
    _s.ModSquareK1(&p.x);
    _p.ModMulK1(&_s, &p.x);
    _p.ModAdd(7);
    _s.ModMulK1(&p.y, &p.y);
    _s.ModSub(&_p);
    return _s.IsZero();
}

// Public key operations
__host__ bool Secp256K1_CUDA::ParsePublicKeyHex(char *str, Point &ret, bool &isCompressed)
{
    int len = strlen(str);
    ret.Clear();
    if (len < 2)
        return false;

    uint8_t type = GetByte(str, 0);
    switch (type)
    {
    case 0x02:
        if (len != 66)
            return false;
        for (int i = 0; i < 32; i++)
            ret.x.SetByte(31 - i, GetByte(str, i + 1));
        ret.y = GetY(ret.x, true);
        isCompressed = true;
        break;

    case 0x03:
        if (len != 66)
            return false;
        for (int i = 0; i < 32; i++)
            ret.x.SetByte(31 - i, GetByte(str, i + 1));
        ret.y = GetY(ret.x, false);
        isCompressed = true;
        break;

    case 0x04:
        if (len != 130)
            return false;
        for (int i = 0; i < 32; i++)
        {
            ret.x.SetByte(31 - i, GetByte(str, i + 1));
            ret.y.SetByte(31 - i, GetByte(str, i + 33));
        }
        isCompressed = false;
        break;

    default:
        return false;
    }

    ret.z.SetInt32(1);
    return EC(ret);
}

// Hash operations implementation
__host__ void Secp256K1_CUDA::GetHash160(int type, bool compressed,
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

__host__ void Secp256K1_CUDA::GetHash160(int type, bool compressed, Point &pubKey, unsigned char *hash)
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
            publicKeyBytes[0] = 0x4;
            pubKey.x.Get32Bytes(publicKeyBytes + 1);
            pubKey.y.Get32Bytes(publicKeyBytes + 33);
            sha256_65(publicKeyBytes, shapk);
        }
        else
        {
            publicKeyBytes[0] = pubKey.y.IsEven() ? 0x2 : 0x3;
            pubKey.x.Get32Bytes(publicKeyBytes + 1);
            sha256_33(publicKeyBytes, shapk);
        }

        ripemd160_32(shapk, hash);
    }
    break;

    case P2SH:
    {
        unsigned char script[64];
        script[0] = 0x00;
        script[1] = 0x14;
        GetHash160(P2PKH, compressed, pubKey, script + 2);

        sha256(script, 22, shapk);
        ripemd160_32(shapk, hash);
    }
    break;
    }
}

__host__ void Secp256K1_CUDA::GetPublicKeyHex(bool compressed, Point &pubKey, char *dst)
{
    unsigned char publicKeyBytes[65];
    if (!compressed)
    {
        publicKeyBytes[0] = 0x4;
        pubKey.x.Get32Bytes(publicKeyBytes + 1);
        pubKey.y.Get32Bytes(publicKeyBytes + 33);
        tohex_dst((char *)publicKeyBytes, 65, dst);
    }
    else
    {
        publicKeyBytes[0] = pubKey.y.IsEven() ? 0x2 : 0x3;
        pubKey.x.Get32Bytes(publicKeyBytes + 1);
        tohex_dst((char *)publicKeyBytes, 33, dst);
    }
}

__host__ void Secp256K1_CUDA::GetPublicKeyRaw(bool compressed, Point &pubKey, char *dst)
{
    if (!compressed)
    {
        dst[0] = 0x4;
        pubKey.x.Get32Bytes((unsigned char *)(dst + 1));
        pubKey.y.Get32Bytes((unsigned char *)(dst + 33));
    }
    else
    {
        dst[0] = pubKey.y.IsEven() ? 0x2 : 0x3;
        pubKey.x.Get32Bytes((unsigned char *)(dst + 1));
    }
}

__host__ uint8_t Secp256K1_CUDA::GetByte(char *str, int idx)
{
    char tmp[3];
    int val;
    tmp[0] = str[2 * idx];
    tmp[1] = str[2 * idx + 1];
    tmp[2] = 0;
    if (sscanf(tmp, "%X", &val) != 1)
    {
        printf("ParsePublicKeyHex: Error invalid public key specified\n");
        exit(-1);
    }
    return (uint8_t)val;
}

__host__ bool Secp256K1_CUDA::VerifyPoint(Point &p, const char *label)
{
    printf("Verifying point %s:\n", label);
    printf("x: %s\n", p.x.GetBase16());
    printf("y: %s\n", p.y.GetBase16());
    printf("z: %s\n", p.z.GetBase16());

    if (!EC(p))
    {
        printf("FAILED: Point is not on curve!\n");
        return false;
    }

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

__host__ Point Secp256K1_CUDA::GetIdentity()
{
    Point identity;
    identity.Clear();
    identity.z.SetInt32(0);
    return identity;
}

__host__ Point Secp256K1_CUDA::SubtractPoints(Point &P1, Point &P2)
{
    Point negP2;
    negP2.x = P2.x;
    negP2.z.SetInt32(1);
    negP2.y = P2.y;
    negP2.y.ModNeg();

    return AddDirect(P1, negP2);
}

// CUDA Kernel implementations
__global__ void computePublicKeysKernel(Int *privKeys, Point *publicKeys,
                                        Point *gTable, int count)
{
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= count)
        return;

    Point Q;
    Q.Clear();

    Int *privKey = &privKeys[idx];

    int i = 0;
    uint8_t b;
    for (i = 0; i < 32; i++)
    {
        b = privKey->GetByte(i);
        if (b)
            break;
    }

    if (b)
        Q = gTable[256 * i + (b - 1)];
    i++;

    for (; i < 32; i++)
    {
        b = privKey->GetByte(i);
        if (b)
            Q = Secp256K1_CUDA::Add2(Q, gTable[256 * i + (b - 1)]);
    }

    Q.Reduce();
    publicKeys[idx] = Q;
}

__global__ void nextKeysKernel(Point *keys, Point g, int count)
{
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= count)
        return;

    keys[idx] = Secp256K1_CUDA::AddDirect(keys[idx], g);
}

// Point multiplication implementation
__host__ Point Secp256K1_CUDA::ScalarMultiplication(Point &P, Int *scalar, bool debug)
{
    if (scalar->IsZero())
    {
        Point result;
        result.Clear();
        return result;
    }

    if (P.equals(G))
    {
        return ComputePublicKey(scalar);
    }

    const int WINDOW_SIZE = 4;
    const int TABLE_SIZE = 1 << WINDOW_SIZE;
    Point precomp[16];

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