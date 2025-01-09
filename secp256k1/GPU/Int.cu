/*
 * CUDA implementation of Int.cpp
 * Converted from BSGS distribution (https://github.com/JeanLucPons/BSGS)
 */

#include "Int.cuh"
#include <cuda_runtime.h>
#include <device_launch_parameters.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curand.h>
#include <curand_kernel.h>

// Device constants
__constant__ CudaInt d_ONE;
__constant__ CudaInt d_P;  // Field characteristic
__constant__ CudaInt d_R;  // Montgomery multiplication R
__constant__ CudaInt d_R2; // Montgomery multiplication R2
__constant__ CudaInt d_R3; // Montgomery multiplication R3
__constant__ CudaInt d_R4; // Montgomery multiplication R4

// Static variables
static CudaInt _ONE((uint64_t)1);
static CudaInt _P;
static CudaInt _R;
static CudaInt _R2;
static CudaInt _R3;
static CudaInt _R4;
static int32_t Msize;
static uint32_t MM32;
static uint64_t MM64;

// Constructors
CudaInt::CudaInt() : allocated(false)
{
    AllocateMemory();
    CLEAR();
}

CudaInt::CudaInt(CudaInt *a) : allocated(false)
{
    AllocateMemory();
    if (a)
        Set(a);
    else
        CLEAR();
}

CudaInt::CudaInt(int32_t i32) : allocated(false)
{
    AllocateMemory();
    if (i32 < 0)
    {
        CLEARFF();
    }
    else
    {
        CLEAR();
    }
    bits[0] = i32;
}

CudaInt::CudaInt(int64_t i64) : allocated(false)
{
    AllocateMemory();
    if (i64 < 0)
    {
        CLEARFF();
    }
    else
    {
        CLEAR();
    }
    bits64[0] = i64;
}

CudaInt::CudaInt(uint64_t u64) : allocated(false)
{
    AllocateMemory();
    CLEAR();
    bits64[0] = u64;
}

CudaInt::~CudaInt()
{
    FreeMemory();
}

// Memory management
void CudaInt::AllocateMemory()
{
    if (!allocated)
    {
        cudaMalloc(&d_bits, NB32BLOCK * sizeof(uint32_t));
        cudaMalloc(&d_bits64, NB64BLOCK * sizeof(uint64_t));
        allocated = true;
    }
}

void CudaInt::FreeMemory()
{
    if (allocated)
    {
        cudaFree(d_bits);
        cudaFree(d_bits64);
        allocated = false;
    }
}

void CudaInt::CopyToDevice()
{
    cudaMemcpy(d_bits, bits, NB32BLOCK * sizeof(uint32_t), cudaMemcpyHostToDevice);
    cudaMemcpy(d_bits64, bits64, NB64BLOCK * sizeof(uint64_t), cudaMemcpyHostToDevice);
}

void CudaInt::CopyFromDevice()
{
    cudaMemcpy(bits, d_bits, NB32BLOCK * sizeof(uint32_t), cudaMemcpyDeviceToHost);
    cudaMemcpy(bits64, d_bits64, NB64BLOCK * sizeof(uint64_t), cudaMemcpyDeviceToHost);
}

// Core Functions
__device__ void CudaInt::CLEAR()
{
    for (int i = 0; i < NB64BLOCK; i++)
        bits64[i] = 0;
}

__device__ void CudaInt::CLEARFF()
{
    for (int i = 0; i < NB64BLOCK; i++)
        bits64[i] = 0xFFFFFFFFFFFFFFFF;
}

__device__ void CudaInt::Set(CudaInt *a)
{
    for (int i = 0; i < NB64BLOCK; i++)
        bits64[i] = a->bits64[i];
}

// Addition operations
__device__ void CudaInt::Add(uint64_t a)
{
    unsigned char c = 0;
    c = __add_cc(bits64[0], a);
    for (int i = 1; i < NB64BLOCK && c; i++)
        c = __add_cc(bits64[i], 0);
}

__device__ void CudaInt::Add(CudaInt *a)
{
    unsigned char c = 0;
    for (int i = 0; i < NB64BLOCK; i++)
        c = __add_cc(bits64[i], a->bits64[i]);
}

__device__ void CudaInt::Add(CudaInt *a, CudaInt *b)
{
    unsigned char c = 0;
    for (int i = 0; i < NB64BLOCK; i++)
        c = __add_cc(b->bits64[i], a->bits64[i], bits64[i]);
}

__device__ void CudaInt::AddOne()
{
    Add((uint64_t)1);
}

// Subtraction operations
__device__ void CudaInt::Sub(uint64_t a)
{
    unsigned char c = 0;
    c = __sub_cc(bits64[0], a);
    for (int i = 1; i < NB64BLOCK && c; i++)
        c = __sub_cc(bits64[i], 0);
}

__device__ void CudaInt::Sub(CudaInt *a)
{
    unsigned char c = 0;
    for (int i = 0; i < NB64BLOCK; i++)
        c = __sub_cc(bits64[i], a->bits64[i]);
}

__device__ void CudaInt::Sub(CudaInt *a, CudaInt *b)
{
    unsigned char c = 0;
    for (int i = 0; i < NB64BLOCK; i++)
        c = __sub_cc(a->bits64[i], b->bits64[i], bits64[i]);
}

__device__ void CudaInt::SubOne()
{
    Sub((uint64_t)1);
}

// Multiplication operations
__device__ void CudaInt::Mult(CudaInt *a)
{
    CudaInt t(this);
    Mult(a, &t);
}

__device__ void CudaInt::Mult(uint64_t a)
{
    cuda_imm_mul(bits64, a, bits64);
}

__device__ void CudaInt::IMult(int64_t a)
{
    if (a < 0)
    {
        Neg();
        a = -a;
    }
    cuda_imm_mul(bits64, a, bits64);
}

__device__ void CudaInt::Mult(CudaInt *a, uint64_t b)
{
    cuda_imm_mul(a->bits64, b, bits64);
}

__device__ void CudaInt::Mult(CudaInt *a, CudaInt *b)
{
    uint64_t r512[16]; // Temporary storage for multiplication
    uint64_t t[NB64BLOCK + 1];
    unsigned char c = 0;

    // Main multiplication loop using Karatsuba method
    for (int i = 0; i < NB64BLOCK; i++)
    {
        uint64_t h, l;
        l = __umul64hi(a->bits64[0], b->bits64[i], &h);
        r512[i] = l;
        t[0] = h;

        for (int j = 1; j < NB64BLOCK - i; j++)
        {
            l = __umul64hi(a->bits64[j], b->bits64[i], &h);
            c = __add_cc(r512[i + j], l);
            c = __add_cc(t[j - 1], c);
            t[j] = h + (c != 0);
        }
    }

    // Copy result back
    for (int i = 0; i < NB64BLOCK; i++)
    {
        bits64[i] = r512[i];
    }
}

// Comparison operations
__device__ bool CudaInt::IsGreater(CudaInt *a)
{
    int i = NB64BLOCK - 1;
    while (i >= 0 && a->bits64[i] == bits64[i])
        i--;
    if (i >= 0)
        return bits64[i] > a->bits64[i];
    return false;
}

__device__ bool CudaInt::IsLower(CudaInt *a)
{
    int i = NB64BLOCK - 1;
    while (i >= 0 && a->bits64[i] == bits64[i])
        i--;
    if (i >= 0)
        return bits64[i] < a->bits64[i];
    return false;
}

__device__ bool CudaInt::IsEqual(CudaInt *a)
{
    for (int i = 0; i < NB64BLOCK; i++)
        if (bits64[i] != a->bits64[i])
            return false;
    return true;
}

__device__ bool CudaInt::IsZero()
{
    for (int i = 0; i < NB64BLOCK; i++)
        if (bits64[i] != 0)
            return false;
    return true;
}

__device__ bool CudaInt::IsOne()
{
    if (bits64[0] != 1)
        return false;
    for (int i = 1; i < NB64BLOCK; i++)
        if (bits64[i] != 0)
            return false;
    return true;
}

// Status check operations
__device__ bool CudaInt::IsPositive()
{
    return (int64_t)bits64[NB64BLOCK - 1] >= 0;
}

__device__ bool CudaInt::IsNegative()
{
    return (int64_t)bits64[NB64BLOCK - 1] < 0;
}

__device__ bool CudaInt::IsEven()
{
    return (bits[0] & 0x1) == 0;
}

__device__ bool CudaInt::IsOdd()
{
    return (bits[0] & 0x1) == 1;
}

// Shift operations
__device__ void CudaInt::ShiftL32Bit()
{
    for (int i = NB32BLOCK - 1; i > 0; i--)
        bits[i] = bits[i - 1];
    bits[0] = 0;
}

__device__ void CudaInt::ShiftR32Bit()
{
    for (int i = 0; i < NB32BLOCK - 1; i++)
        bits[i] = bits[i + 1];
    bits[NB32BLOCK - 1] = IsNegative() ? 0xFFFFFFFF : 0;
}

__device__ void CudaInt::ShiftL(uint32_t n)
{
    if (n >= 64)
    {
        uint32_t nb64 = n / 64;
        for (int i = 0; i < nb64; i++)
            ShiftL64Bit();
        n %= 64;
    }
    if (n > 0)
    {
        for (int i = NB64BLOCK - 1; i > 0; i--)
            bits64[i] = (bits64[i] << n) | (bits64[i - 1] >> (64 - n));
        bits64[0] <<= n;
    }
}

__device__ void CudaInt::ShiftR(uint32_t n)
{
    if (n >= 64)
    {
        uint32_t nb64 = n / 64;
        for (int i = 0; i < nb64; i++)
            ShiftR64Bit();
        n %= 64;
    }
    if (n > 0)
    {
        for (int i = 0; i < NB64BLOCK - 1; i++)
            bits64[i] = (bits64[i] >> n) | (bits64[i + 1] << (64 - n));
        bits64[NB64BLOCK - 1] >>= n;
    }
}

// Modular arithmetic
__device__ void CudaInt::ModAdd(CudaInt *a)
{
    Add(a);
    while (IsGreaterOrEqual(&d_P))
        Sub(&d_P);
}

__device__ void CudaInt::ModSub(CudaInt *a)
{
    Sub(a);
    while (IsNegative())
        Add(&d_P);
}

__device__ void CudaInt::ModMul(CudaInt *a)
{
    CudaInt t;
    t.MontgomeryMult(this, a);
    MontgomeryMult(&d_R2, &t);
}

// Montgomery multiplication
__device__ void CudaInt::MontgomeryMult(CudaInt *a, CudaInt *b)
{
    // Implementation of Montgomery multiplication
    uint64_t r[NB64BLOCK * 2];
    uint64_t t[NB64BLOCK + 1];
    unsigned char c = 0;

    // First multiplication phase
    for (int i = 0; i < NB64BLOCK; i++)
    {
        uint64_t h;
        r[i] = __umul64hi(a->bits64[0], b->bits64[i], &h);
        t[0] = h;

        for (int j = 1; j < NB64BLOCK; j++)
        {
            uint64_t l = __umul64hi(a->bits64[j], b->bits64[i], &h);
            c = __add_cc(r[i + j], l);
            c = __add_cc(t[j - 1], c);
            t[j - 1] = h + (c != 0);
        }
        t[NB64BLOCK - 1] = 0;
    }

    // Montgomery reduction
    for (int i = 0; i < NB64BLOCK; i++)
    {
        uint64_t m = r[i] * MM64;
        uint64_t h;
        c = 0;

        for (int j = 0; j < NB64BLOCK; j++)
        {
            uint64_t l = __umul64hi(m, d_P.bits64[j], &h);
            c = __add_cc(r[i + j], l);
            c = __add_cc(h, c);
            r[i + j] = __add_cc(0, c);
        }
    }

    // Final adjustment
    CudaInt result;
    c = 0;
    for (int i = 0; i < NB64BLOCK; i++)
    {
        result.bits64[i] = r[NB64BLOCK + i];
    }

    if (result.IsGreaterOrEqual(&d_P))
    {
        result.Sub(&d_P);
    }
    Set(&result);
}

__device__ void CudaInt::ModNeg()
{
    Neg();
    Add(&d_P);
}

__device__ void CudaInt::ModInv()
{
    CudaInt u(&d_P);
    CudaInt v(this);
    CudaInt r((uint64_t)0);
    CudaInt s((uint64_t)1);

    while (!u.IsZero())
    {
        if (u.IsEven())
        {
            u.ShiftR(1);
            if (!r.IsEven())
                r.Add(&d_P);
            r.ShiftR(1);
        }
        else if (v.IsEven())
        {
            v.ShiftR(1);
            if (!s.IsEven())
                s.Add(&d_P);
            s.ShiftR(1);
        }
        else if (u.IsGreater(&v))
        {
            u.Sub(&v);
            u.ShiftR(1);
            r.Sub(&s);
            if (!r.IsEven())
                r.Add(&d_P);
            r.ShiftR(1);
        }
        else
        {
            v.Sub(&u);
            v.ShiftR(1);
            s.Sub(&r);
            if (!s.IsEven())
                s.Add(&d_P);
            s.ShiftR(1);
        }
    }

    if (!v.IsOne())
    {
        CLEAR();
        return;
    }

    Set(&s);
    if (IsNegative())
        Add(&d_P);
}

// Base conversion methods
void CudaInt::SetBase10(const char *value)
{
    CLEAR();
    CudaInt pw((uint64_t)1);
    CudaInt c;
    int lgth = (int)strlen(value);

    for (int i = lgth - 1; i >= 0; i--)
    {
        uint32_t id = (uint32_t)(value[i] - '0');
        c.Set(&pw);
        c.Mult(id);
        Add(&c);
        pw.Mult(10);
    }
}

void CudaInt::SetBase16(const char *value)
{
    SetBaseN(16, "0123456789ABCDEF", value);
}

void CudaInt::SetBaseN(int n, const char *charset, const char *value)
{
    CLEAR();
    CudaInt pw((uint64_t)1);
    CudaInt nb((uint64_t)n);
    CudaInt c;
    int lgth = (int)strlen(value);

    for (int i = lgth - 1; i >= 0; i--)
    {
        char *p = strchr((char *)charset, toupper(value[i]));
        if (!p)
        {
            printf("Invalid charset !!\n");
            return;
        }
        int id = (int)(p - charset);
        c.SetInt32(id);
        c.Mult(&pw);
        Add(&c);
        pw.Mult(&nb);
    }
}

__device__ char *CudaInt::GetBase2()
{
    char *ret = (char *)malloc(1024);
    int k = 0;

    for (int i = 0; i < NB32BLOCK - 1; i++)
    {
        unsigned int mask = 0x80000000;
        for (int j = 0; j < 32; j++)
        {
            ret[k++] = (bits[i] & mask) ? '1' : '0';
            mask = mask >> 1;
        }
    }
    ret[k] = 0;
    return ret;
}

__device__ char *CudaInt::GetBase10()
{
    return GetBaseN(10, "0123456789");
}

__device__ char *CudaInt::GetBase16()
{
    return GetBaseN(16, "0123456789abcdef");
}

__device__ char *CudaInt::GetBaseN(int n, const char *charset)
{
    char *ret = (char *)malloc(1024);

    CudaInt N(this);
    int offset = 0;
    int isNegative = N.IsNegative();
    if (isNegative)
        N.Neg();

    unsigned char digits[1024];
    memset(digits, 0, sizeof(digits));

    int digitslen = 1;
    for (int i = 0; i < NB64BLOCK * 8; i++)
    {
        unsigned int carry = N.GetByte(NB64BLOCK * 8 - i - 1);
        for (int j = 0; j < digitslen; j++)
        {
            carry += (unsigned int)(digits[j]) << 8;
            digits[j] = (unsigned char)(carry % n);
            carry /= n;
        }
        while (carry > 0)
        {
            digits[digitslen++] = (unsigned char)(carry % n);
            carry /= n;
        }
    }

    if (isNegative)
        ret[offset++] = '-';

    for (int i = 0; i < digitslen; i++)
        ret[offset++] = charset[digits[digitslen - 1 - i]];

    if (offset == 0)
        ret[offset++] = '0';
    ret[offset] = '\0';

    return ret;
}

char *CudaInt::GetBlockStr()
{
    char *tmp = (char *)malloc(256);
    char bStr[256];
    tmp[0] = 0;

    for (int i = NB32BLOCK - 3; i >= 0; i--)
    {
        sprintf(bStr, "%08X", bits[i]);
        strcat(tmp, bStr);
        if (i != 0)
            strcat(tmp, " ");
    }
    return tmp;
}

char *CudaInt::GetC64Str(int nbDigit)
{
    char *tmp = (char *)malloc(256);
    char bStr[256];
    tmp[0] = '{';
    tmp[1] = 0;

    for (int i = 0; i < nbDigit; i++)
    {
        if (bits64[i] != 0)
        {
#ifdef _WIN64
            sprintf(bStr, "0x%016I64XULL", bits64[i]);
#else
            sprintf(bStr, "0x%" PRIx64 "ULL", bits64[i]);
#endif
        }
        else
        {
            sprintf(bStr, "0ULL");
        }
        strcat(tmp, bStr);
        if (i != nbDigit - 1)
            strcat(tmp, ",");
    }
    strcat(tmp, "}");
    return tmp;
}

// Static methods implementation
void CudaInt::SetupField(CudaInt *n, CudaInt *R, CudaInt *R2, CudaInt *R3, CudaInt *R4)
{
    // Size in number of 32bit word
    int nSize = n->GetSize();

    // Last digit inversions (Newton's iteration)
    {
        int64_t x, t;
        x = t = (int64_t)n->bits64[0];
        x = x * (2 - t * x);
        x = x * (2 - t * x);
        x = x * (2 - t * x);
        x = x * (2 - t * x);
        x = x * (2 - t * x);
        MM64 = (uint64_t)(-x);
        MM32 = (uint32_t)MM64;
    }

    _P.Set(n);

    // Size of Montgomery mult (64bits digit)
    Msize = nSize / 2;

    // Compute few powers of R
    CudaInt Ri;
    Ri.MontgomeryMult(&_ONE, &_ONE); // Ri = R^-1
    _R.Set(&Ri);                     // R  = R^-1
    _R2.MontgomeryMult(&Ri, &_ONE);  // R2 = R^-2
    _R3.MontgomeryMult(&Ri, &Ri);    // R3 = R^-3
    _R4.MontgomeryMult(&_R3, &_ONE); // R4 = R^-4

    _R.ModInv();  // R  = R
    _R2.ModInv(); // R2 = R^2
    _R3.ModInv(); // R3 = R^3
    _R4.ModInv(); // R4 = R^4

    // Copy to device constants
    cudaMemcpyToSymbol(d_P, &_P, sizeof(CudaInt));
    cudaMemcpyToSymbol(d_R, &_R, sizeof(CudaInt));
    cudaMemcpyToSymbol(d_R2, &_R2, sizeof(CudaInt));
    cudaMemcpyToSymbol(d_R3, &_R3, sizeof(CudaInt));
    cudaMemcpyToSymbol(d_R4, &_R4, sizeof(CudaInt));

    if (R)
        R->Set(&_R);
    if (R2)
        R2->Set(&_R2);
    if (R3)
        R3->Set(&_R3);
    if (R4)
        R4->Set(&_R4);
}

// Utility functions
__device__ uint32_t CudaInt::GetInt32()
{
    return bits[0];
}

__device__ uint64_t CudaInt::GetInt64()
{
    return bits64[0];
}

__device__ void CudaInt::SetInt32(uint32_t value)
{
    CLEAR();
    bits[0] = value;
}

__device__ void CudaInt::SetInt64(uint64_t value)
{
    CLEAR();
    bits64[0] = value;
}

__device__ void CudaInt::Set32Bytes(unsigned char *bytes)
{
    CLEAR();
    uint64_t *ptr = (uint64_t *)bytes;
    for (int i = 0; i < 4; i++)
    {
        uint64_t v = ptr[i];
        v = ((v << 8) & 0xFF00FF00FF00FF00ULL) | ((v >> 8) & 0x00FF00FF00FF00FFULL);
        v = ((v << 16) & 0xFFFF0000FFFF0000ULL) | ((v >> 16) & 0x0000FFFF0000FFFFULL);
        bits64[3 - i] = (v << 32) | (v >> 32);
    }
}

__device__ void CudaInt::Get32Bytes(unsigned char *buff)
{
    uint64_t *ptr = (uint64_t *)buff;
    for (int i = 0; i < 4; i++)
    {
        uint64_t v = bits64[3 - i];
        v = ((v << 8) & 0xFF00FF00FF00FF00ULL) | ((v >> 8) & 0x00FF00FF00FF00FFULL);
        v = ((v << 16) & 0xFFFF0000FFFF0000ULL) | ((v >> 16) & 0x0000FFFF0000FFFFULL);
        ptr[i] = (v << 32) | (v >> 32);
    }
}

// Random number generation
void CudaInt::Rand(int nbit)
{
    curandGenerator_t gen;
    curandCreateGenerator(&gen, CURAND_RNG_PSEUDO_DEFAULT);
    curandSetPseudoRandomGeneratorSeed(gen, clock());

    uint32_t nwords = (nbit + 31) / 32;
    curandGenerateUniform(gen, d_bits, nwords);

    CopyFromDevice();

    // Mask off excess bits
    uint32_t excess = nbit % 32;
    if (excess)
    {
        uint32_t mask = (1u << excess) - 1;
        bits[nwords - 1] &= mask;
    }

    curandDestroyGenerator(gen);
}

void CudaInt::Rand(CudaInt *min, CudaInt *max)
{
    CudaInt diff;
    diff.Set(max);
    diff.Sub(min);

    do
    {
        Rand(diff.GetBitLength());
    } while (IsGreater(&diff));

    Add(min);
}

// IntGroup implementation
CudaIntGroup::CudaIntGroup(int size)
{
    this->size = size;
    cudaMalloc(&subp, size * sizeof(CudaInt));
    cudaMalloc(&ints, size * sizeof(CudaInt));
}

CudaIntGroup::~CudaIntGroup()
{
    if (subp)
        cudaFree(subp);
    if (ints)
        cudaFree(ints);
}

void CudaIntGroup::Set(CudaInt *pts)
{
    cudaMemcpy(ints, pts, size * sizeof(CudaInt), cudaMemcpyHostToDevice);
}

// GPU kernel for parallel ModInv
__global__ void groupModInvKernel(CudaInt *ints, CudaInt *subp, int size)
{
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx < size)
    {
        if (idx == 0)
        {
            subp[0].Set(&ints[0]);
        }
        else
        {
            subp[idx].ModMulK1(&subp[idx - 1], &ints[idx]);
        }
        __syncthreads();

        if (idx == size - 1)
        {
            CudaInt inverse;
            inverse.Set(&subp[size - 1]);
            inverse.ModInv();

            for (int i = size - 1; i > 0; i--)
            {
                CudaInt newValue;
                newValue.ModMulK1(&subp[i - 1], &inverse);
                inverse.ModMulK1(&ints[i]);
                ints[i].Set(&newValue);
            }
            ints[0].Set(&inverse);
        }
    }
}

void CudaIntGroup::ModInv()
{
    int threadsPerBlock = 256;
    int blocks = (size + threadsPerBlock - 1) / threadsPerBlock;
    groupModInvKernel<<<blocks, threadsPerBlock>>>(ints, subp, size);
    cudaDeviceSynchronize();
}

// Error checking wrapper
#define CUDA_CHECK(call)                                            \
    {                                                               \
        cudaError_t err = call;                                     \
        if (err != cudaSuccess)                                     \
        {                                                           \
            printf("CUDA error at %s:%d: %s\n", __FILE__, __LINE__, \
                   cudaGetErrorString(err));                        \
            return;                                                 \
        }                                                           \
    }