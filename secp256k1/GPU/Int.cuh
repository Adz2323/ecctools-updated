#ifndef CUDA_INT_H
#define CUDA_INT_H

#include <cuda_runtime.h>
#include <device_launch_parameters.h>
#include <inttypes.h>
#include <stdio.h>

#define BISIZE 256

#if BISIZE == 256
#define NB64BLOCK 5
#define NB32BLOCK 10
#elif BISIZE == 512
#define NB64BLOCK 9
#define NB32BLOCK 18
#else
#error Unsupported size
#endif

#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#define MIN(x, y) (((x) < (y)) ? (x) : (y))
#define MSK62 0x3FFFFFFFFFFFFFFF

class CudaInt
{
public:
    // Constructors/Destructors
    CudaInt();
    CudaInt(int32_t i32);
    CudaInt(int64_t i64);
    CudaInt(uint64_t u64);
    CudaInt(CudaInt *a);
    ~CudaInt();

    // Memory management
    void AllocateMemory();
    void FreeMemory();
    void CopyToDevice();
    void CopyFromDevice();

    // Core arithmetic operations
    __device__ void Add(uint64_t a);
    __device__ void Add(CudaInt *a);
    __device__ void Add(CudaInt *a, CudaInt *b);
    __device__ void AddOne();
    __device__ void Sub(uint64_t a);
    __device__ void Sub(CudaInt *a);
    __device__ void Sub(CudaInt *a, CudaInt *b);
    __device__ void SubOne();
    __device__ void Mult(CudaInt *a);
    __device__ void Mult(uint64_t a);
    __device__ void IMult(int64_t a);
    __device__ void Mult(CudaInt *a, uint64_t b);
    __device__ void IMult(CudaInt *a, int64_t b);
    __device__ void Mult(CudaInt *a, CudaInt *b);
    __device__ void Div(CudaInt *a, CudaInt *mod = nullptr);
    __device__ void MultModN(CudaInt *a, CudaInt *b, CudaInt *n);
    __device__ void Neg();
    __device__ void Abs();

    // Shift operations
    __device__ void ShiftR(uint32_t n);
    __device__ void ShiftR32Bit();
    __device__ void ShiftR64Bit();
    __device__ void ShiftL(uint32_t n);
    __device__ void ShiftL32Bit();
    __device__ void ShiftL64Bit();
    __device__ void ShiftL32BitAndSub(CudaInt *a, int n);

    // Comparison operations
    __device__ bool IsGreater(CudaInt *a);
    __device__ bool IsGreaterOrEqual(CudaInt *a);
    __device__ bool IsLowerOrEqual(CudaInt *a);
    __device__ bool IsLower(CudaInt *a);
    __device__ bool IsEqual(CudaInt *a);
    __device__ bool IsZero();
    __device__ bool IsOne();
    __device__ bool IsStrictPositive();
    __device__ bool IsPositive();
    __device__ bool IsNegative();
    __device__ bool IsEven();
    __device__ bool IsOdd();

    // Modular arithmetic
    __device__ void GCD(CudaInt *a);
    __device__ void Mod(CudaInt *n);
    __device__ void ModInv();
    __device__ void ModAdd(CudaInt *a);
    __device__ void ModAdd(uint64_t a);
    __device__ void ModAdd(CudaInt *a, CudaInt *b);
    __device__ void ModSub(CudaInt *a);
    __device__ void ModSub(uint64_t a);
    __device__ void ModSub(CudaInt *a, CudaInt *b);
    __device__ void ModMul(CudaInt *a);
    __device__ void ModMul(CudaInt *a, CudaInt *b);
    __device__ void ModSquare(CudaInt *a);
    __device__ void ModDouble();
    __device__ void ModExp(CudaInt *e);
    __device__ void ModNeg();
    __device__ bool HasSqrt();
    __device__ void ModSqrt();
    __device__ void ModMulK1(CudaInt *a, CudaInt *b);
    __device__ void ModMulK1(CudaInt *a);
    __device__ void ModSquareK1(CudaInt *a);
    __device__ void ModMulK1order(CudaInt *a);
    __device__ void ModAddK1order(CudaInt *a, CudaInt *b);

    // Basic getters/setters
    __device__ int GetSize();
    __device__ int GetBitLength();
    __device__ int GetBit(uint32_t n);
    __device__ void Set(CudaInt *a);
    __device__ void SetInt32(uint32_t value);
    __device__ void SetInt64(uint64_t value);
    __device__ void Set32Bytes(unsigned char *bytes);
    __device__ void SetByte(int n, unsigned char byte);
    __device__ void SetDWord(int n, uint32_t b);
    __device__ void SetQWord(int n, uint64_t b);
    __device__ uint64_t GetInt64();
    __device__ uint32_t GetInt32();
    __device__ unsigned char GetByte(int n);
    __device__ void Get32Bytes(unsigned char *buff);
    __device__ void MaskByte(int n);
    __device__ void CLEAR();
    __device__ void CLEARFF();

    // Base conversion
    void SetBase10(const char *value);
    void SetBase16(const char *value);
    void SetBaseN(int n, const char *charset, const char *value);
    char *GetBase10();
    char *GetBase16();
    char *GetBase2();
    char *GetBaseN(int n, const char *charset);
    char *GetBlockStr();
    char *GetC64Str(int nbDigit);

    // Random number generation
    void Rand(int nbit);
    void Rand(CudaInt *min, CudaInt *max);

    // Static field methods
    static void SetupField(CudaInt *n, CudaInt *R = nullptr, CudaInt *R2 = nullptr,
                           CudaInt *R3 = nullptr, CudaInt *R4 = nullptr);
    static void InitK1(CudaInt *order);
    static CudaInt *GetFieldCharacteristic();
    static CudaInt *GetR();
    static CudaInt *GetR2();
    static CudaInt *GetR3();
    static CudaInt *GetR4();

    union
    {
        uint32_t bits[NB32BLOCK];
        uint64_t bits64[NB64BLOCK];
    };

private:
    __device__ uint64_t AddC(CudaInt *a);
    __device__ void AddAndShift(CudaInt *a, CudaInt *b, uint64_t cH);
    __device__ void MontgomeryMult(CudaInt *a, CudaInt *b);
    __device__ void MontgomeryMult(CudaInt *a);

    uint32_t *d_bits;
    uint64_t *d_bits64;
    bool allocated;
};

// CUDA utility functions
__device__ uint64_t cuda_umul128(uint64_t a, uint64_t b, uint64_t *high);
__device__ uint64_t cuda_addcarry_u64(uint64_t a, uint64_t b, uint64_t *out);
__device__ uint64_t cuda_subborrow_u64(uint64_t a, uint64_t b, uint64_t *out);
__device__ void cuda_imm_mul(uint64_t *x, uint64_t y, uint64_t *dst);
__device__ void cuda_shiftR(unsigned char n, uint64_t *d);
__device__ void cuda_shiftL(unsigned char n, uint64_t *d);

// IntGroup class
class CudaIntGroup
{
public:
    CudaIntGroup(int size);
    ~CudaIntGroup();
    void Set(CudaInt *pts);
    void ModInv();

private:
    CudaInt *ints;
    CudaInt *subp;
    int size;
};

#endif // CUDA_INT_H