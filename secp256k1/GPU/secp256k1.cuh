#ifndef SECP256K1_CUH
#define SECP256K1_CUH

#include <cuda_runtime.h>
#include "Point.h"
#include <vector>

// Address type definitions
#define P2PKH 0
#define P2SH 1
#define BECH32 2

class Secp256K1_CUDA
{
public:
    Secp256K1_CUDA();
    ~Secp256K1_CUDA();

    void Init();
    void InitCUDA(); // Initialize CUDA resources
    void Cleanup();  // Cleanup CUDA resources

    // Host functions
    __host__ Point ComputePublicKey(Int *privKey);
    __host__ Point NextKey(Point &key);
    __host__ bool EC(Point &p);
    __host__ Int GetY(Int x, bool isEven);

    // CUDA kernel wrappers
    __host__ void BatchComputePublicKeys(Int *privKeys, Point *publicKeys, int count);
    __host__ void BatchNextKeys(Point *keys, int count);

    // Device functions
    __device__ Point DeviceComputePublicKey(Int *privKey);
    __device__ Point DeviceNextKey(Point &key);
    __device__ bool DeviceEC(Point &p);
    __device__ Int DeviceGetY(Int x, bool isEven);

    // Point operations
    __host__ __device__ Point Add(Point &p1, Point &p2);
    __host__ __device__ Point AddDirect(Point &p1, Point &p2);
    __host__ __device__ Point Double(Point &p);
    __host__ __device__ Point DoubleDirect(Point &p);
    __host__ __device__ Point Negation(Point &p);

    // Public key operations
    __host__ bool ParsePublicKeyHex(char *str, Point &p, bool &isCompressed);
    __host__ void GetPublicKeyHex(bool compressed, Point &pubKey, char *dst);
    __host__ void GetPublicKeyRaw(bool compressed, Point &pubKey, char *dst);

    // Hash operations
    __host__ void GetHash160(int type, bool compressed,
                             Point &k0, Point &k1, Point &k2, Point &k3,
                             uint8_t *h0, uint8_t *h1, uint8_t *h2, uint8_t *h3);

    __host__ void GetHash160(int type, bool compressed,
                             Point &pubKey, unsigned char *hash);

    // Constants
    Point G;   // Generator point
    Int P;     // Prime for finite field
    Int order; // Curve order

private:
    // Device memory pointers
    Point *d_GTable; // Generator table on device
    Point *d_points; // Temporary point storage
    Int *d_scalars;  // Temporary scalar storage

    // Host memory
    Point *h_GTable; // Generator table on host

    // Utility functions
    __host__ uint8_t GetByte(char *str, int idx);
    __host__ void CopyToDevice();
    __host__ void CopyFromDevice();

    // CUDA parameters
    static const int BLOCK_SIZE = 256;
    static const int MAX_BLOCKS = 65535;
};

// Global CUDA kernel declarations
__global__ void computePublicKeysKernel(Int *privKeys, Point *publicKeys,
                                        Point *gTable, int count);
__global__ void nextKeysKernel(Point *keys, Point g, int count);

#endif // SECP256K1_CUH