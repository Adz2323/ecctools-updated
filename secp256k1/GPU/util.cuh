#ifndef CUDA_UTIL_H
#define CUDA_UTIL_H

#include <cuda_runtime.h>
#include <device_launch_parameters.h>

typedef struct str_list
{
    int n;
    char **data;
    int *lengths;
} List;

typedef struct str_tokenizer
{
    int current;
    int n;
    char **tokens;
} Tokenizer;

// Device helper functions
__device__ size_t d_strlen(const char *str);
__device__ char *d_strchr(const char *str, int c);
__device__ size_t d_strspn(const char *str, const char *accept);
__device__ void d_memmove(void *dest, const void *src, size_t n);

// Device functions
__device__ char *d_ltrim(char *str, const char *seps);
__device__ char *d_rtrim(char *str, const char *seps);
__device__ char *d_trim(char *str, const char *seps);
__device__ int d_indexOf(char *s, const char **array, int length_array);
__device__ int d_hexchr2bin(const char hex, char *out);
__device__ int d_hexs2bin(char *hex, unsigned char *out);
__device__ void d_tohex_dst(char *ptr, int length, char *dst);
__device__ int d_isValidHex(char *data);

// Host functions
__host__ char *cuda_ltrim(char *str, const char *seps);
__host__ char *cuda_rtrim(char *str, const char *seps);
__host__ char *cuda_trim(char *str, const char *seps);
__host__ int cuda_indexOf(char *s, const char **array, int length_array);
__host__ char *cuda_tohex(char *ptr, int length);
__host__ void cuda_tohex_dst(char *ptr, int length, char *dst);
__host__ int cuda_hexs2bin(char *hex, unsigned char *out);
__host__ int cuda_hexchr2bin(const char hex, char *out);
__host__ char *cuda_nextToken(Tokenizer *t);
__host__ int cuda_hasMoreTokens(Tokenizer *t);
__host__ void cuda_stringtokenizer(char *data, Tokenizer *t);
__host__ void cuda_freetokenizer(Tokenizer *t);
__host__ void cuda_addItemList(char *data, List *l);
__host__ int cuda_isValidHex(char *data);

// CUDA kernels
__global__ void ltrimKernel(char *str, const char *seps);
__global__ void rtrimKernel(char *str, const char *seps);
__global__ void trimKernel(char *str, const char *seps);
__global__ void indexOfKernel(char *s, const char **array, int length_array, int *result);
__global__ void hexchr2binKernel(const char hex, char *out, int *result);
__global__ void hexs2binKernel(char *hex, unsigned char *out, int *length);
__global__ void tohexKernel(char *ptr, int length, char *hex_string);
__global__ void isValidHexKernel(char *data, int *result);

// Helper functions
__host__ void checkCudaError(cudaError_t error, const char *msg);

#endif
