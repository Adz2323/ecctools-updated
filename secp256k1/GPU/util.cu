#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "util.cuh"

// Device helper functions implementation
__device__ size_t d_strlen(const char *str)
{
    size_t len = 0;
    while (str[len] != '\0')
        len++;
    return len;
}

__device__ char *d_strchr(const char *str, int c)
{
    while (*str != '\0' && *str != c)
        str++;
    return (*str == c) ? (char *)str : NULL;
}

__device__ size_t d_strspn(const char *str, const char *accept)
{
    size_t count = 0;
    while (*str)
    {
        if (!d_strchr(accept, *str))
            break;
        str++;
        count++;
    }
    return count;
}

__device__ void d_memmove(void *dest, const void *src, size_t n)
{
    char *d = (char *)dest;
    const char *s = (const char *)src;
    if (d > s)
    {
        d += n - 1;
        s += n - 1;
        while (n--)
            *d-- = *s--;
    }
    else if (d < s)
    {
        while (n--)
            *d++ = *s++;
    }
}

// Device functions implementation
__device__ char *d_ltrim(char *str, const char *seps)
{
    size_t totrim;
    if (seps == NULL)
    {
        seps = "\t\n\v\f\r ";
    }
    totrim = d_strspn(str, seps);
    if (totrim > 0)
    {
        size_t len = d_strlen(str);
        if (totrim == len)
        {
            str[0] = '\0';
        }
        else
        {
            d_memmove(str, str + totrim, len + 1 - totrim);
        }
    }
    return str;
}

__device__ char *d_rtrim(char *str, const char *seps)
{
    if (seps == NULL)
    {
        seps = "\t\n\v\f\r ";
    }
    int i = d_strlen(str) - 1;
    while (i >= 0 && d_strchr(seps, str[i]) != NULL)
    {
        str[i] = '\0';
        i--;
    }
    return str;
}

__device__ char *d_trim(char *str, const char *seps)
{
    return d_ltrim(d_rtrim(str, seps), seps);
}

__device__ int d_indexOf(char *s, const char **array, int length_array)
{
    int index = -1;
    for (int i = 0; i < length_array; i++)
    {
        bool equal = true;
        int j = 0;
        while (s[j] != '\0' && array[i][j] != '\0')
        {
            if (s[j] != array[i][j])
            {
                equal = false;
                break;
            }
            j++;
        }
        if (equal && s[j] == '\0' && array[i][j] == '\0')
        {
            index = i;
            break;
        }
    }
    return index;
}

__device__ int d_hexchr2bin(const char hex, char *out)
{
    if (out == NULL)
        return 0;

    if (hex >= '0' && hex <= '9')
    {
        *out = hex - '0';
    }
    else if (hex >= 'A' && hex <= 'F')
    {
        *out = hex - 'A' + 10;
    }
    else if (hex >= 'a' && hex <= 'f')
    {
        *out = hex - 'a' + 10;
    }
    else
    {
        return 0;
    }

    return 1;
}

__device__ int d_hexs2bin(char *hex, unsigned char *out)
{
    int len;
    char b1, b2;

    if (hex == NULL || *hex == '\0' || out == NULL)
        return 0;

    len = d_strlen(hex);
    if (len % 2 != 0)
        return 0;

    len /= 2;
    for (int i = 0; i < len; i++)
    {
        if (!d_hexchr2bin(hex[i * 2], &b1) || !d_hexchr2bin(hex[i * 2 + 1], &b2))
        {
            return 0;
        }
        out[i] = (b1 << 4) | b2;
    }
    return len;
}

__device__ void d_tohex_dst(char *ptr, int length, char *dst)
{
    if (ptr == NULL || length <= 0)
        return;

    for (int i = 0; i < length; i++)
    {
        int high = ((uint8_t)ptr[i] >> 4) & 0x0F;
        int low = (uint8_t)ptr[i] & 0x0F;
        dst[i * 2] = high < 10 ? '0' + high : 'a' + (high - 10);
        dst[i * 2 + 1] = low < 10 ? '0' + low : 'a' + (low - 10);
    }
    dst[length * 2] = 0;
}

__device__ int d_isValidHex(char *data)
{
    int len = d_strlen(data);
    for (int i = 0; i < len; i++)
    {
        char c = data[i];
        if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')))
        {
            return 0;
        }
    }
    return 1;
}

// CUDA kernels implementation
__global__ void ltrimKernel(char *str, const char *seps)
{
    if (threadIdx.x == 0)
    {
        d_ltrim(str, seps);
    }
}

__global__ void rtrimKernel(char *str, const char *seps)
{
    if (threadIdx.x == 0)
    {
        d_rtrim(str, seps);
    }
}

__global__ void trimKernel(char *str, const char *seps)
{
    if (threadIdx.x == 0)
    {
        d_trim(str, seps);
    }
}

__global__ void indexOfKernel(char *s, const char **array, int length_array, int *result)
{
    if (threadIdx.x == 0)
    {
        *result = d_indexOf(s, array, length_array);
    }
}

__global__ void hexchr2binKernel(const char hex, char *out, int *result)
{
    if (threadIdx.x == 0)
    {
        *result = d_hexchr2bin(hex, out);
    }
}

__global__ void hexs2binKernel(char *hex, unsigned char *out, int *length)
{
    if (threadIdx.x == 0)
    {
        *length = d_hexs2bin(hex, out);
    }
}

__global__ void tohexKernel(char *ptr, int length, char *hex_string)
{
    if (threadIdx.x == 0)
    {
        d_tohex_dst(ptr, length, hex_string);
    }
}

__global__ void isValidHexKernel(char *data, int *result)
{
    if (threadIdx.x == 0)
    {
        *result = d_isValidHex(data);
    }
}

// Host functions implementation
__host__ char *cuda_ltrim(char *str, const char *seps)
{
    char *d_str, *d_seps;
    size_t str_len = strlen(str) + 1;
    size_t seps_len = seps ? strlen(seps) + 1 : 7;

    cudaMalloc(&d_str, str_len);
    cudaMalloc(&d_seps, seps_len);

    cudaMemcpy(d_str, str, str_len, cudaMemcpyHostToDevice);
    cudaMemcpy(d_seps, seps ? seps : "\t\n\v\f\r ", seps_len, cudaMemcpyHostToDevice);

    ltrimKernel<<<1, 1>>>(d_str, d_seps);
    cudaDeviceSynchronize();

    cudaMemcpy(str, d_str, str_len, cudaMemcpyDeviceToHost);

    cudaFree(d_str);
    cudaFree(d_seps);

    return str;
}

__host__ char *cuda_rtrim(char *str, const char *seps)
{
    char *d_str, *d_seps;
    size_t str_len = strlen(str) + 1;
    size_t seps_len = seps ? strlen(seps) + 1 : 7;

    cudaMalloc(&d_str, str_len);
    cudaMalloc(&d_seps, seps_len);

    cudaMemcpy(d_str, str, str_len, cudaMemcpyHostToDevice);
    cudaMemcpy(d_seps, seps ? seps : "\t\n\v\f\r ", seps_len, cudaMemcpyHostToDevice);

    rtrimKernel<<<1, 1>>>(d_str, d_seps);
    cudaDeviceSynchronize();

    cudaMemcpy(str, d_str, str_len, cudaMemcpyDeviceToHost);

    cudaFree(d_str);
    cudaFree(d_seps);

    return str;
}

__host__ char *cuda_trim(char *str, const char *seps)
{
    char *d_str, *d_seps;
    size_t str_len = strlen(str) + 1;
    size_t seps_len = seps ? strlen(seps) + 1 : 7;

    cudaMalloc(&d_str, str_len);
    cudaMalloc(&d_seps, seps_len);

    cudaMemcpy(d_str, str, str_len, cudaMemcpyHostToDevice);
    cudaMemcpy(d_seps, seps ? seps : "\t\n\v\f\r ", seps_len, cudaMemcpyHostToDevice);

    trimKernel<<<1, 1>>>(d_str, d_seps);
    cudaDeviceSynchronize();

    cudaMemcpy(str, d_str, str_len, cudaMemcpyDeviceToHost);

    cudaFree(d_str);
    cudaFree(d_seps);

    return str;
}

__host__ int cuda_indexOf(char *s, const char **array, int length_array)
{
    char *d_s;
    char **d_array;
    int *d_result, result;

    cudaMalloc(&d_s, strlen(s) + 1);
    cudaMalloc(&d_array, length_array * sizeof(char *));
    cudaMalloc(&d_result, sizeof(int));

    cudaMemcpy(d_s, s, strlen(s) + 1, cudaMemcpyHostToDevice);
    cudaMemcpy(d_array, array, length_array * sizeof(char *), cudaMemcpyHostToDevice);

    indexOfKernel<<<1, 1>>>(d_s, d_array, length_array, d_result);
    cudaDeviceSynchronize();

    cudaMemcpy(&result, d_result, sizeof(int), cudaMemcpyDeviceToHost);

    cudaFree(d_s);
    cudaFree(d_array);
    cudaFree(d_result);

    return result;
}

__host__ char *cuda_tohex(char *ptr, int length)
{
    if (ptr == NULL || length <= 0)
        return NULL;

    char *hex_string = (char *)calloc((2 * length) + 1, sizeof(char));
    if (hex_string == NULL)
    {
        fprintf(stderr, "Error calloc()\n");
        return NULL;
    }

    char *d_ptr, *d_hex;
    cudaMalloc(&d_ptr, length);
    cudaMalloc(&d_hex, (2 * length) + 1);

    cudaMemcpy(d_ptr, ptr, length, cudaMemcpyHostToDevice);

    tohexKernel<<<1, 1>>>(d_ptr, length, d_hex);
    cudaDeviceSynchronize();

    cudaMemcpy(hex_string, d_hex, (2 * length) + 1, cudaMemcpyDeviceToHost);

    cudaFree(d_ptr);
    cudaFree(d_hex);

    return hex_string;
}

__host__ void cuda_tohex_dst(char *ptr, int length, char *dst)
{
    if (ptr == NULL || length <= 0)
        return;

    char *d_ptr, *d_dst;
    cudaMalloc(&d_ptr, length);
    cudaMalloc(&d_dst, (2 * length) + 1);

    cudaMemcpy(d_ptr, ptr, length, cudaMemcpyHostToDevice);

    tohexKernel<<<1, 1>>>(d_ptr, length, d_dst);
    cudaDeviceSynchronize();

    cudaMemcpy(dst, d_dst, (2 * length) + 1, cudaMemcpyDeviceToHost);

    cudaFree(d_ptr);
    cudaFree(d_dst);
}

__host__ int cuda_hexchr2bin(const char hex, char *out)
{
    char *d_out;
    int *d_result, result;

    cudaMalloc(&d_out, sizeof(char));
    cudaMalloc(&d_result, sizeof(int));

    hexchr2binKernel<<<1, 1>>>(hex, d_out, d_result);
    cudaDeviceSynchronize();

    cudaMemcpy(out, d_out, sizeof(char), cudaMemcpyDeviceToHost);
    cudaMemcpy(&result, d_result, sizeof(int), cudaMemcpyDeviceToHost);

    cudaFree(d_out);
    cudaFree(d_result);

    return result;
}

__host__ int cuda_hexs2bin(char *hex, unsigned char *out)
{
    if (hex == NULL || *hex == '\0' || out == NULL)
        return 0;

    char *d_hex;
    unsigned char *d_out;
    int *d_length, length;

    size_t hex_len = strlen(hex) + 1;
    size_t out_len = hex_len / 2;

    cudaMalloc(&d_hex, hex_len);
    cudaMalloc(&d_out, out_len);
    cudaMalloc(&d_length, sizeof(int));

    cudaMemcpy(d_hex, hex, hex_len, cudaMemcpyHostToDevice);

    hexs2binKernel<<<1, 1>>>(d_hex, d_out, d_length);
    cudaDeviceSynchronize();

    cudaMemcpy(out, d_out, out_len, cudaMemcpyDeviceToHost);
    cudaMemcpy(&length, d_length, sizeof(int), cudaMemcpyDeviceToHost);

    cudaFree(d_hex);
    cudaFree(d_out);
    cudaFree(d_length);

    return length;
}

__host__ char *cuda_nextToken(Tokenizer *t)
{
    if (t->current < t->n)
    {
        t->current++;
        return t->tokens[t->current - 1];
    }
    return NULL;
}

__host__ int cuda_hasMoreTokens(Tokenizer *t)
{
    return (t->current < t->n);
}

__host__ void cuda_stringtokenizer(char *data, Tokenizer *t)
{
    t->tokens = NULL;
    t->n = 0;
    t->current = 0;

    cuda_trim(data, "\t\n\r ");

    char *token = strtok(data, " \t:");
    while (token != NULL)
    {
        t->n++;
        t->tokens = (char **)realloc(t->tokens, sizeof(char *) * t->n);
        if (t->tokens == NULL)
        {
            printf("Out of memory\n");
            exit(0);
        }
        t->tokens[t->n - 1] = token;
        token = strtok(NULL, " \t");
    }
}

__host__ void cuda_freetokenizer(Tokenizer *t)
{
    if (t->n > 0)
    {
        free(t->tokens);
    }
    memset(t, 0, sizeof(Tokenizer));
}

__host__ void cuda_addItemList(char *data, List *l)
{
    l->data = (char **)realloc(l->data, sizeof(char *) * (l->n + 1));
    l->data[l->n] = data;
    l->n++;
}

__host__ int cuda_isValidHex(char *data)
{
    char *d_data;
    int *d_result, result;
    size_t data_len = strlen(data) + 1;

    cudaMalloc(&d_data, data_len);
    cudaMalloc(&d_result, sizeof(int));

    cudaMemcpy(d_data, data, data_len, cudaMemcpyHostToDevice);

    isValidHexKernel<<<1, 1>>>(d_data, d_result);
    cudaDeviceSynchronize();

    cudaMemcpy(&result, d_result, sizeof(int), cudaMemcpyDeviceToHost);

    cudaFree(d_data);
    cudaFree(d_result);

    return result;
}

__host__ void checkCudaError(cudaError_t error, const char *msg)
{
    if (error != cudaSuccess)
    {
        fprintf(stderr, "CUDA Error: %s: %s\n", msg, cudaGetErrorString(error));
        exit(EXIT_FAILURE);
    }
}