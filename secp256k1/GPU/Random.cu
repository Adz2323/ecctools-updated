#include "Random.cuh"
#include <cuda_runtime.h>

// Global state for host
static rk_state h_localState;

__device__ void d_rk_seed(unsigned long seed, rk_state *state)
{
    int pos;
    seed &= 0xffffffffUL;

    for (pos = 0; pos < RK_STATE_LEN; pos++)
    {
        state->key[pos] = seed;
        seed = (1812433253UL * (seed ^ (seed >> 30)) + pos + 1) & 0xffffffffUL;
    }
    state->pos = RK_STATE_LEN;
}

__device__ unsigned long d_rk_random(rk_state *state)
{
    unsigned long y;

    if (state->pos == RK_STATE_LEN)
    {
        int i;

        for (i = 0; i < N - M; i++)
        {
            y = (state->key[i] & UPPER_MASK) | (state->key[i + 1] & LOWER_MASK);
            state->key[i] = state->key[i + M] ^ (y >> 1) ^ (-(y & 1) & MATRIX_A);
        }
        for (; i < N - 1; i++)
        {
            y = (state->key[i] & UPPER_MASK) | (state->key[i + 1] & LOWER_MASK);
            state->key[i] = state->key[i + (M - N)] ^ (y >> 1) ^ (-(y & 1) & MATRIX_A);
        }
        y = (state->key[N - 1] & UPPER_MASK) | (state->key[0] & LOWER_MASK);
        state->key[N - 1] = state->key[M - 1] ^ (y >> 1) ^ (-(y & 1) & MATRIX_A);

        state->pos = 0;
    }

    y = state->key[state->pos++];

    y ^= (y >> 11);
    y ^= (y << 7) & 0x9d2c5680UL;
    y ^= (y << 15) & 0xefc60000UL;
    y ^= (y >> 18);

    return y;
}

__device__ double d_rk_double(rk_state *state)
{
    long a = d_rk_random(state) >> 5;
    long b = d_rk_random(state) >> 6;
    return (a * 67108864.0 + b) / 9007199254740992.0;
}

// Host functions
void rseed(unsigned long seed)
{
    // Initialize host state
    int pos;
    seed &= 0xffffffffUL;

    for (pos = 0; pos < RK_STATE_LEN; pos++)
    {
        h_localState.key[pos] = seed;
        seed = (1812433253UL * (seed ^ (seed >> 30)) + pos + 1) & 0xffffffffUL;
    }
    h_localState.pos = RK_STATE_LEN;
}

__global__ void init_rng_kernel(rk_state *states, unsigned long seed, int num_states)
{
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx < num_states)
    {
        d_rk_seed(seed + idx, &states[idx]);
    }
}

__global__ void generate_random_kernel(rk_state *states, double *output, int n)
{
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx < n)
    {
        output[idx] = d_rk_double(&states[idx]);
    }
}

void init_rng_states(rk_state *states, unsigned long seed, int num_states)
{
    const int blockSize = 256;
    const int numBlocks = (num_states + blockSize - 1) / blockSize;
    init_rng_kernel<<<numBlocks, blockSize>>>(states, seed, num_states);
    cudaDeviceSynchronize();
}

void generate_random_numbers(double *d_output, int n)
{
    const int blockSize = 256;
    const int numBlocks = (n + blockSize - 1) / blockSize;

    // Allocate states on device
    rk_state *d_states;
    cudaMalloc(&d_states, n * sizeof(rk_state));

    // Initialize RNG states
    init_rng_states(d_states, time(NULL), n);

    // Generate random numbers
    generate_random_kernel<<<numBlocks, blockSize>>>(d_states, d_output, n);

    // Cleanup
    cudaFree(d_states);
}

// Host wrapper functions
double rnd()
{
    double result;
    double *d_result;
    cudaMalloc(&d_result, sizeof(double));
    generate_random_numbers(d_result, 1);
    cudaMemcpy(&result, d_result, sizeof(double), cudaMemcpyDeviceToHost);
    cudaFree(d_result);
    return result;
}

unsigned long rndl()
{
    return (unsigned long)(rnd() * RK_MAX);
}