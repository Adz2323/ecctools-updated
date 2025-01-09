#ifndef RANDOM_CUH
#define RANDOM_CUH

#include <cuda_runtime.h>

#define RK_STATE_LEN 624
#define N 624
#define M 397
#define MATRIX_A 0x9908b0dfUL
#define UPPER_MASK 0x80000000UL
#define LOWER_MASK 0x7fffffffUL
#define RK_MAX 0xFFFFFFFFUL

struct rk_state
{
    unsigned long key[RK_STATE_LEN];
    int pos;
};

// Host functions
void rseed(unsigned long seed);
double rnd();
unsigned long rndl();

// Device functions
__device__ void d_rk_seed(unsigned long seed, rk_state *state);
__device__ unsigned long d_rk_random(rk_state *state);
__device__ double d_rk_double(rk_state *state);

// Kernel launchers
void init_rng_states(rk_state *states, unsigned long seed, int num_states);
void generate_random_numbers(double *d_output, int n);

#endif