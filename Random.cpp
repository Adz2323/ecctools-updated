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

#include "Random.h"

#if defined(_WIN64) && !defined(__CYGWIN__)
#include <windows.h>
#elif defined(__APPLE__)
#include <stdlib.h> // For arc4random on macOS
#else
#include <sys/random.h>
#ifdef __unix__
#include <linux/random.h>
#endif
#endif

#define RK_STATE_LEN 624
#define RK_MAX 0xFFFFFFFFUL

typedef struct
{
    unsigned long key[RK_STATE_LEN];
    int pos;
} rk_state;

rk_state localState;

static inline void rk_seed(unsigned long seed, rk_state *state)
{
    seed &= 0xFFFFFFFFUL;

    for (int pos = 0; pos < RK_STATE_LEN; pos += 4)
    {
        state->key[pos] = seed;
        seed = (1812433253UL * (seed ^ (seed >> 30)) + pos + 1) & 0xFFFFFFFFUL;

        state->key[pos + 1] = seed;
        seed = (1812433253UL * (seed ^ (seed >> 30)) + pos + 2) & 0xFFFFFFFFUL;

        state->key[pos + 2] = seed;
        seed = (1812433253UL * (seed ^ (seed >> 30)) + pos + 3) & 0xFFFFFFFFUL;

        state->key[pos + 3] = seed;
        seed = (1812433253UL * (seed ^ (seed >> 30)) + pos + 4) & 0xFFFFFFFFUL;
    }

    state->pos = RK_STATE_LEN;
}

#define N 624
#define M 397
#define MATRIX_A 0x9908B0DFUL
#define UPPER_MASK 0x80000000UL
#define LOWER_MASK 0x7FFFFFFFUL

#ifdef _WIN64
#pragma warning(disable : 4146)
#endif

static inline unsigned long rk_random(rk_state *state)
{
    unsigned long y;

    if (state->pos == RK_STATE_LEN)
    {
        for (int i = 0; i < N - M; i++)
        {
            y = (state->key[i] & UPPER_MASK) | (state->key[i + 1] & LOWER_MASK);
            state->key[i] = state->key[i + M] ^ (y >> 1) ^ (-(y & 1) & MATRIX_A);
        }
        for (int i = N - M; i < N - 1; i++)
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
    y ^= (y << 7) & 0x9D2C5680UL;
    y ^= (y << 15) & 0xEFC60000UL;
    y ^= (y >> 18);

    return y;
}

static inline double rk_double(rk_state *state)
{
    return (rk_random(state) >> 11) * (1.0 / (0xFFFFFFFF >> 11));
}

void rseed(unsigned long seed)
{
    rk_seed(seed, &localState);
}

unsigned long rndl()
{
#if defined(_WIN64) && !defined(__CYGWIN__)
    return rk_random(&localState);
#elif defined(__APPLE__)
    return arc4random(); // macOS alternative to getrandom()
#else
    unsigned long r;
    ssize_t bytes_read = getrandom(&r, sizeof(unsigned long), GRND_NONBLOCK);
    if (bytes_read == sizeof(unsigned long))
    {
        return r;
    }
    return rk_random(&localState);
#endif
}

double rnd()
{
    return rk_double(&localState);
}
