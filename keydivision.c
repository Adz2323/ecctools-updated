#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <gmp.h>
#include <string.h>
#include <unistd.h>
#include <math.h>
#include <time.h>
#include <pthread.h>
#include <signal.h>
#include "util.h"
#include "gmpecc.h"
#include "bloom/bloom.h"
#include "base58/libbase58.h"
#include "rmd160/rmd160.h"
#include "sha256/sha256.h"
#include "xxhash/xxhash.h"

// Pre-computation and caching structures
#define WINDOW_SIZE 4
#define TABLE_SIZE (1 << WINDOW_SIZE)
#define PARTIAL_KEY_BYTES 8
#define BATCH_SIZE 1000

// Structures
struct PrecomputedPoint
{
    struct Point point;
    bool initialized;
};

// Fast key check structure
typedef struct
{
    unsigned char partial[PARTIAL_KEY_BYTES];
    char *full_key;
    size_t full_length;
} FastKeyCheck;

// Thread structure
typedef struct
{
    uint64_t thread_id;
    struct Point *pubkey;
    mpz_t start_range;
    mpz_t end_range;
    mpz_t k;
    const char *search_pubkey;
    bool *found;
    mpz_t *found_index;
    pthread_mutex_t *mutex;
    mpz_t total_keys;
    FastKeyCheck *fast_check;
} ThreadData;

// Function prototypes
void init_precomputed_table(void);
void Scalar_Multiplication_Custom(struct Point P, struct Point *R, mpz_t m);
void init_bloom_filter(const char *target_pubkey);
void cleanup_bloom(void);
FastKeyCheck *create_fast_key_check(const char *pubkey);
bool fast_key_match(const char *current_pubkey, const FastKeyCheck *checker);
void free_fast_key_check(FastKeyCheck *checker);
void *thread_search(void *arg);
void handle_signal(int sig);
uint64_t load_checkpoint(const char *input_pubkey, const char *search_pubkey, int nbits);
void delete_checkpoint(void);
bool perform_bit_reduction(struct Point *pubkey, int nbits, const char *search_pubkey, int num_threads);
void generate_strpublickey(struct Point *publickey, bool compress, char *dst);
void set_publickey(char *param, struct Point *publickey);

struct Elliptic_Curve EC;
struct Point G;
struct PrecomputedPoint g_table[TABLE_SIZE];
struct Point DoublingG[256];

const char *version = "0.2.231130";
const char *EC_constant_N = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
const char *EC_constant_P = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f";
const char *EC_constant_Gx = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const char *EC_constant_Gy = "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";

const char *formats[3] = {"publickey", "rmd160", "address"};
const char *looks[2] = {"compress", "uncompress"};

// Global variables
volatile bool should_exit = false;
volatile uint64_t current_index = 0;
char checkpoint_pubkey[132];
char checkpoint_target[132];
int checkpoint_nbits = 0;
char checkpoint_filename[256];
bool continuous_mode = false;
int num_threads = 1;
const int MAX_BITS = 40;

// Bloom filter globals
struct bloom bloom_filter;
bool use_bloom = false;

// Auto-subtraction globals
mpz_t base_subtraction;
mpz_t subtraction_increment;
mpz_t subtraction_max;
const char *SUBTRACTION_START = "21778071482940061661655974875633165533184";
const char *SUBTRACTION_INCREMENT = "34028236692093846346337460743176821145";
const char *SUBTRACTION_MAX = "43556142965880123323311949751266331066367";

// Global state
char str_publickey[132];
char str_rmd160[41];
char str_address[41];
struct Point A, B, C;
int FLAG_NUMBER = 0;
mpz_t inversemultiplier, number;

// Pre-computation initialization
void init_precomputed_table()
{
    struct Point temp;
    mpz_init(temp.x);
    mpz_init(temp.y);

    // Initialize first point with G
    mpz_init(g_table[0].point.x);
    mpz_init(g_table[0].point.y);
    mpz_set(g_table[0].point.x, G.x);
    mpz_set(g_table[0].point.y, G.y);
    g_table[0].initialized = true;

    // Pre-compute window points
    for (int i = 1; i < TABLE_SIZE; i++)
    {
        mpz_init(g_table[i].point.x);
        mpz_init(g_table[i].point.y);
        if (i & 1)
        {
            Point_Addition(&g_table[i - 1].point, &G, &g_table[i].point);
        }
        else
        {
            Point_Doubling(&g_table[i / 2].point, &g_table[i].point);
        }
        g_table[i].initialized = true;
    }

    mpz_clear(temp.x);
    mpz_clear(temp.y);
}

// Optimized scalar multiplication using window method
void Scalar_Multiplication_Custom(struct Point P, struct Point *R, mpz_t m)
{
// Using sliding window method with width 4
#define WINDOW_WIDTH 4
#define PRECOMP_SIZE (1 << (WINDOW_WIDTH - 1))

    struct Point precomp[PRECOMP_SIZE];
    struct Point tmp;
    int i, j;
    long no_of_bits;

    // Initialize temporary points
    mpz_init(tmp.x);
    mpz_init(tmp.y);

    // Initialize precomputed points
    for (i = 0; i < PRECOMP_SIZE; i++)
    {
        mpz_init(precomp[i].x);
        mpz_init(precomp[i].y);
    }

    // Precompute odd multiples: 1P, 3P, 5P, 7P, ..., (2^(w-1)-1)P
    mpz_set(precomp[0].x, P.x);
    mpz_set(precomp[0].y, P.y);

    Point_Doubling(&P, &tmp); // Calculate 2P

    for (i = 1; i < PRECOMP_SIZE; i++)
    {
        Point_Addition(&precomp[i - 1], &tmp, &precomp[i]);
    }

    // Initialize result to infinity point
    mpz_set_ui(R->x, 0);
    mpz_set_ui(R->y, 0);

    no_of_bits = mpz_sizeinbase(m, 2);

    // Process bits from left to right
    i = no_of_bits - 1;
    while (i >= 0)
    {
        if (!mpz_tstbit(m, i))
        {
            // If bit is 0, just double
            Point_Doubling(R, &tmp);
            mpz_set(R->x, tmp.x);
            mpz_set(R->y, tmp.y);
            i--;
        }
        else
        {
            // Find longest window of 1's starting at position i
            j = 0;
            int window_val = 0;
            while (j < WINDOW_WIDTH && (i - j) >= 0)
            {
                if (mpz_tstbit(m, i - j))
                    window_val |= (1 << j);
                else
                    break;
                j++;
            }

            // Perform required doublings
            for (int k = 0; k < j; k++)
            {
                Point_Doubling(R, &tmp);
                mpz_set(R->x, tmp.x);
                mpz_set(R->y, tmp.y);
            }

            // Add appropriate precomputed value
            if (window_val > 0)
            {
                int precomp_index = window_val >> 1; // Integer division by 2
                Point_Addition(R, &precomp[precomp_index], &tmp);
                mpz_set(R->x, tmp.x);
                mpz_set(R->y, tmp.y);
            }

            i -= j;
        }
    }

    // Cleanup
    mpz_clear(tmp.x);
    mpz_clear(tmp.y);

    for (i = 0; i < PRECOMP_SIZE; i++)
    {
        mpz_clear(precomp[i].x);
        mpz_clear(precomp[i].y);
    }
}

void get_random_subtraction(mpz_t result)
{
    mpz_t range;
    mpz_init(range);

    // Calculate range
    mpz_sub(range, subtraction_max, base_subtraction);

    // Generate random number
    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, time(NULL));

    mpz_urandomm(result, state, range);
    mpz_add(result, result, base_subtraction);

    gmp_randclear(state);
    mpz_clear(range);
}

// Bloom filter functions
void init_bloom_filter(const char *target_pubkey)
{
    bloom_init2(&bloom_filter, 1000000, 0.001);
    bloom_add(&bloom_filter, target_pubkey, strlen(target_pubkey));
    use_bloom = true;
}

void cleanup_bloom(void)
{
    if (use_bloom)
    {
        bloom_free(&bloom_filter);
    }
}

// Fast key checking functions
FastKeyCheck *create_fast_key_check(const char *pubkey)
{
    FastKeyCheck *checker = (FastKeyCheck *)malloc(sizeof(FastKeyCheck));
    checker->full_length = strlen(pubkey);
    checker->full_key = strdup(pubkey);

    for (size_t i = 0; i < PARTIAL_KEY_BYTES && i < checker->full_length / 2; i++)
    {
        sscanf(pubkey + (i * 2), "%2hhx", &checker->partial[i]);
    }

    return checker;
}

bool fast_key_match(const char *current_pubkey, const FastKeyCheck *checker)
{
    unsigned char current_partial[PARTIAL_KEY_BYTES];
    for (size_t i = 0; i < PARTIAL_KEY_BYTES && i < strlen(current_pubkey) / 2; i++)
    {
        sscanf(current_pubkey + (i * 2), "%2hhx", &current_partial[i]);
    }

    if (memcmp(current_partial, checker->partial, PARTIAL_KEY_BYTES) != 0)
    {
        return false;
    }

    return strcmp(current_pubkey, checker->full_key) == 0;
}

void free_fast_key_check(FastKeyCheck *checker)
{
    if (checker)
    {
        free(checker->full_key);
        free(checker);
    }
}

// Thread search function with batch processing
void *thread_search(void *arg)
{
    ThreadData *data = (ThreadData *)arg;
    char current_pubkey[132];
    struct Point P, R, temp_point;
    mpz_t i, increment;
    uint64_t local_index = 0;

    mpz_init(P.x);
    mpz_init(P.y);
    mpz_init(R.x);
    mpz_init(R.y);
    mpz_init(temp_point.x);
    mpz_init(temp_point.y);
    mpz_init_set(i, data->start_range);
    mpz_init_set_ui(increment, 1);

    FastKeyCheck *checker = create_fast_key_check(data->search_pubkey);
    bool should_continue = true;

    while (mpz_cmp(i, data->end_range) < 0 && !should_exit && should_continue)
    {
        for (int batch = 0; batch < BATCH_SIZE && mpz_cmp(i, data->end_range) < 0; batch++)
        {
            if (*(data->found))
            {
                should_continue = false;
                break;
            }

            local_index = mpz_get_ui(i);

            // Use original scalar multiplication methods
            Scalar_Multiplication(G, &temp_point, i);
            Point_Negation(&temp_point, &R);
            Point_Addition(data->pubkey, &R, &P);
            Scalar_Multiplication_Custom(P, &R, data->k);

            generate_strpublickey(&R, false, current_pubkey);

            if (!use_bloom || bloom_check(&bloom_filter, current_pubkey, strlen(current_pubkey)) != 0)
            {
                if (fast_key_match(current_pubkey, checker))
                {
                    pthread_mutex_lock(data->mutex);
                    if (!*(data->found))
                    {
                        *(data->found) = true;
                        mpz_set(*data->found_index, i);
                        printf("\n[+] Found target public key!\n");
                        printf("[+] Generated at index: %s\n", mpz_get_str(NULL, 10, i));
                        printf("[+] Out of total possible: %s\n", mpz_get_str(NULL, 10, data->total_keys));
                        delete_checkpoint();
                    }
                    pthread_mutex_unlock(data->mutex);
                    should_continue = false;
                    break;
                }
            }

            mpz_add(i, i, increment);
        }

        pthread_mutex_lock(data->mutex);
        current_index = local_index;
        pthread_mutex_unlock(data->mutex);
    }

    mpz_clear(increment);
    free_fast_key_check(checker);
    mpz_clear(i);
    mpz_clear(P.x);
    mpz_clear(P.y);
    mpz_clear(R.x);
    mpz_clear(R.y);
    mpz_clear(temp_point.x);
    mpz_clear(temp_point.y);

    return NULL;
}

// Signal handler
void handle_signal(int sig)
{
    if (sig == SIGINT)
    {
        printf("\n[+] Saving checkpoint...\n");
        should_exit = true;

        FILE *f = fopen(checkpoint_filename, "wb");
        if (f)
        {
            fprintf(f, "%llu\n%s\n%s", current_index, checkpoint_pubkey, checkpoint_target);
            fclose(f);
            printf("[+] Saved at index: %llu\n", current_index);
        }
        cleanup_bloom();
        exit(0);
    }
}

// Checkpoint functions
uint64_t load_checkpoint(const char *input_pubkey, const char *search_pubkey, int nbits)
{
    snprintf(checkpoint_filename, sizeof(checkpoint_filename), "checkpoint_%d.dat", nbits);

    FILE *f = fopen(checkpoint_filename, "r");
    if (f)
    {
        char saved_pubkey[132], saved_target[132];
        uint64_t index;

        if (fscanf(f, "%llu\n%131s\n%131s", &index, saved_pubkey, saved_target) == 3)
        {
            if (strcmp(saved_pubkey, input_pubkey) == 0 &&
                strcmp(saved_target, search_pubkey) == 0)
            {
                printf("[+] Resuming from checkpoint at index: %llu\n", index);
                fclose(f);
                return index;
            }
        }
        fclose(f);
    }
    return 0;
}

void delete_checkpoint()
{
    if (remove(checkpoint_filename) == 0)
    {
        printf("[+] Checkpoint file deleted\n");
    }
}

// Main bit reduction function
bool perform_bit_reduction(struct Point *pubkey, int nbits, const char *search_pubkey, int num_threads)
{
    signal(SIGINT, handle_signal);

    generate_strpublickey(pubkey, false, checkpoint_pubkey);
    strncpy(checkpoint_target, search_pubkey, sizeof(checkpoint_target) - 1);
    checkpoint_nbits = nbits;

    mpz_t total_keys, k, temp;
    bool found = false;
    mpz_t found_index;
    pthread_t *threads;
    ThreadData *thread_args;
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

    current_index = load_checkpoint(checkpoint_pubkey, search_pubkey, nbits);

    mpz_init(total_keys);
    mpz_init(k);
    mpz_init(temp);
    mpz_init(found_index);

    // Initialize pre-computed table
    init_precomputed_table();

    // Calculate total keyspace
    mpz_ui_pow_ui(total_keys, 2, nbits);
    mpz_sub_ui(temp, EC.n, 2);
    mpz_powm(k, total_keys, temp, EC.n);

    init_bloom_filter(search_pubkey);

    printf("[+] Starting search with %d threads...\n", num_threads);
    printf("[+] Target pubkey: %s\n", search_pubkey);
    printf("[+] Total keyspace: %s\n", mpz_get_str(NULL, 10, total_keys));

    time_t start_time = time(NULL);

    threads = (pthread_t *)malloc(num_threads * sizeof(pthread_t));
    thread_args = (ThreadData *)malloc(num_threads * sizeof(ThreadData));

    // Calculate chunk size for better load balancing
    mpz_t chunk_size, remaining, thread_start;
    mpz_init(chunk_size);
    mpz_init(remaining);
    mpz_init(thread_start);

    mpz_sub_ui(remaining, total_keys, current_index);
    mpz_fdiv_q_ui(chunk_size, remaining, num_threads);

    // Create and launch threads
    for (int t = 0; t < num_threads; t++)
    {
        mpz_init(thread_args[t].start_range);
        mpz_init(thread_args[t].end_range);
        mpz_init_set(thread_args[t].k, k);
        mpz_init_set(thread_args[t].total_keys, total_keys);

        // Calculate ranges for each thread
        mpz_mul_ui(thread_start, chunk_size, t);
        mpz_add_ui(thread_start, thread_start, current_index);
        mpz_set(thread_args[t].start_range, thread_start);

        if (t == num_threads - 1)
        {
            mpz_set(thread_args[t].end_range, total_keys);
        }
        else
        {
            mpz_add(thread_args[t].end_range, thread_start, chunk_size);
        }

        thread_args[t].thread_id = t;
        thread_args[t].pubkey = pubkey;
        thread_args[t].found = &found;
        thread_args[t].found_index = &found_index;
        thread_args[t].mutex = &mutex;
        thread_args[t].search_pubkey = search_pubkey;

        pthread_create(&threads[t], NULL, thread_search, &thread_args[t]);
    }

    // Wait for threads to complete
    for (int t = 0; t < num_threads; t++)
    {
        pthread_join(threads[t], NULL);
    }

    time_t end_time = time(NULL);
    printf("\n[+] %s\n", found ? "Search completed - key was found!" : "Search completed - key was not found.");
    printf("[+] Time taken: %ld seconds\n", end_time - start_time);

    // Cleanup
    cleanup_bloom();
    pthread_mutex_destroy(&mutex);

    for (int t = 0; t < num_threads; t++)
    {
        mpz_clear(thread_args[t].start_range);
        mpz_clear(thread_args[t].end_range);
        mpz_clear(thread_args[t].k);
        mpz_clear(thread_args[t].total_keys);
    }

    // Clear pre-computed table
    for (int i = 0; i < TABLE_SIZE; i++)
    {
        if (g_table[i].initialized)
        {
            mpz_clear(g_table[i].point.x);
            mpz_clear(g_table[i].point.y);
        }
    }

    mpz_clear(chunk_size);
    mpz_clear(remaining);
    mpz_clear(thread_start);
    mpz_clear(total_keys);
    mpz_clear(k);
    mpz_clear(temp);
    mpz_clear(found_index);

    free(threads);
    free(thread_args);

    return found;
}

void generate_strpublickey(struct Point *publickey, bool compress, char *dst)
{
    memset(dst, 0, 131);
    if (compress)
    {
        if (mpz_tstbit(publickey->y, 0) == 0)
        {
            gmp_snprintf(dst, 67, "02%0.64Zx", publickey->x);
        }
        else
        {
            gmp_snprintf(dst, 67, "03%0.64Zx", publickey->x);
        }
    }
    else
    {
        gmp_snprintf(dst, 131, "04%0.64Zx%0.64Zx", publickey->x, publickey->y);
    }
}

void set_publickey(char *param, struct Point *publickey)
{
    char hexvalue[65];
    char *dest;
    int len;
    len = strlen(param);
    dest = (char *)calloc(len + 1, 1);
    if (dest == NULL)
    {
        fprintf(stderr, "[E] Error calloc\n");
        exit(0);
    }
    memset(hexvalue, 0, 65);
    memcpy(dest, param, len);
    trim(dest, " \t\n\r");
    len = strlen(dest);

    switch (len)
    {
    case 66:
        mpz_set_str(publickey->x, dest + 2, 16);
        break;
    case 130:
        memcpy(hexvalue, dest + 2, 64);
        mpz_set_str(publickey->x, hexvalue, 16);
        memcpy(hexvalue, dest + 66, 64);
        mpz_set_str(publickey->y, hexvalue, 16);
        if (mpz_cmp_ui(publickey->y, 0) == 0)
        {
            mpz_set_ui(publickey->x, 0);
        }
        else if (mpz_cmp_ui(publickey->x, 0) == 0)
        {
            mpz_set_ui(publickey->y, 0);
        }
        break;
    }

    if (mpz_cmp_ui(publickey->x, 0) == 0)
    {
        mpz_set_ui(publickey->y, 0);
    }
    else if (mpz_cmp_ui(publickey->y, 0) == 0)
    {
        mpz_t mpz_aux, mpz_aux2, Ysquared;
        mpz_init(mpz_aux);
        mpz_init(mpz_aux2);
        mpz_init(Ysquared);

        mpz_pow_ui(mpz_aux, publickey->x, 3);
        mpz_add_ui(mpz_aux2, mpz_aux, 7);
        mpz_mod(Ysquared, mpz_aux2, EC.p);
        mpz_add_ui(mpz_aux, EC.p, 1);
        mpz_fdiv_q_ui(mpz_aux2, mpz_aux, 4);
        mpz_powm(publickey->y, Ysquared, mpz_aux2, EC.p);
        mpz_sub(mpz_aux, EC.p, publickey->y);

        switch (dest[1])
        {
        case '2':
            if (mpz_tstbit(publickey->y, 0) == 1)
            {
                mpz_set(publickey->y, mpz_aux);
            }
            break;
        case '3':
            if (mpz_tstbit(publickey->y, 0) == 0)
            {
                mpz_set(publickey->y, mpz_aux);
            }
            break;
        default:
            fprintf(stderr, "[E] Some invalid bit in the publickey: %s\n", dest);
            exit(0);
            break;
        }

        mpz_clear(mpz_aux);
        mpz_clear(mpz_aux2);
        mpz_clear(Ysquared);
    }
    free(dest);
}

int main(int argc, char **argv)
{
    // Initialize curve constants
    mpz_init_set_str(EC.p, EC_constant_P, 16);
    mpz_init_set_str(EC.n, EC_constant_N, 16);
    mpz_init_set_str(G.x, EC_constant_Gx, 16);
    mpz_init_set_str(G.y, EC_constant_Gy, 16);
    init_doublingG(&G);

    mpz_init_set_ui(A.x, 0);
    mpz_init_set_ui(A.y, 0);
    mpz_init_set_ui(B.x, 0);
    mpz_init_set_ui(B.y, 0);
    mpz_init_set_ui(C.x, 0);
    mpz_init_set_ui(C.y, 0);

    mpz_init(number);
    mpz_init(inversemultiplier);

    if (argc < 4)
    {
        printf("Usage:\n");
        printf("Standard operations: %s <pubkey1> <operation> <pubkey2/number>\n", argv[0]);
        printf("Bit reduction search: %s --reduce <pubkey> <nbits> <search_pubkey> [-t threads] [-c]\n", argv[0]);
        printf("Auto-subtraction: %s --auto-sub <pubkey> <search_pubkey> [-t threads] [-R]\n", argv[0]);
        printf("Operations: +, -, /, x\n");
        printf("Use Ctrl+C to stop and save progress\n");
        exit(0);
    }

    // Handle --reduce command
    if (strcmp(argv[1], "--reduce") == 0)
    {
        if (argc < 5)
        {
            printf("For bit reduction search: %s --reduce <pubkey> <nbits> <search_pubkey> [-t threads] [-c]\n", argv[0]);
            exit(0);
        }

        num_threads = 1;
        continuous_mode = false;

        for (int i = 5; i < argc; i++)
        {
            if (strcmp(argv[i], "-t") == 0 && i + 1 < argc)
            {
                num_threads = atoi(argv[i + 1]);
                i++;
            }
            else if (strcmp(argv[i], "-c") == 0)
            {
                continuous_mode = true;
            }
        }

        set_publickey(argv[2], &A);
        int start_nbits = atoi(argv[3]);
        if (start_nbits <= 0)
        {
            printf("Error: nbits must be greater than 0\n");
            exit(0);
        }

        bool key_found = false;
        int current_bits = start_nbits;

        do
        {
            printf("\n[+] Trying %d bits...\n", current_bits);
            key_found = perform_bit_reduction(&A, current_bits, argv[4], num_threads);

            if (!key_found && continuous_mode && current_bits < MAX_BITS)
            {
                current_bits++;
                printf("\n[+] No match found, increasing to %d bits\n", current_bits);
                sleep(1);
            }
            else
            {
                break;
            }
        } while (continuous_mode && current_bits <= MAX_BITS);

        if (!key_found)
        {
            printf("\n[+] No match found up to %d bits\n", current_bits - 1);
        }

        return 0;
    }

    // Handle --auto-sub command
    if (strcmp(argv[1], "--auto-sub") == 0)
    {
        if (argc < 4)
        {
            printf("Usage: %s --auto-sub <pubkey> <search_pubkey> [-t threads] [-R]\n", argv[0]);
            exit(0);
        }

        int num_threads = 1;
        bool random_mode = false;

        // Check for thread parameter and random mode
        for (int i = 4; i < argc; i++)
        {
            if (strcmp(argv[i], "-t") == 0 && i + 1 < argc)
            {
                num_threads = atoi(argv[i + 1]);
                i++;
            }
            else if (strcmp(argv[i], "-R") == 0)
            {
                random_mode = true;
            }
        }

        struct Point original_pubkey;
        mpz_init(original_pubkey.x);
        mpz_init(original_pubkey.y);
        set_publickey(argv[2], &original_pubkey);

        mpz_init_set_str(base_subtraction, SUBTRACTION_START, 10);
        mpz_init_set_str(subtraction_increment, SUBTRACTION_INCREMENT, 10);
        mpz_init_set_str(subtraction_max, SUBTRACTION_MAX, 10);

        bool found = false;
        uint64_t subtraction_count = 0;
        printf("[+] Starting %s subtraction search...\n", random_mode ? "random" : "sequential");

        while (!found && mpz_cmp(base_subtraction, subtraction_max) <= 0)
        {
            mpz_t current_sub;
            mpz_init(current_sub);

            if (random_mode)
            {
                get_random_subtraction(current_sub);
            }
            else
            {
                mpz_set(current_sub, base_subtraction);
            }

            Point_Negation(&G, &B);
            Scalar_Multiplication(B, &C, current_sub);
            Point_Addition(&original_pubkey, &C, &A);

            char subtracted_pubkey[132];
            generate_strpublickey(&A, true, subtracted_pubkey);
            char *sub_str = mpz_get_str(NULL, 10, current_sub);

            printf("\n[+] After subtracting %s from original pubkey:\n", sub_str);
            printf("[+] New pubkey: %s\n", subtracted_pubkey);
            printf("[+] Starting bit reductions 1-20 on this pubkey...\n\n");
            free(sub_str);

            for (int bits = 1; bits <= 20 && !found; bits++)
            {
                printf("[+] Trying %d bits...\n", bits);
                found = perform_bit_reduction(&A, bits, argv[3], num_threads);

                if (found)
                {
                    printf("\n[+] Found match with subtraction value: %s\n",
                           mpz_get_str(NULL, 10, current_sub));
                    break;
                }
            }

            if (!found)
            {
                if (!random_mode)
                {
                    mpz_add(base_subtraction, base_subtraction, subtraction_increment);
                    char *next_sub = mpz_get_str(NULL, 10, base_subtraction);
                    printf("\n[+] No matches found with current subtraction.");
                    printf("\n[+] Incrementing subtraction to: %s\n", next_sub);
                    free(next_sub);
                }
            }

            mpz_clear(current_sub);
        }

        if (!found)
        {
            printf("\n[+] No match found in entire subtraction range\n");
        }

        // Cleanup
        mpz_clear(base_subtraction);
        mpz_clear(subtraction_increment);
        mpz_clear(subtraction_max);
        mpz_clear(original_pubkey.x);
        mpz_clear(original_pubkey.y);
        return 0;
    }

    // Handle standard operations
    switch (strlen(argv[1]))
    {
    case 66:
    case 130:
        set_publickey(argv[1], &A);
        break;
    default:
        printf("unknown publickey length\n");
        exit(0);
    }

    switch (strlen(argv[3]))
    {
    case 66:
        if (argv[3][0] == '0' && argv[3][1] == 'x')
        {
            mpz_set_str(number, argv[3], 0);
            FLAG_NUMBER = 1;
        }
        else
        {
            set_publickey(argv[3], &B);
            FLAG_NUMBER = 0;
        }
        break;
    case 130:
        set_publickey(argv[3], &B);
        FLAG_NUMBER = 0;
        break;
    default:
        mpz_set_str(number, argv[3], 0);
        FLAG_NUMBER = 1;
        break;
    }

    mpz_mod(number, number, EC.n);
    switch (argv[2][0])
    {
    case '+':
        if (FLAG_NUMBER)
        {
            struct Point temp;
            mpz_init(temp.x);
            mpz_init(temp.y);
            Scalar_Multiplication_Custom(G, &B, number);
            mpz_clear(temp.x);
            mpz_clear(temp.y);
        }
        Point_Addition(&A, &B, &C);
        break;
    case '-':
        if (FLAG_NUMBER)
        {
            struct Point temp;
            mpz_init(temp.x);
            mpz_init(temp.y);
            Scalar_Multiplication_Custom(G, &B, number);
            mpz_clear(temp.x);
            mpz_clear(temp.y);
        }
        Point_Negation(&B, &C);
        mpz_set(B.x, C.x);
        mpz_set(B.y, C.y);
        Point_Addition(&A, &B, &C);
        break;
    case '/':
        if (!FLAG_NUMBER)
        {
            printf("We don't know how to divide 2 publickeys, we need an escalar number\n");
            exit(0);
        }
        mpz_invert(inversemultiplier, number, EC.n);
        struct Point temp;
        mpz_init(temp.x);
        mpz_init(temp.y);
        Scalar_Multiplication_Custom(A, &C, inversemultiplier);
        mpz_clear(temp.x);
        mpz_clear(temp.y);
        break;
    case 'x':
        if (!FLAG_NUMBER)
        {
            printf("We don't know how to multiply 2 publickeys, we need an escalar number\n");
            exit(0);
        }
        struct Point temp2;
        mpz_init(temp2.x);
        mpz_init(temp2.y);
        Scalar_Multiplication_Custom(A, &C, number);
        mpz_clear(temp2.x);
        mpz_clear(temp2.y);
        break;
    }

    generate_strpublickey(&C, true, str_publickey);
    printf("Result: %s\n\n", str_publickey);

    // Cleanup
    mpz_clear(number);
    mpz_clear(inversemultiplier);
    mpz_clear(EC.p);
    mpz_clear(EC.n);
    mpz_clear(G.x);
    mpz_clear(G.y);
    mpz_clear(A.x);
    mpz_clear(A.y);
    mpz_clear(B.x);
    mpz_clear(B.y);
    mpz_clear(C.x);
    mpz_clear(C.y);

    return 0;
}
