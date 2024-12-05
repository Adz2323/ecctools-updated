#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include <immintrin.h>
#include <stdbool.h>
#include "secp256k1/SECP256k1.h"
#include "secp256k1/Point.h"
#include "secp256k1/Int.h"
#include "bloom/bloom.h"
#include "xxhash/xxhash.h"

// Enhanced configuration for better performance
#define BATCH_SIZE 1024 // Increased batch size for SIMD
#define MAX_THREADS 256
#define MAX_BITS 40
#define BUFFER_SIZE (1024 * 1024) // 1MB buffer for file I/O
#define POINT_POOL_SIZE 2048
#define PREFETCH_DISTANCE 8

Secp256K1 secp;

// Global state
volatile bool should_exit = false;
volatile uint64_t current_index = 0;
char checkpoint_pubkey[132];
char checkpoint_target[132];
int checkpoint_nbits = 0;
char checkpoint_filename[256];
char keys_filename[256];
bool continuous_mode = false;
int num_threads = 1;
struct bloom bloom_filter;
bool use_bloom = false;
pthread_mutex_t file_mutex = PTHREAD_MUTEX_INITIALIZER;
FILE *keys_file = NULL;

// Optimized buffer for key writing
typedef struct
{
    char *buffer;
    size_t buffer_pos;
    size_t buffer_size;
    FILE *file;
    pthread_mutex_t mutex;
} KeyBuffer;

// Thread data structure with optimizations
typedef struct
{
    uint64_t thread_id;
    Point pubkey;
    Int start_range;
    Int end_range;
    Int k;
    const char *search_pubkey;
    bool *found;
    Int *found_index;
    pthread_mutex_t *mutex;
    Int total_keys;
    KeyBuffer *key_buffer;
    char *batch_buffer; // Pre-allocated buffer for batch processing
} ThreadData;

// Point pool for efficient memory management
typedef struct
{
    Point *points;
    bool *used;
    size_t size;
    pthread_mutex_t mutex;
} PointPool;

// Global point pool
PointPool point_pool = {0};

// Initialize point pool
void init_point_pool()
{
    point_pool.size = POINT_POOL_SIZE;
    point_pool.points = (Point *)aligned_alloc(32, sizeof(Point) * POINT_POOL_SIZE);
    point_pool.used = (bool *)calloc(POINT_POOL_SIZE, sizeof(bool));
    pthread_mutex_init(&point_pool.mutex, NULL);
}

// Get point from pool
Point *acquire_point()
{
    pthread_mutex_lock(&point_pool.mutex);
    for (size_t i = 0; i < point_pool.size; i++)
    {
        if (!point_pool.used[i])
        {
            point_pool.used[i] = true;
            pthread_mutex_unlock(&point_pool.mutex);
            return &point_pool.points[i];
        }
    }
    pthread_mutex_unlock(&point_pool.mutex);
    return NULL;
}

// Return point to pool
void release_point(Point *p)
{
    size_t index = (p - point_pool.points);
    if (index < point_pool.size)
    {
        pthread_mutex_lock(&point_pool.mutex);
        point_pool.used[index] = false;
        pthread_mutex_unlock(&point_pool.mutex);
    }
}

// Initialize key buffer
KeyBuffer *init_key_buffer(FILE *file)
{
    KeyBuffer *kb = (KeyBuffer *)malloc(sizeof(KeyBuffer));
    kb->buffer = (char *)malloc(BUFFER_SIZE);
    kb->buffer_pos = 0;
    kb->buffer_size = BUFFER_SIZE;
    kb->file = file;
    pthread_mutex_init(&kb->mutex, NULL);
    return kb;
}

// Write key to buffer
void write_key_buffered(KeyBuffer *kb, const char *key)
{
    size_t key_len = strlen(key);
    pthread_mutex_lock(&kb->mutex);

    if (kb->buffer_pos + key_len + 2 >= kb->buffer_size)
    {
        fwrite(kb->buffer, 1, kb->buffer_pos, kb->file);
        kb->buffer_pos = 0;
    }

    memcpy(kb->buffer + kb->buffer_pos, key, key_len);
    kb->buffer_pos += key_len;
    kb->buffer[kb->buffer_pos++] = '\n';

    pthread_mutex_unlock(&kb->mutex);
}

// Flush buffer
void flush_key_buffer(KeyBuffer *kb)
{
    pthread_mutex_lock(&kb->mutex);
    if (kb->buffer_pos > 0)
    {
        fwrite(kb->buffer, 1, kb->buffer_pos, kb->file);
        kb->buffer_pos = 0;
    }
    pthread_mutex_unlock(&kb->mutex);
}

// Cleanup key buffer
void cleanup_key_buffer(KeyBuffer *kb)
{
    flush_key_buffer(kb);
    free(kb->buffer);
    pthread_mutex_destroy(&kb->mutex);
    free(kb);
}

void init_bloom_filter(const char *target_pubkey)
{
    bloom_init2(&bloom_filter, 10000000, 0.0001);
    bloom_add(&bloom_filter, target_pubkey, strlen(target_pubkey));
    use_bloom = true;
}

void cleanup_bloom()
{
    if (use_bloom)
    {
        bloom_free(&bloom_filter);
    }
}

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

        if (keys_file)
        {
            fclose(keys_file);
        }

        cleanup_bloom();
        exit(0);
    }
}

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
    remove(checkpoint_filename);
}

// Fix for the Int* compatibility issue
void process_point_batch(Point *points, Int *keys, int batch_size)
{
#pragma omp simd
    for (int i = 0; i < batch_size; i++)
    {
        // Create a copy of the key to match the function signature
        Int privKey;
        privKey.Set(&keys[i]);
        points[i] = secp.ComputePublicKey(&privKey);
    }
}

void *thread_search(void *arg)
{
    ThreadData *data = (ThreadData *)arg;
    char current_pubkey[132];
    Point Q, R;
    Int i(data->start_range);
    Int increment((uint64_t)1);
    uint64_t local_index = 0;

    // Fix the batch array declarations
    Int *batch_keys = (Int *)aligned_alloc(32, sizeof(Int) * BATCH_SIZE);
    Point *batch_points = (Point *)aligned_alloc(32, sizeof(Point) * BATCH_SIZE);
    // Fix the array declaration
    char **batch_pubkeys = (char **)malloc(sizeof(char *) * BATCH_SIZE);
    for (int i = 0; i < BATCH_SIZE; i++)
    {
        batch_pubkeys[i] = (char *)malloc(132); // Allocate each string separately
    }

    while (i.IsLower(&data->end_range) && !should_exit)
    {
        int batch_count = 0;

        // Fill batch
        while (batch_count < BATCH_SIZE && i.IsLower(&data->end_range))
        {
            batch_keys[batch_count].Set(&i);

            // Prefetch next iteration's data
            _mm_prefetch(&batch_keys[batch_count + PREFETCH_DISTANCE], _MM_HINT_T0);

            i.Add(&increment);
            batch_count++;
        }

        // Process batch
        process_point_batch(batch_points, batch_keys, batch_count);

        // Process results
        for (int j = 0; j < batch_count; j++)
        {
            if (*(data->found))
                goto cleanup;

            local_index = batch_keys[j].GetInt64();

            Q = batch_points[j];
            Point negQ = secp.Negation(Q);
            R = secp.AddDirect(data->pubkey, negQ);

            secp.GetPublicKeyHex(true, R, batch_pubkeys[j]);

            // Buffered write
            write_key_buffered(data->key_buffer, batch_pubkeys[j]);

            if (!use_bloom || bloom_check(&bloom_filter, batch_pubkeys[j], strlen(batch_pubkeys[j])))
            {
                if (strcmp(batch_pubkeys[j], data->search_pubkey) == 0)
                {
                    pthread_mutex_lock(data->mutex);
                    if (!*(data->found))
                    {
                        *(data->found) = true;
                        data->found_index->Set(&batch_keys[j]);
                        printf("\n[+] Found target public key!\n");
                        printf("[+] Generated at index: %s\n", batch_keys[j].GetBase10());

                        // Calculate final private key
                        Int base;
                        base.SetBase16("0000000000000000000000000000000000000000000000000000000000000001");
                        base.Add(&batch_keys[j]);
                        printf("[+] Final private key: 0x%s\n", base.GetBase16());

                        delete_checkpoint();
                        should_exit = true;
                    }
                    pthread_mutex_unlock(data->mutex);
                    goto cleanup;
                }
            }
        }

        pthread_mutex_lock(data->mutex);
        current_index = local_index;
        pthread_mutex_unlock(data->mutex);
    }

cleanup:
    free(batch_keys);
    free(batch_points);
    // Fix the cleanup of batch_pubkeys
    for (int i = 0; i < BATCH_SIZE; i++)
    {
        free(batch_pubkeys[i]);
    }
    free(batch_pubkeys);
    return NULL;
}

bool perform_bit_reduction(Point *pubkey, int nbits, const char *search_pubkey, int num_threads)
{
    signal(SIGINT, handle_signal);

    // Save checkpoint info
    secp.GetPublicKeyHex(false, *pubkey, checkpoint_pubkey);
    strncpy(checkpoint_target, search_pubkey, sizeof(checkpoint_target) - 1);
    checkpoint_nbits = nbits;

    // Open keys file
    snprintf(keys_filename, sizeof(keys_filename), "pubkeys_%d.txt", nbits);
    keys_file = fopen(keys_filename, "a");
    if (!keys_file)
    {
        printf("Error: Could not open keys file for writing\n");
        return false;
    }

    // Initialize optimizations
    init_point_pool();
    KeyBuffer *key_buffer = init_key_buffer(keys_file);

    Int total_keys;
    bool found = false;
    Int found_index;
    pthread_t *threads;
    ThreadData *thread_args;
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

    current_index = load_checkpoint(checkpoint_pubkey, search_pubkey, nbits);

    // Calculate total keyspace
    total_keys.SetInt32(1);
    Int two((uint64_t)2);
    for (int i = 0; i < nbits; i++)
    {
        total_keys.Mult(&two);
    }

    init_bloom_filter(search_pubkey);

    printf("[+] Starting search with %d threads...\n", num_threads);
    printf("[+] Target pubkey: %s\n", search_pubkey);
    printf("[+] Total keyspace: %s\n", total_keys.GetBase10());
    printf("[+] Saving pubkeys to: %s\n", keys_filename);

    time_t start_time = time(NULL);

    // Allocate thread resources
    threads = (pthread_t *)malloc(num_threads * sizeof(pthread_t));
    thread_args = (ThreadData *)malloc(num_threads * sizeof(ThreadData));

    // Calculate ranges for threads
    Int chunk_size, remaining;
    remaining.Set(&total_keys);
    Int current_idx;
    current_idx.SetInt32(current_index);
    remaining.Sub(&current_idx);

    Int divisor;
    divisor.SetInt32(num_threads);
    chunk_size.Set(&remaining);
    chunk_size.Div(&divisor);

    // Launch threads
    for (int t = 0; t < num_threads; t++)
    {
        thread_args[t].thread_id = t;
        thread_args[t].pubkey.Set(*pubkey);
        thread_args[t].found = &found;
        thread_args[t].found_index = &found_index;
        thread_args[t].mutex = &mutex;
        thread_args[t].search_pubkey = search_pubkey;
        thread_args[t].total_keys.Set(&total_keys);
        thread_args[t].key_buffer = key_buffer;

        // Calculate thread range
        Int t_index;
        t_index.SetInt32(t);
        thread_args[t].start_range.Set(&chunk_size);
        thread_args[t].start_range.Mult(&t_index);
        thread_args[t].start_range.Add(&current_idx);

        if (t == num_threads - 1)
        {
            thread_args[t].end_range.Set(&total_keys);
        }
        else
        {
            thread_args[t].end_range.Set(&thread_args[t].start_range);
            thread_args[t].end_range.Add(&chunk_size);
        }

        pthread_create(&threads[t], NULL, thread_search, &thread_args[t]);
    }

    // Wait for threads
    for (int t = 0; t < num_threads; t++)
    {
        pthread_join(threads[t], NULL);
    }

    time_t end_time = time(NULL);
    if (found)
    {
        printf("[+] Search completed successfully!\n");
    }
    else
    {
        printf("\n[+] Search completed - key was not found.\n");
    }
    printf("[+] Time taken: %ld seconds\n", end_time - start_time);

    // Cleanup
    cleanup_key_buffer(key_buffer);
    cleanup_bloom();
    pthread_mutex_destroy(&mutex);
    pthread_mutex_destroy(&file_mutex);
    free(threads);
    free(thread_args);

    return found;
}

int main(int argc, char **argv)
{
    // Enable CPU optimizations
    _MM_SET_FLUSH_ZERO_MODE(_MM_FLUSH_ZERO_ON);
    _MM_SET_DENORMALS_ZERO_MODE(_MM_DENORMALS_ZERO_ON);

    secp.Init();

    if (argc < 4)
    {
        printf("Usage:\n");
        printf("Standard operations: %s <pubkey1> <operation> <pubkey2/number>\n", argv[0]);
        printf("Bit reduction search: %s --reduce <pubkey> <nbits> <search_pubkey> [-t threads] [-c]\n", argv[0]);
        printf("Operations: +, -, /, x\n");
        printf("Use Ctrl+C to stop and save progress\n");
        exit(0);
    }

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
                if (num_threads <= 0 || num_threads > MAX_THREADS)
                {
                    printf("Error: Thread count must be between 1 and %d\n", MAX_THREADS);
                    exit(0);
                }
                i++;
            }
            else if (strcmp(argv[i], "-c") == 0)
            {
                continuous_mode = true;
            }
        }

        Point inputPoint;
        bool isCompressed;
        if (!secp.ParsePublicKeyHex(argv[2], inputPoint, isCompressed))
        {
            printf("Error: Invalid input public key\n");
            exit(0);
        }

        int start_nbits = atoi(argv[3]);
        if (start_nbits <= 0)
        {
            printf("Error: nbits must be greater than 0\n");
            exit(0);
        }

        bool key_found = false;
        int current_bits = start_nbits;

        // Auto-detect optimal thread count if not specified
        if (num_threads == 1)
        {
            num_threads = sysconf(_SC_NPROCESSORS_ONLN);
            if (num_threads > MAX_THREADS)
                num_threads = MAX_THREADS;
            printf("[+] Auto-detected %d CPU cores\n", num_threads);
        }

        do
        {
            printf("\n[+] Trying %d bits...\n", current_bits);
            key_found = perform_bit_reduction(&inputPoint, current_bits, argv[4], num_threads);

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

    // Handle standard point operations
    Point point1, point2, result;
    bool isCompressed;
    Int scalar;

    if (!secp.ParsePublicKeyHex(argv[1], point1, isCompressed))
    {
        printf("Error: Invalid first public key\n");
        exit(0);
    }

    bool isScalar = false;
    if (argv[3][0] == '0' && argv[3][1] == 'x')
    {
        scalar.SetBase16(argv[3] + 2);
        isScalar = true;
    }
    else if (strlen(argv[3]) <= 64)
    {
        scalar.SetBase16(argv[3]);
        isScalar = true;
    }
    else if (!secp.ParsePublicKeyHex(argv[3], point2, isCompressed))
    {
        printf("Error: Invalid second public key or scalar\n");
        exit(0);
    }

    switch (argv[2][0])
    {
    case '+':
    {
        if (isScalar)
        {
            point2 = secp.ComputePublicKey(&scalar);
        }
        result = secp.AddDirect(point1, point2);
        break;
    }
    case '-':
    {
        if (isScalar)
        {
            point2 = secp.ComputePublicKey(&scalar);
        }
        Point negated = secp.Negation(point2);
        result = secp.AddDirect(point1, negated);
        break;
    }
    case '/':
    {
        if (!isScalar)
        {
            printf("Error: Division requires a scalar number\n");
            exit(0);
        }
        Int temp(scalar);
        temp.ModInv();
        result = secp.ComputePublicKey(&temp);
        break;
    }
    case 'x':
    {
        if (!isScalar)
        {
            printf("Error: Multiplication requires a scalar number\n");
            exit(0);
        }
        result = secp.ComputePublicKey(&scalar);
        break;
    }
    default:
    {
        printf("Error: Invalid operation (use +, -, /, or x)\n");
        exit(0);
    }
    }

    char resultHex[132];
    secp.GetPublicKeyHex(true, result, resultHex);
    printf("Result: %s\n", resultHex);

    return 0;
}
