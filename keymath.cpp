#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#include <math.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "secp256k1/SECP256k1.h"
#include "secp256k1/Point.h"
#include "secp256k1/Int.h"
#include "secp256k1/Random.h"
#include "util.h"
#include "bloom/bloom.h"
#include "xxhash/xxhash.h"

#define NUM_THREADS 16
#define BATCH_SIZE 1024
#define PUBKEY_CACHE_SIZE 10000

// Bloom filter configuration
#define MAX_ENTRIES1 10000000000
#define MAX_ENTRIES2 8000000000
#define MAX_ENTRIES3 6000000000
#define PUBKEY_PREFIX_LENGTH 6
#define BLOOM1_FP_RATE 0.0001
#define BLOOM2_FP_RATE 0.00001
#define BLOOM3_FP_RATE 0.000001
#define BUFFER_SIZE (1024 * 1024)
#define COMPRESSED_PUBKEY_SIZE 33
#define HEX_PUBKEY_SIZE 66

struct BatchBuffer
{
    Point *points;
    Int *randoms;
    char **pubKeyHexes;
    char **decimalStrs;
    Point *results;
    Point *negPoints;

    BatchBuffer(size_t size)
    {
        points = new Point[size];
        randoms = new Int[size];
        pubKeyHexes = new char *[size];
        decimalStrs = new char *[size];
        results = new Point[size];
        negPoints = new Point[size];

        for (size_t i = 0; i < size; i++)
        {
            pubKeyHexes[i] = nullptr;
            decimalStrs[i] = nullptr;
        }
    }

    ~BatchBuffer()
    {
        delete[] points;
        delete[] randoms;
        delete[] negPoints;
        for (size_t i = 0; i < BATCH_SIZE; i++)
        {
            if (pubKeyHexes[i])
                free(pubKeyHexes[i]);
            if (decimalStrs[i])
                free(decimalStrs[i]);
        }
        delete[] pubKeyHexes;
        delete[] decimalStrs;
        delete[] results;
    }
};

struct BatchMultiplyArgs
{
    Point *points;
    Int *scalars;
    int start;
    int end;
};

struct ThreadArgs
{
    Point startPoint;
    Int rangeStart;
    Int rangeEnd;
    bool running;
    int thread_id;
    uint64_t total_ops;
    double keys_per_second;
    time_t start_time;
};

struct FileInfo
{
    FILE *file;
    bool is_binary;
    size_t total_entries;
    pthread_mutex_t file_mutex;
};

// Bloom worker structure
struct bloom_load_worker
{
    struct bloom *bloom1;
    struct bloom *bloom2;
    struct bloom *bloom3;
    unsigned char *entries;
    size_t num_entries;
    bool is_binary;
};

// Global variables
Secp256K1 secp;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t print_mutex = PTHREAD_MUTEX_INITIALIZER;

// Bloom filter globals
struct bloom bloom_filter1;
struct bloom bloom_filter2;
struct bloom bloom_filter3;
bool bloom_initialized1 = false;
bool bloom_initialized2 = false;
bool bloom_initialized3 = false;

// Bloom filter functions
uint64_t estimate_bloom_size(uint64_t items, double fp_rate)
{
    return (uint64_t)((-1.0 * items * log(fp_rate)) / (log(2.0) * log(2.0))) / 8;
}

void print_memory_requirements()
{
    uint64_t bloom1_size = estimate_bloom_size(MAX_ENTRIES1, BLOOM1_FP_RATE);
    uint64_t bloom2_size = estimate_bloom_size(MAX_ENTRIES2, BLOOM2_FP_RATE);
    uint64_t bloom3_size = estimate_bloom_size(MAX_ENTRIES3, BLOOM3_FP_RATE);

    double bloom1_mb = bloom1_size / (1024.0 * 1024.0);
    double bloom2_mb = bloom2_size / (1024.0 * 1024.0);
    double bloom3_mb = bloom3_size / (1024.0 * 1024.0);
    double total_mb = bloom1_mb + bloom2_mb + bloom3_mb;

    printf("\nEstimated memory requirements:\n");
    printf("Bloom filter 1 (%d entries): %.2f MB\n", MAX_ENTRIES1, bloom1_mb);
    printf("Bloom filter 2 (%d entries): %.2f MB\n", MAX_ENTRIES2, bloom2_mb);
    printf("Bloom filter 3 (%d entries): %.2f MB\n", MAX_ENTRIES3, bloom3_mb);
    printf("Total bloom filters: %.2f MB\n\n", total_mb);

    uint64_t pages = sysconf(_SC_PHYS_PAGES);
    uint64_t page_size = sysconf(_SC_PAGE_SIZE);
    uint64_t available_mb = ((uint64_t)pages * (uint64_t)page_size) / (1024 * 1024);

    printf("Available system memory: %llu MB\n", (unsigned long long)available_mb);

    if (total_mb > available_mb * 0.9)
    {
        printf("\nWARNING: Estimated memory usage (%.2f MB) exceeds safe limits\n", total_mb);
        printf("Consider reducing MAX_ENTRIES or adjusting parameters\n");
    }
    else
    {
        printf("Memory requirements within safe limits (%.1f%%)\n",
               (total_mb / available_mb) * 100);
    }
}

void *bloom_load_worker_thread(void *arg)
{
    struct bloom_load_worker *worker = (struct bloom_load_worker *)arg;
    char pubkey_hex[67];

    for (size_t i = 0; i < worker->num_entries; i++)
    {
        if (worker->is_binary)
        {
            const unsigned char *pubkey_data = worker->entries + (i * COMPRESSED_PUBKEY_SIZE);
            bloom_add(worker->bloom1, (char *)(pubkey_data + 1), PUBKEY_PREFIX_LENGTH);

            XXH64_hash_t hash = XXH64(pubkey_data + 1, 32, 0x1234);
            bloom_add(worker->bloom2, (char *)&hash, sizeof(hash));

            hash = XXH64(pubkey_data + 1, 32, 0x5678);
            bloom_add(worker->bloom3, (char *)&hash, sizeof(hash));
        }
        else
        {
            memcpy(pubkey_hex, worker->entries + (i * HEX_PUBKEY_SIZE), 66);
            pubkey_hex[66] = '\0';

            unsigned char x_coord[32];
            hexs2bin(pubkey_hex + 2, x_coord);

            bloom_add(worker->bloom1, (char *)x_coord, PUBKEY_PREFIX_LENGTH);

            XXH64_hash_t hash = XXH64(x_coord, 32, 0x1234);
            bloom_add(worker->bloom2, (char *)&hash, sizeof(hash));

            hash = XXH64(x_coord, 32, 0x5678);
            bloom_add(worker->bloom3, (char *)&hash, sizeof(hash));
        }
    }
    return NULL;
}

bool triple_bloom_check(const char *pubkey)
{
    if (!pubkey || strlen(pubkey) < 66)
        return false;
    if (!bloom_initialized1 || !bloom_initialized2 || !bloom_initialized3)
    {
        printf("Error: Bloom filters not initialized\n");
        return false;
    }

    unsigned char x_coord[32];
    char hex_x[65];                 // X coordinate only
    strncpy(hex_x, pubkey + 2, 64); // Skip 02/03 prefix
    hex_x[64] = '\0';

    if (!hexs2bin(hex_x, x_coord))
    {
        return false;
    }

    // First bloom filter - prefix check
    if (!bloom_check(&bloom_filter1, (char *)x_coord, PUBKEY_PREFIX_LENGTH))
    {
        return false;
    }

    // Second bloom filter - full X coordinate hash
    XXH64_hash_t hash1 = XXH64(x_coord, 32, 0x1234);
    if (!bloom_check(&bloom_filter2, (char *)&hash1, sizeof(hash1)))
    {
        return false;
    }

    // Third bloom filter - different hash
    XXH64_hash_t hash2 = XXH64(x_coord, 32, 0x5678);
    return bloom_check(&bloom_filter3, (char *)&hash2, sizeof(hash2));
}

int init_multi_bloom_from_file(const char *filename)
{
    FILE *file = fopen(filename, "rb");
    if (!file)
    {
        printf("Error: Cannot open search file %s\n", filename);
        return 0;
    }

    struct stat sb;
    if (fstat(fileno(file), &sb) == -1)
    {
        perror("stat");
        fclose(file);
        return 0;
    }

    bool is_binary = sb.st_size > 0 && sb.st_size % COMPRESSED_PUBKEY_SIZE == 0;
    size_t total_entries = is_binary ? sb.st_size / COMPRESSED_PUBKEY_SIZE : sb.st_size / (HEX_PUBKEY_SIZE + 1);

    print_memory_requirements();

    if (bloom_init2(&bloom_filter1, MAX_ENTRIES1, BLOOM1_FP_RATE) != 0 ||
        bloom_init2(&bloom_filter2, MAX_ENTRIES2, BLOOM2_FP_RATE) != 0 ||
        bloom_init2(&bloom_filter3, MAX_ENTRIES3, BLOOM3_FP_RATE) != 0)
    {
        printf("Error: Failed to initialize bloom filters\n");
        fclose(file);
        return 0;
    }

    bloom_initialized1 = bloom_initialized2 = bloom_initialized3 = true;

    int num_threads = sysconf(_SC_NPROCESSORS_ONLN);
    if (num_threads > 257)
        num_threads = 257;

    size_t entry_size = is_binary ? COMPRESSED_PUBKEY_SIZE : HEX_PUBKEY_SIZE;
    size_t entries_per_thread = (total_entries + num_threads - 1) / num_threads;

    struct bloom_load_worker *workers = new bloom_load_worker[num_threads];
    pthread_t *threads = new pthread_t[num_threads];
    unsigned char *buffer = new unsigned char[BUFFER_SIZE];

    printf("Loading bloom filters using %d threads...\n", num_threads);
    time_t start_time = time(NULL);
    size_t entries_processed = 0;
    size_t bytes_read;

    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, file)) > 0)
    {
        size_t entries_in_buffer = bytes_read / entry_size;
        size_t entries_per_worker = (entries_in_buffer + num_threads - 1) / num_threads;

        for (int i = 0; i < num_threads; i++)
        {
            workers[i].bloom1 = &bloom_filter1;
            workers[i].bloom2 = &bloom_filter2;
            workers[i].bloom3 = &bloom_filter3;
            workers[i].is_binary = is_binary;

            size_t start_entry = i * entries_per_worker;
            if (start_entry >= entries_in_buffer)
                break;

            workers[i].entries = buffer + (start_entry * entry_size);
            workers[i].num_entries = (i == num_threads - 1) ? entries_in_buffer - start_entry : entries_per_worker;

            if (pthread_create(&threads[i], NULL, bloom_load_worker_thread, &workers[i]) != 0)
            {
                printf("Error creating thread %d\n", i);
                delete[] buffer;
                delete[] workers;
                delete[] threads;
                fclose(file);
                return 0;
            }
        }

        for (int i = 0; i < num_threads; i++)
        {
            pthread_join(threads[i], NULL);
        }

        entries_processed += entries_in_buffer;

        time_t current_time = time(NULL);
        double elapsed = difftime(current_time, start_time);
        double rate = entries_processed / elapsed;
        printf("\rProcessed %zu entries (%.2f entries/sec)...", entries_processed, rate);
        fflush(stdout);
    }

    printf("\nCompleted loading %zu entries in %.1f seconds\n",
           entries_processed, difftime(time(NULL), start_time));

    delete[] buffer;
    delete[] workers;
    delete[] threads;
    fclose(file);
    return 1;
}

void cleanup_bloom_filters()
{
    if (bloom_initialized1)
        bloom_free(&bloom_filter1);
    if (bloom_initialized2)
        bloom_free(&bloom_filter2);
    if (bloom_initialized3)
        bloom_free(&bloom_filter3);
}
void *scalar_multiply_worker(void *arg)
{
    BatchMultiplyArgs *args = (BatchMultiplyArgs *)arg;
    for (int i = args->start; i < args->end; i++)
    {
        args->points[i] = secp.ScalarMultiplication(secp.G, &args->scalars[i]);
    }
    return NULL;
}

void batch_scalar_multiplication(Point *points, Int *scalars, int count)
{
    const int num_threads = 8;
    pthread_t threads[num_threads];
    BatchMultiplyArgs thread_args[num_threads];

    int chunk = count / num_threads;
    for (int i = 0; i < num_threads; i++)
    {
        thread_args[i].points = points;
        thread_args[i].scalars = scalars;
        thread_args[i].start = i * chunk;
        thread_args[i].end = (i == num_threads - 1) ? count : (i + 1) * chunk;
        pthread_create(&threads[i], NULL, scalar_multiply_worker, &thread_args[i]);
    }

    for (int i = 0; i < num_threads; i++)
    {
        pthread_join(threads[i], NULL);
    }
}

Int generate_random_range(Int &start, Int &end)
{
    Int rng;
    Int diff;
    diff.Set(&end);
    diff.Sub(&start);

    unsigned char entropy[32];
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd != -1)
    {
        read(fd, entropy, 32);
        close(fd);
    }
    else
    {
        for (int i = 0; i < 32; i++)
            entropy[i] = rand() & 0xFF;
    }

    rng.Set32Bytes(entropy);
    rng.Mod(&diff);
    rng.Add(&start);
    return rng;
}

void *subtraction_worker(void *arg)
{
    ThreadArgs *args = (ThreadArgs *)arg;
    BatchBuffer buffer(BATCH_SIZE);

    while (args->running)
    {
        // Generate batch of random values
        for (int i = 0; i < BATCH_SIZE; i++)
        {
            buffer.randoms[i] = generate_random_range(args->rangeStart, args->rangeEnd);
        }

        // Perform batch scalar multiplication
        batch_scalar_multiplication(buffer.points, buffer.randoms, BATCH_SIZE);

        // Calculate negations for all points
        for (int i = 0; i < BATCH_SIZE; i++)
        {
            buffer.negPoints[i] = secp.Negation(buffer.points[i]);
        }

        // Perform batch point addition and check results
        for (int i = 0; i < BATCH_SIZE; i++)
        {
            buffer.results[i] = secp.AddDirect(buffer.negPoints[i], args->startPoint);

            // Clean up previous iteration's strings
            if (buffer.pubKeyHexes[i])
                free(buffer.pubKeyHexes[i]);
            if (buffer.decimalStrs[i])
                free(buffer.decimalStrs[i]);

            buffer.pubKeyHexes[i] = secp.GetPublicKeyHex(true, buffer.results[i]);
            buffer.decimalStrs[i] = buffer.randoms[i].GetBase10();

            if (!buffer.pubKeyHexes[i] || !buffer.decimalStrs[i])
                continue;

            args->total_ops++;
            double elapsed = difftime(time(NULL), args->start_time);
            args->keys_per_second = args->total_ops / (elapsed > 0 ? elapsed : 1);

            pthread_mutex_lock(&print_mutex);
            printf("\r%s - %s | %.2f keys/s",
                   buffer.pubKeyHexes[i],
                   buffer.decimalStrs[i],
                   args->keys_per_second);
            fflush(stdout);
            pthread_mutex_unlock(&print_mutex);

            if (bloom_initialized1 && triple_bloom_check(buffer.pubKeyHexes[i]))
            {
                pthread_mutex_lock(&print_mutex);
                printf("\nMATCH FOUND!\n");
                printf("Thread %d: %s - %s\n",
                       args->thread_id,
                       buffer.pubKeyHexes[i],
                       buffer.decimalStrs[i]);
                pthread_mutex_unlock(&print_mutex);
            }
        }
    }
    return NULL;
}

void print_stats(const ThreadArgs *args, int num_threads)
{
    uint64_t total_ops = 0;
    double total_speed = 0;

    for (int i = 0; i < num_threads; i++)
    {
        total_ops += args[i].total_ops;
        total_speed += args[i].keys_per_second;
    }

    printf("\nTotal operations: %llu\n", (unsigned long long)total_ops);
    printf("Average speed: %.2f keys/s\n", total_speed);
}

int main(int argc, char **argv)
{
    secp.Init();

    if (argc < 4)
    {
        printf("Usage: %s [-f bloom_file] <publickey> <range_start>:<range_end>\n", argv[0]);
        return 1;
    }

    const char *bloom_file = NULL;
    bool has_bloom = false;
    int arg_offset = 0;

    if (strcmp(argv[1], "-f") == 0)
    {
        if (argc < 6)
        {
            printf("Error: Missing arguments after -f\n");
            return 1;
        }
        bloom_file = argv[2];
        has_bloom = true;
        arg_offset = 2;
    }

    Point startPoint;
    Int rangeStart, rangeEnd;

    // Parse the public key
    bool isCompressed;
    char *pubKey = strdup(argv[1 + arg_offset]);
    if (!secp.ParsePublicKeyHex(pubKey, startPoint, isCompressed))
    {
        printf("Invalid public key format\n");
        free(pubKey);
        return 1;
    }
    free(pubKey);

    // Parse range
    char *range_str = strdup(argv[3 + arg_offset]);
    char *delimiter = strchr(range_str, ':');
    if (!delimiter)
    {
        printf("Invalid range format. Use start:end\n");
        free(range_str);
        return 1;
    }

    *delimiter = '\0';
    rangeStart.SetBase10(range_str);
    rangeEnd.SetBase10(delimiter + 1);
    free(range_str);

    // Initialize bloom filters if file provided
    if (has_bloom)
    {
        printf("Initializing bloom filters from: %s\n", bloom_file);
        if (!init_multi_bloom_from_file(bloom_file))
        {
            printf("Failed to initialize bloom filters\n");
            return 1;
        }
    }

    // Start worker threads
    pthread_t threads[NUM_THREADS];
    ThreadArgs thread_args[NUM_THREADS];

    printf("Starting subtraction with %d threads...\n", NUM_THREADS);
    bool init_error = false;

    for (int i = 0; i < NUM_THREADS; i++)
    {
        thread_args[i].startPoint = startPoint;
        thread_args[i].rangeStart = rangeStart;
        thread_args[i].rangeEnd = rangeEnd;
        thread_args[i].running = true;
        thread_args[i].thread_id = i;
        thread_args[i].total_ops = 0;
        thread_args[i].keys_per_second = 0;
        thread_args[i].start_time = time(NULL);

        int err = pthread_create(&threads[i], NULL, subtraction_worker, &thread_args[i]);
        if (err)
        {
            fprintf(stderr, "Error creating thread %d: %s\n", i, strerror(err));
            init_error = true;
            for (int j = 0; j < i; j++)
            {
                thread_args[j].running = false;
            }
            for (int j = 0; j < i; j++)
            {
                pthread_join(threads[j], NULL);
            }
            break;
        }
    }

    if (init_error)
    {
        cleanup_bloom_filters();
        pthread_mutex_destroy(&mutex);
        pthread_mutex_destroy(&print_mutex);
        return 1;
    }

    // Wait for user input to stop
    printf("\nPress Enter to stop...\n");
    getchar();

    // Stop all threads
    printf("\nStopping threads...\n");
    for (int i = 0; i < NUM_THREADS; i++)
    {
        thread_args[i].running = false;
    }

    // Wait for threads to finish
    for (int i = 0; i < NUM_THREADS; i++)
    {
        pthread_join(threads[i], NULL);
    }

    // Print final statistics
    print_stats(thread_args, NUM_THREADS);

    // Cleanup
    cleanup_bloom_filters();
    pthread_mutex_destroy(&mutex);
    pthread_mutex_destroy(&print_mutex);

    return 0;
}
