#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <signal.h>
#include <gmp.h>
#include <string.h>
#include <unistd.h>
#include <math.h>
#include <time.h>
#include <pthread.h>
#include "util.h"
#include "bloom/bloom.h"
#include "gmpecc.h"
#include "base58/libbase58.h"
#include "rmd160/rmd160.h"
#include "sha256/sha256.h"
#include "xxhash/xxhash.h"
#include "Random.h"
#include <inttypes.h> // For PRIu64
#include <math.h>     // For log function
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

// Version
const char *VERSION = "1.0.0";

// Optimization constants
#define OPTIMAL_MIN_STEPS 144
#define OPTIMAL_MAX_STEPS 224
#define TARGET_MIN_DIVISIONS 134
#define TARGET_MAX_DIVISIONS 134
#define MIN_SUBTRACTIONS 10
#define MAX_SUBTRACTIONS 90
#define PATHS_PER_SUBTRACTION_LEVEL 5
#define MAX_TIME_AT_LEVEL 900     // 5 minutes in seconds
#define PATH_CHECK_INTERVAL 1000  // Check every 1000 attempts
#define COMPRESSED_PUBKEY_SIZE 33 // Size of binary compressed pubkey
#define HEX_PUBKEY_SIZE 66        // Size of hex string pubkey without null terminator

// Auto subtraction settings
mpz_t auto_subtraction_value;
uint64_t auto_subtraction_count = 0;
bool auto_subtraction_mode = false;
uint64_t global_subtraction_count = 0;
pthread_mutex_t subtraction_count_mutex = PTHREAD_MUTEX_INITIALIZER;
#define CHECKPOINT_FILE "auto_subtraction_checkpoint.txt"
#define CHECKPOINT_INTERVAL 1000 // Save checkpoint every 1000 subtractions
struct thread_args *thread_args_array = NULL;
#define CHUNK_SIZE 100000 // 100K keys per chunk
#define MAX_CHUNKS 100    // Support up to 10M keys total (100 * 100K)

// Thread management
#define MAX_THREADS 256
#define THREAD_SLEEP_MICROSECONDS 100

// Bloom filter configuration
#define MAX_ENTRIES1 10000000000
#define MAX_ENTRIES2 8000000000
#define MAX_ENTRIES3 6000000000
#define PUBKEY_PREFIX_LENGTH 6
// #define BLOOM_PREFIX_LENGTH 6
#define BLOOM1_FP_RATE 0.0001
#define BLOOM2_FP_RATE 0.00001
#define BLOOM3_FP_RATE 0.000001
#define BUFFER_SIZE (1024 * 1024) // 1MB buffer
#define WORKER_BATCH_SIZE 10000   // Number of entries per worker batch

#define CHECKPOINT_FILE "auto_subtraction_checkpoint.txt"

struct PublicKeyChunk
{
    struct Point *points;
    char **current_pubkeys;
    size_t size;
    struct PublicKeyChunk *next;
};

struct ChunkedKeyStorage
{
    struct PublicKeyChunk *chunks;
    size_t total_keys;
    size_t num_chunks;
    pthread_mutex_t *chunk_mutexes;
};

// Structure for storing compressed pubkeys
struct CompressedPubKey
{
    uint8_t prefix[PUBKEY_PREFIX_LENGTH];
    char type;
};

bool debug_mode = false;

// Performance tracking
struct PerformanceMetrics
{
    double avg_path_length;
    double avg_divisions;
    double avg_subtractions;
    double success_rate;
    uint64_t total_attempts;
    uint64_t successful_attempts;
    time_t start_time;
    time_t last_success_time; // New field
    pthread_mutex_t metrics_mutex;
};

// Structure to hold file info
struct FileInfo
{
    FILE *file;
    bool is_binary;
    size_t total_entries;
    pthread_mutex_t file_mutex;
};

// Division control structure
struct DivisionControl
{
    int consecutive_failures;
    int success_count;
    int current_subtractions;
    int completed_paths_at_current_level;
    bool last_was_subtraction;
    pthread_mutex_t mutex;
};

struct thread_args
{
    struct Point *start_pubkeys;        // Original field
    int thread_id;                      // Original field
    char **initial_pks;                 // Original field
    char **current_pks;                 // Original field
    uint64_t start_index;               // Original field
    uint64_t end_index;                 // Original field
    bool auto_subtraction;              // Original field
    int num_pubkeys;                    // Original field
    int target_bit;                     // Original field
    struct DivisionControl *div_ctrl;   // Original field
    struct PerformanceMetrics *metrics; // Original field
    int num_threads;                    // Original field
    // New fields for chunk support
    struct PublicKeyChunk *chunk; // Current chunk being processed
    pthread_mutex_t *chunk_mutex; // Mutex for chunk access
};

struct bloom_load_worker
{
    struct bloom *bloom1;
    struct bloom *bloom2;
    struct bloom *bloom3;
    unsigned char *entries;
    size_t num_entries;
    bool is_binary;
};

struct CheckpointData
{
    uint64_t subtraction_count;
    char **public_keys;
    int num_keys;
};

// Global variables
struct Elliptic_Curve EC;
struct Point G;
struct Point DoublingG[256];
struct FileInfo search_file_info = {NULL, false, 0, PTHREAD_MUTEX_INITIALIZER};

const char *EC_constant_N = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
const char *EC_constant_P = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f";
const char *EC_constant_Gx = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const char *EC_constant_Gy = "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
char current_path[10000] = ""; // To store current path for logging

// Bloom filter globals
struct bloom bloom_filter1;
struct bloom bloom_filter2;
struct bloom bloom_filter3;
bool bloom_initialized1 = false;
bool bloom_initialized2 = false;
bool bloom_initialized3 = false;
bool save_unsuccessful_paths = false;

// Thread-safe globals
pthread_mutex_t print_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t file_mutex = PTHREAD_MUTEX_INITIALIZER;
unsigned long long total_attempts = 0;
pthread_mutex_t attempts_mutex = PTHREAD_MUTEX_INITIALIZER;

// Function declarations
void initialize_performance_metrics(struct PerformanceMetrics *metrics);
void update_performance_metrics(struct PerformanceMetrics *metrics, bool success,
                                int path_length, int divisions, int subtractions);
void initialize_division_control(struct DivisionControl *ctrl);
bool should_divide(struct DivisionControl *ctrl, int current_divisions,
                   int current_subtractions, int remaining_steps,
                   int remaining_divisions_needed);
void update_division_control(struct DivisionControl *ctrl, bool path_successful);
void *find_division_path_thread(void *arg);
int init_multi_bloom_from_file(const char *filename);
void *bloom_load_worker_thread(void *arg);
void cleanup_bloom_filters(void);
bool triple_bloom_check(const char *pubkey);
void generate_strpublickey(struct Point *publickey, bool compress, char *dst);
void set_publickey(char *param, struct Point *publickey);
void save_path_to_file(const char *path, const char *found_pk, bool is_match);
bool Point_is_zero(struct Point *P);
void Scalar_Multiplication_custom(struct Point P, struct Point *R, mpz_t m);
void save_debug_info(const char *path, const char *pubkey, int divisions, int subtractions,
                     char **intermediate_pubkeys, int step_count);
uint64_t estimate_bloom_size(uint64_t items, double fp_rate);
void print_memory_requirements(void);
bool is_binary_file(const char *filename);
int read_pubkey_at_position(size_t pos, char *pubkey_hex);
int64_t binary_search_pubkey(const char *target_pubkey);
int init_search_file(const char *filename);
void handle_interrupt(int sig);
struct ChunkedKeyStorage *init_chunked_storage(void);
int load_keys_from_file(struct ChunkedKeyStorage *storage, const char *filename);
struct PublicKeyChunk *add_chunk(struct ChunkedKeyStorage *storage);
int verify_chunks(struct ChunkedKeyStorage *storage);
static bool setup_thread(struct thread_args *args, int thread_id, size_t start_idx,
                         size_t end_idx, struct ChunkedKeyStorage *storage, int num_threads);
static bool init_thread_resources(pthread_t **threads, int num_threads, size_t num_pubkeys,
                                  struct ChunkedKeyStorage *storage);
static void cleanup_thread_resources(pthread_t *threads, struct thread_args *args,
                                     int num_threads, struct ChunkedKeyStorage *storage);
static void cleanup_storage(struct ChunkedKeyStorage *storage);
static struct PublicKeyChunk *find_chunk_for_range(struct ChunkedKeyStorage *storage,
                                                   size_t start_idx, size_t end_idx);
static int get_chunk_index(struct ChunkedKeyStorage *storage, struct PublicKeyChunk *chunk);

static int get_chunk_index(struct ChunkedKeyStorage *storage, struct PublicKeyChunk *chunk)
{
    struct PublicKeyChunk *current = storage->chunks;
    int index = 0;

    while (current && current != chunk)
    {
        index++;
        current = current->next;
    }

    return index < MAX_CHUNKS ? index : 0;
}

static struct PublicKeyChunk *find_chunk_for_range(struct ChunkedKeyStorage *storage,
                                                   size_t start_idx, size_t end_idx)
{
    struct PublicKeyChunk *current = storage->chunks;
    size_t current_pos = 0;

    while (current)
    {
        if (current_pos + current->size > start_idx)
        {
            return current;
        }
        current_pos += current->size;
        current = current->next;
    }
    return NULL;
}

static bool init_thread_resources(pthread_t **threads, int num_threads, size_t num_pubkeys,
                                  struct ChunkedKeyStorage *storage)
{
    *threads = malloc(num_threads * sizeof(pthread_t));
    thread_args_array = malloc(num_threads * sizeof(struct thread_args));

    if (!*threads || !thread_args_array)
    {
        printf("Failed to allocate thread resources\n");
        free(*threads);
        free(thread_args_array);
        return false;
    }

    // Initialize common thread arguments
    for (int i = 0; i < num_threads; i++)
    {
        thread_args_array[i].num_threads = num_threads;
        thread_args_array[i].auto_subtraction = true;
        thread_args_array[i].div_ctrl = NULL;
        thread_args_array[i].metrics = NULL;
        thread_args_array[i].current_pks = NULL;
    }

    return true;
}

static bool setup_thread(struct thread_args *args, int thread_id, size_t start_idx,
                         size_t end_idx, struct ChunkedKeyStorage *storage, int num_threads)
{
    args->thread_id = thread_id;
    args->start_index = start_idx;
    args->end_index = end_idx;
    args->num_pubkeys = end_idx - start_idx;

    if (storage)
    {
        // Find appropriate chunk and set up chunk-specific data
        struct PublicKeyChunk *chunk = find_chunk_for_range(storage, start_idx, end_idx);
        if (!chunk)
        {
            printf("Failed to find appropriate chunk for thread %d\n", thread_id);
            return false;
        }
        args->chunk = chunk;
        args->chunk_mutex = &storage->chunk_mutexes[get_chunk_index(storage, chunk)];
    }
    else
    {
        args->chunk = NULL;
        args->chunk_mutex = NULL;
    }

    return true;
}

static void cleanup_thread_resources(pthread_t *threads, struct thread_args *args,
                                     int num_threads, struct ChunkedKeyStorage *storage)
{
    if (threads)
        free(threads);

    if (args)
    {
        for (int i = 0; i < num_threads; i++)
        {
            if (args[i].current_pks)
            {
                for (size_t j = 0; j < args[i].num_pubkeys; j++)
                {
                    free(args[i].current_pks[j]);
                }
                free(args[i].current_pks);
            }
        }
        free(args);
    }

    if (storage)
        cleanup_storage(storage);
}

static void cleanup_storage(struct ChunkedKeyStorage *storage)
{
    if (!storage)
        return;

    struct PublicKeyChunk *current = storage->chunks;
    while (current)
    {
        struct PublicKeyChunk *next = current->next;
        for (size_t i = 0; i < current->size; i++)
        {
            mpz_clear(current->points[i].x);
            mpz_clear(current->points[i].y);
            free(current->current_pubkeys[i]);
        }
        free(current->points);
        free(current->current_pubkeys);
        free(current);
        current = next;
    }

    for (int i = 0; i < MAX_CHUNKS; i++)
    {
        pthread_mutex_destroy(&storage->chunk_mutexes[i]);
    }
    free(storage->chunk_mutexes);
    free(storage);
}

struct PublicKeyChunk *add_chunk(struct ChunkedKeyStorage *storage)
{
    if (storage->num_chunks >= MAX_CHUNKS)
    {
        printf("\nWarning: Reached maximum chunks (%d), total keys: %zu\n",
               MAX_CHUNKS, storage->total_keys);
        return NULL;
    }

    struct PublicKeyChunk *chunk = malloc(sizeof(struct PublicKeyChunk));
    if (!chunk)
    {
        printf("Error: Failed to allocate chunk structure\n");
        return NULL;
    }

    // Allocate arrays for points and pubkeys
    chunk->points = malloc(CHUNK_SIZE * sizeof(struct Point));
    chunk->current_pubkeys = malloc(CHUNK_SIZE * sizeof(char *));

    if (!chunk->points || !chunk->current_pubkeys)
    {
        printf("Error: Failed to allocate chunk arrays\n");
        free(chunk->points);
        free(chunk->current_pubkeys);
        free(chunk);
        return NULL;
    }

    // Initialize all GMP variables and strings
    for (size_t i = 0; i < CHUNK_SIZE; i++)
    {
        mpz_init(chunk->points[i].x);
        mpz_init(chunk->points[i].y);
        chunk->current_pubkeys[i] = malloc(67); // 66 chars + null terminator
        if (!chunk->current_pubkeys[i])
        {
            // Cleanup on failure
            for (size_t j = 0; j < i; j++)
            {
                mpz_clear(chunk->points[j].x);
                mpz_clear(chunk->points[j].y);
                free(chunk->current_pubkeys[j]);
            }
            free(chunk->points);
            free(chunk->current_pubkeys);
            free(chunk);
            return NULL;
        }
        chunk->current_pubkeys[i][0] = '\0'; // Initialize to empty string
    }

    chunk->size = 0;
    chunk->next = storage->chunks;
    storage->chunks = chunk;
    storage->num_chunks++;

    printf("\nCreated chunk %zu (capacity: %d keys)\n",
           storage->num_chunks, CHUNK_SIZE);

    return chunk;
}

struct ChunkedKeyStorage *init_chunked_storage(void)
{
    struct ChunkedKeyStorage *storage = malloc(sizeof(struct ChunkedKeyStorage));
    if (!storage)
    {
        printf("Failed to allocate storage structure\n");
        return NULL;
    }

    storage->chunks = NULL;
    storage->total_keys = 0;
    storage->num_chunks = 0;
    storage->chunk_mutexes = malloc(MAX_CHUNKS * sizeof(pthread_mutex_t));

    if (!storage->chunk_mutexes)
    {
        printf("Failed to allocate chunk mutexes\n");
        free(storage);
        return NULL;
    }

    for (int i = 0; i < MAX_CHUNKS; i++)
    {
        pthread_mutex_init(&storage->chunk_mutexes[i], NULL);
    }

    return storage;
}

int load_keys_from_file(struct ChunkedKeyStorage *storage, const char *filename)
{
    FILE *file = fopen(filename, "r");
    if (!file)
    {
        printf("Error: Cannot open file %s\n", filename);
        return 0;
    }

    char buffer[8192] = {0}; // Increased buffer size for longer lines
    struct PublicKeyChunk *current = NULL;
    size_t total_keys = 0;
    char pubkey[67]; // 66 chars + null terminator
    size_t pubkey_len = 0;
    int pos = 0;

    // Initialize first chunk
    current = add_chunk(storage);
    if (!current)
    {
        fclose(file);
        return 0;
    }

    while (fgets(buffer, sizeof(buffer), file))
    {
        pos = 0;

        // Process each character in the buffer
        for (int i = 0; buffer[i] != '\0'; i++)
        {
            if (buffer[i] != ' ' && buffer[i] != '\n')
            {
                if (pos < 66)
                { // Only collect up to 66 characters
                    pubkey[pos++] = buffer[i];
                }
            }
            else if (pos == 66)
            {                      // We have a complete pubkey
                pubkey[66] = '\0'; // Null terminate

                // Create new chunk if current one is full
                if (current->size >= CHUNK_SIZE)
                {
                    current = add_chunk(storage);
                    if (!current)
                    {
                        printf("\nReached maximum capacity at %zu keys\n", storage->total_keys);
                        fclose(file);
                        return storage->total_keys > 0;
                    }
                }

                // Validate pubkey format (should start with 02 or 03)
                if ((pubkey[0] == '0' && (pubkey[1] == '2' || pubkey[1] == '3')))
                {
                    // Set the public key
                    set_publickey(pubkey, &current->points[current->size]);
                    strncpy(current->current_pubkeys[current->size], pubkey, 66);
                    current->current_pubkeys[current->size][66] = '\0';

                    current->size++;
                    storage->total_keys++;
                    total_keys++;

                    if (total_keys % 10000 == 0)
                    {
                        printf("\rLoaded %zu keys into %zu chunks...",
                               total_keys, storage->num_chunks);
                        fflush(stdout);
                    }
                }
                pos = 0; // Reset for next pubkey
            }
        }
    }

    // Handle last key if buffer ended exactly at 66 chars
    if (pos == 66)
    {
        pubkey[66] = '\0';
        if ((pubkey[0] == '0' && (pubkey[1] == '2' || pubkey[1] == '3')))
        {
            if (current->size < CHUNK_SIZE)
            {
                set_publickey(pubkey, &current->points[current->size]);
                strncpy(current->current_pubkeys[current->size], pubkey, 66);
                current->current_pubkeys[current->size][66] = '\0';
                current->size++;
                storage->total_keys++;
                total_keys++;
            }
        }
    }

    printf("\nSuccessfully loaded %zu keys into %zu chunks\n",
           storage->total_keys, storage->num_chunks);

    fclose(file);
    return 1;
}

int verify_chunks(struct ChunkedKeyStorage *storage)
{
    struct PublicKeyChunk *current = storage->chunks;
    size_t total_keys = 0;
    size_t chunk_num = 0;

    while (current)
    {
        chunk_num++;
        if (current->size > CHUNK_SIZE)
        {
            printf("Error: Chunk %zu has invalid size %zu (max: %d)\n",
                   chunk_num, current->size, CHUNK_SIZE);
            return 0;
        }
        total_keys += current->size;
        current = current->next;
    }

    if (total_keys != storage->total_keys)
    {
        printf("Error: Total keys mismatch. Found %zu, expected %zu\n",
               total_keys, storage->total_keys);
        return 0;
    }

    printf("Chunk verification passed: %zu chunks, %zu total keys\n",
           chunk_num, total_keys);
    return 1;
}

void handle_interrupt(int sig)
{
    pthread_mutex_lock(&print_mutex);
    printf("\nReceived interrupt signal. Saving checkpoint...\n");

    struct thread_args *args = &thread_args_array[0]; // Use thread 0's data

    // Only try to save if thread 0's current_pks is initialized
    if (args && args->current_pks)
    {
        FILE *checkpoint = fopen(CHECKPOINT_FILE, "w");
        if (checkpoint)
        {
            // Save the global subtraction count first
            fprintf(checkpoint, "%" PRIu64 "\n", global_subtraction_count);
            fprintf(checkpoint, "Checkpoint Details:\n");
            fprintf(checkpoint, "Total Subtractions: %" PRIu64 "\n", global_subtraction_count);
            fprintf(checkpoint, "Current Public Keys:\n");

            // Safely save each public key
            for (int i = 0; i < args->num_pubkeys; i++)
            {
                if (args->current_pks[i])
                {
                    fprintf(checkpoint, "%s\n", args->current_pks[i]);
                }
            }

            fclose(checkpoint);
            printf("Checkpoint saved. Progress: %" PRIu64 " subtractions\n", global_subtraction_count);
            printf("Current public keys saved\n");
        }
        else
        {
            printf("Error: Could not save checkpoint file\n");
        }
    }
    else
    {
        // Fallback: save just the count if keys aren't available
        FILE *checkpoint = fopen(CHECKPOINT_FILE, "w");
        if (checkpoint)
        {
            fprintf(checkpoint, "%" PRIu64 "\n", global_subtraction_count);
            fclose(checkpoint);
            printf("Checkpoint saved (count only): %" PRIu64 " subtractions\n", global_subtraction_count);
        }
    }

    pthread_mutex_unlock(&print_mutex);
    printf("Exiting safely...\n");
    exit(0);
}

// Load checkpoint function - simplified to only read count
uint64_t load_checkpoint(void)
{
    FILE *checkpoint = fopen(CHECKPOINT_FILE, "r");
    if (!checkpoint)
    {
        return 0;
    }

    uint64_t saved_count = 0;
    if (fscanf(checkpoint, "%" PRIu64, &saved_count) != 1)
    {
        saved_count = 0;
    }
    fclose(checkpoint);
    return saved_count;
}

void *bloom_load_worker_thread(void *arg)
{
    struct bloom_load_worker *worker = (struct bloom_load_worker *)arg;
    char pubkey_hex[67];

    for (size_t i = 0; i < worker->num_entries; i++)
    {
        if (worker->is_binary)
        {
            // Binary input (33 bytes): Skip prefix byte and use next PUBKEY_PREFIX_LENGTH bytes
            const unsigned char *pubkey_data = worker->entries + (i * COMPRESSED_PUBKEY_SIZE);

            // Add prefix of X coordinate to first bloom filter (skip the 02/03 byte)
            bloom_add(worker->bloom1, (char *)(pubkey_data + 1), PUBKEY_PREFIX_LENGTH);

            // Use full X coordinate for second bloom filter with hash
            XXH64_hash_t hash = XXH64(pubkey_data + 1, 32, 0x1234);
            bloom_add(worker->bloom2, (char *)&hash, sizeof(hash));

            // Use different hash for third bloom filter
            hash = XXH64(pubkey_data + 1, 32, 0x5678);
            bloom_add(worker->bloom3, (char *)&hash, sizeof(hash));
        }
        else
        {
            // Converting hex string to binary, skipping first byte pair
            memcpy(pubkey_hex, worker->entries + (i * HEX_PUBKEY_SIZE), 66);
            pubkey_hex[66] = '\0';

            // Convert just the X coordinate part (skip first byte pair)
            unsigned char x_coord[32];
            hexs2bin(pubkey_hex + 2, x_coord);

            // Add prefix to first bloom filter
            bloom_add(worker->bloom1, (char *)x_coord, PUBKEY_PREFIX_LENGTH);

            // Add hash to second bloom filter
            XXH64_hash_t hash = XXH64(x_coord, 32, 0x1234);
            bloom_add(worker->bloom2, (char *)&hash, sizeof(hash));

            // Add different hash to third bloom filter
            hash = XXH64(x_coord, 32, 0x5678);
            bloom_add(worker->bloom3, (char *)&hash, sizeof(hash));
        }
    }

    return NULL;
}

int read_pubkey_at_position(size_t pos, char *pubkey_hex)
{
    pthread_mutex_lock(&search_file_info.file_mutex);

    if (search_file_info.is_binary)
    {
        unsigned char pubkey_data[COMPRESSED_PUBKEY_SIZE];

        // Seek to position
        if (fseek(search_file_info.file, pos * COMPRESSED_PUBKEY_SIZE, SEEK_SET) != 0)
        {
            pthread_mutex_unlock(&search_file_info.file_mutex);
            return 0;
        }

        // Read binary pubkey
        size_t read_bytes = fread(pubkey_data, 1, COMPRESSED_PUBKEY_SIZE, search_file_info.file);
        if (read_bytes != COMPRESSED_PUBKEY_SIZE)
        {
            pthread_mutex_unlock(&search_file_info.file_mutex);
            return 0;
        }

        // Convert to hex
        for (int i = 0; i < COMPRESSED_PUBKEY_SIZE; i++)
        {
            snprintf(pubkey_hex + (i * 2), 3, "%02x", pubkey_data[i]);
        }
        pubkey_hex[66] = '\0'; // Ensure null termination
    }
    else
    {
        // Text file handling
        if (fseek(search_file_info.file, 0, SEEK_SET) != 0)
        {
            pthread_mutex_unlock(&search_file_info.file_mutex);
            return 0;
        }

        char line[132];
        size_t current_pos = 0;

        // Skip to desired position
        while (current_pos < pos)
        {
            if (!fgets(line, sizeof(line), search_file_info.file))
            {
                pthread_mutex_unlock(&search_file_info.file_mutex);
                return 0;
            }
            current_pos++;
        }

        // Read target line
        if (!fgets(line, sizeof(line), search_file_info.file))
        {
            pthread_mutex_unlock(&search_file_info.file_mutex);
            return 0;
        }

        // Remove newline and copy
        line[strcspn(line, "\n")] = 0;
        strncpy(pubkey_hex, line, 66);
        pubkey_hex[66] = '\0';
    }

    pthread_mutex_unlock(&search_file_info.file_mutex);
    return 1;
}

// Binary search for pubkey
int64_t binary_search_pubkey(const char *target_pubkey)
{
    int64_t left = 0;
    int64_t right = search_file_info.total_entries - 1;
    char current_pubkey[HEX_PUBKEY_SIZE + 1];

    while (left <= right)
    {
        int64_t mid = left + (right - left) / 2;

        if (!read_pubkey_at_position(mid, current_pubkey))
        {
            return -1; // Read error
        }

        int cmp = strncmp(current_pubkey, target_pubkey, HEX_PUBKEY_SIZE);

        if (cmp == 0)
        {
            return mid; // Found exact match
        }

        if (cmp < 0)
        {
            left = mid + 1;
        }
        else
        {
            right = mid - 1;
        }
    }

    return -1; // Not found
}

int init_search_file(const char *filename)
{
    search_file_info.file = fopen(filename, "rb");
    if (!search_file_info.file)
    {
        printf("Error: Cannot open search file %s\n", filename);
        return 0;
    }

    // Determine if binary and calculate total entries
    search_file_info.is_binary = is_binary_file(filename);

    // Get file size
    fseek(search_file_info.file, 0, SEEK_END);
    long file_size = ftell(search_file_info.file);
    fseek(search_file_info.file, 0, SEEK_SET);

    if (search_file_info.is_binary)
    {
        search_file_info.total_entries = file_size / COMPRESSED_PUBKEY_SIZE;
        printf("Binary file with %zu compressed pubkeys\n", search_file_info.total_entries);
    }
    else
    {
        // For text file, count lines
        char line[132];
        size_t count = 0;
        while (fgets(line, sizeof(line), search_file_info.file))
        {
            count++;
        }
        search_file_info.total_entries = count;
        fseek(search_file_info.file, 0, SEEK_SET);
        printf("Text file with %zu pubkeys\n", search_file_info.total_entries);
    }

    return 1;
}

bool is_binary_file(const char *filename)
{
    FILE *file = fopen(filename, "rb");
    if (!file)
        return false;

    unsigned char buf[4];
    size_t read = fread(buf, 1, 4, file);
    fclose(file);

    // Check if first byte is 02 or 03 (compressed pubkey prefix)
    if (read >= 1 && (buf[0] == 0x02 || buf[0] == 0x03))
    {
        return true;
    }

    return false;
}

void save_debug_info(const char *path, const char *pubkey, int divisions, int subtractions,
                     char **intermediate_pubkeys, int step_count)
{
    FILE *debug_file = fopen("debug_paths.txt", "a");
    if (debug_file)
    {
        double div_percentage = (divisions * 100.0) / (divisions + subtractions);
        double sub_percentage = (subtractions * 100.0) / (divisions + subtractions);

        fprintf(debug_file, "=== Path Analysis ===\n");
        fprintf(debug_file, "Path: %s\n", path);
        fprintf(debug_file, "Final Public Key: %s\n", pubkey);
        fprintf(debug_file, "Total Steps: %d\n", divisions + subtractions);
        fprintf(debug_file, "Divisions: %d (%.1f%%)\n", divisions, div_percentage);
        fprintf(debug_file, "Subtractions: %d (%.1f%%)\n", subtractions, sub_percentage);

        // Print intermediate public keys
        fprintf(debug_file, "\nIntermediate Keys:\n");
        for (int i = 0; i < step_count; i++)
        {
            fprintf(debug_file, "Step %d: %s\n", i + 1, intermediate_pubkeys[i]);
        }
        fprintf(debug_file, "\n");
        fclose(debug_file);
    }
}

// Performance tracking functions
void initialize_performance_metrics(struct PerformanceMetrics *metrics)
{
    metrics->avg_path_length = 0.0;
    metrics->avg_divisions = 0.0;
    metrics->avg_subtractions = 0.0;
    metrics->success_rate = 0.0;
    metrics->total_attempts = 0;
    metrics->successful_attempts = 0;
    metrics->start_time = time(NULL);
    metrics->last_success_time = time(NULL);
    pthread_mutex_init(&metrics->metrics_mutex, NULL);
}

void update_performance_metrics(struct PerformanceMetrics *metrics, bool success,
                                int path_length, int divisions, int subtractions)
{
    pthread_mutex_lock(&metrics->metrics_mutex);

    metrics->total_attempts++;
    if (success)
    {
        metrics->successful_attempts++;
    }

    // Update rolling averages
    double weight = 1.0 / metrics->total_attempts;
    metrics->avg_path_length = (metrics->avg_path_length * (metrics->total_attempts - 1) + path_length) * weight;
    metrics->avg_divisions = (metrics->avg_divisions * (metrics->total_attempts - 1) + divisions) * weight;
    metrics->avg_subtractions = (metrics->avg_subtractions * (metrics->total_attempts - 1) + subtractions) * weight;
    metrics->success_rate = (double)metrics->successful_attempts / metrics->total_attempts * 100.0;

    pthread_mutex_unlock(&metrics->metrics_mutex);
}

// Path validation
bool is_valid_path(int divisions, int subtractions, int total_steps,
                   struct DivisionControl *ctrl)
{
    return (divisions >= TARGET_MIN_DIVISIONS &&
            divisions <= TARGET_MAX_DIVISIONS &&
            subtractions == ctrl->current_subtractions &&
            total_steps >= OPTIMAL_MIN_STEPS &&
            total_steps <= OPTIMAL_MAX_STEPS);
}

void initialize_division_control(struct DivisionControl *ctrl)
{
    ctrl->consecutive_failures = 0;
    ctrl->success_count = 0;
    ctrl->current_subtractions = MIN_SUBTRACTIONS;
    ctrl->completed_paths_at_current_level = 0;
    ctrl->last_was_subtraction = false;
    pthread_mutex_init(&ctrl->mutex, NULL);
}

bool should_divide(struct DivisionControl *ctrl, int current_divisions,
                   int current_subtractions, int remaining_steps,
                   int remaining_divisions_needed)
{
    pthread_mutex_lock(&ctrl->mutex);

    // Calculate maximum allowed path length
    // Calculate maximum allowed path length
    int max_path_length = TARGET_MAX_DIVISIONS + TARGET_MIN_DIVISIONS + ctrl->current_subtractions;

    // Calculate remaining operations needed
    int needed_divisions = TARGET_MIN_DIVISIONS - current_divisions;
    int needed_subtractions = ctrl->current_subtractions - current_subtractions;
    int remaining_operations = max_path_length - (current_divisions + current_subtractions);

    // If we're at max path length or have all needed operations, no more allowed
    if (current_divisions + current_subtractions >= max_path_length)
    {
        pthread_mutex_unlock(&ctrl->mutex);
        return false;
    }

    // Must divide after a subtraction
    if (ctrl->last_was_subtraction)
    {
        ctrl->last_was_subtraction = false;
        pthread_mutex_unlock(&ctrl->mutex);
        return true;
    }

    // If this is the last possible operation, it must be a division
    if (remaining_operations == 1)
    {
        pthread_mutex_unlock(&ctrl->mutex);
        return true;
    }

    // Calculate probability based on remaining requirements
    double probability = 0.5; // Start with 50/50

    // If we're behind on subtractions relative to path length, favor subtractions
    double current_progress = (double)(current_divisions + current_subtractions) / max_path_length;
    double subtraction_progress = (double)current_subtractions / ctrl->current_subtractions;

    if (subtraction_progress < current_progress && needed_subtractions > 0)
    {
        probability = 0.3; // 30% chance of division to catch up on subtractions
    }

    // If we need most remaining slots for divisions, favor divisions
    if (needed_divisions > (remaining_operations * 0.7))
    {
        probability = 0.7; // 70% chance of division
    }

    // Make random choice
    bool should_do_division = rnd() < probability;

    // Verify we can actually do a subtraction if that's what was chosen
    if (!should_do_division && needed_subtractions > 0 && remaining_operations >= 2)
    {
        ctrl->last_was_subtraction = true;
    }
    else
    {
        should_do_division = true;
    }

    pthread_mutex_unlock(&ctrl->mutex);
    return should_do_division;
}

void update_division_control(struct DivisionControl *ctrl, bool path_successful)
{
    pthread_mutex_lock(&ctrl->mutex);

    if (path_successful)
    {
        ctrl->consecutive_failures = 0;
        ctrl->success_count++;
        ctrl->completed_paths_at_current_level++;

        if (ctrl->completed_paths_at_current_level >= PATHS_PER_SUBTRACTION_LEVEL)
        {
            if (ctrl->current_subtractions == MAX_SUBTRACTIONS)
            {
                pthread_mutex_lock(&print_mutex);
                printf("\rResetting from %d back to %d subtractions        ",
                       ctrl->current_subtractions, MIN_SUBTRACTIONS);
                fflush(stdout);
                pthread_mutex_unlock(&print_mutex);

                ctrl->current_subtractions = MIN_SUBTRACTIONS;
                ctrl->completed_paths_at_current_level = 0;
            }
            else
            {
                ctrl->current_subtractions++;
                pthread_mutex_lock(&print_mutex);
                printf("\rAdvancing to subtraction level: %d        ",
                       ctrl->current_subtractions);
                fflush(stdout);
                pthread_mutex_unlock(&print_mutex);
                ctrl->completed_paths_at_current_level = 0;
            }
        }
    }
    else
    {
        ctrl->consecutive_failures++;

        // Optional: Add failure handling logic here if needed
        if (ctrl->consecutive_failures > 1000000)
        { // Example threshold
            ctrl->consecutive_failures = 0;
        }
    }

    pthread_mutex_unlock(&ctrl->mutex);
}

// Thread worker function
void *find_division_path_thread(void *arg)
{
    struct thread_args *args = (struct thread_args *)arg;
    struct Point *current_points = malloc(args->num_pubkeys * sizeof(struct Point));
    unsigned long long thread_attempts = 0;

    // Initialize current points
    for (int i = 0; i < args->num_pubkeys; i++)
    {
        mpz_init(current_points[i].x);
        mpz_init(current_points[i].y);
    }

    // Initialize GMP variables
    mpz_t two, one;
    mpz_init_set_str(two, "2", 10);
    mpz_init_set_str(one, "1", 10);
    mpz_t inversemultiplier;
    mpz_init(inversemultiplier);

    // Debug mode variables
    char **intermediate_pubkeys = NULL;
    int step_count = 0;
    if (debug_mode)
    {
        intermediate_pubkeys = malloc(OPTIMAL_MAX_STEPS * sizeof(char *));
        for (int i = 0; i < OPTIMAL_MAX_STEPS; i++)
        {
            intermediate_pubkeys[i] = malloc(132);
        }
    }

    while (1)
    {
        // Reset step count for new attempt
        step_count = 0;

        // Allocate memory for current public keys
        char **current_pks = malloc(args->num_pubkeys * sizeof(char *));
        for (int i = 0; i < args->num_pubkeys; i++)
        {
            current_pks[i] = malloc(132);
        }

        // Initialize path variables
        char path[10000] = "";
        int divisions = 0;
        int subtractions = 0;
        int total_steps = 0;
        bool must_divide = false;

        // Initialize current points
        for (int i = 0; i < args->num_pubkeys; i++)
        {
            mpz_set(current_points[i].x, args->start_pubkeys[i].x);
            mpz_set(current_points[i].y, args->start_pubkeys[i].y);
        }

        // Update attempt counters
        pthread_mutex_lock(&attempts_mutex);
        total_attempts++;
        thread_attempts++;
        pthread_mutex_unlock(&attempts_mutex);

        // Check if we need to reset based on time
        pthread_mutex_lock(&args->div_ctrl->mutex);
        time_t current_time = time(NULL);
        if (args->div_ctrl->current_subtractions == MAX_SUBTRACTIONS &&
            current_time - args->metrics->last_success_time > MAX_TIME_AT_LEVEL)
        {
            pthread_mutex_lock(&print_mutex);
            printf("\nResetting due to timeout at max level (no success in %d seconds)\n",
                   MAX_TIME_AT_LEVEL);
            pthread_mutex_unlock(&print_mutex);

            args->div_ctrl->current_subtractions = MIN_SUBTRACTIONS;
            args->div_ctrl->completed_paths_at_current_level = 0;
            args->metrics->last_success_time = current_time;
        }
        pthread_mutex_unlock(&args->div_ctrl->mutex);

        // Main path finding loop
        while (divisions < TARGET_MAX_DIVISIONS && total_steps < OPTIMAL_MAX_STEPS)
        {
            // Generate current public keys
            for (int i = 0; i < args->num_pubkeys; i++)
            {
                generate_strpublickey(&current_points[i], true, current_pks[i]);

                // Save intermediate keys in debug mode
                if (debug_mode && step_count < OPTIMAL_MAX_STEPS)
                {
                    strncpy(intermediate_pubkeys[step_count], current_pks[i], 131);
                    intermediate_pubkeys[step_count][131] = '\0';
                }
            }

            // Update current_path before checking bloom filters
            pthread_mutex_lock(&print_mutex); // Use print_mutex to protect current_path
            strncpy(current_path, path, sizeof(current_path) - 1);
            current_path[sizeof(current_path) - 1] = '\0';
            pthread_mutex_unlock(&print_mutex);

            // Print status for thread 0
            if (args->thread_id == 0)
            {
                pthread_mutex_lock(&print_mutex);
                printf("\r\033[K"); // Clear line
                printf("Attempts: %llu | DIV: %.1f%% SUB: %.1f%% | Steps: %d/%d | "
                       "Divisions: %d/%d | Subs: %d/%d | Level Progress: %d/%d | Key: %.20s",
                       total_attempts,
                       divisions > 0 ? (divisions * 100.0) / (divisions + subtractions) : 0,
                       subtractions > 0 ? (subtractions * 100.0) / (divisions + subtractions) : 0,
                       total_steps,
                       TARGET_MAX_DIVISIONS + args->div_ctrl->current_subtractions,
                       divisions,
                       TARGET_MAX_DIVISIONS,
                       subtractions,
                       args->div_ctrl->current_subtractions,
                       args->div_ctrl->completed_paths_at_current_level,
                       PATHS_PER_SUBTRACTION_LEVEL,
                       current_pks[0]);
                fflush(stdout);
                pthread_mutex_unlock(&print_mutex);
            }

            // Check keys against bloom filter
            for (int i = 0; i < args->num_pubkeys; i++)
            {
                if (bloom_initialized1 && triple_bloom_check(current_pks[i]))
                {
                    pthread_mutex_lock(&print_mutex);
                    printf("\nMatch found! Thread %d, Key %d\n", args->thread_id, i);
                    printf("Original: %s\n", args->initial_pks[i]);
                    printf("Found: %s\n", current_pks[i]);
                    printf("Path: %s\n", path);
                    pthread_mutex_unlock(&print_mutex);

                    save_path_to_file(path, current_pks[i], true);
                }
            }

            int remaining_steps = OPTIMAL_MAX_STEPS - total_steps;
            int remaining_divisions = TARGET_MIN_DIVISIONS - divisions;

            if (should_divide(args->div_ctrl, divisions, subtractions,
                              remaining_steps, remaining_divisions))
            {
                // Perform division
                for (int i = 0; i < args->num_pubkeys; i++)
                {
                    struct Point temp_point;
                    mpz_init(temp_point.x);
                    mpz_init(temp_point.y);

                    mpz_invert(inversemultiplier, two, EC.n);
                    Scalar_Multiplication_custom(current_points[i], &temp_point, inversemultiplier);

                    mpz_set(current_points[i].x, temp_point.x);
                    mpz_set(current_points[i].y, temp_point.y);

                    mpz_clear(temp_point.x);
                    mpz_clear(temp_point.y);
                }
                divisions++;
                total_steps++;
                strcat(path, "/2,");
                must_divide = false;
            }
            else
            {
                // Perform subtraction
                for (int i = 0; i < args->num_pubkeys; i++)
                {
                    struct Point temp_point, point_to_subtract;
                    mpz_init(temp_point.x);
                    mpz_init(temp_point.y);
                    mpz_init(point_to_subtract.x);
                    mpz_init(point_to_subtract.y);

                    Scalar_Multiplication(G, &point_to_subtract, one);
                    Point_Negation(&point_to_subtract, &temp_point);
                    Point_Addition(&current_points[i], &temp_point, &point_to_subtract);

                    mpz_set(current_points[i].x, point_to_subtract.x);
                    mpz_set(current_points[i].y, point_to_subtract.y);

                    mpz_clear(temp_point.x);
                    mpz_clear(temp_point.y);
                    mpz_clear(point_to_subtract.x);
                    mpz_clear(point_to_subtract.y);
                }
                subtractions++;
                total_steps++;
                strcat(path, "-1,");
                must_divide = true;
            }

            // Increment step count after each operation
            if (debug_mode)
            {
                step_count++;
            }

            // Check if all points are zero
            bool all_zero = true;
            for (int i = 0; i < args->num_pubkeys; i++)
            {
                if (!Point_is_zero(&current_points[i]))
                {
                    all_zero = false;
                    break;
                }
            }
            if (all_zero)
                break;
        }

        // Update division control based on path success
        bool path_successful = is_valid_path(divisions, subtractions, total_steps, args->div_ctrl);
        if (path_successful)
        {
            if (debug_mode)
            {
                save_debug_info(path, current_pks[0], divisions, subtractions,
                                intermediate_pubkeys, step_count);
            }
            args->metrics->last_success_time = time(NULL);
        }

        update_division_control(args->div_ctrl, path_successful);
        update_performance_metrics(args->metrics, path_successful, total_steps, divisions, subtractions);

        // Check if we should validate paths at max level
        if (args->div_ctrl->current_subtractions == MAX_SUBTRACTIONS &&
            thread_attempts % PATH_CHECK_INTERVAL == 0)
        {

            pthread_mutex_lock(&args->div_ctrl->mutex);
            time_t current_time = time(NULL);
            if (current_time - args->metrics->last_success_time > MAX_TIME_AT_LEVEL)
            {
                args->div_ctrl->current_subtractions = MIN_SUBTRACTIONS;
                args->div_ctrl->completed_paths_at_current_level = 0;
                args->metrics->last_success_time = current_time;

                pthread_mutex_lock(&print_mutex);
                printf("\nResetting from max level due to inactivity\n");
                pthread_mutex_unlock(&print_mutex);
            }
            pthread_mutex_unlock(&args->div_ctrl->mutex);
        }

        // Save successful paths
        if (path_successful || save_unsuccessful_paths)
        {
            for (int i = 0; i < args->num_pubkeys; i++)
            {
                save_path_to_file(path, current_pks[i], path_successful);
            }
        }

        // Cleanup current iteration
        for (int i = 0; i < args->num_pubkeys; i++)
        {
            free(current_pks[i]);
        }
        free(current_pks);
    }

    // Final cleanup
    mpz_clear(two);
    mpz_clear(one);
    mpz_clear(inversemultiplier);

    // Cleanup debug resources
    if (debug_mode)
    {
        for (int i = 0; i < OPTIMAL_MAX_STEPS; i++)
        {
            free(intermediate_pubkeys[i]);
        }
        free(intermediate_pubkeys);
    }

    for (int i = 0; i < args->num_pubkeys; i++)
    {
        mpz_clear(current_points[i].x);
        mpz_clear(current_points[i].y);
    }
    free(current_points);

    return NULL;
}

// Modified thread setup for auto-subtraction mode
void *auto_subtract_points_thread(void *arg)
{
    struct thread_args *args = (struct thread_args *)arg;
    struct Point *current_points = NULL;
    struct Point G_mult, temp_point, result_point;
    uint64_t local_count = args->thread_id;
    time_t last_update = time(NULL);
    time_t last_checkpoint = time(NULL);

    // Get the chunk size safely
    size_t num_points_to_process = 0;
    if (args->chunk)
    {
        pthread_mutex_lock(args->chunk_mutex);
        num_points_to_process = args->chunk->size;
        pthread_mutex_unlock(args->chunk_mutex);
    }
    else
    {
        num_points_to_process = args->num_pubkeys;
    }

    // Allocate points array
    current_points = malloc(num_points_to_process * sizeof(struct Point));
    if (!current_points)
    {
        printf("Thread %d: Failed to allocate memory for points\n", args->thread_id);
        return NULL;
    }

    // Initialize points
    for (size_t i = 0; i < num_points_to_process; i++)
    {
        mpz_init(current_points[i].x);
        mpz_init(current_points[i].y);
    }

    // Initialize result arrays
    args->current_pks = malloc(num_points_to_process * sizeof(char *));
    if (!args->current_pks)
    {
        for (size_t i = 0; i < num_points_to_process; i++)
        {
            mpz_clear(current_points[i].x);
            mpz_clear(current_points[i].y);
        }
        free(current_points);
        return NULL;
    }

    for (size_t i = 0; i < num_points_to_process; i++)
    {
        args->current_pks[i] = malloc(67); // 66 chars + null terminator
        if (!args->current_pks[i])
        {
            // Cleanup previous allocations
            for (size_t j = 0; j < i; j++)
            {
                free(args->current_pks[j]);
            }
            free(args->current_pks);
            for (size_t j = 0; j < num_points_to_process; j++)
            {
                mpz_clear(current_points[j].x);
                mpz_clear(current_points[j].y);
            }
            free(current_points);
            return NULL;
        }
    }

    // Copy initial points with mutex protection
    if (args->chunk)
    {
        pthread_mutex_lock(args->chunk_mutex);
        for (size_t i = 0; i < num_points_to_process; i++)
        {
            mpz_set(current_points[i].x, args->chunk->points[i].x);
            mpz_set(current_points[i].y, args->chunk->points[i].y);
            strncpy(args->current_pks[i], args->chunk->current_pubkeys[i], 66);
            args->current_pks[i][66] = '\0';
        }
        pthread_mutex_unlock(args->chunk_mutex);
    }
    else
    {
        for (size_t i = 0; i < num_points_to_process; i++)
        {
            mpz_set(current_points[i].x, args->start_pubkeys[i].x);
            mpz_set(current_points[i].y, args->start_pubkeys[i].y);
            strncpy(args->current_pks[i], args->initial_pks[i], 66);
            args->current_pks[i][66] = '\0';
        }
    }

    // Initialize GMP variables
    mpz_init(G_mult.x);
    mpz_init(G_mult.y);
    mpz_init(temp_point.x);
    mpz_init(temp_point.y);
    mpz_init(result_point.x);
    mpz_init(result_point.y);

    // Main processing loop
    while (1)
    {
        // Generate and check current public keys
        for (size_t i = 0; i < num_points_to_process; i++)
        {
            generate_strpublickey(&current_points[i], true, args->current_pks[i]);

            if (bloom_initialized1 && triple_bloom_check(args->current_pks[i]))
            {
                pthread_mutex_lock(&print_mutex);
                printf("\nMatch found! Thread %d at subtraction %" PRIu64 "\n",
                       args->thread_id, local_count);
                if (args->chunk)
                {
                    printf("Original chunk key %zu: %s\n", i, args->chunk->current_pubkeys[i]);
                }
                else
                {
                    printf("Original: %s\n", args->initial_pks[i]);
                }
                printf("Found: %s\n", args->current_pks[i]);
                pthread_mutex_unlock(&print_mutex);
                goto cleanup;
            }
        }

        // Rest of the processing loop remains the same...
        local_count += args->num_threads;
        pthread_mutex_lock(&subtraction_count_mutex);
        global_subtraction_count++;
        pthread_mutex_unlock(&subtraction_count_mutex);

        // Status update
        time_t current_time = time(NULL);
        if (current_time - last_update >= 1)
        {
            pthread_mutex_lock(&print_mutex);
            printf("\rThread %d: %" PRIu64 " subtractions | Global: %" PRIu64 " | Key1: %.20s...",
                   args->thread_id, local_count, global_subtraction_count,
                   args->current_pks[0]);
            fflush(stdout);
            pthread_mutex_unlock(&print_mutex);
            last_update = current_time;
        }

        // Calculate and perform next subtraction
        mpz_t step_subtract;
        mpz_init(step_subtract);
        mpz_mul_ui(step_subtract, auto_subtraction_value, args->num_threads);

        Scalar_Multiplication(G, &G_mult, step_subtract);
        Point_Negation(&G_mult, &temp_point);
        mpz_clear(step_subtract);

        // Apply subtraction to all points with boundary check
        for (size_t i = 0; i < num_points_to_process; i++)
        {
            Point_Addition(&current_points[i], &temp_point, &result_point);
            mpz_set(current_points[i].x, result_point.x);
            mpz_set(current_points[i].y, result_point.y);
        }
    }

cleanup:
    // Cleanup GMP variables
    mpz_clear(G_mult.x);
    mpz_clear(G_mult.y);
    mpz_clear(temp_point.x);
    mpz_clear(temp_point.y);
    mpz_clear(result_point.x);
    mpz_clear(result_point.y);

    // Cleanup points
    for (size_t i = 0; i < num_points_to_process; i++)
    {
        mpz_clear(current_points[i].x);
        mpz_clear(current_points[i].y);
    }
    free(current_points);

    // Cleanup public keys
    for (size_t i = 0; i < num_points_to_process; i++)
    {
        free(args->current_pks[i]);
    }
    free(args->current_pks);

    return NULL;
}

// Estimates the size of a bloom filter in bytes
uint64_t estimate_bloom_size(uint64_t items, double fp_rate)
{
    return (uint64_t)((-1.0 * items * log(fp_rate)) / (log(2.0) * log(2.0))) / 8;
}

void print_memory_requirements()
{
    // Calculate bloom filter sizes using existing defines
    uint64_t bloom1_size = estimate_bloom_size(MAX_ENTRIES1, BLOOM1_FP_RATE);
    uint64_t bloom2_size = estimate_bloom_size(MAX_ENTRIES2, BLOOM2_FP_RATE);
    uint64_t bloom3_size = estimate_bloom_size(MAX_ENTRIES3, BLOOM3_FP_RATE);

    // Convert to MB for display
    double bloom1_mb = bloom1_size / (1024.0 * 1024.0);
    double bloom2_mb = bloom2_size / (1024.0 * 1024.0);
    double bloom3_mb = bloom3_size / (1024.0 * 1024.0);
    double total_mb = bloom1_mb + bloom2_mb + bloom3_mb;

    printf("\nEstimated memory requirements:\n");
    printf("Bloom filter 1 (%d entries): %.2f MB\n", MAX_ENTRIES1, bloom1_mb);
    printf("Bloom filter 2 (%d entries): %.2f MB\n", MAX_ENTRIES2, bloom2_mb);
    printf("Bloom filter 3 (%d entries): %.2f MB\n", MAX_ENTRIES3, bloom3_mb);
    printf("Total bloom filters: %.2f MB\n\n", total_mb);

    // Check available system memory
#if defined(_WIN64) && !defined(__CYGWIN__)
    MEMORYSTATUSEX statex;
    statex.dwLength = sizeof(statex);
    GlobalMemoryStatusEx(&statex);
    uint64_t available_mb = statex.ullAvailPhysMem / (1024 * 1024);
#else
    uint64_t pages = sysconf(_SC_PHYS_PAGES);
    uint64_t page_size = sysconf(_SC_PAGE_SIZE);
    uint64_t available_mb = ((uint64_t)pages * (uint64_t)page_size) / (1024 * 1024);
#endif

    printf("Available system memory: %llu MB\n", (unsigned long long)available_mb);

    if (total_mb > available_mb * 0.9)
    {
        printf("\nWARNING: Estimated memory usage (%.2f MB) is close to or exceeds available memory (%llu MB)\n",
               total_mb, (unsigned long long)available_mb);
        printf("Consider reducing MAX_ENTRIES or adjusting bloom filter parameters\n");
    }
    else
    {
        printf("Memory requirements are within safe limits (%.1f%% of available memory)\n",
               (total_mb / available_mb) * 100);
    }
}

int init_multi_bloom_from_file(const char *filename)
{
    if (!init_search_file(filename))
    {
        return 0;
    }

    print_memory_requirements();

    // Initialize bloom filters
    if (bloom_init2(&bloom_filter1, MAX_ENTRIES1, BLOOM1_FP_RATE) != 0 ||
        bloom_init2(&bloom_filter2, MAX_ENTRIES2, BLOOM2_FP_RATE) != 0 ||
        bloom_init2(&bloom_filter3, MAX_ENTRIES3, BLOOM3_FP_RATE) != 0)
    {
        printf("Error: Failed to initialize bloom filters\n");
        return 0;
    }

    bloom_initialized1 = bloom_initialized2 = bloom_initialized3 = true;

    // Memory map the file for faster reading
    int fd = fileno(search_file_info.file);
    struct stat sb;
    if (fstat(fd, &sb) == -1)
    {
        perror("fstat");
        return 0;
    }

    // Determine number of threads based on CPU cores
    int num_threads = sysconf(_SC_NPROCESSORS_ONLN);
    if (num_threads > 64)
        num_threads = 64;

    // Calculate entries per thread
    size_t entry_size = search_file_info.is_binary ? COMPRESSED_PUBKEY_SIZE : HEX_PUBKEY_SIZE;
    size_t total_entries = sb.st_size / entry_size;
    size_t entries_per_thread = (total_entries + num_threads - 1) / num_threads;

    // Allocate worker structures
    struct bloom_load_worker *workers = malloc(num_threads * sizeof(struct bloom_load_worker));
    pthread_t *threads = malloc(num_threads * sizeof(pthread_t));

    // Read file in chunks and process in parallel
    unsigned char *buffer = malloc(BUFFER_SIZE);
    size_t entries_processed = 0;
    size_t bytes_read;

    printf("Loading bloom filters using %d threads...\n", num_threads);
    time_t start_time = time(NULL);

    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, search_file_info.file)) > 0)
    {
        size_t entries_in_buffer = bytes_read / entry_size;
        size_t entries_per_worker = (entries_in_buffer + num_threads - 1) / num_threads;

        // Create worker threads
        for (int i = 0; i < num_threads; i++)
        {
            workers[i].bloom1 = &bloom_filter1;
            workers[i].bloom2 = &bloom_filter2;
            workers[i].bloom3 = &bloom_filter3;
            workers[i].is_binary = search_file_info.is_binary;

            size_t start_entry = i * entries_per_worker;
            if (start_entry >= entries_in_buffer)
                break;

            workers[i].entries = buffer + (start_entry * entry_size);
            workers[i].num_entries = (i == num_threads - 1) ? entries_in_buffer - start_entry : entries_per_worker;

            if (pthread_create(&threads[i], NULL, bloom_load_worker_thread, &workers[i]) != 0)
            {
                printf("Error creating thread %d\n", i);
                return 0;
            }
        }

        // Wait for all threads to complete
        for (int i = 0; i < num_threads; i++)
        {
            pthread_join(threads[i], NULL);
        }

        entries_processed += entries_in_buffer;

        // Print progress
        time_t current_time = time(NULL);
        double elapsed = difftime(current_time, start_time);
        double rate = entries_processed / elapsed;
        printf("\rProcessed %zu entries (%.2f entries/sec)...",
               entries_processed, rate);
        fflush(stdout);
    }

    printf("\nCompleted loading %zu entries in %.1f seconds\n",
           entries_processed, difftime(time(NULL), start_time));

    // Cleanup
    free(buffer);
    free(workers);
    free(threads);

    // Reset file position for future reads
    fseek(search_file_info.file, 0, SEEK_SET);
    return 1;
}

bool triple_bloom_check(const char *pubkey)
{
    if (!pubkey || strlen(pubkey) < 66)
    {
        return false;
    }

    if (!bloom_initialized1 || !bloom_initialized2 || !bloom_initialized3)
    {
        printf("Error: Bloom filters not initialized\n");
        return false;
    }

    unsigned char x_coord[32];
    hexs2bin(pubkey + 2, x_coord);

    // First bloom filter check - prefix of X coordinate
    if (!bloom_check(&bloom_filter1, (char *)x_coord, PUBKEY_PREFIX_LENGTH))
    {
        return false;
    }

    // Second bloom filter check - hash of full X coordinate
    XXH64_hash_t hash1 = XXH64(x_coord, 32, 0x1234);
    if (!bloom_check(&bloom_filter2, (char *)&hash1, sizeof(hash1)))
    {
        return false;
    }

    // Third bloom filter check - different hash of full X coordinate
    XXH64_hash_t hash2 = XXH64(x_coord, 32, 0x5678);
    if (!bloom_check(&bloom_filter3, (char *)&hash2, sizeof(hash2)))
    {
        return false;
    }

    // Binary search for exact match
    int64_t index = binary_search_pubkey(pubkey);

    if (index >= 0)
    {
        pthread_mutex_lock(&print_mutex);
        printf("\nVerified match found!\n");
        printf("Index: %ld\n", index);
        printf("Public Key: %s\n", pubkey);
        printf("Line Number Private Key (Hex): %lX\n", index);

        // Start with the line number as our private key
        uint64_t current_privkey = index;

        // Split the path into steps
        char *path_copy = strdup(current_path);
        char *token = strtok(path_copy, ",");
        char *steps[1000];
        int step_count = 0;

        // Store all steps
        while (token != NULL && step_count < 1000)
        {
            steps[step_count++] = strdup(token);
            token = strtok(NULL, ",");
        }

        // Work backwards through the path to find original private key
        for (int i = step_count - 1; i >= 0; i--)
        {
            if (strstr(steps[i], "/2"))
            {
                // If it was divided by 2, multiply by 2
                current_privkey *= 2;
                printf("After reversing %s: %lX\n", steps[i], current_privkey);
            }
            else if (strstr(steps[i], "-1"))
            {
                // If it was subtracted by 1, subtract 1
                current_privkey -= 1;
                printf("After reversing %s: %lX\n", steps[i], current_privkey);
            }
            free(steps[i]);
        }
        free(path_copy);

        printf("Original Private Key: %lX\n", current_privkey);

        if (search_file_info.is_binary)
        {
            printf("File Position: %ld bytes\n", index * COMPRESSED_PUBKEY_SIZE);
        }

        char match_info[512];
        snprintf(match_info, sizeof(match_info),
                 "Index: %ld, Key: %s, Line PrivKey: %lX, Original PrivKey: %lX",
                 index, pubkey, index, current_privkey);
        save_path_to_file(current_path, match_info, true);

        pthread_mutex_unlock(&print_mutex);
        return true;
    }

    return false;
}

void cleanup_bloom_filters(void)
{
    if (search_file_info.file)
    {
        fclose(search_file_info.file);
        pthread_mutex_destroy(&search_file_info.file_mutex);
    }

    if (bloom_initialized1)
    {
        bloom_free(&bloom_filter1);
    }
    if (bloom_initialized2)
    {
        bloom_free(&bloom_filter2);
    }
    if (bloom_initialized3)
    {
        bloom_free(&bloom_filter3);
    }
}

// Public key operations
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
            fprintf(stderr, "[E] Invalid public key format: %s\n", dest);
            exit(0);
        }

        mpz_clear(mpz_aux);
        mpz_clear(mpz_aux2);
        mpz_clear(Ysquared);
    }
    free(dest);
}

void save_path_to_file(const char *path, const char *found_pk, bool is_match)
{
    pthread_mutex_lock(&file_mutex);
    time_t now;
    time(&now);

    FILE *file = fopen("found_paths.txt", "a");
    if (file)
    {
        fprintf(file, "=== Search Result %s", ctime(&now));
        fprintf(file, "Public Key: %s\n", found_pk);
        fprintf(file, "Path: %s\n", path);
        fprintf(file, "Match Type: %s\n\n", is_match ? "CONFIRMED" : "POTENTIAL");
        fclose(file);
    }
    else
    {
        printf("Warning: Could not save path to file\n");
    }
    pthread_mutex_unlock(&file_mutex);
}

bool Point_is_zero(struct Point *P)
{
    return (mpz_cmp_ui(P->x, 0) == 0 && mpz_cmp_ui(P->y, 0) == 0);
}

void Scalar_Multiplication_custom(struct Point P, struct Point *R, mpz_t m)
{
    struct Point Q, T;
    long no_of_bits, loop;
    mpz_init(Q.x);
    mpz_init(Q.y);
    mpz_init(T.x);
    mpz_init(T.y);

    no_of_bits = mpz_sizeinbase(m, 2);
    mpz_set_ui(R->x, 0);
    mpz_set_ui(R->y, 0);

    if (mpz_cmp_ui(m, 0) != 0)
    {
        mpz_set(Q.x, P.x);
        mpz_set(Q.y, P.y);

        if (mpz_tstbit(m, 0) == 1)
        {
            mpz_set(R->x, P.x);
            mpz_set(R->y, P.y);
        }

        for (loop = 1; loop < no_of_bits; loop++)
        {
            Point_Doubling(&Q, &T);
            mpz_set(Q.x, T.x);
            mpz_set(Q.y, T.y);
            mpz_set(T.x, R->x);
            mpz_set(T.y, R->y);

            if (mpz_tstbit(m, loop))
            {
                Point_Addition(&T, &Q, R);
            }
        }
    }

    mpz_clear(Q.x);
    mpz_clear(Q.y);
    mpz_clear(T.x);
    mpz_clear(T.y);
}

int main(int argc, char **argv)
{
    rseed(time(NULL));

    mpz_init_set_str(EC.p, EC_constant_P, 16);
    mpz_init_set_str(EC.n, EC_constant_N, 16);
    mpz_init_set_str(G.x, EC_constant_Gx, 16);
    mpz_init_set_str(G.y, EC_constant_Gy, 16);
    init_doublingG(&G);

    struct Point A, B, C;
    mpz_init_set_ui(A.x, 0);
    mpz_init_set_ui(A.y, 0);
    mpz_init_set_ui(B.x, 0);
    mpz_init_set_ui(B.y, 0);
    mpz_init_set_ui(C.x, 0);
    mpz_init_set_ui(C.y, 0);

    mpz_t number, inversemultiplier;
    mpz_init(number);
    mpz_init(inversemultiplier);
    bool FLAG_NUMBER = false;
    char str_publickey[132];
    struct ChunkedKeyStorage *storage = NULL;

    struct PerformanceMetrics metrics;
    initialize_performance_metrics(&metrics);

    int opt;
    char *bloom_file = NULL;
    char *input_file = NULL;
    int target_bit = 0;
    int num_threads = 1;

    while ((opt = getopt(argc, argv, "f:b:st:d:a:i:")) != -1)
    {
        switch (opt)
        {
        case 'a':
            auto_subtraction_mode = true;
            mpz_init_set_str(auto_subtraction_value, optarg, 10);
            break;
        case 'd':
            debug_mode = true;
            break;
        case 'f':
            bloom_file = optarg;
            break;
        case 'i':
            input_file = optarg;
            break;
        case 'b':
            target_bit = atoi(optarg);
            break;
        case 's':
            save_unsuccessful_paths = true;
            break;
        case 't':
            num_threads = atoi(optarg);
            if (num_threads < 1)
                num_threads = 1;
            if (num_threads > MAX_THREADS)
                num_threads = MAX_THREADS;
            break;
        default:
            printf("Usage: %s [-f bloom_file] [-b target_bit] [-t threads] [-s] [-a subtraction_value] [-i input_file] <pubkey>\n", argv[0]);
            printf("Operations:\n");
            printf("  Normal mode: <pubkey1> [+|-|x|/] <pubkey2/number>\n");
            printf("  Auto subtraction mode (command line): -f <bloom_file> -a <value> <pubkey>\n");
            printf("  Auto subtraction mode (file input): -f <bloom_file> -a <value> -i <input_file>\n");
            printf("  Division path mode: -b <target_bit> <pubkey1> [pubkey2...]\n");
            exit(1);
        }
    }

    argc -= optind;
    argv += optind;

    if (bloom_file && !init_multi_bloom_from_file(bloom_file))
    {
        printf("Failed to initialize bloom filters\n");
        exit(1);
    }

    if (!input_file && argc < 1)
    {
        printf("Error: No public key provided and no input file specified\n");
        exit(1);
    }
    if (auto_subtraction_mode)
    {
        if (!bloom_file)
        {
            printf("Error: Bloom filter (-f) required for auto subtraction mode\n");
            exit(1);
        }

        // Set up signal handler for Ctrl+C
        signal(SIGINT, handle_interrupt);

        int num_pubkeys;
        struct Point *start_points = NULL;
        char **initial_pks = NULL;

        if (input_file)
        {
            storage = init_chunked_storage();
            if (!storage)
            {
                printf("Failed to initialize storage\n");
                exit(1);
            }

            if (!load_keys_from_file(storage, input_file))
            {
                printf("Failed to load keys from input file\n");
                if (storage)
                {
                    cleanup_storage(storage);
                }
                exit(1);
            }

            num_pubkeys = storage->total_keys;
            if (num_pubkeys == 0)
            {
                printf("Error: No valid public keys loaded from file\n");
                cleanup_storage(storage);
                exit(1);
            }

            printf("Loaded %d keys from file\n", num_pubkeys);

            // Verify chunks after loading
            if (!verify_chunks(storage))
            {
                printf("Error: Chunk verification failed\n");
                cleanup_storage(storage);
                exit(1);
            }
        }
        else
        {
            num_pubkeys = argc;
        }

        // Allocate memory for points and keys
        start_points = malloc(num_pubkeys * sizeof(struct Point));
        initial_pks = malloc(num_pubkeys * sizeof(char *));

        if (!start_points || !initial_pks)
        {
            printf("Failed to allocate memory for points or keys\n");
            free(start_points);
            free(initial_pks);
            cleanup_storage(storage);
            exit(1);
        }

        printf("Starting unlimited auto subtraction with %d threads\n", num_threads);
        printf("Processing %d public keys\n", num_pubkeys);

        // Initialize start points and keys
        for (int i = 0; i < num_pubkeys; i++)
        {
            mpz_init(start_points[i].x);
            mpz_init(start_points[i].y);

            if (storage)
            {
                struct PublicKeyChunk *current = storage->chunks;
                int accumulated_size = 0;

                // Find the correct chunk for this key
                while (current && i >= accumulated_size + current->size)
                {
                    accumulated_size += current->size;
                    current = current->next;
                }

                if (!current)
                {
                    printf("Error: Invalid chunk access at key %d\n", i);
                    // Cleanup already initialized points
                    for (int j = 0; j < i; j++)
                    {
                        mpz_clear(start_points[j].x);
                        mpz_clear(start_points[j].y);
                        free(initial_pks[j]);
                    }
                    free(start_points);
                    free(initial_pks);
                    cleanup_storage(storage);
                    exit(1);
                }

                int chunk_index = i - accumulated_size;
                if (chunk_index < 0 || chunk_index >= current->size)
                {
                    printf("Error: Invalid chunk index %d at key %d\n", chunk_index, i);
                    // Cleanup
                    for (int j = 0; j < i; j++)
                    {
                        mpz_clear(start_points[j].x);
                        mpz_clear(start_points[j].y);
                        free(initial_pks[j]);
                    }
                    free(start_points);
                    free(initial_pks);
                    cleanup_storage(storage);
                    exit(1);
                }

                // Copy from storage with mutex protection
                pthread_mutex_lock(&storage->chunk_mutexes[get_chunk_index(storage, current)]);
                mpz_set(start_points[i].x, current->points[chunk_index].x);
                mpz_set(start_points[i].y, current->points[chunk_index].y);
                initial_pks[i] = strdup(current->current_pubkeys[chunk_index]);
                pthread_mutex_unlock(&storage->chunk_mutexes[get_chunk_index(storage, current)]);

                if (!initial_pks[i])
                {
                    printf("Failed to allocate memory for key %d\n", i);
                    // Cleanup
                    for (int j = 0; j < i; j++)
                    {
                        mpz_clear(start_points[j].x);
                        mpz_clear(start_points[j].y);
                        free(initial_pks[j]);
                    }
                    free(start_points);
                    free(initial_pks);
                    cleanup_storage(storage);
                    exit(1);
                }
            }
            else
            {
                // Use command line input
                if (i >= argc)
                {
                    printf("Error: Not enough command line arguments\n");
                    // Cleanup
                    for (int j = 0; j < i; j++)
                    {
                        mpz_clear(start_points[j].x);
                        mpz_clear(start_points[j].y);
                        free(initial_pks[j]);
                    }
                    free(start_points);
                    free(initial_pks);
                    exit(1);
                }

                initial_pks[i] = strdup(argv[i]);
                if (!initial_pks[i])
                {
                    printf("Failed to allocate memory for key %d\n", i);
                    // Cleanup
                    for (int j = 0; j < i; j++)
                    {
                        mpz_clear(start_points[j].x);
                        mpz_clear(start_points[j].y);
                        free(initial_pks[j]);
                    }
                    free(start_points);
                    free(initial_pks);
                    exit(1);
                }
                set_publickey(argv[i], &start_points[i]);
            }
            printf("Public key %d: %s\n", i + 1, initial_pks[i]);
        }
        // Calculate optimal thread distribution
        int keys_per_thread = (num_pubkeys + num_threads - 1) / num_threads;

        // Create and initialize threads
        pthread_t *threads = malloc(num_threads * sizeof(pthread_t));
        thread_args_array = malloc(num_threads * sizeof(struct thread_args));

        if (!threads || !thread_args_array)
        {
            printf("Failed to allocate memory for threads\n");
            // Cleanup points and keys
            for (int i = 0; i < num_pubkeys; i++)
            {
                mpz_clear(start_points[i].x);
                mpz_clear(start_points[i].y);
                free(initial_pks[i]);
            }
            free(start_points);
            free(initial_pks);
            free(threads);
            free(thread_args_array);
            cleanup_storage(storage);
            exit(1);
        }

        // Initialize threads
        for (int i = 0; i < num_threads; i++)
        {
            int start_idx = i * keys_per_thread;
            int end_idx = (i == num_threads - 1) ? num_pubkeys : (start_idx + keys_per_thread);

            thread_args_array[i].start_pubkeys = start_points;
            thread_args_array[i].initial_pks = initial_pks;
            thread_args_array[i].num_pubkeys = end_idx - start_idx;
            thread_args_array[i].thread_id = i;
            thread_args_array[i].auto_subtraction = true;
            thread_args_array[i].num_threads = num_threads;
            thread_args_array[i].start_index = start_idx;
            thread_args_array[i].end_index = end_idx;
            thread_args_array[i].target_bit = 0;
            thread_args_array[i].div_ctrl = NULL;
            thread_args_array[i].metrics = NULL;
            thread_args_array[i].current_pks = NULL;

            if (storage)
            {
                // Find the correct chunk for this thread's start index
                struct PublicKeyChunk *current = storage->chunks;
                int accumulated_size = 0;

                while (current && start_idx >= accumulated_size + current->size)
                {
                    accumulated_size += current->size;
                    current = current->next;
                }

                if (!current)
                {
                    printf("Error: Could not find appropriate chunk for thread %d\n", i);
                    // Cleanup and exit
                    for (int j = 0; j < num_pubkeys; j++)
                    {
                        mpz_clear(start_points[j].x);
                        mpz_clear(start_points[j].y);
                        free(initial_pks[j]);
                    }
                    free(start_points);
                    free(initial_pks);
                    free(threads);
                    free(thread_args_array);
                    cleanup_storage(storage);
                    exit(1);
                }

                thread_args_array[i].chunk = current;
                thread_args_array[i].chunk_mutex = &storage->chunk_mutexes[get_chunk_index(storage, current)];
            }
            else
            {
                thread_args_array[i].chunk = NULL;
                thread_args_array[i].chunk_mutex = NULL;
            }

            if (pthread_create(&threads[i], NULL, auto_subtract_points_thread, &thread_args_array[i]) != 0)
            {
                printf("Failed to create thread %d\n", i);
                // Cleanup everything
                for (int j = 0; j < num_pubkeys; j++)
                {
                    mpz_clear(start_points[j].x);
                    mpz_clear(start_points[j].y);
                    free(initial_pks[j]);
                }
                free(start_points);
                free(initial_pks);
                free(threads);
                free(thread_args_array);
                cleanup_storage(storage);
                exit(1);
            }
        }

        // Wait for threads to complete
        for (int i = 0; i < num_threads; i++)
        {
            pthread_join(threads[i], NULL);
        }

        // Cleanup auto-subtraction mode resources
        for (int i = 0; i < num_pubkeys; i++)
        {
            mpz_clear(start_points[i].x);
            mpz_clear(start_points[i].y);
            free(initial_pks[i]);
        }
        free(start_points);
        free(initial_pks);
        free(threads);
        free(thread_args_array);
    }
    // Normal operation mode (non-threaded)
    if (target_bit == 0 && !auto_subtraction_mode)
    {
        if (argc != 3)
        {
            printf("Error: Incorrect number of arguments for normal operation\n");
            exit(1);
        }

        switch (strlen(argv[0]))
        {
        case 66:
        case 130:
            set_publickey(argv[0], &A);
            break;
        default:
            printf("Error: Invalid public key length\n");
            exit(1);
        }

        char operation = argv[1][0];
        if (operation != '+' && operation != '-' && operation != 'x' && operation != '/')
        {
            printf("Error: Invalid operation '%c'\n", operation);
            exit(1);
        }

        switch (strlen(argv[2]))
        {
        case 66:
            if (argv[2][0] == '0' && argv[2][1] == 'x')
            {
                mpz_set_str(number, argv[2], 0);
                FLAG_NUMBER = true;
            }
            else
            {
                set_publickey(argv[2], &B);
                FLAG_NUMBER = false;
            }
            break;
        case 130:
            set_publickey(argv[2], &B);
            FLAG_NUMBER = false;
            break;
        default:
            mpz_set_str(number, argv[2], 0);
            FLAG_NUMBER = true;
            break;
        }

        mpz_mod(number, number, EC.n);

        switch (operation)
        {
        case '+':
            if (FLAG_NUMBER)
            {
                Scalar_Multiplication(G, &B, number);
            }
            Point_Addition(&A, &B, &C);
            break;

        case '-':
            if (FLAG_NUMBER)
            {
                Scalar_Multiplication(G, &B, number);
            }
            Point_Negation(&B, &C);
            mpz_set(B.x, C.x);
            mpz_set(B.y, C.y);
            Point_Addition(&A, &B, &C);
            break;

        case 'x':
            if (!FLAG_NUMBER)
            {
                printf("Error: Multiplication requires a scalar number\n");
                exit(1);
            }
            Scalar_Multiplication_custom(A, &C, number);
            break;

        case '/':
            if (!FLAG_NUMBER)
            {
                printf("Error: Division requires a scalar number\n");
                exit(1);
            }
            mpz_invert(inversemultiplier, number, EC.n);
            Scalar_Multiplication_custom(A, &C, inversemultiplier);
            break;
        }

        generate_strpublickey(&C, true, str_publickey);
        printf("Result: %s\n\n", str_publickey);
    }
    else if (target_bit != 0) // Division path mode
    {
        int num_pubkeys = argc;
        struct Point *pubkeys = malloc(num_pubkeys * sizeof(struct Point));
        char **initial_pks = malloc(num_pubkeys * sizeof(char *));

        if (!pubkeys || !initial_pks)
        {
            printf("Failed to allocate memory for division path mode\n");
            free(pubkeys);
            free(initial_pks);
            exit(1);
        }

        for (int i = 0; i < num_pubkeys; i++)
        {
            mpz_init(pubkeys[i].x);
            mpz_init(pubkeys[i].y);
            initial_pks[i] = malloc(132);
            if (!initial_pks[i])
            {
                printf("Failed to allocate memory for public key %d\n", i);
                // Cleanup
                for (int j = 0; j < i; j++)
                {
                    mpz_clear(pubkeys[j].x);
                    mpz_clear(pubkeys[j].y);
                    free(initial_pks[j]);
                }
                free(pubkeys);
                free(initial_pks);
                exit(1);
            }
            set_publickey(argv[i], &pubkeys[i]);
            generate_strpublickey(&pubkeys[i], true, initial_pks[i]);
        }

        pthread_t *threads = malloc(num_threads * sizeof(pthread_t));
        struct thread_args *args = malloc(num_threads * sizeof(struct thread_args));
        struct DivisionControl *div_ctrl = malloc(sizeof(struct DivisionControl));

        if (!threads || !args || !div_ctrl)
        {
            printf("Failed to allocate memory for thread resources\n");
            // Cleanup
            for (int i = 0; i < num_pubkeys; i++)
            {
                mpz_clear(pubkeys[i].x);
                mpz_clear(pubkeys[i].y);
                free(initial_pks[i]);
            }
            free(pubkeys);
            free(initial_pks);
            free(threads);
            free(args);
            free(div_ctrl);
            exit(1);
        }

        initialize_division_control(div_ctrl);

        printf("Starting search with %d threads for %d public keys\n", num_threads, num_pubkeys);
        for (int i = 0; i < num_pubkeys; i++)
        {
            printf("Initial public key %d: %s\n", i + 1, initial_pks[i]);
        }

        for (int i = 0; i < num_threads; i++)
        {
            args[i].start_pubkeys = pubkeys;
            args[i].num_pubkeys = num_pubkeys;
            args[i].target_bit = target_bit;
            args[i].thread_id = i;
            args[i].initial_pks = initial_pks;
            args[i].div_ctrl = div_ctrl;
            args[i].metrics = &metrics;
            args[i].chunk = NULL;
            args[i].chunk_mutex = NULL;

            if (pthread_create(&threads[i], NULL, find_division_path_thread, &args[i]) != 0)
            {
                printf("Failed to create thread %d\n", i);
                // Cleanup
                for (int j = 0; j < num_pubkeys; j++)
                {
                    mpz_clear(pubkeys[j].x);
                    mpz_clear(pubkeys[j].y);
                    free(initial_pks[j]);
                }
                free(pubkeys);
                free(initial_pks);
                free(threads);
                free(args);
                pthread_mutex_destroy(&div_ctrl->mutex);
                free(div_ctrl);
                exit(1);
            }
        }

        // Wait for division path threads
        for (int i = 0; i < num_threads; i++)
        {
            pthread_join(threads[i], NULL);
        }

        // Cleanup division path mode
        for (int i = 0; i < num_pubkeys; i++)
        {
            mpz_clear(pubkeys[i].x);
            mpz_clear(pubkeys[i].y);
            free(initial_pks[i]);
        }
        free(pubkeys);
        free(initial_pks);
        free(threads);
        free(args);
        pthread_mutex_destroy(&div_ctrl->mutex);
        free(div_ctrl);
    }

    // Final cleanup
    cleanup_bloom_filters();
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
    mpz_clear(number);
    mpz_clear(inversemultiplier);
    pthread_mutex_destroy(&metrics.metrics_mutex);

    if (storage)
    {
        cleanup_storage(storage);
    }

    if (auto_subtraction_mode)
    {
        mpz_clear(auto_subtraction_value);
    }

    return 0;
}
