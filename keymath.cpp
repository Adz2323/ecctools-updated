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

#define NUM_THREADS 2
#define BATCH_SIZE 1024
#define PUBKEY_CACHE_SIZE 10000

// Bloom filter configuration
#define MAX_ENTRIES1 100000000
#define MAX_ENTRIES2 80000000
#define MAX_ENTRIES3 60000000
#define PUBKEY_PREFIX_LENGTH 6
#define BLOOM1_FP_RATE 0.0001
#define BLOOM2_FP_RATE 0.00001
#define BLOOM3_FP_RATE 0.000001
#define BUFFER_SIZE (1024 * 1024)
#define COMPRESSED_PUBKEY_SIZE 33
#define HEX_PUBKEY_SIZE 66

Int BILLION;
void InitBILLION()
{
    BILLION.SetBase10("1000000000"); // One billion
}

typedef void *(*worker_func_t)(void *);

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

struct Fraction
{
    int numerator;
    int denominator;
};

struct SystematicState
{
    bool enabled;
    Int current_step;
    Int min_range;
    Int max_range;
    Point start_point;
    Int running_total;
    pthread_mutex_t step_mutex;
};

struct StepSubtractionState
{
    bool enabled;
    Fraction step_fraction;
    Int initial_value;
    Point current_point;
    Int current_value;
    bool first_step;
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
    StepSubtractionState *step_state;
    SystematicState *systematic_state; // Add this line
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

Fraction parse_fraction(const char *fraction_str)
{
    Fraction result = {0, 0};
    char *str_copy = strdup(fraction_str);
    char *delimiter = strchr(str_copy, '/');

    if (!delimiter)
    {
        free(str_copy);
        return result;
    }

    *delimiter = '\0';
    result.numerator = atoi(str_copy);
    result.denominator = atoi(delimiter + 1);
    free(str_copy);

    return result;
}

Int calculate_next_step_value(const Int &value, const Fraction &fraction)
{
    Int result;
    result.Set((Int *)&value); // Fix: Cast to non-const Int*

    // Multiply by numerator
    Int num;
    num.SetInt32(fraction.numerator);
    result.Mult(&num); // Fix: Changed Mul to Mult

    // Divide by denominator
    Int den;
    den.SetInt32(fraction.denominator);
    result.Div(&den);

    return result;
}
void initStepSubtractionState(StepSubtractionState &state, const Int &initialValue, const Point &startPoint)
{
    state.first_step = true;
    state.current_point = startPoint;
    state.initial_value.Set((Int *)&initialValue);
    state.current_value.Set((Int *)&initialValue);
}

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
    StepSubtractionState *step_state = (StepSubtractionState *)args->step_state;

    if (step_state && step_state->enabled)
    {
        // Step subtraction mode
        Point result = args->startPoint;
        Int subtract_value(&args->rangeEnd); // Initialize with command line value

        while (args->running)
        {
            // Calculate point for subtraction
            Int negValue;
            negValue.Set(&subtract_value);
            negValue.Neg();
            Point negPoint = secp.ScalarMultiplication(secp.G, &negValue);

            // Add the negated point (effectively subtracting)
            result = secp.AddDirect(result, negPoint);

            // Get the result
            char *pubKeyHex = secp.GetPublicKeyHex(true, result);
            char *decimalStr = subtract_value.GetBase10();

            args->total_ops++;
            double elapsed = difftime(time(NULL), args->start_time);
            args->keys_per_second = args->total_ops / (elapsed > 0 ? elapsed : 1);

            pthread_mutex_lock(&print_mutex);
            printf("\r\033[K"); // Clear line
            printf("\rStep %llu: %s - %s | %.2f keys/s",
                   (unsigned long long)args->total_ops,
                   pubKeyHex,
                   decimalStr,
                   args->keys_per_second);
            fflush(stdout);

            if (bloom_initialized1 && triple_bloom_check(pubKeyHex))
            {
                printf("\nMATCH FOUND!\n");
                printf("Step %llu: %s - %s\n",
                       (unsigned long long)args->total_ops,
                       pubKeyHex,
                       decimalStr);
            }
            pthread_mutex_unlock(&print_mutex);

            // Calculate next subtraction value (fraction of previous value)
            Int next_value;
            Int numerator;
            Int denominator;

            numerator.SetInt32(step_state->step_fraction.numerator);
            denominator.SetInt32(step_state->step_fraction.denominator);

            next_value.Set(&subtract_value);
            next_value.Mult(&numerator);
            next_value.Div(&denominator);

            subtract_value.Set(&next_value);

            // Check if we should continue
            Int billion;
            billion.SetBase10("1000000000");
            if (subtract_value.IsLower(&billion))
            {
                pthread_mutex_lock(&print_mutex);
                printf("\nReached value below 1 billion. Stopping.\n");
                pthread_mutex_unlock(&print_mutex);
                args->running = false;
            }

            free(pubKeyHex);
            free(decimalStr);
            usleep(100000); // Small delay to prevent CPU overload
        }
    }
    else
    {
        // Original random range mode
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

                if (bloom_initialized1 && triple_bloom_check(buffer.pubKeyHexes[i]))
                {
                    printf("\nMATCH FOUND!\n");
                    printf("Thread %d: %s - %s\n",
                           args->thread_id,
                           buffer.pubKeyHexes[i],
                           buffer.decimalStrs[i]);
                }
                pthread_mutex_unlock(&print_mutex);
            }
        }
    }
    return NULL;
}

void *systematic_worker(void *arg)
{
    ThreadArgs *args = (ThreadArgs *)arg;
    SystematicState *state = (SystematicState *)args->systematic_state;

    // Initialize starting values
    Point current_point = state->start_point;
    Int step_value;
    step_value.Set(&args->rangeStart);

    Int total_subtracted;
    total_subtracted.SetInt32(0);

    // Initialize step reduction rate (0.5%)
    Int reduction_numerator;
    reduction_numerator.SetInt32(5);
    Int reduction_denominator;
    reduction_denominator.SetInt32(1000);

    static int reset_count = 0;
    bool first_subtraction = true;

    while (args->running && !step_value.IsLower(&BILLION))
    {
        if (first_subtraction)
        {
            // First subtraction - always subtract initial value from original point
            Int neg_initial;
            neg_initial.Set(&args->rangeStart);
            neg_initial.Neg();
            Point neg_point = secp.ScalarMultiplication(secp.G, &neg_initial);
            current_point = secp.AddDirect(state->start_point, neg_point);
            total_subtracted.Add(&args->rangeStart);
            first_subtraction = false;
        }
        else
        {
            // Subsequent subtractions
            Int neg_step;
            neg_step.Set(&step_value);
            neg_step.Neg();
            Point neg_point = secp.ScalarMultiplication(secp.G, &neg_step);
            current_point = secp.AddDirect(current_point, neg_point);
            total_subtracted.Add(&step_value);
        }

        // Get current results
        char *pubkey = secp.GetPublicKeyHex(true, current_point);
        char *step_str = step_value.GetBase10();
        char *total_str = total_subtracted.GetBase10();

        // Update stats
        args->total_ops++;
        double elapsed = difftime(time(NULL), args->start_time);
        args->keys_per_second = args->total_ops / (elapsed > 0 ? elapsed : 1);

        // Print status with shortened pubkey
        pthread_mutex_lock(&print_mutex);
        char pubkey_short[9];
        strncpy(pubkey_short, pubkey, 8);
        pubkey_short[8] = '\0';

        printf("\r[Reset #%d] %s... | Step: %s | Total: %s | %.2f k/s     ",
               reset_count,
               pubkey_short,
               step_str,
               total_str,
               args->keys_per_second);
        fflush(stdout);

        // Check for match in bloom filters
        if (bloom_initialized1 && triple_bloom_check(pubkey))
        {
            printf("\nMATCH FOUND!\n");
            printf("Public Key: %s\n", pubkey);
            printf("Step Size: %s\n", step_str);
            printf("Total Subtracted: %s\n", total_str);
            printf("Reset Count: %d\n", reset_count);

            FILE *f = fopen("matches.txt", "a");
            if (f)
            {
                fprintf(f, "Public Key: %s\nStep: %s\nTotal: %s\nReset: %d\n\n",
                        pubkey, step_str, total_str, reset_count);
                fclose(f);
            }
        }
        pthread_mutex_unlock(&print_mutex);

        // Check if total exceeds range end
        if (total_subtracted.IsGreater(&args->rangeEnd))
        {
            // Calculate 0.5% reduction of step value
            Int reduction;
            reduction.Set(&step_value);
            reduction.Mult(&reduction_numerator);
            reduction.Div(&reduction_denominator);

            // Subtract the reduction from step value
            step_value.Sub(&reduction);

            // Reset to starting point
            current_point = state->start_point;
            total_subtracted.SetInt32(0);
            reset_count++;
            first_subtraction = true;

            pthread_mutex_lock(&print_mutex);
            char *new_step = step_value.GetBase10();
            printf("\nReset with new step value: %s (0.5%% reduction)\n", new_step);
            free(new_step);
            pthread_mutex_unlock(&print_mutex);
        }

        free(pubkey);
        free(step_str);
        free(total_str);
        usleep(1000); // Small delay to prevent CPU overload
    }

    pthread_mutex_lock(&print_mutex);
    printf("\nThread finished: Step value went below 1 billion or stopped\n");
    pthread_mutex_unlock(&print_mutex);

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
    InitBILLION();

    if (argc < 4)
    {
        printf("Usage: %s [-f bloom_file] [-s fraction] <publickey> - <range_start>:<range_end>\n", argv[0]);
        printf("   or: %s [-f bloom_file] [-b] <publickey> - <range_start>:<range_end>\n", argv[0]);
        printf("Example systematic mode: %s -f bloom.bin -b 02345...ABCD - 1000:2000\n", argv[0]);
        printf("Example step mode: %s -f bloom.bin -s 1/4 02345...ABCD - 1000:2000\n", argv[0]);
        return 1;
    }

    const char *bloom_file = NULL;
    const char *fraction_str = NULL;
    bool has_bloom = false;
    bool step_mode = false;
    bool systematic_mode = false;
    int current_arg = 1;
    const char *pubkey_arg = NULL;
    const char *range_arg = NULL;

    while (current_arg < argc - 2)
    {
        if (strcmp(argv[current_arg], "-f") == 0 && current_arg + 1 < argc)
        {
            bloom_file = argv[current_arg + 1];
            has_bloom = true;
            current_arg += 2;
        }
        else if (strcmp(argv[current_arg], "-s") == 0 && current_arg + 1 < argc)
        {
            fraction_str = argv[current_arg + 1];
            step_mode = true;
            current_arg += 2;
        }
        else if (strcmp(argv[current_arg], "-b") == 0)
        {
            systematic_mode = true;
            current_arg++;
        }
        else
        {
            break;
        }
    }

    if (current_arg >= argc - 1)
    {
        printf("Error: Missing required arguments after options\n");
        return 1;
    }

    pubkey_arg = argv[current_arg++];
    range_arg = argv[current_arg];

    StepSubtractionState step_state = {0};
    SystematicState *systematic_state = NULL;

    if (step_mode && systematic_mode)
    {
        printf("Error: Cannot use both step mode (-s) and systematic mode (-b) together\n");
        return 1;
    }

    if (step_mode)
    {
        step_state.enabled = true;
        step_state.step_fraction = parse_fraction(fraction_str);
        if (step_state.step_fraction.numerator <= 0 ||
            step_state.step_fraction.denominator <= 0)
        {
            printf("Error: Invalid fraction format. Use n/m format (e.g., 1/4)\n");
            return 1;
        }
        printf("Step mode enabled with fraction %d/%d\n",
               step_state.step_fraction.numerator,
               step_state.step_fraction.denominator);
    }

    Point startPoint;
    Int rangeStart, rangeEnd;

    // Parse public key
    char *pubKey = strdup(pubkey_arg);
    bool isCompressed;
    if (!secp.ParsePublicKeyHex(pubKey, startPoint, isCompressed))
    {
        printf("Invalid public key format\n");
        free(pubKey);
        return 1;
    }
    free(pubKey);

    // Parse range for systematic or step mode
    if (step_mode)
    {
        if (strcmp(range_arg, "-") != 0 || current_arg + 1 >= argc)
        {
            printf("Error: Step mode requires format: - <value>\n");
            return 1;
        }
        rangeStart.SetInt32(0);
        rangeEnd.SetBase10(argv[current_arg + 1]);
    }
    else if (systematic_mode)
    {
        if (strcmp(range_arg, "-") != 0 || current_arg + 1 >= argc)
        {
            printf("Error: Systematic mode requires format: - <range_start>:<range_end>\n");
            return 1;
        }

        char *range_str = argv[current_arg + 1];
        char *delimiter = strchr(range_str, ':');
        if (!delimiter)
        {
            printf("Error: Invalid range format. Use start:end\n");
            return 1;
        }

        *delimiter = '\0';
        rangeStart.SetBase10(range_str);
        rangeEnd.SetBase10(delimiter + 1);

        if (rangeStart.IsZero() || rangeEnd.IsZero())
        {
            printf("Error: Invalid range values\n");
            return 1;
        }
    }
    else
    {
        char *range_ptr = strdup(range_arg);
        char *delimiter = strchr(range_ptr, ':');
        if (!delimiter)
        {
            printf("Invalid range format. Use start:end\n");
            free(range_ptr);
            return 1;
        }

        *delimiter = '\0';
        rangeStart.SetBase10(range_ptr);
        rangeEnd.SetBase10(delimiter + 1);
        free(range_ptr);
    }

    if (has_bloom)
    {
        printf("Initializing bloom filters from: %s\n", bloom_file);
        if (!init_multi_bloom_from_file(bloom_file))
        {
            printf("Failed to initialize bloom filters\n");
            return 1;
        }
    }

    pthread_t threads[NUM_THREADS];
    ThreadArgs thread_args[NUM_THREADS];

    int num_threads = (step_mode || systematic_mode) ? 1 : NUM_THREADS;

    if (systematic_mode)
    {
        systematic_state = new SystematicState();
        systematic_state->enabled = true;
        systematic_state->start_point = startPoint;
        systematic_state->min_range.Set(&rangeStart);
        systematic_state->max_range.Set(&rangeEnd);
        systematic_state->current_step.Set(&rangeStart);
        pthread_mutex_init(&systematic_state->step_mutex, NULL);
        char *start_str = rangeStart.GetBase10();
        char *end_str = rangeEnd.GetBase10();
        printf("Systematic mode enabled\nStart: %s\nEnd: %s\n",
               start_str, end_str);
        free(start_str);
        free(end_str);
    }

    printf("Starting %s with %d thread%s...\n",
           systematic_mode ? "systematic subtraction" : step_mode ? "step subtraction"
                                                                  : "subtraction",
           num_threads, num_threads > 1 ? "s" : "");

    bool init_error = false;

    for (int i = 0; i < num_threads; i++)
    {
        thread_args[i].startPoint = startPoint;
        thread_args[i].rangeStart = rangeStart;
        thread_args[i].rangeEnd = rangeEnd;
        thread_args[i].running = true;
        thread_args[i].thread_id = i;
        thread_args[i].total_ops = 0;
        thread_args[i].keys_per_second = 0;
        thread_args[i].start_time = time(NULL);
        thread_args[i].step_state = step_mode ? &step_state : NULL;
        thread_args[i].systematic_state = systematic_state;

        worker_func_t worker_func = systematic_mode ? systematic_worker : step_mode ? subtraction_worker
                                                                                    : subtraction_worker;

        int err = pthread_create(&threads[i], NULL, worker_func, &thread_args[i]);
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
        if (systematic_state)
        {
            pthread_mutex_destroy(&systematic_state->step_mutex);
            delete systematic_state;
        }
        cleanup_bloom_filters();
        pthread_mutex_destroy(&mutex);
        pthread_mutex_destroy(&print_mutex);
        return 1;
    }

    if (!step_mode && !systematic_mode)
    {
        printf("\nPress Enter to stop...\n");
        getchar();

        printf("\nStopping threads...\n");
        for (int i = 0; i < num_threads; i++)
        {
            thread_args[i].running = false;
        }
    }

    for (int i = 0; i < num_threads; i++)
    {
        pthread_join(threads[i], NULL);
    }

    print_stats(thread_args, num_threads);

    if (systematic_state)
    {
        pthread_mutex_destroy(&systematic_state->step_mutex);
        delete systematic_state;
    }

    cleanup_bloom_filters();
    pthread_mutex_destroy(&mutex);
    pthread_mutex_destroy(&print_mutex);

    return 0;
}
