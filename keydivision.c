#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include <iomanip>
#include <stdexcept>
#include "secp256k1/SECP256k1.h"
#include "secp256k1/Point.h"
#include "secp256k1/Int.h"
#include "bloom/bloom.h"
#include "xxhash/xxhash.h"

#define BATCH_SIZE 100000
#define MAX_THREADS 256
#define MAX_BITS 40
pthread_mutex_t bit_reduce_mutex = PTHREAD_MUTEX_INITIALIZER;

// Forward declarations
class OutputManager;
bool perform_bit_reduction(Point *pubkey, int nbits, const char *search_pubkey, int num_threads);
void autosub_mode(Point *input_pubkey, const char *search_pubkey, int num_threads, int argc, char **argv);

class OutputManager
{
private:
    pthread_mutex_t output_mutex;
    uint64_t total_subtractions;
    time_t start_time;
    bool initialized;

public:
    OutputManager() : total_subtractions(0), initialized(false)
    {
        pthread_mutex_init(&output_mutex, NULL);
    }

    ~OutputManager()
    {
        pthread_mutex_destroy(&output_mutex);
    }

    void initialize(const char *mode, int threads, const Int &start_range, const Int &max_range)
    {
        pthread_mutex_lock(&output_mutex);
        printf("\033[2J\033[H"); // Clear screen
        printf("╔══════════════════════════════════════════════════════════╗\n");
        printf("║                 Key Division Search Tool                  ║\n");
        printf("╠══════════════════════════════════════════════════════════╣\n");
        printf("║ Mode: %-51s║\n", mode);
        printf("║ Threads: %-48d║\n", threads);
        printf("╠══════════════════════════════════════════════════════════╣\n");
        char *start_str = const_cast<Int &>(start_range).GetBase10();
        char *max_str = const_cast<Int &>(max_range).GetBase10();
        printf("║ Range Start: %-45s║\n", start_str);
        printf("║ Range End:   %-45s║\n", max_str);
        printf("╚══════════════════════════════════════════════════════════╝\n\n");
        start_time = time(NULL);
        initialized = true;
        pthread_mutex_unlock(&output_mutex);
    }

    void updateProgress(int batch_num, int current_subtraction, int total_subs,
                        int thread_id, int current_bits)
    {
        if (!initialized)
            return;
        pthread_mutex_lock(&output_mutex);
        time_t current_time = time(NULL);
        double elapsed = difftime(current_time, start_time);
        printf("\r[+] Batch: %d | Progress: %d/%d | Thread: %d | Bits: %d | Time: %.0fs",
               batch_num, current_subtraction, total_subs, thread_id, current_bits, elapsed);
        fflush(stdout);
        pthread_mutex_unlock(&output_mutex);
    }

    void updateSubtractionGeneration(int current, int total)
    {
        if (!initialized)
            return;
        pthread_mutex_lock(&output_mutex);
        printf("\r[+] Generating subtractions: %d/%d", current, total);
        fflush(stdout);
        pthread_mutex_unlock(&output_mutex);
    }

    void reportSuccess(const char *subtraction, const char *pubkey, const char *privkey)
    {
        pthread_mutex_lock(&output_mutex);
        printf("\n\n");
        printf("╔══════════════════════════════════════════════════════════╗\n");
        printf("║                    Match Found!                          ║\n");
        printf("╠══════════════════════════════════════════════════════════╣\n");
        printf("║ Subtraction: %-45s║\n", subtraction);
        printf("║ Public Key:  %-45s║\n", pubkey);
        printf("║ Private Key: %-45s║\n", privkey);
        printf("╚══════════════════════════════════════════════════════════╝\n");
        pthread_mutex_unlock(&output_mutex);
    }

    void reportBatchComplete(uint64_t total_tested, const char *time_taken)
    {
        pthread_mutex_lock(&output_mutex);
        total_subtractions += total_tested;
        printf("\r[+] Batch complete. Total tested: %llu | Time: %s",
               total_subtractions, time_taken);
        printf("\n\n");
        pthread_mutex_unlock(&output_mutex);
    }

    void newLine()
    {
        pthread_mutex_lock(&output_mutex);
        printf("\n");
        pthread_mutex_unlock(&output_mutex);
    }
};

struct BloomFilterWrapper
{
    struct bloom filter;
    bool initialized;

    BloomFilterWrapper() : initialized(false) {}

    void init(const char *target_pubkey)
    {
        if (initialized)
        {
            bloom_free(&filter);
        }
        bloom_init2(&filter, 10000000, 0.0001);
        bloom_add(&filter, target_pubkey, strlen(target_pubkey));
        initialized = true;
    }

    bool check(const char *pubkey, size_t len)
    {
        if (!initialized)
            return true;
        return bloom_check(&filter, pubkey, len);
    }

    void cleanup()
    {
        if (initialized)
        {
            bloom_free(&filter);
            initialized = false;
        }
    }

    ~BloomFilterWrapper()
    {
        cleanup();
    }
};

struct ThreadData
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

    ThreadData() : thread_id(0), search_pubkey(nullptr),
                   found(nullptr), found_index(nullptr), mutex(nullptr) {}

    bool isValid() const
    {
        return search_pubkey != nullptr &&
               found != nullptr &&
               found_index != nullptr &&
               mutex != nullptr;
    }
};

struct BatchThreadData
{
    int thread_id;
    int batch_start;
    int batch_end;
    Int *subtractions;
    Point *pubkeys;
    Point *input_pubkey;
    const char *search_pubkey;
    bool *found;
    Int *found_subtraction;
    Point *found_pubkey;
    pthread_mutex_t *mutex;

    BatchThreadData() : thread_id(0), batch_start(0), batch_end(0),
                        subtractions(nullptr), pubkeys(nullptr),
                        input_pubkey(nullptr), search_pubkey(nullptr),
                        found(nullptr), found_subtraction(nullptr),
                        found_pubkey(nullptr), mutex(nullptr) {}

    bool isValid() const
    {
        return batch_start >= 0 &&
               batch_end >= batch_start &&
               subtractions != nullptr &&
               pubkeys != nullptr &&
               input_pubkey != nullptr &&
               search_pubkey != nullptr &&
               found != nullptr &&
               found_subtraction != nullptr &&
               found_pubkey != nullptr &&
               mutex != nullptr;
    }

    bool isIndexValid(int index) const
    {
        return index >= batch_start && index < batch_end &&
               index < BATCH_SIZE;
    }
};

// Global instances
Secp256K1 secp;
OutputManager output;
BloomFilterWrapper bloom_wrapper;
volatile bool should_exit = false;
volatile uint64_t current_index = 0;
char checkpoint_pubkey[132];
char checkpoint_target[132];
int checkpoint_nbits = 0;
char checkpoint_filename[256];
bool continuous_mode = false;
int num_threads = 1;
bool use_bloom = false;

const char *SUBTRACTION_START = "21778071482940061661655974875633165533184";
const char *SUBTRACTION_MAX = "43556142965880123323311949751266331066367";

// Helper functions for thread management
void initThreadData(BatchThreadData *data, int num_threads)
{
    if (!data)
        return;

    pthread_mutex_t *shared_mutex = new pthread_mutex_t;
    pthread_mutex_init(shared_mutex, NULL);
    bool *shared_found = new bool(false);

    int keys_per_thread = BATCH_SIZE / num_threads;
    int remainder = BATCH_SIZE % num_threads;
    int current_start = 0;

    for (int t = 0; t < num_threads; t++)
    {
        data[t].thread_id = t;
        data[t].batch_start = current_start;
        data[t].batch_end = current_start + keys_per_thread + (t < remainder ? 1 : 0);
        data[t].mutex = shared_mutex;
        data[t].found = shared_found;
        current_start = data[t].batch_end;
    }
}

void cleanupThreadData(BatchThreadData *data, int num_threads)
{
    if (!data)
        return;

    if (num_threads > 0 && data[0].mutex)
    {
        pthread_mutex_destroy(data[0].mutex);
        delete data[0].mutex;
        delete data[0].found;
    }
}

void init_bloom_filter(const char *target_pubkey)
{
    bloom_wrapper.init(target_pubkey);
    use_bloom = true;
}

void cleanup_bloom()
{
    if (use_bloom)
    {
        bloom_wrapper.cleanup();
        use_bloom = false;
    }
}

void handle_signal(int sig)
{
    if (sig == SIGINT)
    {
        output.newLine();
        printf("[+] Saving checkpoint...\n");
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

// Thread processing functions
void *thread_search(void *arg)
{
    ThreadData *data = (ThreadData *)arg;
    if (!data->isValid())
        return NULL;

    char current_pubkey[132];
    Point Q, R;
    Int i(data->start_range);
    Int increment((uint64_t)1);
    uint64_t local_index = 0;

    while (i.IsLower(&data->end_range) && !should_exit)
    {
        for (int batch = 0; batch < BATCH_SIZE && i.IsLower(&data->end_range); batch++)
        {
            if (*(data->found))
                return NULL;

            local_index = i.GetInt64();

            output.updateProgress(0, local_index, data->total_keys.GetInt64(),
                                  data->thread_id, 0);

            Q = secp.ComputePublicKey(&i);
            Point negQ = secp.Negation(Q);
            R = secp.AddDirect(data->pubkey, negQ);

            secp.GetPublicKeyHex(true, R, current_pubkey);

            if (!use_bloom || bloom_wrapper.check(current_pubkey, strlen(current_pubkey)))
            {
                if (strcmp(current_pubkey, data->search_pubkey) == 0)
                {
                    pthread_mutex_lock(data->mutex);
                    if (!*(data->found))
                    {
                        *(data->found) = true;
                        data->found_index->Set(&i);
                        output.newLine();
                        printf("\n[+] Found target public key!\n");
                        printf("[+] Generated at index: %s\n", i.GetBase10());

                        Int base;
                        base.SetBase16("0000000000000000000000000000000000000000000000000000000000000001");
                        base.Add(&i);
                        printf("[+] Final private key: 0x%s\n", base.GetBase16());

                        delete_checkpoint();
                        should_exit = true;
                    }
                    pthread_mutex_unlock(data->mutex);
                    return NULL;
                }
            }

            i.Add(&increment);
        }

        pthread_mutex_lock(data->mutex);
        current_index = local_index;
        pthread_mutex_unlock(data->mutex);
    }

    return NULL;
}

void *batch_bit_reduction(void *arg)
{
    BatchThreadData *data = (BatchThreadData *)arg;

    // Debug output - uncomment if needed
    /*
    printf("Thread %d starting\n", data->thread_id);
    printf("Thread %d range: %d to %d\n", data->thread_id, data->batch_start, data->batch_end);
    */

    if (!data || !data->subtractions || !data->pubkeys || !data->found)
    {
        // printf("Thread %d: NULL pointer detected\n", data->thread_id);
        return NULL;
    }

    for (int i = data->batch_start; i < data->batch_end && !(*data->found); i++)
    {
        try
        {
            // Debug output - uncomment if needed
            /*
            printf("\rThread %d processing subtraction %d", data->thread_id, i);
            fflush(stdout);
            */

            for (int bits = 1; bits <= 20 && !(*data->found); bits++)
            {
                pthread_mutex_lock(&bit_reduce_mutex);
                bool result = perform_bit_reduction(&data->pubkeys[i], bits, data->search_pubkey, 1);
                pthread_mutex_unlock(&bit_reduce_mutex);

                if (result)
                {
                    pthread_mutex_lock(&bit_reduce_mutex);
                    if (!(*data->found))
                    {
                        *data->found = true;
                        data->found_subtraction->Set(&data->subtractions[i]);
                        data->found_pubkey->Set(data->pubkeys[i]);
                        // printf("\nThread %d found match\n", data->thread_id);
                    }
                    pthread_mutex_unlock(&bit_reduce_mutex);
                    return NULL;
                }
            }
        }
        catch (const std::exception &e)
        {
            // Debug output - uncomment if needed
            /*
            printf("\nThread %d error at subtraction %d: %s\n",
                   data->thread_id, i, e.what());
            */
        }
    }

    // printf("\nThread %d completed\n", data->thread_id);
    return NULL;
}

bool perform_bit_reduction(Point *pubkey, int nbits, const char *search_pubkey, int num_threads)
{
    signal(SIGINT, handle_signal);

    if (!pubkey || !search_pubkey || nbits <= 0 || num_threads <= 0)
    {
        printf("Invalid parameters for bit reduction\n");
        return false;
    }

    secp.GetPublicKeyHex(false, *pubkey, checkpoint_pubkey);
    strncpy(checkpoint_target, search_pubkey, sizeof(checkpoint_target) - 1);
    checkpoint_nbits = nbits;

    Int total_keys;
    bool found = false;
    Int found_index;
    pthread_t *threads = nullptr;
    ThreadData *thread_args = nullptr;
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

    try
    {
        current_index = load_checkpoint(checkpoint_pubkey, search_pubkey, nbits);

        total_keys.SetInt32(1);
        Int two((uint64_t)2);
        for (int i = 0; i < nbits; i++)
        {
            total_keys.Mult(&two);
        }

        init_bloom_filter(search_pubkey);

        threads = new pthread_t[num_threads];
        thread_args = new ThreadData[num_threads];

        Int chunk_size, remaining;
        remaining.Set(&total_keys);
        Int current_idx;
        current_idx.SetInt32(current_index);
        remaining.Sub(&current_idx);

        Int divisor;
        divisor.SetInt32(num_threads);
        chunk_size.Set(&remaining);
        chunk_size.Div(&divisor);

        for (int t = 0; t < num_threads; t++)
        {
            thread_args[t].thread_id = t;
            thread_args[t].pubkey.Set(*pubkey);
            thread_args[t].found = &found;
            thread_args[t].found_index = &found_index;
            thread_args[t].mutex = &mutex;
            thread_args[t].search_pubkey = search_pubkey;
            thread_args[t].total_keys.Set(&total_keys);

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

            if (pthread_create(&threads[t], NULL, thread_search, &thread_args[t]) != 0)
            {
                throw std::runtime_error("Failed to create thread");
            }
        }

        for (int t = 0; t < num_threads; t++)
        {
            pthread_join(threads[t], NULL);
        }
    }
    catch (const std::exception &e)
    {
        printf("\nError: %s\n", e.what());
        found = false;
    }

    cleanup_bloom();
    pthread_mutex_destroy(&mutex);
    delete[] threads;
    delete[] thread_args;

    return found;
}

void save_subtraction(const Point &pubkey, const Int &subtraction, FILE *file)
{
    char pubkey_hex[132];
    Point non_const_pubkey = pubkey; // Create non-const copy
    secp.GetPublicKeyHex(true, non_const_pubkey, pubkey_hex);

    // Create non-const copy for GetBase10
    Int non_const_subtraction = subtraction;
    fprintf(file, "%s # %s\n", pubkey_hex, non_const_subtraction.GetBase10());
}

void autosub_mode(Point *input_pubkey, const char *search_pubkey, int num_threads, int argc, char **argv)
{
    if (!input_pubkey || !search_pubkey || num_threads <= 0)
        return;

    bool save_only = false;
    FILE *output_file = nullptr;

    // Check if -k flag is present
    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "-k") == 0)
        {
            save_only = true;
            output_file = fopen("135.txt", "w");
            if (!output_file)
            {
                printf("Error: Could not open 135.txt for writing\n");
                return;
            }
            break;
        }
    }

    signal(SIGINT, handle_signal);

    Int subtraction_start, subtraction_max;
    subtraction_start.SetBase10(SUBTRACTION_START);
    subtraction_max.SetBase10(SUBTRACTION_MAX);

    output.initialize("Auto Subtraction", num_threads, subtraction_start, subtraction_max);

    rseed(time(NULL));

    std::vector<Int> subtractions(BATCH_SIZE);
    std::vector<Point> pubkeys(BATCH_SIZE);
    std::vector<pthread_t> threads(num_threads);
    std::vector<BatchThreadData> thread_data(num_threads);

    bool found = false;
    Int found_subtraction;
    Point found_pubkey;
    uint64_t batch_number = 0;

    while (!should_exit && !found)
    {
        batch_number++;
        printf("\n[+] Starting Batch %llu\n", batch_number);

        for (int i = 0; i < BATCH_SIZE && !should_exit; i++)
        {
            subtractions[i].Rand(&subtraction_start, &subtraction_max);
            Point subtraction_point = secp.ComputePublicKey(&subtractions[i]);
            Point negated_point = secp.Negation(subtraction_point);
            pubkeys[i] = secp.AddDirect(*input_pubkey, negated_point);

            if (save_only)
            {
                save_subtraction(pubkeys[i], subtractions[i], output_file);
            }

            printf("\r[+] Generated subtraction %d/%d", i + 1, BATCH_SIZE);
            fflush(stdout);
        }
        printf("\n");

        if (should_exit || save_only)
            break;

        // Rest of the original autosub_mode code for searching...
        int keys_per_thread = BATCH_SIZE / num_threads;
        int remainder = BATCH_SIZE % num_threads;
        int current_start = 0;

        for (int t = 0; t < num_threads; t++)
        {
            thread_data[t].thread_id = t;
            thread_data[t].subtractions = subtractions.data();
            thread_data[t].pubkeys = pubkeys.data();
            thread_data[t].search_pubkey = search_pubkey;
            thread_data[t].found = &found;
            thread_data[t].found_subtraction = &found_subtraction;
            thread_data[t].found_pubkey = &found_pubkey;
            thread_data[t].batch_start = current_start;
            thread_data[t].batch_end = current_start + keys_per_thread + (t < remainder ? 1 : 0);
            current_start = thread_data[t].batch_end;

            int rc = pthread_create(&threads[t], NULL, batch_bit_reduction, &thread_data[t]);
            if (rc)
            {
                should_exit = true;
                break;
            }
        }

        for (int t = 0; t < num_threads; t++)
        {
            pthread_join(threads[t], NULL);
        }

        if (found)
        {
            printf("\n[+] Found match with subtraction: %s\n", found_subtraction.GetBase10());
            char pubkey_hex[132];
            secp.GetPublicKeyHex(true, found_pubkey, pubkey_hex);
            printf("[+] Matching public key: %s\n", pubkey_hex);
            break;
        }
        else
        {
            printf("\n[+] Batch %llu complete | No match found\n", batch_number);
        }
    }

    if (save_only && output_file)
    {
        fclose(output_file);
        printf("\n[+] Subtractions saved to 135.txt\n");
    }
}

int main(int argc, char **argv)
{
    secp.Init();

    if (argc < 4)
    {
        printf("╔══════════════════════════════════════════════════════════╗\n");
        printf("║                 Key Division Usage Guide                  ║\n");
        printf("╠══════════════════════════════════════════════════════════╣\n");
        printf("║ Standard operations:                                      ║\n");
        printf("║ %s <pubkey1> <operation> <pubkey2/number>                ║\n", argv[0]);
        printf("║                                                          ║\n");
        printf("║ Bit reduction search:                                    ║\n");
        printf("║ %s --reduce <pubkey> <nbits> <search_pubkey> [-t threads]║\n", argv[0]);
        printf("║                                                          ║\n");
        printf("║ Autosub mode:                                           ║\n");
        printf("║ %s --autosub <pubkey> <search_pubkey> [-t threads]      ║\n", argv[0]);
        printf("║                                                          ║\n");
        printf("║ Operations: +, -, /, x                                   ║\n");
        printf("║ Use Ctrl+C to stop and save progress                     ║\n");
        printf("╚══════════════════════════════════════════════════════════╝\n");
        exit(0);
    }

    if (strcmp(argv[1], "--autosub") == 0)
    {
        if (argc < 4)
        {
            printf("For autosub mode: %s --autosub <pubkey> <search_pubkey> [-t threads] [-k]\n", argv[0]);
            printf("  -t threads : Number of threads to use\n");
            printf("  -k        : Only generate and save subtractions to 135.txt\n");
            exit(0);
        }

        num_threads = 1;
        bool save_only = false;

        for (int i = 4; i < argc; i++)
        {
            if (strcmp(argv[i], "-t") == 0 && i + 1 < argc)
            {
                num_threads = atoi(argv[i + 1]);
                i++;
                if (num_threads > MAX_THREADS)
                {
                    printf("Warning: Thread count exceeds maximum, using %d threads\n", MAX_THREADS);
                    num_threads = MAX_THREADS;
                }
            }
            else if (strcmp(argv[i], "-k") == 0)
            {
                save_only = true;
            }
        }

        Point inputPoint;
        bool isCompressed;
        if (!secp.ParsePublicKeyHex(argv[2], inputPoint, isCompressed))
        {
            printf("Error: Invalid input public key\n");
            exit(0);
        }

        autosub_mode(&inputPoint, argv[3], num_threads, argc, argv);
        return 0;
    }

    else if (strcmp(argv[1], "--reduce") == 0)
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
                if (num_threads > MAX_THREADS)
                {
                    printf("Warning: Thread count exceeds maximum, using %d threads\n", MAX_THREADS);
                    num_threads = MAX_THREADS;
                }
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

        Int zero;
        zero.SetInt32(0);
        output.initialize("Bit Reduction", num_threads, zero, zero);

        bool key_found = false;
        int current_bits = start_nbits;

        do
        {
            key_found = perform_bit_reduction(&inputPoint, current_bits, argv[4], num_threads);

            if (!key_found && continuous_mode && current_bits < MAX_BITS)
            {
                current_bits++;
                output.newLine();
                printf("\r[+] Increasing to %d bits\n", current_bits);
                sleep(1);
            }
            else
            {
                break;
            }
        } while (continuous_mode && current_bits <= MAX_BITS);

        if (!key_found)
        {
            output.newLine();
            printf("\r[+] No match found up to %d bits\n", current_bits - 1);
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
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║                    Operation Result                       ║\n");
    printf("╠══════════════════════════════════════════════════════════╣\n");
    printf("║ %s ║\n", resultHex);
    printf("╚══════════════════════════════════════════════════════════╝\n");

    return 0;
}
