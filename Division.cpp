// division.cpp - Optimized Fast Public Key Division Tool with Full Pubkey Bloom Filter
// OPTIMIZED: CPU_GRP_SIZE batch processing with IntGroup ModInv
// Usage: ./division <pubkey_hex> -f <bloom_file> [-t threads] [-s min_steps] [-S max_steps] [-d min_divs] [-D max_divs] [-B]

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <vector>
#include <algorithm>
#include <random>
#include <atomic>
#include <sys/stat.h>
#include <chrono>
#include "secp256k1/SECP256k1.h"
#include "secp256k1/Point.h"
#include "secp256k1/Int.h"
#include "secp256k1/IntGroup.h"
#include "secp256k1/Random.h"
#include "bloom/bloom.h"

#define COMPRESSED_PUBKEY_SIZE 33
#define MAX_PATH_LENGTH 10000
#define MAX_THREADS 256
#define CPU_GRP_SIZE 1024
#define BLOOM_FP_RATE 0.00001
#define INPUT_BUFFER_SIZE (16 * 1024 * 1024)
#define BATCH_SIZE (CPU_GRP_SIZE / 2)  // Process paths in batches

// Global configuration
struct Config {
    int min_steps = 85;
    int max_steps = 135;
    int min_divisions = 75;
    int max_divisions = 75;
    int num_threads = 1;
    int paths_per_config = 10;
    bool save_paths = false;
    bool debug_mode = false;
    bool skip_verification = false;
    char *bloom_file = NULL;
    char *input_pubkey = NULL;
    int current_steps = 0;
};

// Path tracking structure
struct PathState {
    char path[MAX_PATH_LENGTH];
    int divisions;
    int subtractions;
    int total_steps;
    Point current_point;
    Int current_key;
    char last_operation[8];
    std::vector<int> subtraction_positions;
    std::vector<Point> all_points;
    
    PathState() {
        memset(path, 0, MAX_PATH_LENGTH);
        divisions = 0;
        subtractions = 0;
        total_steps = 0;
        memset(last_operation, 0, 8);
        strcpy(last_operation, "START");
        current_point.Clear();
        current_key.SetInt32(0);
        subtraction_positions.reserve(20);
    }
    
    void clear() {
        path[0] = '\0';
        divisions = 0;
        subtractions = 0;
        total_steps = 0;
        strcpy(last_operation, "START");
        subtraction_positions.clear();
        all_points.clear();
        current_point.Clear();
        current_key.SetInt32(0);
    }
};

// Batch processing structure
struct BatchWork {
    std::vector<PathState> paths;
    std::vector<Point> points;
    std::vector<bool> active;
    int batch_size;
    
    BatchWork(int size) : batch_size(size) {
        paths.resize(size);
        points.resize(size);
        active.resize(size, true);
    }
};

// Thread work structure for path finding
struct ThreadWork {
    int thread_id;
    Point start_point;
    Int start_key;
    std::atomic<bool> *found;
    PathState *result_path;
    pthread_mutex_t *result_mutex;
    std::atomic<int> *valid_paths_for_current_config;
    std::atomic<int> *current_steps;
    pthread_mutex_t *config_mutex;
    std::atomic<bool> *debug_path_printed;
    IntGroup *grp;  // Pre-allocated IntGroup for batch processing
    BatchWork *batch;  // Batch work structure
};

// Bloom loading worker structure
struct BloomLoadWorker {
    struct bloom *bloom_filter;
    unsigned char *entries;
    size_t num_entries;
    int thread_id;
    pthread_mutex_t *bloom_mutex;
};

// Single bloom filter for full pubkeys
struct bloom *bloom_filter = NULL;
pthread_mutex_t bloom_mutex = PTHREAD_MUTEX_INITIALIZER;
bool bloom_initialized = false;
size_t total_entries = 0;

// Global variables
Secp256K1 *secp;
Config config;
std::atomic<bool> key_found(false);
std::atomic<int> global_valid_paths_current_config(0);
std::atomic<int> global_current_steps(0);
std::atomic<bool> debug_path_printed(false);
pthread_mutex_t print_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t found_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t stats_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t config_mutex = PTHREAD_MUTEX_INITIALIZER;
time_t start_time;

// Pre-computed points for optimization
std::vector<Point> Gn;
Point _2Gn;
std::vector<Point> GSn;
Point _2GSn;
Int INVERSE_OF_2;

// Pre-computed division points
std::vector<Point> DivPoints;  // Points for fast division by 2^i

// Current state for display
PathState current_display_state;
char input_pubkey_compressed[67];

// Random number generators
static pthread_key_t rng_key;
static pthread_once_t rng_key_once = PTHREAD_ONCE_INIT;

void rng_key_destructor(void* ptr) {
    delete static_cast<std::mt19937*>(ptr);
}

void rng_key_create() {
    pthread_key_create(&rng_key, rng_key_destructor);
}

std::mt19937& get_thread_rng() {
    pthread_once(&rng_key_once, rng_key_create);
    std::mt19937* rng = (std::mt19937*)pthread_getspecific(rng_key);
    if (!rng) {
        rng = new std::mt19937(std::random_device{}());
        pthread_setspecific(rng_key, rng);
    }
    return *rng;
}

// Function declarations
void init_secp256k1();
void init_generator();
void init_division_points();
bool init_bloom_filter(const char *filename);
bool check_bloom_filter(Point &point);
void *path_finder_thread(void *arg);
void *bloom_load_worker_thread(void *arg);
Point ScalarMultiplication_fast(Secp256K1 &secp, Point &P, Int *m);
void handle_interrupt(int sig);
void save_found_path(const PathState &path, const char *pubkey);
void cleanup();
Point compute_point_half(Point &P);
Point compute_point_half_batch(Point &P, IntGroup *grp);
void update_display(const PathState &state, int target_steps, int target_subs, int target_divs);
bool build_path_with_config(PathState &state, Point start_point, int target_steps, int target_subs, int target_divs, int thread_id);
bool build_paths_batch(BatchWork &batch, Point start_point, int target_steps, int target_subs, int target_divs, int thread_id, IntGroup *grp);
void print_debug_path(const PathState &state);
size_t estimate_bloom_memory(size_t entries, double fp_rate);
bool is_binary_file(const char *filename);
bool verify_in_file(Point &point, const char *filename);

// Check if file is binary (compressed pubkeys)
bool is_binary_file(const char *filename) {
    FILE *file = fopen(filename, "rb");
    if (!file) return false;
    
    unsigned char buf[4];
    size_t read = fread(buf, 1, 4, file);
    fclose(file);
    
    return (read >= 1 && (buf[0] == 0x02 || buf[0] == 0x03));
}

// Verify point exists in actual file
bool verify_in_file(Point &point, const char *filename) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        pthread_mutex_lock(&print_mutex);
        fprintf(stderr, "[E] Cannot open file for verification: %s\n", filename);
        pthread_mutex_unlock(&print_mutex);
        return false;
    }
    
    unsigned char compressed[COMPRESSED_PUBKEY_SIZE];
    unsigned char x_bytes[32];
    point.x.Get32Bytes(x_bytes);
    
    bool y_is_odd = point.y.IsOdd();
    compressed[0] = y_is_odd ? 0x03 : 0x02;
    memcpy(compressed + 1, x_bytes, 32);
    
    const size_t VERIFY_BUFFER_SIZE = 1024 * 1024; // 1MB
    unsigned char *buffer = (unsigned char*)malloc(VERIFY_BUFFER_SIZE);
    if (!buffer) {
        pthread_mutex_lock(&print_mutex);
        fprintf(stderr, "[E] Cannot allocate verification buffer\n");
        pthread_mutex_unlock(&print_mutex);
        fclose(file);
        return false;
    }
    
    size_t bytes_read;
    bool found = false;
    size_t total_checked = 0;
    
    auto start_verify = std::chrono::high_resolution_clock::now();
    
    while ((bytes_read = fread(buffer, 1, VERIFY_BUFFER_SIZE, file)) > 0) {
        size_t entries = bytes_read / COMPRESSED_PUBKEY_SIZE;
        
        for (size_t i = 0; i < entries; i++) {
            if (memcmp(buffer + (i * COMPRESSED_PUBKEY_SIZE), compressed, COMPRESSED_PUBKEY_SIZE) == 0) {
                found = true;
                break;
            }
        }
        
        total_checked += entries;
        
        if (found) break;
        
        if (total_checked > total_entries + 1000) {
            pthread_mutex_lock(&print_mutex);
            fprintf(stderr, "[W] Verification read more entries than expected\n");
            pthread_mutex_unlock(&print_mutex);
            break;
        }
    }
    
    auto end_verify = std::chrono::high_resolution_clock::now();
    auto verify_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_verify - start_verify).count();
    
    if (found) {
        pthread_mutex_lock(&print_mutex);
        printf("\n[+] Verification completed in %ld ms - MATCH CONFIRMED!\n", verify_ms);
        pthread_mutex_unlock(&print_mutex);
    }
    
    free(buffer);
    fclose(file);
    return found;
}

// Optimized scalar multiplication
Point ScalarMultiplication_fast(Secp256K1 &secp, Point &P, Int *m) {
    Point Q, R, T;
    Q.Clear();
    R.Clear();
    T.Clear();
    
    int no_of_bits = m->GetBitLength();
    
    R.x.SetInt32(0);
    R.y.SetInt32(0);
    R.z.SetInt32(0);
    
    if (!m->IsZero()) {
        Q = P;
        
        if (m->GetBit(0) == 1) {
            R = P;
        }
        
        for (int loop = 1; loop < no_of_bits; loop++) {
            if (Q.z.IsOne()) {
                Q = secp.DoubleDirect(Q);
            } else {
                Q = secp.Double(Q);
            }
            
            if (m->GetBit(loop) == 1) {
                if (R.isZero()) {
                    R = Q;
                } else {
                    if (R.z.IsOne() && Q.z.IsOne()) {
                        R = secp.AddDirect(R, Q);
                    } else if (Q.z.IsOne()) {
                        R = secp.Add2(R, Q);
                    } else {
                        R = secp.Add(R, Q);
                    }
                }
            }
        }
    }
    
    return R;
}

// Initialize secp256k1
void init_secp256k1() {
    secp = new Secp256K1();
    if (!secp) {
        fprintf(stderr, "[E] Failed to allocate Secp256K1\n");
        exit(1);
    }
    secp->Init();
    init_generator();
    init_division_points();
    
    INVERSE_OF_2.SetBase16("7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a1");
}

// Initialize generator points
void init_generator() {
    Int one;
    one.SetInt32(1);
    Point G = secp->ComputePublicKey(&one);
    
    Gn.clear();
    GSn.clear();
    
    Gn.reserve(CPU_GRP_SIZE / 2);
    Gn.push_back(G);
    Point g = secp->DoubleDirect(G);
    Gn.push_back(g);
    
    for (int i = 2; i < CPU_GRP_SIZE / 2; i++) {
        g = secp->AddDirect(g, G);
        Gn.push_back(g);
    }
    _2Gn = secp->DoubleDirect(Gn[CPU_GRP_SIZE / 2 - 1]);
    
    GSn.reserve(CPU_GRP_SIZE / 2);
    Point negG = secp->Negation(G);
    g = negG;
    GSn.push_back(g);
    g = secp->DoubleDirect(g);
    GSn.push_back(g);
    
    for (int i = 2; i < CPU_GRP_SIZE / 2; i++) {
        g = secp->AddDirect(g, negG);
        GSn.push_back(g);
    }
    _2GSn = secp->DoubleDirect(GSn[CPU_GRP_SIZE / 2 - 1]);
    
    printf("[+] Generator points initialized: Gn=%zu, GSn=%zu\n", Gn.size(), GSn.size());
}

// Initialize division points for batch processing
void init_division_points() {
    DivPoints.clear();
    DivPoints.reserve(256);  // Pre-compute for divisions up to 2^256
    
    Int div_scalar;
    div_scalar.SetInt32(1);
    
    // Pre-compute points for division by 2^i
    for (int i = 0; i < 256; i++) {
        Point div_point = secp->ComputePublicKey(&div_scalar);
        DivPoints.push_back(div_point);
        div_scalar.ShiftR(1);  // Divide by 2
    }
    
    printf("[+] Division points initialized: %zu points\n", DivPoints.size());
}

// Optimized batch point halving using IntGroup
Point compute_point_half_batch(Point &P, IntGroup *grp) {
    // Use pre-computed inverse of 2 for fast division
    Point result = ScalarMultiplication_fast(*secp, P, &INVERSE_OF_2);
    result.Reduce();
    return result;
}

// Original compute_point_half for single operations
Point compute_point_half(Point &P) {
    Point result = ScalarMultiplication_fast(*secp, P, &INVERSE_OF_2);
    result.Reduce();
    return result;
}

// Estimate bloom filter memory usage
size_t estimate_bloom_memory(size_t entries, double fp_rate) {
    long double num = -log(fp_rate);
    long double denom = 0.480453013918201; // ln(2)^2
    long double bpe = num / denom;
    
    long double dentries = (long double)entries;
    long double allbits = dentries * bpe;
    uint64_t bits = (uint64_t)allbits;
    
    uint64_t bytes = bits / 8;
    if (bits % 8) bytes += 1;
    
    return bytes;
}

// Bloom loading worker thread
void *bloom_load_worker_thread(void *arg) {
    struct BloomLoadWorker *worker = (struct BloomLoadWorker *)arg;
    
    for (size_t i = 0; i < worker->num_entries; i++) {
        unsigned char *entry = worker->entries + (i * COMPRESSED_PUBKEY_SIZE);
        
        // Add full compressed pubkey to bloom filter
        pthread_mutex_lock(worker->bloom_mutex);
        bloom_add(worker->bloom_filter, (char*)entry, COMPRESSED_PUBKEY_SIZE);
        pthread_mutex_unlock(worker->bloom_mutex);
    }
    
    return NULL;
}

// Initialize single bloom filter from binary file
bool init_bloom_filter(const char *filename) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        fprintf(stderr, "[E] Cannot open bloom file %s\n", filename);
        return false;
    }
    
    if (!is_binary_file(filename)) {
        fprintf(stderr, "[E] Only binary compressed pubkey files are supported\n");
        fclose(file);
        return false;
    }
    
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    if (file_size % COMPRESSED_PUBKEY_SIZE != 0) {
        fprintf(stderr, "[E] Invalid binary file size\n");
        fclose(file);
        return false;
    }
    
    total_entries = file_size / COMPRESSED_PUBKEY_SIZE;
    printf("[+] Loading %zu public keys from binary file\n", total_entries);
    
    // Adjust false positive rate based on dataset size
    double fp_rate = BLOOM_FP_RATE;
    if (total_entries > 1000000000) {  // Over 1 billion
        fp_rate = 0.000001;  // More stringent for large datasets
    } else if (total_entries > 100000000) {  // Over 100 million
        fp_rate = 0.00001;
    }
    
    size_t estimated_memory = estimate_bloom_memory(total_entries, fp_rate);
    double memory_mb = estimated_memory / (1024.0 * 1024.0);
    double memory_gb = memory_mb / 1024.0;
    
    printf("[+] Estimated bloom filter memory usage: %.2f MB (%.2f GB)\n", memory_mb, memory_gb);
    printf("[+] Target false positive rate: %.8f\n", fp_rate);
    
    // Allocate single bloom filter
    bloom_filter = (struct bloom*)calloc(1, sizeof(struct bloom));
    if (!bloom_filter) {
        fprintf(stderr, "[E] Memory allocation failed for bloom filter\n");
        fclose(file);
        return false;
    }
    
    // Initialize bloom filter
    printf("[+] Initializing bloom filter for %zu entries...\n", total_entries);
    
    if (bloom_init2(bloom_filter, total_entries, fp_rate) != 0) {
        fprintf(stderr, "[E] Failed to initialize bloom filter\n");
        fclose(file);
        free(bloom_filter);
        return false;
    }
    
    // Determine number of threads for loading
    int num_load_threads = sysconf(_SC_NPROCESSORS_ONLN);
    if (num_load_threads < 1) num_load_threads = 1;
    if (num_load_threads > MAX_THREADS) num_load_threads = MAX_THREADS;
    
    printf("[+] Using %d threads to load bloom filter\n", num_load_threads);
    printf("[+] Storing full %d-byte compressed pubkeys\n", COMPRESSED_PUBKEY_SIZE);
    
    // Allocate buffer and worker structures
    unsigned char *buffer = (unsigned char*)malloc(INPUT_BUFFER_SIZE);
    if (!buffer) {
        fprintf(stderr, "[E] Failed to allocate buffer\n");
        fclose(file);
        bloom_free(bloom_filter);
        free(bloom_filter);
        return false;
    }
    
    struct BloomLoadWorker *workers = (struct BloomLoadWorker*)malloc(num_load_threads * sizeof(struct BloomLoadWorker));
    pthread_t *threads = (pthread_t*)malloc(num_load_threads * sizeof(pthread_t));
    
    if (!workers || !threads) {
        fprintf(stderr, "[E] Failed to allocate worker structures\n");
        free(buffer);
        fclose(file);
        bloom_free(bloom_filter);
        free(bloom_filter);
        return false;
    }
    
    // Start timing
    auto start_time = std::chrono::high_resolution_clock::now();
    size_t entries_processed = 0;
    size_t bytes_read;
    
    // Process file in chunks
    while ((bytes_read = fread(buffer, 1, INPUT_BUFFER_SIZE, file)) > 0) {
        size_t entries_in_buffer = bytes_read / COMPRESSED_PUBKEY_SIZE;
        size_t entries_per_worker = (entries_in_buffer + num_load_threads - 1) / num_load_threads;
        
        // Distribute work to threads
        int active_threads = 0;
        for (int i = 0; i < num_load_threads; i++) {
            size_t start_entry = i * entries_per_worker;
            if (start_entry >= entries_in_buffer) break;
            
            workers[i].bloom_filter = bloom_filter;
            workers[i].entries = buffer + (start_entry * COMPRESSED_PUBKEY_SIZE);
            workers[i].num_entries = (i == num_load_threads - 1) ? 
                                    entries_in_buffer - start_entry : 
                                    entries_per_worker;
            workers[i].thread_id = i;
            workers[i].bloom_mutex = &bloom_mutex;
            
            if (pthread_create(&threads[i], NULL, bloom_load_worker_thread, &workers[i]) == 0) {
                active_threads++;
            } else {
                fprintf(stderr, "[W] Failed to create worker thread %d\n", i);
            }
        }
        
        // Wait for all threads to complete
        for (int i = 0; i < active_threads; i++) {
            pthread_join(threads[i], NULL);
        }
        
        entries_processed += entries_in_buffer;
        
        // Update progress
        auto current_time = std::chrono::high_resolution_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(current_time - start_time);
        double rate = (entries_processed * 1000.0) / elapsed.count();
        double percent = (double)entries_processed / total_entries * 100.0;
        
        printf("\r[+] Processed %zu/%zu entries (%.1f%%) at %.0f entries/sec", 
               entries_processed, total_entries, percent, rate);
        fflush(stdout);
    }
    
    printf("\n");
    
    // End timing
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(end_time - start_time);
    
    printf("[+] Loading completed in %ld seconds\n", duration.count());
    printf("[+] Successfully loaded %zu keys into bloom filter\n", entries_processed);
    
    // Display bloom filter stats
    printf("[+] Bloom filter: %d entries, %.8f error rate\n", 
           bloom_filter->entries, bloom_filter->error);
    printf("[+] Single-tier bloom filter storing complete compressed pubkeys\n");
    printf("[+] Expected false positives: ~%zu out of %zu entries\n", 
           (size_t)(entries_processed * bloom_filter->error), entries_processed);
    
    // Memory usage warning
    printf("[!] Total memory usage: ~%.1f GB for bloom filter\n", memory_gb);
    printf("[!] Ensure system has sufficient free RAM for path finding operations\n");
    
    // Cleanup
    free(buffer);
    free(workers);
    free(threads);
    fclose(file);
    
    bloom_initialized = true;
    return true;
}

// Check bloom filter for compressed pubkey
bool check_bloom_filter(Point &point) {
    if (!bloom_initialized || !bloom_filter) return false;
    
    // Generate compressed pubkey
    unsigned char compressed[COMPRESSED_PUBKEY_SIZE];
    unsigned char x_bytes[32];
    point.x.Get32Bytes(x_bytes);
    
    bool y_is_odd = point.y.IsOdd();
    compressed[0] = y_is_odd ? 0x03 : 0x02;
    memcpy(compressed + 1, x_bytes, 32);
    
    // Check bloom filter
    pthread_mutex_lock(&bloom_mutex);
    bool result = bloom_check(bloom_filter, (char*)compressed, COMPRESSED_PUBKEY_SIZE);
    pthread_mutex_unlock(&bloom_mutex);
    
    return result;
}

// Update display
void update_display(const PathState &state, int target_steps, int target_subs, int target_divs) {
    char current_hex[67];
    bool compressed = true;
    Point point_copy = state.current_point;
    secp->GetPublicKeyHex(compressed, point_copy, current_hex);
    
    pthread_mutex_lock(&print_mutex);
    printf("\r%s %s %s %d/%d %d/%d %d/%d",
           input_pubkey_compressed,
           state.last_operation,
           current_hex,
           state.divisions, target_divs,
           state.subtractions, target_subs,
           global_valid_paths_current_config.load(), config.paths_per_config);
    fflush(stdout);
    pthread_mutex_unlock(&print_mutex);
}

// Print debug path
void print_debug_path(const PathState &state) {
    pthread_mutex_lock(&print_mutex);
    printf("\n\n=== DEBUG PATH ANALYSIS ===\n");
    printf("Total Steps: %d (Divisions: %d, Subtractions: %d)\n", 
           state.total_steps, state.divisions, state.subtractions);
    printf("Path: %s\n\n", state.path);
    
    if (config.debug_mode && state.all_points.size() > 0) {
        printf("All Public Keys in Path:\n");
        char hex[67];
        bool compressed = true;
        
        const char *p = state.path;
        int op_index = 0;
        
        Point start = state.all_points[0];
        secp->GetPublicKeyHex(compressed, start, hex);
        printf("START: %s\n", hex);
        
        int point_index = 1;
        while (*p && point_index < state.all_points.size()) {
            char op[4] = {0};
            if (*p == '-' && *(p+1) == '1') {
                strcpy(op, "-1");
                p += 2;
            } else if (*p == '/' && *(p+1) == '2') {
                strcpy(op, "/2");
                p += 2;
            }
            
            if (op[0] && point_index < state.all_points.size()) {
                Point pt = state.all_points[point_index];
                secp->GetPublicKeyHex(compressed, pt, hex);
                printf("After %s: %s\n", op, hex);
                point_index++;
            }
            
            if (*p == ',') p++;
        }
        
        printf("\nSubtraction positions: ");
        for (int pos : state.subtraction_positions) {
            printf("%d ", pos);
        }
        printf("\n");
    }
    
    printf("=== END DEBUG PATH ===\n\n");
    pthread_mutex_unlock(&print_mutex);
}

// Build paths in batch using CPU_GRP_SIZE optimization
bool build_paths_batch(BatchWork &batch, Point start_point, int target_steps, int target_subs, int target_divs, int thread_id, IntGroup *grp) {
    int batch_size = batch.batch_size;
    
    // Initialize all paths in batch
    for (int b = 0; b < batch_size; b++) {
        batch.paths[b].clear();
        batch.paths[b].current_point = start_point;
        batch.paths[b].divisions = 0;
        batch.paths[b].subtractions = 0;
        batch.paths[b].total_steps = 0;
        strcpy(batch.paths[b].last_operation, "START");
        batch.active[b] = true;
        batch.points[b] = start_point;
        
        if (config.debug_mode) {
            batch.paths[b].all_points.reserve(target_steps + 1);
            batch.paths[b].all_points.push_back(start_point);
        }
        batch.paths[b].subtraction_positions.reserve(target_subs);
    }
    
    if (target_subs + target_divs != target_steps) {
        return false;
    }
    
    // Generate operation sequences for each path
    std::vector<std::vector<int>> all_operations(batch_size);
    
    for (int b = 0; b < batch_size; b++) {
        all_operations[b].reserve(target_steps);
        
        // Create operation pool
        for (int i = 0; i < target_subs; i++) {
            all_operations[b].push_back(0); // 0 = subtraction
        }
        for (int i = 0; i < target_divs; i++) {
            all_operations[b].push_back(1); // 1 = division
        }
        
        // Shuffle operations
        std::shuffle(all_operations[b].begin(), all_operations[b].end(), get_thread_rng());
        
        // Validate and fix consecutive subtractions
        bool valid = false;
        int attempts = 0;
        const int MAX_ATTEMPTS = 100;
        
        while (!valid && attempts < MAX_ATTEMPTS) {
            valid = true;
            attempts++;
            
            for (size_t i = 0; i < all_operations[b].size() - 1; i++) {
                if (all_operations[b][i] == 0 && all_operations[b][i+1] == 0) {
                    valid = false;
                    for (size_t j = i + 2; j < all_operations[b].size(); j++) {
                        if (all_operations[b][j] == 1) {
                            std::swap(all_operations[b][i+1], all_operations[b][j]);
                            break;
                        }
                    }
                }
            }
            
            if (!valid && attempts < MAX_ATTEMPTS - 1) {
                std::shuffle(all_operations[b].begin(), all_operations[b].end(), get_thread_rng());
            }
        }
        
        if (!valid) {
            batch.active[b] = false;
        }
    }
    
    // Process operations step by step for all paths
    for (int step = 0; step < target_steps; step++) {
        // Prepare batch operations
        std::vector<int> step_operations(batch_size);
        int num_divisions = 0;
        int num_subtractions = 0;
        
        for (int b = 0; b < batch_size; b++) {
            if (!batch.active[b]) continue;
            
            step_operations[b] = all_operations[b][step];
            if (step_operations[b] == 0) num_subtractions++;
            else if (step_operations[b] == 1) num_divisions++;
        }
        
        // Process divisions in batch if there are many
        if (num_divisions > batch_size / 4) {  // If more than 25% are divisions
            // Setup division calculations using IntGroup
            Int dx[BATCH_SIZE];
            grp->Set(dx);
            
            int div_idx = 0;
            for (int b = 0; b < batch_size; b++) {
                if (batch.active[b] && step_operations[b] == 1) {
                    // Prepare for batch division
                    dx[div_idx].Set(&INVERSE_OF_2);
                    div_idx++;
                }
            }
            
            // Batch modular inversion
            if (div_idx > 0) {
                grp->ModInv();
            }
            
            // Apply results
            div_idx = 0;
            for (int b = 0; b < batch_size; b++) {
                if (!batch.active[b]) continue;
                
                if (step_operations[b] == 1) {
                    // Division by 2
                    batch.points[b] = compute_point_half_batch(batch.points[b], grp);
                    batch.paths[b].current_point = batch.points[b];
                    
                    size_t current_len = strlen(batch.paths[b].path);
                    if (current_len + 3 < MAX_PATH_LENGTH - 1) {
                        strncat(batch.paths[b].path, "/2,", 3);
                    }
                    strcpy(batch.paths[b].last_operation, "/2");
                    batch.paths[b].divisions++;
                    batch.paths[b].total_steps++;
                    
                    if (config.debug_mode) {
                        batch.paths[b].all_points.push_back(batch.points[b]);
                    }
                    
                    div_idx++;
                } else if (step_operations[b] == 0) {
                    // Subtraction
                    if (GSn.empty()) {
                        batch.active[b] = false;
                        continue;
                    }
                    
                    Point sub = GSn[0];
                    batch.points[b] = secp->AddDirect(batch.points[b], sub);
                    batch.paths[b].current_point = batch.points[b];
                    
                    size_t current_len = strlen(batch.paths[b].path);
                    if (current_len + 3 < MAX_PATH_LENGTH - 1) {
                        strncat(batch.paths[b].path, "-1,", 3);
                    }
                    strcpy(batch.paths[b].last_operation, "-1");
                    batch.paths[b].subtractions++;
                    batch.paths[b].total_steps++;
                    batch.paths[b].subtraction_positions.push_back(batch.paths[b].total_steps - 1);
                    
                    if (config.debug_mode) {
                        batch.paths[b].all_points.push_back(batch.points[b]);
                    }
                }
            }
        } else {
            // Process operations individually if not many divisions
            for (int b = 0; b < batch_size; b++) {
                if (!batch.active[b]) continue;
                
                if (step_operations[b] == 0) {
                    // Subtraction
                    if (GSn.empty()) {
                        batch.active[b] = false;
                        continue;
                    }
                    
                    Point sub = GSn[0];
                    batch.points[b] = secp->AddDirect(batch.points[b], sub);
                    batch.paths[b].current_point = batch.points[b];
                    
                    size_t current_len = strlen(batch.paths[b].path);
                    if (current_len + 3 < MAX_PATH_LENGTH - 1) {
                        strncat(batch.paths[b].path, "-1,", 3);
                    }
                    strcpy(batch.paths[b].last_operation, "-1");
                    batch.paths[b].subtractions++;
                    batch.paths[b].total_steps++;
                    batch.paths[b].subtraction_positions.push_back(batch.paths[b].total_steps - 1);
                    
                    if (config.debug_mode) {
                        batch.paths[b].all_points.push_back(batch.points[b]);
                    }
                } else if (step_operations[b] == 1) {
                    // Division by 2
                    batch.points[b] = compute_point_half(batch.points[b]);
                    batch.paths[b].current_point = batch.points[b];
                    
                    size_t current_len = strlen(batch.paths[b].path);
                    if (current_len + 3 < MAX_PATH_LENGTH - 1) {
                        strncat(batch.paths[b].path, "/2,", 3);
                    }
                    strcpy(batch.paths[b].last_operation, "/2");
                    batch.paths[b].divisions++;
                    batch.paths[b].total_steps++;
                    
                    if (config.debug_mode) {
                        batch.paths[b].all_points.push_back(batch.points[b]);
                    }
                }
            }
        }
        
        // Update display for first path periodically
        if (thread_id == 0 && step % 10 == 0 && batch.active[0]) {
            update_display(batch.paths[0], target_steps, target_subs, target_divs);
        }
    }
    
    // Validate all paths
    bool any_success = false;
    for (int b = 0; b < batch_size; b++) {
        if (batch.active[b]) {
            batch.active[b] = (batch.paths[b].divisions == target_divs && 
                              batch.paths[b].subtractions == target_subs && 
                              batch.paths[b].total_steps == target_steps);
            if (batch.active[b]) any_success = true;
        }
    }
    
    return any_success;
}

// Build a path with exact configuration (fallback for single path)
bool build_path_with_config(PathState &state, Point start_point, int target_steps, int target_subs, int target_divs, int thread_id) {
    // Clear and shrink vectors to release memory from previous paths
    state.subtraction_positions.clear();
    state.subtraction_positions.shrink_to_fit();
    state.all_points.clear();
    state.all_points.shrink_to_fit();
    
    // Initialize state
    state.current_point = start_point;
    state.divisions = 0;
    state.subtractions = 0;
    state.total_steps = 0;
    state.path[0] = '\0';
    strcpy(state.last_operation, "START");
    
    // Only reserve space if we're actually using it
    if (config.debug_mode) {
        state.all_points.reserve(target_steps + 1);
        state.all_points.push_back(start_point);
    }
    state.subtraction_positions.reserve(target_subs);
    
    if (target_subs + target_divs != target_steps) {
        return false;
    }
    
    if (thread_id == 0) {
        update_display(state, target_steps, target_subs, target_divs);
    }
    
    std::vector<int> operations;
    operations.reserve(target_steps);
    
    if (target_subs > target_divs) {
        return false;
    }
    
    // Generate more random and distributed paths
    operations.clear();
    
    // First, create a pool of all operations
    for (int i = 0; i < target_subs; i++) {
        operations.push_back(0); // 0 = subtraction
    }
    for (int i = 0; i < target_divs; i++) {
        operations.push_back(1); // 1 = division
    }
    
    // Shuffle the operations for random distribution
    std::shuffle(operations.begin(), operations.end(), get_thread_rng());
    
    // Now enforce the constraint that subtraction must be followed by division
    bool valid = false;
    int attempts = 0;
    const int MAX_ATTEMPTS = 1000;
    
    while (!valid && attempts < MAX_ATTEMPTS) {
        valid = true;
        attempts++;
        
        // Check for consecutive subtractions
        for (size_t i = 0; i < operations.size() - 1; i++) {
            if (operations[i] == 0 && operations[i+1] == 0) {
                // Found two consecutive subtractions, need to fix
                valid = false;
                
                // Find a division to swap with
                for (size_t j = i + 2; j < operations.size(); j++) {
                    if (operations[j] == 1) {
                        // Swap the second subtraction with this division
                        std::swap(operations[i+1], operations[j]);
                        break;
                    }
                }
            }
        }
        
        // If still not valid after fixing, reshuffle and try again
        if (!valid && attempts < MAX_ATTEMPTS - 1) {
            std::shuffle(operations.begin(), operations.end(), get_thread_rng());
        }
    }
    
    // If we couldn't generate a valid sequence, fall back to alternating pattern
    if (!valid) {
        operations.clear();
        int subs_remaining = target_subs;
        int divs_remaining = target_divs;
        bool last_was_subtraction = false;
        
        while (operations.size() < target_steps) {
            if (last_was_subtraction) {
                operations.push_back(1);
                divs_remaining--;
                last_was_subtraction = false;
            } else {
                if (subs_remaining == 0) {
                    operations.push_back(1);
                    divs_remaining--;
                } else if (divs_remaining == 0) {
                    return false;
                } else {
                    // Randomly choose between subtraction and division
                    if (get_thread_rng()() % 2 == 0 && subs_remaining > 0) {
                        operations.push_back(0);
                        subs_remaining--;
                        last_was_subtraction = true;
                    } else {
                        operations.push_back(1);
                        divs_remaining--;
                    }
                }
            }
        }
    }
    
    // Validate operations vector
    if (operations.size() != target_steps) {
        fprintf(stderr, "[E] Operations size mismatch: %zu vs %d\n", 
                operations.size(), target_steps);
        return false;
    }
    
    // Count operations to verify
    int op_subs = 0, op_divs = 0;
    for (int i = 0; i < operations.size(); i++) {
        if (operations[i] < 0 || operations[i] > 1) {
            fprintf(stderr, "[E] Invalid operation at index %d: %d\n", 
                    i, operations[i]);
            return false;
        }
        if (operations[i] == 0) op_subs++;
        else if (operations[i] == 1) op_divs++;
    }
    
    if (op_subs != target_subs || op_divs != target_divs) {
        return false;
    }
    
    int update_frequency = (target_steps > 100) ? target_steps / 20 : 5;
    
    for (int i = 0; i < target_steps; i++) {
        size_t current_len = strlen(state.path);
        if (current_len + 3 >= MAX_PATH_LENGTH - 1) {
            return false;
        }
        
        if (operations[i] == 0) {
            if (state.subtractions >= target_subs) {
                return false;
            }
            
            if (GSn.empty()) {
                fprintf(stderr, "[E] GSn array not initialized!\n");
                return false;
            }
            
            Point sub = GSn[0];
            state.current_point = secp->AddDirect(state.current_point, sub);
            
            strncat(state.path, "-1,", 3);
            strcpy(state.last_operation, "-1");
            state.subtractions++;
            state.total_steps++;
            state.subtraction_positions.push_back(state.total_steps - 1);
            
        } else if (operations[i] == 1) {
            if (state.divisions >= target_divs) {
                return false;
            }
            Point half = compute_point_half(state.current_point);
            state.current_point = half;
            
            strncat(state.path, "/2,", 3);
            strcpy(state.last_operation, "/2");
            state.divisions++;
            state.total_steps++;
        }
        
        if (config.debug_mode) {
            state.all_points.push_back(state.current_point);
        }
        
        if (thread_id == 0 && state.total_steps > 0 && 
            (state.total_steps % update_frequency == 0 || i == target_steps - 1)) {
            update_display(state, target_steps, target_subs, target_divs);
            usleep(1000);
        }
    }
    
    // Release operations vector memory
    std::vector<int>().swap(operations);
    
    if (thread_id == 0) {
        update_display(state, target_steps, target_subs, target_divs);
    }
    
    bool success = (state.divisions == target_divs && 
                    state.subtractions == target_subs && 
                    state.total_steps == target_steps);
    
    return success;
}

// Path finder thread with batch processing
void *path_finder_thread(void *arg) {
    ThreadWork *work = (ThreadWork*)arg;
    bool compressed = true;
    int paths_attempted = 0;
    int paths_built = 0;
    int paths_in_current_config = 0;
    
    const int MEMORY_RELEASE_INTERVAL = 1000;
    const int MIN_BATCH_SIZE = 16;  // Minimum paths to process in batch
    const int MAX_BATCH_SIZE = BATCH_SIZE;  // Maximum batch size
    
    // Determine batch size based on configuration
    int batch_size = MIN_BATCH_SIZE;
    if (config.paths_per_config >= 100) {
        batch_size = MAX_BATCH_SIZE / 4;  // 128 paths
    } else if (config.paths_per_config >= 50) {
        batch_size = MAX_BATCH_SIZE / 8;  // 64 paths
    } else if (config.paths_per_config >= 20) {
        batch_size = MIN_BATCH_SIZE * 2;  // 32 paths
    }
    
    // Use batch processing only when beneficial
    bool use_batch = (config.paths_per_config >= 20 && batch_size >= MIN_BATCH_SIZE);
    
    if (use_batch && work->thread_id == 0) {
        pthread_mutex_lock(&print_mutex);
        printf("[+] Using batch processing with batch size: %d\n", batch_size);
        pthread_mutex_unlock(&print_mutex);
    }
    
    while (!work->found->load()) {
        int current_steps = work->current_steps->load();
        int current_valid_paths = work->valid_paths_for_current_config->load();
        
        if (current_valid_paths >= config.paths_per_config) {
            usleep(1000);
            continue;
        }
        
        int current_subs = current_steps - config.min_divisions;
        
        if (current_subs < 0 || current_steps < config.min_divisions) {
            continue;
        }
        
        if (current_steps > config.max_steps) {
            pthread_mutex_lock(work->config_mutex);
            if (work->current_steps->load() > config.max_steps) {
                work->current_steps->store(config.min_steps);
                work->valid_paths_for_current_config->store(0);
                global_valid_paths_current_config.store(0);
                paths_in_current_config = 0;
                
                pthread_mutex_lock(&print_mutex);
                printf("\n[!] Completed full search range. Restarting from beginning...\n");
                pthread_mutex_unlock(&print_mutex);
            }
            pthread_mutex_unlock(work->config_mutex);
            continue;
        }
        
        if (use_batch && (config.paths_per_config - current_valid_paths) >= batch_size) {
            // Process multiple paths in batch
            bool batch_success = build_paths_batch(*work->batch, work->start_point,
                                                  current_steps, current_subs,
                                                  config.min_divisions, work->thread_id,
                                                  work->grp);
            paths_attempted += batch_size;
            
            if (!batch_success) {
                continue;
            }
            
            // Check all paths in batch for matches
            for (int b = 0; b < batch_size; b++) {
                if (!work->batch->active[b]) continue;
                
                paths_built++;
                paths_in_current_config++;
                
                // Debug path printing
                if (config.debug_mode && !work->debug_path_printed->load() && 
                    paths_in_current_config >= 5 && paths_in_current_config <= 10) {
                    if (rand() % 2 == 0) {
                        bool expected = false;
                        if (work->debug_path_printed->compare_exchange_strong(expected, true)) {
                            print_debug_path(work->batch->paths[b]);
                            work->batch->paths[b].all_points.clear();
                            work->batch->paths[b].all_points.shrink_to_fit();
                        }
                    }
                }
                
                // Check bloom filter
                if (check_bloom_filter(work->batch->paths[b].current_point)) {
                    bool is_valid_match = true;
                    
                    if (!config.skip_verification) {
                        is_valid_match = verify_in_file(work->batch->paths[b].current_point, config.bloom_file);
                        if (!is_valid_match) {
                            pthread_mutex_lock(&print_mutex);
                            printf("\n[!] False positive from bloom filter (Thread %d, Batch %d)\n", 
                                   work->thread_id, b);
                            pthread_mutex_unlock(&print_mutex);
                        }
                    }
                    
                    if (is_valid_match) {
                        pthread_mutex_lock(work->result_mutex);
                        bool expected = false;
                        if (work->found->compare_exchange_strong(expected, true)) {
                            *work->result_path = work->batch->paths[b];
                            key_found.store(true);
                            
                            char final_hex[67];
                            Point final_point = work->batch->paths[b].current_point;
                            secp->GetPublicKeyHex(compressed, final_point, final_hex);
                            
                            pthread_mutex_lock(&print_mutex);
                            printf("\n[!] MATCH FOUND %sby Thread %d (Batch)!\n", 
                                   config.skip_verification ? "(bloom filter) " : "AND VERIFIED ",
                                   work->thread_id);
                            printf("%s -> %s %d/%d %d/%d FOUND\n",
                                   input_pubkey_compressed, final_hex,
                                   work->batch->paths[b].divisions, config.min_divisions,
                                   work->batch->paths[b].subtractions, current_subs);
                            printf("Path: %s\n", work->batch->paths[b].path);
                            printf("Steps: %d, Divisions: %d, Subtractions: %d\n",
                                   work->batch->paths[b].total_steps, 
                                   work->batch->paths[b].divisions, 
                                   work->batch->paths[b].subtractions);
                            pthread_mutex_unlock(&print_mutex);
                        }
                        pthread_mutex_unlock(work->result_mutex);
                        return NULL;
                    }
                }
            }
            
            // Update valid paths counter
            pthread_mutex_lock(work->config_mutex);
            
            if (work->current_steps->load() == current_steps) {
                int valid_count = 0;
                for (int b = 0; b < batch_size; b++) {
                    if (work->batch->active[b]) valid_count++;
                }
                
                int new_count = work->valid_paths_for_current_config->fetch_add(valid_count) + valid_count;
                global_valid_paths_current_config.store(new_count);
                
                if (new_count >= config.paths_per_config) {
                    work->current_steps->fetch_add(1);
                    work->valid_paths_for_current_config->store(0);
                    global_valid_paths_current_config.store(0);
                    paths_in_current_config = 0;
                    work->debug_path_printed->store(false);
                }
            }
            
            pthread_mutex_unlock(work->config_mutex);
            
        } else {
            // Fall back to single path processing
            PathState state;
            bool path_built = build_path_with_config(state, work->start_point, 
                                                     current_steps, current_subs, 
                                                     config.min_divisions, work->thread_id);
            paths_attempted++;
            
            if (!path_built) {
                continue;
            }
            
            paths_built++;
            paths_in_current_config++;
            
            // Debug path printing
            if (config.debug_mode && !work->debug_path_printed->load() && 
                paths_in_current_config >= 5 && paths_in_current_config <= 10) {
                if (rand() % 2 == 0) {
                    bool expected = false;
                    if (work->debug_path_printed->compare_exchange_strong(expected, true)) {
                        print_debug_path(state);
                        state.all_points.clear();
                        state.all_points.shrink_to_fit();
                    }
                }
            }
            
            // Check bloom filter
            if (check_bloom_filter(state.current_point)) {
                bool is_valid_match = true;
                
                if (!config.skip_verification) {
                    is_valid_match = verify_in_file(state.current_point, config.bloom_file);
                    if (!is_valid_match) {
                        pthread_mutex_lock(&print_mutex);
                        printf("\n[!] False positive from bloom filter (Thread %d)\n", work->thread_id);
                        pthread_mutex_unlock(&print_mutex);
                    }
                }
                
                if (is_valid_match) {
                    pthread_mutex_lock(work->result_mutex);
                    bool expected = false;
                    if (work->found->compare_exchange_strong(expected, true)) {
                        *work->result_path = state;
                        key_found.store(true);
                        
                        char final_hex[67];
                        Point final_point = state.current_point;
                        secp->GetPublicKeyHex(compressed, final_point, final_hex);
                        
                        pthread_mutex_lock(&print_mutex);
                        printf("\n[!] MATCH FOUND %sby Thread %d!\n", 
                               config.skip_verification ? "(bloom filter) " : "AND VERIFIED ",
                               work->thread_id);
                        printf("%s -> %s %d/%d %d/%d FOUND\n",
                               input_pubkey_compressed, final_hex,
                               state.divisions, config.min_divisions,
                               state.subtractions, current_subs);
                        printf("Path: %s\n", state.path);
                        printf("Steps: %d, Divisions: %d, Subtractions: %d\n",
                               state.total_steps, state.divisions, state.subtractions);
                        pthread_mutex_unlock(&print_mutex);
                    }
                    pthread_mutex_unlock(work->result_mutex);
                    break;
                }
            }
            
            // Update counter
            pthread_mutex_lock(work->config_mutex);
            
            if (work->current_steps->load() == current_steps && 
                work->valid_paths_for_current_config->load() < config.paths_per_config) {
                
                int new_count = work->valid_paths_for_current_config->fetch_add(1) + 1;
                global_valid_paths_current_config.store(new_count);
                
                if (new_count >= config.paths_per_config) {
                    work->current_steps->fetch_add(1);
                    work->valid_paths_for_current_config->store(0);
                    global_valid_paths_current_config.store(0);
                    paths_in_current_config = 0;
                    work->debug_path_printed->store(false);
                }
            }
            
            pthread_mutex_unlock(work->config_mutex);
        }
        
        // Periodic memory release
        if (paths_attempted % MEMORY_RELEASE_INTERVAL == 0) {
            if (work->batch) {
                for (int b = 0; b < work->batch->batch_size; b++) {
                    work->batch->paths[b].subtraction_positions.clear();
                    work->batch->paths[b].subtraction_positions.shrink_to_fit();
                    work->batch->paths[b].all_points.clear();
                    work->batch->paths[b].all_points.shrink_to_fit();
                }
            }
        }
        
        usleep(10);
    }
    
    return NULL;
}

// Save found path to file
void save_found_path(const PathState &path, const char *pubkey) {
    FILE *file = fopen("found_paths.txt", "a");
    if (file) {
        time_t now = time(NULL);
        fprintf(file, "=== Path Found %s", ctime(&now));
        fprintf(file, "Input Public Key: %s\n", pubkey);
        
        char final_hex[67];
        bool compressed = true;
        Point final_point = path.current_point;
        secp->GetPublicKeyHex(compressed, final_point, final_hex);
        fprintf(file, "Final Public Key: %s\n", final_hex);
        
        fprintf(file, "Path: %s\n", path.path);
        fprintf(file, "Total Steps: %d\n", path.total_steps);
        fprintf(file, "Divisions: %d\n", path.divisions);
        fprintf(file, "Subtractions: %d\n", path.subtractions);
        
        fprintf(file, "Subtraction positions: ");
        for (int pos : path.subtraction_positions) {
            fprintf(file, "%d ", pos);
        }
        fprintf(file, "\n");
        
        double div_pct = (path.divisions * 100.0) / path.total_steps;
        fprintf(file, "Division %%: %.2f\n\n", div_pct);
        fclose(file);
    }
}

// Signal handler
void handle_interrupt(int sig) {
    (void)sig;
    printf("\n[!] Received interrupt signal. Shutting down...\n");
    key_found.store(true);
    cleanup();
    exit(0);
}

// Cleanup resources
void cleanup() {
    if (bloom_initialized && bloom_filter) {
        if (bloom_filter->ready) bloom_free(bloom_filter);
        free(bloom_filter);
    }
    pthread_mutex_destroy(&bloom_mutex);
    if (secp) delete secp;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <pubkey> -f <bloom_file> [options]\n", argv[0]);
        printf("Options:\n");
        printf("  -t <threads>    Number of threads (default: 1)\n");
        printf("  -s <min_steps>  Minimum steps (default: 85)\n");
        printf("  -S <max_steps>  Maximum steps (default: 135)\n");
        printf("  -d <min_divs>   Minimum divisions (default: 75)\n");
        printf("  -D <max_divs>   Maximum divisions (default: 75)\n");
        printf("  -p <paths>      Paths per configuration (default: 10)\n");
        printf("  -w              Save all paths to file\n");
        printf("  -B              Debug mode - print sample path (HIGH MEMORY USAGE)\n");
        printf("  -V              Skip file verification (trust bloom filters)\n");
        printf("\nMemory usage estimate:\n");
        printf("  Single-tier bloom filter: ~14 bytes per entry at 0.00001 FP rate\n");
        printf("  For 1B entries: ~14GB bloom filter memory\n");
        printf("  Path finding: ~50-200MB per thread (more with -B flag)\n");
        printf("\nOptimizations:\n");
        printf("  - CPU_GRP_SIZE batch processing with IntGroup ModInv\n");
        printf("  - Pre-computed division points\n");
        printf("  - Batch path generation for high path counts\n");
        return 1;
    }
    
    config.input_pubkey = argv[1];
    
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-f") == 0 && i + 1 < argc) {
            config.bloom_file = argv[++i];
        } else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            config.num_threads = atoi(argv[++i]);
            if (config.num_threads < 1) config.num_threads = 1;
            if (config.num_threads > MAX_THREADS) config.num_threads = MAX_THREADS;
        } else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
            config.min_steps = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-S") == 0 && i + 1 < argc) {
            config.max_steps = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
            config.min_divisions = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-D") == 0 && i + 1 < argc) {
            config.max_divisions = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            config.paths_per_config = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-w") == 0) {
            config.save_paths = true;
        } else if (strcmp(argv[i], "-B") == 0) {
            config.debug_mode = true;
        } else if (strcmp(argv[i], "-V") == 0) {
            config.skip_verification = true;
        }
    }
    
    if (!config.bloom_file) {
        fprintf(stderr, "[E] Bloom filter file required (-f)\n");
        return 1;
    }
    
    config.current_steps = config.min_steps;
    global_current_steps.store(config.min_steps);
    
    int initial_subs = config.min_steps - config.min_divisions;
    
    printf("[+] Fast Division Path Finder v3.0 - Optimized with CPU_GRP_SIZE Batch Processing\n");
    printf("[+] Threads: %d\n", config.num_threads);
    printf("[+] Steps: %d-%d\n", config.min_steps, config.max_steps);
    printf("[+] Divisions: %d (fixed)\n", config.min_divisions);
    printf("[+] Starting subtractions: %d (steps - divisions)\n", initial_subs);
    printf("[+] Paths per configuration: %d\n", config.paths_per_config);
    printf("[+] CPU_GRP_SIZE: %d\n", CPU_GRP_SIZE);
    printf("[+] Batch processing: %s\n", 
           config.paths_per_config >= 20 ? "ENABLED" : "DISABLED (use -p 20+ to enable)");
    
    if (config.skip_verification) {
        printf("[+] File verification DISABLED - trusting bloom filters\n");
    }
    if (config.debug_mode) {
        printf("[+] Debug mode enabled - will print sample path\n");
        printf("[!] WARNING: Debug mode stores all points in memory. With large paths and many threads,\n");
        printf("[!]          this can consume significant RAM. Consider running without -B flag.\n");
    }
    
    signal(SIGINT, handle_interrupt);
    
    init_secp256k1();
    
    Point input_point;
    bool compressed;
    if (!secp->ParsePublicKeyHex(config.input_pubkey, input_point, compressed)) {
        fprintf(stderr, "[E] Invalid public key\n");
        return 1;
    }
    
    strcpy(input_pubkey_compressed, config.input_pubkey);
    
    printf("[+] Input public key: %s\n", config.input_pubkey);
    
    if (!init_bloom_filter(config.bloom_file)) {
        fprintf(stderr, "[E] Failed to initialize bloom filter\n");
        return 1;
    }
    
    start_time = time(NULL);
    
    pthread_t *threads = (pthread_t*)malloc(config.num_threads * sizeof(pthread_t));
    ThreadWork *thread_work = (ThreadWork*)malloc(config.num_threads * sizeof(ThreadWork));
    PathState result_path;
    pthread_mutex_t result_mutex = PTHREAD_MUTEX_INITIALIZER;
    
    std::atomic<int> valid_paths_current_config(0);
    std::atomic<int> current_steps_atomic(config.min_steps);
    std::atomic<bool> debug_printed(false);
    
    printf("[+] Starting systematic search with %d threads...\n", config.num_threads);
    printf("[+] Only checking final points in paths against bloom filter\n");
    printf("[+] Starting at: Steps=%d, Subtractions=%d, Divisions=%d\n\n",
           config.current_steps, initial_subs, config.min_divisions);
    
    // Determine batch size for batch processing
    int batch_size = 16;  // Default minimum
    if (config.paths_per_config >= 100) {
        batch_size = BATCH_SIZE / 4;
    } else if (config.paths_per_config >= 50) {
        batch_size = BATCH_SIZE / 8;
    } else if (config.paths_per_config >= 20) {
        batch_size = 32;
    }
    
    for (int i = 0; i < config.num_threads; i++) {
        thread_work[i].thread_id = i;
        thread_work[i].start_point = input_point;
        thread_work[i].start_key.SetInt32(0);
        thread_work[i].found = &key_found;
        thread_work[i].result_path = &result_path;
        thread_work[i].result_mutex = &result_mutex;
        thread_work[i].valid_paths_for_current_config = &valid_paths_current_config;
        thread_work[i].current_steps = &current_steps_atomic;
        thread_work[i].config_mutex = &config_mutex;
        thread_work[i].debug_path_printed = &debug_printed;
        
        // Allocate IntGroup and BatchWork for each thread
        thread_work[i].grp = new IntGroup(batch_size + 1);
        thread_work[i].batch = new BatchWork(batch_size);
        
        pthread_create(&threads[i], NULL, path_finder_thread, &thread_work[i]);
    }
    
    for (int i = 0; i < config.num_threads; i++) {
        pthread_join(threads[i], NULL);
    }
    
    if (key_found.load()) {
        printf("\n[+] SUCCESS! Path found!\n");
        printf("[+] Total steps: %d\n", result_path.total_steps);
        printf("[+] Divisions: %d (%.1f%%)\n", result_path.divisions,
               (result_path.divisions * 100.0) / result_path.total_steps);
        printf("[+] Subtractions: %d (%.1f%%)\n", result_path.subtractions,
               (result_path.subtractions * 100.0) / result_path.total_steps);
        
        if (config.save_paths) {
            save_found_path(result_path, config.input_pubkey);
            printf("[+] Path saved to found_paths.txt\n");
        }
    } else {
        printf("\n[!] No match found in the given range.\n");
    }
    
    time_t end_time = time(NULL);
    printf("[+] Time elapsed: %ld seconds\n", end_time - start_time);
    
    // Cleanup
    for (int i = 0; i < config.num_threads; i++) {
        delete thread_work[i].grp;
        delete thread_work[i].batch;
    }
    
    free(threads);
    free(thread_work);
    pthread_mutex_destroy(&result_mutex);
    pthread_mutex_destroy(&config_mutex);
    cleanup();
    
    return 0;
}
