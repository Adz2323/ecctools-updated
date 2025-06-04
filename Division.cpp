// division.cpp - Optimized Fast Public Key Division Tool with Path Finding
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
#include <sys/stat.h>
#include "secp256k1/SECP256k1.h"
#include "secp256k1/Point.h"
#include "secp256k1/Int.h"
#include "secp256k1/IntGroup.h"
#include "secp256k1/Random.h"
#include "bloom/bloom.h"
#include "hash/sha256.h"
#include "xxhash/xxhash.h"

#define COMPRESSED_PUBKEY_SIZE 33
#define PUBKEY_PREFIX_LENGTH 6
#define MAX_PATH_LENGTH 10000
#define MAX_THREADS 256
#define CPU_GRP_SIZE 1024
#define BLOOM_FP_RATE 0.000001
#define PATHS_PER_CONFIG 10

// Global configuration
struct Config {
    int min_steps = 85;
    int max_steps = 135;
    int min_divisions = 75;
    int max_divisions = 75;
    int num_threads = 1;
    int max_paths_per_level = 5;
    bool save_paths = false;
    bool debug_mode = false;
    char *bloom_file = NULL;
    char *input_pubkey = NULL;
    // Current search configuration
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
    char last_operation[4];
    std::vector<int> subtraction_positions;
    std::vector<Point> all_points;  // For debug mode
};

// Thread work structure
struct ThreadWork {
    int thread_id;
    Point start_point;
    Int start_key;
    volatile bool *found;
    PathState *result_path;
    pthread_mutex_t *result_mutex;
    volatile int *valid_paths_for_current_config;
    volatile int *current_steps;
    pthread_mutex_t *config_mutex;
    volatile bool *debug_path_printed;
};

// Bloom filter structures
struct bloom *bloom_filters = NULL;
struct bloom *bloom_filters_2nd = NULL;
struct bloom *bloom_filters_3rd = NULL;
pthread_mutex_t *bloom_mutexes = NULL;
bool bloom_initialized = false;
size_t total_entries = 0;
int num_filters = 256;

// Global variables
Secp256K1 *secp;
Config config;
volatile bool key_found = false;
volatile int global_valid_paths_current_config = 0;
volatile int global_current_steps = 0;
volatile bool debug_path_printed = false;
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

// Current state for display
PathState current_display_state;
char input_pubkey_compressed[67];

// Random number generator
std::mt19937 rng;
std::random_device rd;

// Function declarations
void init_secp256k1();
void init_generator();
bool init_bloom_filters(const char *filename);
bool check_bloom_filters(Point &point);
void *path_finder_thread(void *arg);
Point ScalarMultiplication_fast(Secp256K1 &secp, Point &P, Int *m);
void handle_interrupt(int sig);
void save_found_path(const PathState &path, const char *pubkey);
void cleanup();
Point compute_point_half(Point &P);
void update_display(const PathState &state, int target_steps, int target_subs, int target_divs);
bool build_path_with_config(PathState &state, Point start_point, int target_steps, int target_subs, int target_divs, int thread_id);
void print_debug_path(const PathState &state);

// Optimized scalar multiplication using the working algorithm
Point ScalarMultiplication_fast(Secp256K1 &secp, Point &P, Int *m) {
    Point Q, R, T;
    Q.Clear();
    R.Clear();
    T.Clear();
    
    int no_of_bits = m->GetBitLength();
    
    // Initialize R to zero (point at infinity)
    R.x.SetInt32(0);
    R.y.SetInt32(0);
    R.z.SetInt32(0);
    
    if (!m->IsZero()) {
        // Q = P (already normalized)
        Q = P;
        
        // If bit 0 is set, R = P
        if (m->GetBit(0) == 1) {
            R = P;
        }
        
        // Process remaining bits using optimized operations
        for (int loop = 1; loop < no_of_bits; loop++) {
            // Q = 2*Q using optimized DoubleDirect
            if (Q.z.IsOne()) {
                Q = secp.DoubleDirect(Q);
            } else {
                Q = secp.Double(Q);
            }
            
            // If bit is set, add Q to R
            if (m->GetBit(loop) == 1) {
                if (R.isZero()) {
                    R = Q;
                } else {
                    // Use optimized addition when possible
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

// Initialize secp256k1 with optimizations
void init_secp256k1() {
    secp = new Secp256K1();
    secp->Init();
    init_generator();
    
    // Initialize the inverse of 2
    INVERSE_OF_2.SetBase16("7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a1");
}

// Initialize generator points for optimization
void init_generator() {
    Int one;
    one.SetInt32(1);
    Point G = secp->ComputePublicKey(&one);
    
    // Pre-compute small multiples of G
    Gn.reserve(CPU_GRP_SIZE / 2);
    Gn.push_back(G);
    Point g = secp->DoubleDirect(G);
    Gn.push_back(g);
    
    for (int i = 2; i < CPU_GRP_SIZE / 2; i++) {
        g = secp->AddDirect(g, G);
        Gn.push_back(g);
    }
    _2Gn = secp->DoubleDirect(Gn[CPU_GRP_SIZE / 2 - 1]);
    
    // Pre-compute negative multiples for subtraction
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
}

Point compute_point_half(Point &P) {
    Point result = ScalarMultiplication_fast(*secp, P, &INVERSE_OF_2);
    result.Reduce();
    return result;
}

// Initialize bloom filters from binary file
bool init_bloom_filters(const char *filename) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        fprintf(stderr, "[E] Cannot open bloom file %s\n", filename);
        return false;
    }
    
    // Get file size
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    // Check if binary format (33 bytes per compressed pubkey)
    if (file_size % COMPRESSED_PUBKEY_SIZE != 0) {
        fprintf(stderr, "[E] Invalid binary file size\n");
        fclose(file);
        return false;
    }
    
    total_entries = file_size / COMPRESSED_PUBKEY_SIZE;
    printf("[+] Loading %zu public keys from binary file\n", total_entries);
    
    // Adjust number of bloom filters based on total entries
    double fp_rate = BLOOM_FP_RATE;
    
    if (total_entries < 10000) {
        num_filters = 16;
        fp_rate = 0.0001;
    } else if (total_entries < 100000) {
        num_filters = 64;
        fp_rate = 0.00001;
    }
    
    // Allocate bloom filters
    bloom_filters = (struct bloom*)calloc(num_filters, sizeof(struct bloom));
    bloom_filters_2nd = (struct bloom*)calloc(num_filters, sizeof(struct bloom));
    bloom_filters_3rd = (struct bloom*)calloc(num_filters, sizeof(struct bloom));
    bloom_mutexes = (pthread_mutex_t*)calloc(num_filters, sizeof(pthread_mutex_t));
    
    if (!bloom_filters || !bloom_filters_2nd || !bloom_filters_3rd || !bloom_mutexes) {
        fprintf(stderr, "[E] Memory allocation failed\n");
        fclose(file);
        return false;
    }
    
    // Initialize bloom filters with optimal parameters
    size_t items_per_filter = (total_entries / num_filters) + 1;
    if (items_per_filter < 100) {
        items_per_filter = 100;
    }
    
    for (int i = 0; i < num_filters; i++) {
        pthread_mutex_init(&bloom_mutexes[i], NULL);
        if (bloom_init2(&bloom_filters[i], items_per_filter, fp_rate) != 0 ||
            bloom_init2(&bloom_filters_2nd[i], items_per_filter, fp_rate) != 0 ||
            bloom_init2(&bloom_filters_3rd[i], items_per_filter, fp_rate) != 0) {
            fprintf(stderr, "[E] Failed to initialize bloom filter %d\n", i);
            fclose(file);
            return false;
        }
    }
    
    // Load keys into bloom filters
    unsigned char buffer[COMPRESSED_PUBKEY_SIZE];
    unsigned char x_coord[32];
    size_t loaded = 0;
    
    while (fread(buffer, 1, COMPRESSED_PUBKEY_SIZE, file) == COMPRESSED_PUBKEY_SIZE) {
        // Extract X coordinate (skip first byte)
        memcpy(x_coord, buffer + 1, 32);
        
        // Add to bloom filters
        int idx = buffer[1] % num_filters;
        bloom_add(&bloom_filters[idx], (char*)x_coord, PUBKEY_PREFIX_LENGTH);
        
        XXH64_hash_t hash = XXH64(x_coord, 32, 0x1234);
        bloom_add(&bloom_filters_2nd[idx], (char*)&hash, sizeof(hash));
        
        hash = XXH64(x_coord, 32, 0x5678);
        bloom_add(&bloom_filters_3rd[idx], (char*)&hash, sizeof(hash));
        
        loaded++;
    }
    
    fclose(file);
    
    printf("[+] Successfully loaded %zu keys into bloom filters\n", loaded);
    bloom_initialized = true;
    return true;
}

// Check bloom filters
bool check_bloom_filters(Point &point) {
    if (!bloom_initialized) return false;
    
    unsigned char x_bytes[32];
    point.x.Get32Bytes(x_bytes);
    
    int idx = x_bytes[0] % num_filters;
    
    // First bloom filter check
    if (!bloom_check(&bloom_filters[idx], (char*)x_bytes, PUBKEY_PREFIX_LENGTH)) {
        return false;
    }
    
    // Second bloom filter check
    XXH64_hash_t hash1 = XXH64(x_bytes, 32, 0x1234);
    if (!bloom_check(&bloom_filters_2nd[idx], (char*)&hash1, sizeof(hash1))) {
        return false;
    }
    
    // Third bloom filter check
    XXH64_hash_t hash2 = XXH64(x_bytes, 32, 0x5678);
    if (!bloom_check(&bloom_filters_3rd[idx], (char*)&hash2, sizeof(hash2))) {
        return false;
    }
    
    return true;
}

// Update display with current state showing progress
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
           global_valid_paths_current_config, PATHS_PER_CONFIG);
    fflush(stdout);
    pthread_mutex_unlock(&print_mutex);
}

// Print debug path with all public keys
void print_debug_path(const PathState &state) {
    pthread_mutex_lock(&print_mutex);
    printf("\n\n=== DEBUG PATH ANALYSIS ===\n");
    printf("Total Steps: %d (Divisions: %d, Subtractions: %d)\n", 
           state.total_steps, state.divisions, state.subtractions);
    printf("Path: %s\n\n", state.path);
    
    // Print all public keys if stored
    if (config.debug_mode && state.all_points.size() > 0) {
        printf("All Public Keys in Path:\n");
        char hex[67];
        bool compressed = true;
        
        // Parse path to show operation with each key
        const char *p = state.path;
        int op_index = 0;
        
        // Show starting key
        Point start = state.all_points[0];
        secp->GetPublicKeyHex(compressed, start, hex);
        printf("START: %s\n", hex);
        
        // Show each operation result
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

// Build a path with exact configuration (with real-time display for thread 0)
bool build_path_with_config(PathState &state, Point start_point, int target_steps, int target_subs, int target_divs, int thread_id) {
    state.current_point = start_point;
    state.divisions = 0;
    state.subtractions = 0;
    state.total_steps = 0;
    strcpy(state.path, "");
    strcpy(state.last_operation, "START");
    state.subtraction_positions.clear();
    state.all_points.clear();
    
    // Store starting point for debug
    if (config.debug_mode) {
        state.all_points.push_back(start_point);
    }
    
    // Validate configuration
    if (target_subs + target_divs != target_steps) {
        return false;
    }
    
    // Show initial state for thread 0
    if (thread_id == 0) {
        update_display(state, target_steps, target_subs, target_divs);
    }
    
    // Generate a valid random sequence where subtractions are always followed by divisions
    std::vector<int> operations;
    
    // We need to place target_subs subtractions, each MUST be followed by a division
    // So we need at least target_subs divisions for this to work
    if (target_subs > target_divs) {
        return false;  // Impossible configuration
    }
    
    // Build the sequence
    operations.clear();
    
    // First, create pairs of (-1, /2) for each subtraction
    std::vector<std::pair<int, int>> sub_div_pairs;
    for (int i = 0; i < target_subs; i++) {
        sub_div_pairs.push_back({0, 1});  // 0 = subtraction, 1 = division
    }
    
    // We have target_divs - target_subs extra divisions to place
    int extra_divisions = target_divs - target_subs;
    
    // Generate random positions for subtraction-division pairs and extra divisions
    std::vector<int> positions;
    for (int i = 0; i < target_subs + extra_divisions; i++) {
        positions.push_back(i);
    }
    std::shuffle(positions.begin(), positions.end(), rng);
    
    // Build final sequence
    operations.resize(target_steps, -1);
    
    // Place the subtraction-division pairs
    for (int i = 0; i < target_subs; i++) {
        int pos = positions[i] * 2;  // Each pair takes 2 positions
        if (pos + 1 < target_steps) {
            operations[pos] = 0;      // subtraction
            operations[pos + 1] = 1;  // division (must follow)
        }
    }
    
    // Fill remaining positions with extra divisions
    int fill_index = 0;
    for (int i = 0; i < target_steps; i++) {
        if (operations[i] == -1) {
            operations[i] = 1;  // division
        }
    }
    
    // Alternative approach: build sequence step by step
    operations.clear();
    int subs_remaining = target_subs;
    int divs_remaining = target_divs;
    bool last_was_subtraction = false;
    
    while (operations.size() < target_steps) {
        if (last_was_subtraction) {
            // MUST add a division
            operations.push_back(1);
            divs_remaining--;
            last_was_subtraction = false;
        } else {
            // Can add either, but check constraints
            if (subs_remaining == 0) {
                // No more subtractions, must add division
                operations.push_back(1);
                divs_remaining--;
            } else if (divs_remaining == 0) {
                // No more divisions - this shouldn't happen with valid config
                return false;
            } else {
                // Choose randomly between subtraction and division
                // But ensure we can still place all remaining subtractions
                int steps_left = target_steps - operations.size();
                int min_steps_needed_for_subs = subs_remaining * 2;  // Each sub needs a following div
                
                if (min_steps_needed_for_subs > steps_left) {
                    // Must start placing subtractions now
                    operations.push_back(0);
                    subs_remaining--;
                    last_was_subtraction = true;
                } else {
                    // Random choice
                    if (rng() % 2 == 0 && subs_remaining > 0) {
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
    
    // Execute operations with periodic display updates
    int update_frequency = (target_steps > 100) ? target_steps / 20 : 5;
    
    for (int i = 0; i < target_steps; i++) {
        if (operations[i] == 0) {  // Subtraction
            Point sub = GSn[0]; // -G
            state.current_point = secp->AddDirect(state.current_point, sub);
            strcat(state.path, "-1,");
            strcpy(state.last_operation, "-1");
            state.subtractions++;
            state.total_steps++;
            state.subtraction_positions.push_back(state.total_steps - 1);
            
        } else if (operations[i] == 1) {  // Division
            Point half = compute_point_half(state.current_point);
            state.current_point = half;
            strcat(state.path, "/2,");
            strcpy(state.last_operation, "/2");
            state.divisions++;
            state.total_steps++;
        }
        
        // Store point for debug
        if (config.debug_mode) {
            state.all_points.push_back(state.current_point);
        }
        
        // Update display periodically for thread 0
        if (thread_id == 0 && state.total_steps > 0 && 
            (state.total_steps % update_frequency == 0 || i == target_steps - 1)) {
            update_display(state, target_steps, target_subs, target_divs);
            usleep(1000); // Small delay to make progress visible (1ms)
        }
    }
    
    // Final display update for thread 0
    if (thread_id == 0) {
        update_display(state, target_steps, target_subs, target_divs);
    }
    
    // Verify we achieved the target
    bool success = (state.divisions == target_divs && 
                    state.subtractions == target_subs && 
                    state.total_steps == target_steps);
    
    return success;
}

// Path finder thread with systematic search
void *path_finder_thread(void *arg) {
    ThreadWork *work = (ThreadWork*)arg;
    PathState state;
    bool compressed = true;
    int paths_attempted = 0;
    int paths_built = 0;
    int paths_in_current_config = 0;
    
    while (!*work->found) {
        // Get current configuration
        pthread_mutex_lock(work->config_mutex);
        int current_steps = *work->current_steps;
        int current_valid_paths = *work->valid_paths_for_current_config;
        
        // Skip if we already have enough paths for this configuration
        if (current_valid_paths >= PATHS_PER_CONFIG) {
            pthread_mutex_unlock(work->config_mutex);
            usleep(1000); // Wait for configuration to change
            continue;
        }
        pthread_mutex_unlock(work->config_mutex);
        
        // Calculate subtractions based on steps and divisions
        int current_subs = current_steps - config.min_divisions;
        
        // Check if we've exceeded limits
        if (current_steps > config.max_steps) {
            // Reset to beginning
            pthread_mutex_lock(work->config_mutex);
            if (*work->current_steps > config.max_steps) {  // Double check
                *work->current_steps = config.min_steps;
                *work->valid_paths_for_current_config = 0;
                global_valid_paths_current_config = 0;
                paths_in_current_config = 0;
                
                pthread_mutex_lock(&print_mutex);
                printf("\n[!] Completed full search range. Restarting from beginning...\n");
                pthread_mutex_unlock(&print_mutex);
            }
            pthread_mutex_unlock(work->config_mutex);
            continue;
        }
        
        // Build a path with current configuration
        bool path_built = build_path_with_config(state, work->start_point, 
                                                 current_steps, current_subs, 
                                                 config.min_divisions, work->thread_id);
        paths_attempted++;
        
        if (!path_built) {
            continue;
        }
        
        paths_built++;
        paths_in_current_config++;
        
        // Debug: Show first operation of every 10th path to verify randomness
        if (work->thread_id == 0 && paths_built % 10 == 0) {
            pthread_mutex_lock(&print_mutex);
            printf("\n[Path %d] First ops: %.20s...\n", paths_built, state.path);
            pthread_mutex_unlock(&print_mutex);
        }
        
        // Debug mode: print one random path from first 10
        if (config.debug_mode && !*work->debug_path_printed && 
            paths_in_current_config >= 5 && paths_in_current_config <= 10) {
            // 50% chance to print this path
            if (rand() % 2 == 0) {
                pthread_mutex_lock(work->config_mutex);
                if (!*work->debug_path_printed) {
                    *work->debug_path_printed = true;
                    pthread_mutex_unlock(work->config_mutex);
                    print_debug_path(state);
                } else {
                    pthread_mutex_unlock(work->config_mutex);
                }
            }
        }
        
        // Check bloom filter
        if (check_bloom_filters(state.current_point)) {
            pthread_mutex_lock(work->result_mutex);
            if (!*work->found) {
                *work->found = true;
                *work->result_path = state;
                key_found = true;
                
                // Final display - any thread can show this
                char final_hex[67];
                Point final_point = state.current_point;
                secp->GetPublicKeyHex(compressed, final_point, final_hex);
                
                pthread_mutex_lock(&print_mutex);
                printf("\n[!] MATCH FOUND by Thread %d!\n", work->thread_id);
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
        
        // Successfully built a path - count it for configuration
        pthread_mutex_lock(work->config_mutex);
        
        // Re-check current configuration and counter
        if (*work->current_steps == current_steps && 
            *work->valid_paths_for_current_config < PATHS_PER_CONFIG) {
            
            // Increment counter
            (*work->valid_paths_for_current_config)++;
            global_valid_paths_current_config = *work->valid_paths_for_current_config;
            int new_valid_count = *work->valid_paths_for_current_config;
            
            // Check if we've completed this configuration
            if (new_valid_count >= PATHS_PER_CONFIG) {
                // Move to next configuration
                (*work->current_steps)++;
                *work->valid_paths_for_current_config = 0;
                global_valid_paths_current_config = 0;
                paths_in_current_config = 0;
                *work->debug_path_printed = false;  // Reset for next config
                
                int new_steps = *work->current_steps;
                int new_subs = new_steps - config.min_divisions;
                
                pthread_mutex_lock(&print_mutex);
                printf("\n[+] Moving to: Steps=%d, Subtractions=%d, Divisions=%d\n", 
                       new_steps, new_subs, config.min_divisions);
                pthread_mutex_unlock(&print_mutex);
            }
        }
        
        pthread_mutex_unlock(work->config_mutex);
        
        // Small delay to prevent CPU spinning
        usleep(10);  // 0.01ms delay
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
        fprintf(file, "Path: %s\n", path.path);
        fprintf(file, "Total Steps: %d\n", path.total_steps);
        fprintf(file, "Divisions: %d\n", path.divisions);
        fprintf(file, "Subtractions: %d\n", path.subtractions);
        
        // Show subtraction positions
        fprintf(file, "Subtraction positions: ");
        for (int pos : path.subtraction_positions) {
            fprintf(file, "%d ", pos);
        }
        fprintf(file, "\n");
        
        // Calculate division percentage
        double div_pct = (path.divisions * 100.0) / path.total_steps;
        fprintf(file, "Division %%: %.2f\n\n", div_pct);
        fclose(file);
    }
}

// Signal handler for clean shutdown
void handle_interrupt(int sig) {
    printf("\n[!] Received interrupt signal. Shutting down...\n");
    key_found = true;
    cleanup();
    exit(0);
}

// Cleanup resources
void cleanup() {
    if (bloom_initialized && bloom_filters) {
        for (int i = 0; i < num_filters; i++) {
            if (bloom_filters[i].ready) bloom_free(&bloom_filters[i]);
            if (bloom_filters_2nd && bloom_filters_2nd[i].ready) bloom_free(&bloom_filters_2nd[i]);
            if (bloom_filters_3rd && bloom_filters_3rd[i].ready) bloom_free(&bloom_filters_3rd[i]);
            pthread_mutex_destroy(&bloom_mutexes[i]);
        }
        free(bloom_filters);
        free(bloom_filters_2nd);
        free(bloom_filters_3rd);
        free(bloom_mutexes);
    }
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
        printf("  -p <paths>      Max paths per level (default: 5)\n");
        printf("  -w              Save all paths to file\n");
        printf("  -B              Debug mode - print sample path\n");
        return 1;
    }
    
    // Parse arguments
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
            config.max_paths_per_level = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-w") == 0) {
            config.save_paths = true;
        } else if (strcmp(argv[i], "-B") == 0) {
            config.debug_mode = true;
        }
    }
    
    if (!config.bloom_file) {
        fprintf(stderr, "[E] Bloom filter file required (-f)\n");
        return 1;
    }
    
    // Initialize random seed
    srand(time(NULL));
    rng.seed(rd());
    
    // Initialize search configuration
    config.current_steps = config.min_steps;
    global_current_steps = config.min_steps;
    
    // Calculate initial subtractions
    int initial_subs = config.min_steps - config.min_divisions;
    
    // Initialize
    printf("[+] Fast Division Path Finder v1.0 - Systematic Search\n");
    printf("[+] Threads: %d\n", config.num_threads);
    printf("[+] Steps: %d-%d\n", config.min_steps, config.max_steps);
    printf("[+] Divisions: %d (fixed)\n", config.min_divisions);
    printf("[+] Starting subtractions: %d (steps - divisions)\n", initial_subs);
    printf("[+] Paths per configuration: %d\n", PATHS_PER_CONFIG);
    if (config.debug_mode) {
        printf("[+] Debug mode enabled - will print sample path\n");
    }
    
    // Set up signal handler
    signal(SIGINT, handle_interrupt);
    
    // Initialize secp256k1
    init_secp256k1();
    
    // Parse input public key
    Point input_point;
    bool compressed;
    if (!secp->ParsePublicKeyHex(config.input_pubkey, input_point, compressed)) {
        fprintf(stderr, "[E] Invalid public key\n");
        return 1;
    }
    
    // Store compressed version of input pubkey
    strcpy(input_pubkey_compressed, config.input_pubkey);
    
    printf("[+] Input public key: %s\n", config.input_pubkey);
    
    // Load bloom filters
    if (!init_bloom_filters(config.bloom_file)) {
        fprintf(stderr, "[E] Failed to initialize bloom filters\n");
        return 1;
    }
    
    // Start timing
    start_time = time(NULL);
    
    // Create thread pool
    pthread_t *threads = (pthread_t*)malloc(config.num_threads * sizeof(pthread_t));
    ThreadWork *thread_work = (ThreadWork*)malloc(config.num_threads * sizeof(ThreadWork));
    PathState result_path;
    pthread_mutex_t result_mutex = PTHREAD_MUTEX_INITIALIZER;
    
    // Launch threads
    printf("[+] Starting systematic search with %d threads...\n", config.num_threads);
    printf("[+] Starting at: Steps=%d, Subtractions=%d, Divisions=%d\n\n",
           config.current_steps, initial_subs, config.min_divisions);
    
    for (int i = 0; i < config.num_threads; i++) {
        thread_work[i].thread_id = i;
        thread_work[i].start_point = input_point;
        thread_work[i].start_key.SetInt32(0);
        thread_work[i].found = &key_found;
        thread_work[i].result_path = &result_path;
        thread_work[i].result_mutex = &result_mutex;
        thread_work[i].valid_paths_for_current_config = &global_valid_paths_current_config;
        thread_work[i].current_steps = &global_current_steps;
        thread_work[i].config_mutex = &config_mutex;
        thread_work[i].debug_path_printed = &debug_path_printed;
        
        pthread_create(&threads[i], NULL, path_finder_thread, &thread_work[i]);
    }
    
    // Wait for threads
    for (int i = 0; i < config.num_threads; i++) {
        pthread_join(threads[i], NULL);
    }
    
    // Results
    if (key_found) {
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
    
    // Timing
    time_t end_time = time(NULL);
    printf("[+] Time elapsed: %ld seconds\n", end_time - start_time);
    
    // Cleanup
    free(threads);
    free(thread_work);
    pthread_mutex_destroy(&result_mutex);
    pthread_mutex_destroy(&config_mutex);
    cleanup();
    
    return 0;
}
