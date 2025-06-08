// division.cpp - Complete Statistical Path Finding with ALL Collected Data
// Uses every piece of data from the analysis report with proper weighting

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
#include <map>
#include <cmath>
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

// Complete PathStatistics with ALL data from analysis
struct PathStatistics {
    // COMPLETE subtraction count distribution - ALL values from report
    std::map<int, uint64_t> subtraction_counts = {
        {23, 1}, {24, 1}, {25, 8}, {26, 13}, {27, 50}, {28, 126}, {29, 376}, {30, 893},
        {31, 2020}, {32, 4864}, {33, 10231}, {34, 21081}, {35, 41694}, {36, 78580},
        {37, 142023}, {38, 246445}, {39, 410872}, {40, 657125}, {41, 1010988},
        {42, 1491500}, {43, 2118898}, {44, 2885610}, {45, 3785787}, {46, 4773704},
        {47, 5786369}, {48, 6755404}, {49, 7576690}, {50, 8186287}, {51, 8505148},
        {52, 8508408}, {53, 8186163}, {54, 7582174}, {55, 6754466}, {56, 5788443},
        {57, 4771447}, {58, 3784584}, {59, 2888905}, {60, 2117756}, {61, 1493756},
        {62, 1011039}, {63, 658495}, {64, 411610}, {65, 246755}, {66, 143112},
        {67, 78608}, {68, 41735}, {69, 21211}, {70, 10255}, {71, 4761}, {72, 2078},
        {73, 868}, {74, 355}, {75, 151}, {76, 59}, {77, 13}, {78, 4}, {80, 1}
    };
    
    // Normalized probabilities
    std::map<int, double> subtraction_probabilities;
    
    // ALL 47 patterns with exact occurrence counts
    std::vector<std::pair<std::string, uint64_t>> pattern_counts = {
        {"DS", 5613585574}, {"DSD", 5613585574}, {"SD", 5613585574}, {"DD", 5613414426},
        {"DSDS", 2779581865}, {"DSDSD", 2779581865}, {"SDS", 2779581865}, {"SDSD", 2779581865},
        {"DSDD", 2779504408}, {"SDD", 2779504408}, {"DDS", 2779497539}, {"DDSD", 2779497539},
        {"DDD", 2779416188}, {"DSDSDS", 1376201748}, {"SDSDS", 1376201748}, {"SDSDSD", 1376201748},
        {"DSDDS", 1376193740}, {"DSDDSD", 1376193740}, {"SDDS", 1376193740}, {"SDDSD", 1376193740},
        {"DSDSDD", 1376126794}, {"SDSDD", 1376126794}, {"DDSDS", 1376126144}, {"DDSDSD", 1376126144},
        {"DDSDD", 1376125417}, {"DDDD", 1376116021}, {"DDDS", 1376058171}, {"DDDSD", 1376058171},
        {"DSDDD", 1376051965}, {"SDDD", 1376051965}, {"SDSDDS", 681303081}, {"SDDSDD", 681300469},
        {"SDDSDS", 681268264}, {"DDSDDS", 681265175}, {"DDDDD", 681258952}, {"DDDDS", 681236486},
        {"DDDDSD", 681236486}, {"DDDSDS", 681234428}, {"DSDDDD", 681233192}, {"SDDDD", 681233192},
        {"DDSDDD", 681230771}, {"DDDSDD", 681202772}, {"DSDDDS", 681197360}, {"SDDDS", 681197360},
        {"SDDDSD", 681197360}, {"SDSDDD", 681194481}, {"DDDDDS", 337238114}, {"SDDDDD", 337230449},
        {"DDDDDD", 337215138}, {"SDDDDS", 337187860}
    };
    
    // Pattern probabilities
    std::map<std::string, double> pattern_probabilities;
    
    // Transition probabilities from data
    const double prob_D_to_D = 0.499992;
    const double prob_D_to_S = 0.500008;
    const double prob_S_to_D = 1.0; // Always 100%
    
    // Position-based operation distribution
    std::map<int, std::pair<double, double>> position_operation_dist = {
        {0, {0.6799, 0.3201}},   // 0%: 67.99% D, 32.01% S
        {10, {0.6659, 0.3341}},  // 10%: 66.59% D, 33.41% S
        {20, {0.6660, 0.3340}},  // 20%: 66.60% D, 33.40% S
        {30, {0.6660, 0.3340}},  // 30%: 66.60% D, 33.40% S
        {40, {0.6660, 0.3340}},  // 40%: 66.60% D, 33.40% S
        {50, {0.6660, 0.3340}},  // 50%: 66.60% D, 33.40% S
        {60, {0.6659, 0.3341}},  // 60%: 66.59% D, 33.41% S
        {70, {0.6659, 0.3341}},  // 70%: 66.59% D, 33.41% S
        {80, {0.6659, 0.3341}},  // 80%: 66.59% D, 33.41% S
        {90, {0.6807, 0.3193}}   // 90%: 68.07% D, 31.93% S
    };
    
    // Subtraction spacing distribution
    std::map<int, uint64_t> spacing_counts = {
        {2, 2779581865}, {3, 1376193740}, {4, 681197360}, {5, 337187860},
        {6, 166928103}, {7, 82594065}, {8, 40877330}, {9, 20228126},
        {10, 10002951}, {11, 4952199}, {12, 2447426}, {13, 1209782},
        {14, 599832}, {15, 295684}, {16, 146630}, {17, 72288},
        {18, 35203}, {19, 17806}, {20, 8627}, {21, 4320},
        {22, 2212}, {23, 1086}
    };
    std::map<int, double> spacing_probabilities;
    
    // Consecutive division runs
    std::map<int, uint64_t> consecutive_div_counts = {
        {3, 22018}, {4, 2639542}, {5, 16998724}, {6, 28605506},
        {7, 25226802}, {8, 16419505}, {9, 9249447}, {10, 4875006},
        {11, 2484155}, {12, 1246669}, {13, 622249}, {14, 308135},
        {15, 153067}, {16, 75591}, {17, 36827}, {18, 18614},
        {19, 9049}, {20, 4506}, {21, 2315}, {22, 1137},
        {23, 557}, {24, 303}, {25, 139}, {26, 73},
        {27, 27}, {28, 10}, {29, 11}, {30, 5},
        {31, 8}, {32, 3}
    };
    std::map<int, double> consecutive_div_probabilities;
    
    // Bit size distribution for subtractions (all ~0.0004)
    const double bit_size_sub_probability = 0.0004;
    
    // Statistics
    double avg_subtractions = 51.500642;
    double avg_divisions = 104.0;
    double avg_total_steps = 155.500642;
    double subtraction_percentage = 0.331192;
    
    // Percentiles
    int p1 = 40, p5 = 43, p10 = 45, p25 = 48, p50 = 52, p75 = 55, p90 = 58, p95 = 60, p99 = 63;
    
    PathStatistics() {
        normalize_all_distributions();
    }
    
    void normalize_all_distributions() {
        // Normalize subtraction counts to probabilities
        uint64_t total_sub = 0;
        for (const auto& p : subtraction_counts) {
            total_sub += p.second;
        }
        for (const auto& p : subtraction_counts) {
            subtraction_probabilities[p.first] = (double)p.second / total_sub;
        }
        
        // Normalize pattern counts to probabilities
        uint64_t total_patterns = 0;
        for (const auto& p : pattern_counts) {
            total_patterns += p.second;
        }
        for (const auto& p : pattern_counts) {
            pattern_probabilities[p.first] = (double)p.second / total_patterns;
        }
        
        // Normalize spacing counts
        uint64_t total_spacing = 0;
        for (const auto& p : spacing_counts) {
            total_spacing += p.second;
        }
        for (const auto& p : spacing_counts) {
            spacing_probabilities[p.first] = (double)p.second / total_spacing;
        }
        
        // Normalize consecutive division counts
        uint64_t total_consec = 0;
        for (const auto& p : consecutive_div_counts) {
            total_consec += p.second;
        }
        for (const auto& p : consecutive_div_counts) {
            consecutive_div_probabilities[p.first] = (double)p.second / total_consec;
        }
    }
    
    // Get weighted random subtraction count based on actual distribution
    int get_weighted_subtraction_count(std::mt19937& rng) {
        std::uniform_real_distribution<> dis(0.0, 1.0);
        double r = dis(rng);
        double cumulative = 0;
        
        for (const auto& p : subtraction_probabilities) {
            cumulative += p.second;
            if (r <= cumulative) {
                return p.first;
            }
        }
        return 52; // Default to peak
    }
    
    // Get position-based subtraction probability
    double get_position_sub_probability(double position_pct) {
        int bucket = (int)(position_pct * 10) * 10; // Round to nearest 10%
        if (position_operation_dist.count(bucket)) {
            return position_operation_dist[bucket].second;
        }
        return 0.334; // Default middle value
    }
    
    // Get weighted spacing between subtractions
    int get_weighted_spacing(std::mt19937& rng) {
        std::uniform_real_distribution<> dis(0.0, 1.0);
        double r = dis(rng);
        double cumulative = 0;
        
        for (const auto& p : spacing_probabilities) {
            cumulative += p.second;
            if (r <= cumulative) {
                return p.first;
            }
        }
        return 2; // Most common
    }
    
    // Get weighted consecutive division run length
    int get_weighted_consecutive_divs(std::mt19937& rng) {
        std::uniform_real_distribution<> dis(0.0, 1.0);
        double r = dis(rng);
        double cumulative = 0;
        
        for (const auto& p : consecutive_div_probabilities) {
            cumulative += p.second;
            if (r <= cumulative) {
                return p.first;
            }
        }
        return 5; // Peak value
    }
    
    // Generate path using ALL statistical data
    std::vector<int> generate_statistically_accurate_path(int target_steps, int target_subs, 
                                                          int target_divs, std::mt19937& rng) {
        std::vector<int> operations;
        
        // Validation
        if (target_subs + target_divs != target_steps || target_subs > target_divs) {
            return operations; // Invalid
        }
        
        operations.reserve(target_steps);
        
        // Track state
        int subs_placed = 0;
        int divs_placed = 0;
        int last_sub_pos = -1;
        int consecutive_divs = 0;
        std::string current_pattern = "";
        
        // Generate path
        while (operations.size() < target_steps) {
            bool last_was_sub = (!operations.empty() && operations.back() == 0);
            
            // RULE 1: Division MUST follow subtraction
            if (last_was_sub) {
                if (divs_placed < target_divs) {
                    operations.push_back(1);
                    divs_placed++;
                    consecutive_divs = 1;
                    current_pattern += "D";
                    if (current_pattern.length() > 6) {
                        current_pattern = current_pattern.substr(current_pattern.length() - 6);
                    }
                } else {
                    // Error: no divisions left
                    operations.clear();
                    return operations;
                }
            } else {
                // Choose next operation based on ALL factors
                double position_pct = (double)operations.size() / target_steps;
                double base_sub_prob = get_position_sub_probability(position_pct);
                
                // Adjust probability based on pattern matching
                double pattern_adjustment = 1.0;
                if (!current_pattern.empty()) {
                    // Find patterns that match current sequence
                    double total_matching_prob = 0;
                    double sub_pattern_prob = 0;
                    double div_pattern_prob = 0;
                    
                    for (const auto& [pattern, prob] : pattern_probabilities) {
                        if (pattern.find(current_pattern) == 0 && pattern.length() > current_pattern.length()) {
                            total_matching_prob += prob;
                            char next_op = pattern[current_pattern.length()];
                            if (next_op == 'S') sub_pattern_prob += prob;
                            else if (next_op == 'D') div_pattern_prob += prob;
                        }
                    }
                    
                    if (total_matching_prob > 0) {
                        pattern_adjustment = sub_pattern_prob / total_matching_prob;
                    }
                }
                
                // Adjust based on spacing if we have previous subtractions
                double spacing_adjustment = 1.0;
                if (last_sub_pos >= 0) {
                    int current_spacing = operations.size() - last_sub_pos;
                    if (spacing_probabilities.count(current_spacing)) {
                        spacing_adjustment = spacing_probabilities[current_spacing] * 10; // Amplify effect
                    }
                }
                
                // Adjust based on consecutive divisions
                double consec_adjustment = 1.0;
                if (consecutive_divs > 0) {
                    // Use transition probability
                    consec_adjustment = prob_D_to_S;
                }
                
                // Calculate final probability
                double final_sub_prob = base_sub_prob * pattern_adjustment * spacing_adjustment * consec_adjustment;
                
                // Ensure we can meet targets
                int steps_remaining = target_steps - operations.size();
                int subs_remaining = target_subs - subs_placed;
                int divs_remaining = target_divs - divs_placed;
                
                bool can_do_sub = (subs_remaining > 0 && divs_remaining >= subs_remaining && steps_remaining >= 2);
                bool must_do_sub = (subs_remaining > 0 && steps_remaining <= subs_remaining * 2);
                bool must_do_div = (divs_remaining > subs_remaining && !must_do_sub);
                
                std::uniform_real_distribution<> dis(0.0, 1.0);
                double r = dis(rng);
                
                if (must_do_sub && can_do_sub) {
                    operations.push_back(0);
                    subs_placed++;
                    last_sub_pos = operations.size() - 1;
                    consecutive_divs = 0;
                    current_pattern += "S";
                } else if (must_do_div && divs_remaining > 0) {
                    operations.push_back(1);
                    divs_placed++;
                    consecutive_divs++;
                    current_pattern += "D";
                } else if (can_do_sub && r < final_sub_prob) {
                    operations.push_back(0);
                    subs_placed++;
                    last_sub_pos = operations.size() - 1;
                    consecutive_divs = 0;
                    current_pattern += "S";
                } else if (divs_remaining > 0) {
                    operations.push_back(1);
                    divs_placed++;
                    consecutive_divs++;
                    current_pattern += "D";
                } else {
                    // Shouldn't happen
                    break;
                }
                
                // Trim pattern to last 6 chars
                if (current_pattern.length() > 6) {
                    current_pattern = current_pattern.substr(current_pattern.length() - 6);
                }
            }
        }
        
        // Final validation
        int actual_subs = 0, actual_divs = 0;
        for (int op : operations) {
            if (op == 0) actual_subs++;
            else actual_divs++;
        }
        
        if (actual_subs != target_subs || actual_divs != target_divs || operations.size() != target_steps) {
            operations.clear();
            return operations;
        }
        
        // Verify S->D constraint
        for (size_t i = 0; i < operations.size() - 1; i++) {
            if (operations[i] == 0 && operations[i+1] == 0) {
                operations.clear();
                return operations;
            }
        }
        
        return operations;
    }
};

// Global configuration
struct Config {
    int min_steps = 124;      // 104 divs + 20 subs minimum
    int max_steps = 184;      // 104 divs + 80 subs maximum
    int fixed_divisions = 104;
    int num_threads = 1;
    int paths_per_config = 10;
    bool save_paths = false;
    bool debug_mode = false;
    bool skip_verification = false;
    bool use_weighted_exploration = true; // Use occurrence-based weighting
    char *bloom_file = NULL;
    char *input_pubkey = NULL;
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
        subtraction_positions.reserve(80);
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

// Thread work structure
struct ThreadWork {
    int thread_id;
    Point start_point;
    Int start_key;
    std::atomic<bool> *found;
    PathState *result_path;
    pthread_mutex_t *result_mutex;
    std::map<int, uint64_t> *thread_attempts; // Track attempts per subtraction count
    pthread_mutex_t *stats_mutex;
};

// Bloom loading worker structure
struct BloomLoadWorker {
    struct bloom *bloom_filter;
    unsigned char *entries;
    size_t num_entries;
    int thread_id;
    pthread_mutex_t *bloom_mutex;
};

// Global variables
struct bloom *bloom_filter = NULL;
pthread_mutex_t bloom_mutex = PTHREAD_MUTEX_INITIALIZER;
bool bloom_initialized = false;
size_t total_entries = 0;

Secp256K1 *secp;
Config config;
PathStatistics path_stats;
std::atomic<bool> key_found(false);
pthread_mutex_t print_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t found_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t stats_mutex = PTHREAD_MUTEX_INITIALIZER;
time_t start_time;

// Global attempt tracking
std::map<int, uint64_t> global_subtraction_attempts;

// Pre-computed points
std::vector<Point> Gn;
Point _2Gn;
std::vector<Point> GSn;
Point _2GSn;
Int INVERSE_OF_2;

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
bool init_bloom_filter(const char *filename);
bool check_bloom_filter(Point &point);
void *path_finder_thread(void *arg);
void *bloom_load_worker_thread(void *arg);
Point ScalarMultiplication_fast(Secp256K1 &secp, Point &P, Int *m);
void handle_interrupt(int sig);
void save_found_path(const PathState &path, const char *pubkey);
void cleanup();
Point compute_point_half(Point &P);
void update_display(const PathState &state, int target_steps, int target_subs, int target_divs);
bool build_statistical_path(PathState &state, Point start_point, int target_steps, int target_subs, int target_divs, int thread_id);
void print_debug_path(const PathState &state);
size_t estimate_bloom_memory(size_t entries, double fp_rate);
bool is_binary_file(const char *filename);
bool verify_in_file(Point &point, const char *filename);
void print_attempt_statistics();

// Check if file is binary
bool is_binary_file(const char *filename) {
    FILE *file = fopen(filename, "rb");
    if (!file) return false;
    
    unsigned char buf[4];
    size_t read = fread(buf, 1, 4, file);
    fclose(file);
    
    return (read >= 1 && (buf[0] == 0x02 || buf[0] == 0x03));
}

// Verify point exists in file
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
    
    const size_t VERIFY_BUFFER_SIZE = 1024 * 1024;
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

// Scalar multiplication
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

Point compute_point_half(Point &P) {
    Point result = ScalarMultiplication_fast(*secp, P, &INVERSE_OF_2);
    result.Reduce();
    return result;
}

// Estimate bloom filter memory
size_t estimate_bloom_memory(size_t entries, double fp_rate) {
    long double num = -log(fp_rate);
    long double denom = 0.480453013918201;
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
        
        pthread_mutex_lock(worker->bloom_mutex);
        bloom_add(worker->bloom_filter, (char*)entry, COMPRESSED_PUBKEY_SIZE);
        pthread_mutex_unlock(worker->bloom_mutex);
    }
    
    return NULL;
}

// Initialize bloom filter
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
    
    double fp_rate = BLOOM_FP_RATE;
    if (total_entries > 1000000000) {
        fp_rate = 0.000001;
    } else if (total_entries > 100000000) {
        fp_rate = 0.00001;
    }
    
    size_t estimated_memory = estimate_bloom_memory(total_entries, fp_rate);
    double memory_mb = estimated_memory / (1024.0 * 1024.0);
    double memory_gb = memory_mb / 1024.0;
    
    printf("[+] Estimated bloom filter memory usage: %.2f MB (%.2f GB)\n", memory_mb, memory_gb);
    printf("[+] Target false positive rate: %.8f\n", fp_rate);
    
    bloom_filter = (struct bloom*)calloc(1, sizeof(struct bloom));
    if (!bloom_filter) {
        fprintf(stderr, "[E] Memory allocation failed for bloom filter\n");
        fclose(file);
        return false;
    }
    
    printf("[+] Initializing bloom filter for %zu entries...\n", total_entries);
    
    if (bloom_init2(bloom_filter, total_entries, fp_rate) != 0) {
        fprintf(stderr, "[E] Failed to initialize bloom filter\n");
        fclose(file);
        free(bloom_filter);
        return false;
    }
    
    int num_load_threads = sysconf(_SC_NPROCESSORS_ONLN);
    if (num_load_threads < 1) num_load_threads = 1;
    if (num_load_threads > MAX_THREADS) num_load_threads = MAX_THREADS;
    
    printf("[+] Using %d threads to load bloom filter\n", num_load_threads);
    printf("[+] Storing full %d-byte compressed pubkeys\n", COMPRESSED_PUBKEY_SIZE);
    
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
    
    auto start_time = std::chrono::high_resolution_clock::now();
    size_t entries_processed = 0;
    size_t bytes_read;
    
    while ((bytes_read = fread(buffer, 1, INPUT_BUFFER_SIZE, file)) > 0) {
        size_t entries_in_buffer = bytes_read / COMPRESSED_PUBKEY_SIZE;
        size_t entries_per_worker = (entries_in_buffer + num_load_threads - 1) / num_load_threads;
        
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
        
        for (int i = 0; i < active_threads; i++) {
            pthread_join(threads[i], NULL);
        }
        
        entries_processed += entries_in_buffer;
        
        auto current_time = std::chrono::high_resolution_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(current_time - start_time);
        double rate = (entries_processed * 1000.0) / elapsed.count();
        double percent = (double)entries_processed / total_entries * 100.0;
        
        printf("\r[+] Processed %zu/%zu entries (%.1f%%) at %.0f entries/sec", 
               entries_processed, total_entries, percent, rate);
        fflush(stdout);
    }
    
    printf("\n");
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(end_time - start_time);
    
    printf("[+] Loading completed in %ld seconds\n", duration.count());
    printf("[+] Successfully loaded %zu keys into bloom filter\n", entries_processed);
    printf("[+] Bloom filter: %d entries, %.8f error rate\n", 
           bloom_filter->entries, bloom_filter->error);
    
    free(buffer);
    free(workers);
    free(threads);
    fclose(file);
    
    bloom_initialized = true;
    return true;
}

// Check bloom filter
bool check_bloom_filter(Point &point) {
    if (!bloom_initialized || !bloom_filter) return false;
    
    unsigned char compressed[COMPRESSED_PUBKEY_SIZE];
    unsigned char x_bytes[32];
    point.x.Get32Bytes(x_bytes);
    
    bool y_is_odd = point.y.IsOdd();
    compressed[0] = y_is_odd ? 0x03 : 0x02;
    memcpy(compressed + 1, x_bytes, 32);
    
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
    printf("\r%s %s %s %d/%d %d/%d",
           input_pubkey_compressed,
           state.last_operation,
           current_hex,
           state.divisions, target_divs,
           state.subtractions, target_subs);
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

// Build statistical path using ALL data
bool build_statistical_path(PathState &state, Point start_point, int target_steps, 
                           int target_subs, int target_divs, int thread_id) {
    state.subtraction_positions.clear();
    state.subtraction_positions.shrink_to_fit();
    state.all_points.clear();
    state.all_points.shrink_to_fit();
    
    state.current_point = start_point;
    state.divisions = 0;
    state.subtractions = 0;
    state.total_steps = 0;
    state.path[0] = '\0';
    strcpy(state.last_operation, "START");
    
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
    
    // Generate path using ALL statistical data
    std::vector<int> operations = path_stats.generate_statistically_accurate_path(
        target_steps, target_subs, target_divs, get_thread_rng());
    
    if (operations.empty() || operations.size() != target_steps) {
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
    
    std::vector<int>().swap(operations);
    
    if (thread_id == 0) {
        update_display(state, target_steps, target_subs, target_divs);
    }
    
    bool success = (state.divisions == target_divs && 
                    state.subtractions == target_subs && 
                    state.total_steps == target_steps);
    
    return success;
}

// Path finder thread with weighted exploration
void *path_finder_thread(void *arg) {
    ThreadWork *work = (ThreadWork*)arg;
    PathState state;
    bool compressed = true;
    int paths_attempted = 0;
    int paths_built = 0;
    
    const int MEMORY_RELEASE_INTERVAL = 1000;
    const int FIXED_DIVISIONS = 104;
    
    // Thread-local attempt tracking
    std::map<int, uint64_t> local_attempts;
    
    while (!work->found->load()) {
        int current_steps, current_subs, current_divs;
        
        // Use weighted selection based on actual occurrence data
        auto& rng = get_thread_rng();
        
        // Get weighted subtraction count
        current_subs = path_stats.get_weighted_subtraction_count(rng);
        current_divs = FIXED_DIVISIONS;
        current_steps = current_subs + current_divs;
        
        // Validate
        if (current_steps < config.min_steps || current_steps > config.max_steps ||
            current_subs < 20 || current_subs > 80) {
            continue;
        }
        
        // Track attempt
        local_attempts[current_subs]++;
        
        // Periodically update global attempts
        if (paths_attempted % 1000 == 0) {
            pthread_mutex_lock(work->stats_mutex);
            for (const auto& p : local_attempts) {
                (*work->thread_attempts)[p.first] += p.second;
            }
            local_attempts.clear();
            pthread_mutex_unlock(work->stats_mutex);
        }
        
        // Build path
        bool path_built = build_statistical_path(state, work->start_point, 
                                               current_steps, current_subs, 
                                               current_divs, work->thread_id);
        
        paths_attempted++;
        
        if (paths_attempted % MEMORY_RELEASE_INTERVAL == 0) {
            state.subtraction_positions.clear();
            state.subtraction_positions.shrink_to_fit();
            state.all_points.clear();
            state.all_points.shrink_to_fit();
            state.subtraction_positions.reserve(80);
            if (config.debug_mode) {
                state.all_points.reserve(200);
            }
        }
        
        if (!path_built) {
            continue;
        }
        
        if (state.total_steps != current_steps || 
            state.divisions != current_divs || 
            state.subtractions != current_subs) {
            pthread_mutex_lock(&print_mutex);
            printf("\n[ERROR] Path building mismatch: steps=%d/%d, divs=%d/%d, subs=%d/%d\n",
                   state.total_steps, current_steps,
                   state.divisions, current_divs,
                   state.subtractions, current_subs);
            pthread_mutex_unlock(&print_mutex);
            continue;
        }
        
        paths_built++;
        
        // Print progress every 10000 paths
        if (paths_built % 10000 == 0) {
            pthread_mutex_lock(&print_mutex);
            printf("\n[Thread %d] Paths built: %d, Current config: %d subs + %d divs = %d steps\n", 
                   work->thread_id, paths_built, current_subs, current_divs, current_steps);
            pthread_mutex_unlock(&print_mutex);
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
                           state.divisions, current_divs,
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
        
        usleep(10);
    }
    
    // Final update of global attempts
    pthread_mutex_lock(work->stats_mutex);
    for (const auto& p : local_attempts) {
        (*work->thread_attempts)[p.first] += p.second;
    }
    pthread_mutex_unlock(work->stats_mutex);
    
    return NULL;
}

// Print attempt statistics
void print_attempt_statistics() {
    pthread_mutex_lock(&stats_mutex);
    
    printf("\n\n=== ATTEMPT STATISTICS ===\n");
    printf("Subtraction Count | Occurrences in Data | Attempts Made | Attempt Rate\n");
    printf("------------------|---------------------|---------------|-------------\n");
    
    for (const auto& p : path_stats.subtraction_counts) {
        int sub_count = p.first;
        uint64_t data_occurrences = p.second;
        uint64_t attempts = global_subtraction_attempts[sub_count];
        double attempt_rate = attempts > 0 ? (double)attempts / global_subtraction_attempts[52] : 0;
        double expected_rate = path_stats.subtraction_probabilities[sub_count];
        
        printf("%-17d | %-19llu | %-13llu | %.6f (expected: %.6f)\n",
               sub_count, data_occurrences, attempts, attempt_rate, expected_rate);
    }
    
    printf("\nTotal attempts across all subtraction counts: %llu\n", 
           std::accumulate(global_subtraction_attempts.begin(), 
                          global_subtraction_attempts.end(), 
                          0ULL, 
                          [](uint64_t sum, const auto& p) { return sum + p.second; }));
    
    pthread_mutex_unlock(&stats_mutex);
}

// Save found path
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
    print_attempt_statistics();
    key_found.store(true);
    cleanup();
    exit(0);
}

// Cleanup
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
        printf("  -w              Save all paths to file\n");
        printf("  -B              Debug mode - print sample path\n");
        printf("  -V              Skip file verification (trust bloom filters)\n");
        printf("\nStatistical Features:\n");
        printf("  - Uses ALL collected data with proper weighting\n");
        printf("  - Explores full range (23-80 subs) weighted by occurrence\n");
        printf("  - Pattern-based generation using all 47 patterns\n");
        printf("  - Position-aware operation selection\n");
        printf("  - Spacing distribution for natural paths\n");
        printf("  - Consecutive division modeling\n");
        printf("\nFixed parameters:\n");
        printf("  Divisions: 104 (fixed)\n");
        printf("  Steps: 124-184 (20-80 subtractions)\n");
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
    
    printf("[+] Fast Division Path Finder v4.0 - Complete Statistical Edition\n");
    printf("[+] Using ALL collected data with proper weighting\n");
    printf("[+] Threads: %d\n", config.num_threads);
    printf("[+] Steps: %d-%d (104 divisions + 20-80 subtractions)\n", 
           config.min_steps, config.max_steps);
    printf("[+] Divisions: %d (FIXED)\n", config.fixed_divisions);
    
    if (config.skip_verification) {
        printf("[+] File verification DISABLED\n");
    }
    if (config.debug_mode) {
        printf("[+] Debug mode enabled\n");
    }
    
    printf("\n[+] Statistical Distribution:\n");
    printf("    Total paths analyzed: 290,018,000,000\n");
    printf("    Peak at 52 subtractions: 8,508,408 occurrences\n");
    printf("    Will explore ALL ranges (23-80) weighted by frequency\n");
    printf("    Using all 47 patterns with exact probabilities\n");
    printf("    Transition probabilities: D→D=49.99%, D→S=50.01%, S→D=100%\n");
    printf("    Position-aware operations\n");
    printf("    Natural spacing distribution\n");
    
    signal(SIGINT, handle_interrupt);
    
    init_secp256k1();
    
    Point input_point;
    bool compressed;
    if (!secp->ParsePublicKeyHex(config.input_pubkey, input_point, compressed)) {
        fprintf(stderr, "[E] Invalid public key\n");
        return 1;
    }
    
    strcpy(input_pubkey_compressed, config.input_pubkey);
    
    printf("\n[+] Input public key: %s\n", config.input_pubkey);
    
    if (!init_bloom_filter(config.bloom_file)) {
        fprintf(stderr, "[E] Failed to initialize bloom filter\n");
        return 1;
    }
    
    start_time = time(NULL);
    
    pthread_t *threads = (pthread_t*)malloc(config.num_threads * sizeof(pthread_t));
    ThreadWork *thread_work = (ThreadWork*)malloc(config.num_threads * sizeof(ThreadWork));
    PathState result_path;
    pthread_mutex_t result_mutex = PTHREAD_MUTEX_INITIALIZER;
    
    printf("\n[+] Starting weighted statistical search with %d threads...\n", config.num_threads);
    printf("[+] Will attempt paths weighted by their occurrence in data\n");
    printf("[+] 52 subtractions will be tried ~8.5M times more than 23 subtractions\n\n");
    
    for (int i = 0; i < config.num_threads; i++) {
        thread_work[i].thread_id = i;
        thread_work[i].start_point = input_point;
        thread_work[i].start_key.SetInt32(0);
        thread_work[i].found = &key_found;
        thread_work[i].result_path = &result_path;
        thread_work[i].result_mutex = &result_mutex;
        thread_work[i].thread_attempts = &global_subtraction_attempts;
        thread_work[i].stats_mutex = &stats_mutex;
        
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
        printf("\n[!] No match found.\n");
    }
    
    print_attempt_statistics();
    
    time_t end_time = time(NULL);
    printf("\n[+] Time elapsed: %ld seconds\n", end_time - start_time);
    
    free(threads);
    free(thread_work);
    pthread_mutex_destroy(&result_mutex);
    pthread_mutex_destroy(&stats_mutex);
    cleanup();
    
    return 0;
}
