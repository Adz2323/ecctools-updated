// division_optimized.cpp - High Performance Division Tool with Path Distribution
// Version 4.0 with systematic path coverage across all threads

#include <algorithm>
#include <atomic>
#include <chrono>
#include <climits>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <mutex>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#include <queue>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "secp256k1/SECP256k1.h"
#include "secp256k1/Point.h"
#include "secp256k1/Int.h"
#include "secp256k1/IntGroup.h"
#include "secp256k1/Random.h"
#include "bloom/bloom.h"

// Constants
constexpr size_t COMPRESSED_PUBKEY_SIZE = 33;
constexpr size_t MAX_THREADS = 257;
constexpr size_t CPU_GRP_SIZE = 1024;
constexpr double BLOOM_FP_RATE = 0.00001;
constexpr size_t BLOOM_LOAD_BUFFER = 1024 * 1024 * 10; // 10MB buffer per thread
constexpr size_t PATH_BATCH_SIZE = 256;
constexpr size_t DEFAULT_PATH_BATCH = 1000; // Default batch when rotating

// Forward declarations
struct Config;
class OptimizedBloomFilter;

// Path configuration structure
struct PathConfig {
    int total_steps;
    int divisions;
    int subtractions;
    std::atomic<uint64_t> paths_completed{0};
    std::atomic<uint64_t> paths_quota{0};
    std::atomic<int> active_threads{0};
    std::atomic<bool> quota_reached{false};
    std::mutex config_mutex;
    
    PathConfig(int steps, int divs, int subs, uint64_t quota) 
        : total_steps(steps), divisions(divs), subtractions(subs), paths_quota(quota) {}
};

// Global path configurations
std::vector<std::unique_ptr<PathConfig>> g_path_configs;
std::mutex g_config_assignment_mutex;
std::atomic<int> g_configs_completed{0};

// Live display structure - Enhanced
struct LiveDisplay {
    std::atomic<int> current_step{0};
    std::atomic<int> total_steps{0};
    std::atomic<int> current_divs{0};
    std::atomic<int> current_subs{0};
    std::atomic<uint64_t> paths_completed{0};
    std::atomic<uint64_t> paths_quota{0};
    std::string current_pubkey;
    int target_divs;
    int target_subs;
    std::mutex display_mutex;
    
    // New fields for path distribution
    std::atomic<int> active_configs{0};
    std::atomic<int> completed_configs{0};
    std::atomic<int> total_configs{0};
};

// Global live display
LiveDisplay* g_live_display = nullptr;

// Thread work structure - Enhanced
struct ThreadWork {
    int thread_id;
    PathConfig* assigned_config;  // Assigned path configuration
    uint64_t paths_completed;
    std::atomic<bool> finished;
    std::atomic<bool> should_rotate{false};
    
    // Pointers to shared resources
    Config* config_ptr;
    OptimizedBloomFilter* bloom_ptr;
    
    // Live tracking for this thread
    int current_step;
    int current_total_steps;
    int current_divs;
    int current_subs;
    std::string current_key;
    
    // Rotation tracking
    uint64_t rotation_batch_count{0};
};

// Bloom loader work structure (unchanged)
struct BloomLoadWork {
    int thread_id;
    size_t start_entry;
    size_t end_entry;
    const char* filename;
    std::atomic<bool> finished;
};

// Global thread management
pthread_mutex_t write_keys_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t result_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t stats_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t debug_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t* bloom_mutexes = nullptr;

// Global statistics
std::atomic<uint64_t> global_paths_tested(0);
std::atomic<uint64_t> global_paths_generated(0);
std::atomic<uint64_t> global_bloom_checks(0);
std::atomic<uint64_t> global_bloom_entries_loaded(0);
std::atomic<bool> solution_found(false);

// Configuration - Enhanced
struct Config {
    int min_steps = 120;
    int max_steps = 190;
    int min_divisions = 100;
    int max_divisions = 100;
    size_t num_threads = std::thread::hardware_concurrency();
    uint64_t paths_per_thread = 1000000;
    bool save_paths = false;
    
    // New fields for path distribution
    bool enable_path_distribution = true;  // Enable the new feature
    bool infinite_on_completion = true;    // Continue infinitely when quota reached
    
    // Debug options
    bool debug_mode = false;
    int debug_log_every = 1;
    int debug_verbose = 1;
    
    std::string bloom_file;
    std::vector<std::string> input_pubkeys_hex;
    std::vector<Point> input_points;
    int bloom_load_threads = 4;
    
    bool validate() const {
        if (min_steps > max_steps) return false;
        if (min_divisions > min_steps) return false;
        if (max_divisions > max_steps) return false;
        if (num_threads == 0 || num_threads > MAX_THREADS) return false;
        if (bloom_file.empty()) return false;
        if (input_pubkeys_hex.empty()) return false;
        return true;
    }
};

// Pre-computed points manager (unchanged)
class PrecomputedPoints {
public:
    std::vector<Point> GSn;
    Point _2GSn;
    Int inverse_of_2;
    
    void initialize(Secp256K1* secp) {
        if (!secp) {
            std::cerr << "[E] Invalid secp256k1 context\n";
            return;
        }
        
        inverse_of_2.SetBase16("7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a1");
        
        GSn.clear();
        GSn.reserve(CPU_GRP_SIZE / 2);
        
        Int one;
        one.SetInt32(1);
        Point G = secp->ComputePublicKey(&one);
        
        if (G.isZero()) {
            std::cerr << "[E] Failed to compute generator point\n";
            return;
        }
        
        Point negG = secp->Negation(G);
        
        Point g = negG;
        GSn.push_back(g);
        
        for (size_t i = 1; i < CPU_GRP_SIZE / 2; ++i) {
            g = secp->AddDirect(g, negG);
            GSn.push_back(g);
        }
        
        _2GSn = secp->DoubleDirect(GSn[CPU_GRP_SIZE / 2 - 1]);
        
        std::cout << "[+] Pre-computed " << GSn.size() << " subtraction points\n";
    }
};

// Global bloom filters
bloom* g_bloom_filters = nullptr;

// Bloom filter manager (unchanged - keeping your original implementation)
class OptimizedBloomFilter {
public:
    OptimizedBloomFilter() = default;
    
    ~OptimizedBloomFilter() {
        if (bloom_filters_) {
            for (int i = 0; i < 256; i++) {
                if (bloom_filters_[i].ready) {
                    bloom_free(&bloom_filters_[i]);
                }
            }
            delete[] bloom_filters_;
        }
        if (bloom_mutexes) {
            delete[] bloom_mutexes;
        }
    }
    
    static void* bloom_loader_thread(void* arg) {
        BloomLoadWork* work = (BloomLoadWork*)arg;
        
        FILE* file = fopen(work->filename, "rb");
        if (!file) {
            work->finished.store(true);
            return nullptr;
        }
        
        fseek(file, work->start_entry * COMPRESSED_PUBKEY_SIZE, SEEK_SET);
        
        unsigned char* buffer = new unsigned char[BLOOM_LOAD_BUFFER];
        size_t entries_to_read = work->end_entry - work->start_entry;
        size_t entries_read = 0;
        
        while (entries_read < entries_to_read) {
            size_t batch_entries = std::min(
                BLOOM_LOAD_BUFFER / COMPRESSED_PUBKEY_SIZE,
                entries_to_read - entries_read
            );
            
            size_t read = fread(buffer, COMPRESSED_PUBKEY_SIZE, batch_entries, file);
            if (read == 0) break;
            
            for (size_t i = 0; i < read; i++) {
                unsigned char* entry = buffer + (i * COMPRESSED_PUBKEY_SIZE);
                uint8_t index = entry[1];
                
                pthread_mutex_lock(&bloom_mutexes[index]);
                bloom_add(&g_bloom_filters[index], (char*)entry, COMPRESSED_PUBKEY_SIZE);
                pthread_mutex_unlock(&bloom_mutexes[index]);
            }
            
            entries_read += read;
            global_bloom_entries_loaded.fetch_add(read);
            
            if (work->thread_id == 0 && entries_read % 1000000 == 0) {
                uint64_t total = global_bloom_entries_loaded.load();
                printf("\r[+] Loading bloom filters: %llu entries", (unsigned long long)total);
                fflush(stdout);
            }
        }
        
        delete[] buffer;
        fclose(file);
        work->finished.store(true);
        
        return nullptr;
    }
    
    bool initialize_parallel(const std::string& filename, int num_threads) {
        auto file_size = get_file_size(filename);
        if (file_size % COMPRESSED_PUBKEY_SIZE != 0) {
            std::cerr << "Invalid binary file size\n";
            return false;
        }
        
        total_entries_ = file_size / COMPRESSED_PUBKEY_SIZE;
        std::cout << "[+] Loading " << total_entries_ << " public keys using " 
                  << num_threads << " threads\n";
        
        bloom_filters_ = new bloom[256];
        g_bloom_filters = bloom_filters_;
        bloom_mutexes = new pthread_mutex_t[256];
        
        for (int i = 0; i < 256; i++) {
            pthread_mutex_init(&bloom_mutexes[i], NULL);
            size_t items_per_bloom = (total_entries_ / 256) + 1000;
            if (bloom_init2(&bloom_filters_[i], items_per_bloom, BLOOM_FP_RATE) != 0) {
                std::cerr << "Failed to initialize bloom filter " << i << "\n";
                return false;
            }
        }
        
        size_t entries_per_thread = total_entries_ / num_threads;
        size_t remainder = total_entries_ % num_threads;
        
        std::vector<pthread_t> threads(num_threads);
        std::vector<BloomLoadWork> work(num_threads);
        
        auto start_time = std::chrono::steady_clock::now();
        
        for (int t = 0; t < num_threads; t++) {
            work[t].thread_id = t;
            work[t].filename = filename.c_str();
            work[t].start_entry = t * entries_per_thread;
            work[t].end_entry = (t == num_threads - 1) ? 
                                (work[t].start_entry + entries_per_thread + remainder) :
                                (work[t].start_entry + entries_per_thread);
            work[t].finished.store(false);
            
            pthread_create(&threads[t], NULL, bloom_loader_thread, &work[t]);
        }
        
        while (true) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            
            bool all_finished = true;
            for (int t = 0; t < num_threads; t++) {
                if (!work[t].finished.load()) {
                    all_finished = false;
                    break;
                }
            }
            
            uint64_t loaded = global_bloom_entries_loaded.load();
            double progress = (double)loaded / total_entries_ * 100.0;
            printf("\r[+] Loading bloom filters: %.1f%% (%llu/%llu entries)", 
                   progress, (unsigned long long)loaded, (unsigned long long)total_entries_);
            fflush(stdout);
            
            if (all_finished) break;
        }
        
        for (int t = 0; t < num_threads; t++) {
            pthread_join(threads[t], NULL);
        }
        
        auto end_time = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(end_time - start_time).count();
        
        std::cout << "\n[+] Successfully loaded " << total_entries_ << " keys in " 
                  << elapsed << " seconds\n";
        
        double rate = total_entries_ / (double)elapsed;
        std::cout << "[+] Loading rate: " << std::fixed << std::setprecision(1) 
                  << rate / 1000000.0 << " million keys/second\n";
        
        bloom_file_ = filename;
        return true;
    }
    
    bool check(Point& point) {
        if (!bloom_filters_) return false;
        
        unsigned char compressed[COMPRESSED_PUBKEY_SIZE];
        unsigned char x_bytes[32];
        point.x.Get32Bytes(x_bytes);
        
        bool y_is_odd = point.y.IsOdd();
        compressed[0] = y_is_odd ? 0x03 : 0x02;
        std::memcpy(compressed + 1, x_bytes, 32);
        
        uint8_t index = compressed[1];
        
        return bloom_check(&bloom_filters_[index], 
                          reinterpret_cast<char*>(compressed), 
                          COMPRESSED_PUBKEY_SIZE);
    }
    
    bool verify_in_file(Point& point) {
        std::ifstream file(bloom_file_, std::ios::binary);
        if (!file) return false;
        
        unsigned char compressed[COMPRESSED_PUBKEY_SIZE];
        unsigned char x_bytes[32];
        point.x.Get32Bytes(x_bytes);
        
        bool y_is_odd = point.y.IsOdd();
        compressed[0] = y_is_odd ? 0x03 : 0x02;
        std::memcpy(compressed + 1, x_bytes, 32);
        
        const size_t BUFFER_SIZE = 1024 * 1024;
        std::vector<unsigned char> buffer(BUFFER_SIZE);
        
        while (file.read(reinterpret_cast<char*>(buffer.data()), BUFFER_SIZE) || file.gcount() > 0) {
            size_t bytes_read = file.gcount();
            size_t entries = bytes_read / COMPRESSED_PUBKEY_SIZE;
            
            for (size_t i = 0; i < entries; ++i) {
                if (std::memcmp(buffer.data() + i * COMPRESSED_PUBKEY_SIZE, 
                               compressed, COMPRESSED_PUBKEY_SIZE) == 0) {
                    return true;
                }
            }
        }
        
        return false;
    }
    
private:
    bloom* bloom_filters_ = nullptr;
    size_t total_entries_ = 0;
    std::string bloom_file_;
    
    size_t get_file_size(const std::string& filename) {
        struct stat st;
        if (stat(filename.c_str(), &st) != 0) {
            return 0;
        }
        return st.st_size;
    }
};

// Path generator - Modified for specific configurations
class BatchPathProcessor {
public:
    struct PathBatch {
        std::vector<std::vector<int>> operations;
        std::vector<int> divisions;
        std::vector<int> subtractions;
        std::vector<int> total_steps;
    };
    
    // Generate batch for specific configuration
    PathBatch generate_batch_for_config(int batch_size, PathConfig* config) {
        PathBatch batch;
        batch.operations.reserve(batch_size);
        batch.divisions.reserve(batch_size);
        batch.subtractions.reserve(batch_size);
        batch.total_steps.reserve(batch_size);
        
        if (!config || config->total_steps <= 0 || config->divisions < 0 || config->subtractions < 0) {
            std::cerr << "[E] Invalid path configuration\n";
            return batch;
        }
        
        for (int i = 0; i < batch_size; i++) {
            auto ops = generate_valid_path(config->total_steps, 
                                          config->divisions, 
                                          config->subtractions);
            
            batch.operations.push_back(ops);
            batch.divisions.push_back(config->divisions);
            batch.subtractions.push_back(config->subtractions);
            batch.total_steps.push_back(config->total_steps);
        }
        
        return batch;
    }
    
    // Original random batch generation (for fallback)
    PathBatch generate_batch(int batch_size, int min_steps, int max_steps, 
                             int min_divs, int max_divs) {
        PathBatch batch;
        batch.operations.reserve(batch_size);
        batch.divisions.reserve(batch_size);
        batch.subtractions.reserve(batch_size);
        batch.total_steps.reserve(batch_size);
        
        for (int i = 0; i < batch_size; i++) {
            int steps = rand_range(min_steps, max_steps);
            int divs = rand_range(min_divs, std::min(max_divs, steps));
            int subs = steps - divs;
            
            auto ops = generate_valid_path(steps, divs, subs);
            
            batch.operations.push_back(ops);
            batch.divisions.push_back(divs);
            batch.subtractions.push_back(subs);
            batch.total_steps.push_back(steps);
        }
        
        return batch;
    }
    
private:
    int rand_range(int min, int max) {
        static thread_local std::mt19937 gen(std::random_device{}());
        std::uniform_int_distribution<> dis(min, max);
        return dis(gen);
    }
    
    std::vector<int> generate_valid_path(int total, int divs, int subs) {
        std::vector<int> ops;
        
        if (total <= 0 || divs < 0 || subs < 0 || (divs + subs) != total) {
            std::cerr << "[E] Invalid path parameters: total=" << total 
                     << " divs=" << divs << " subs=" << subs << "\n";
            return ops;  // Return empty vector
        }
        
        ops.reserve(total);
        
        for (int i = 0; i < divs; i++) ops.push_back(1);
        for (int i = 0; i < subs; i++) ops.push_back(0);
        
        static thread_local std::mt19937 gen(std::random_device{}());
        std::shuffle(ops.begin(), ops.end(), gen);
        
        fix_constraints(ops);
        
        return ops;
    }
    
    void fix_constraints(std::vector<int>& ops) {
        bool fixed = false;
        int iterations = 0;
        
        while (!fixed && iterations < 100) {
            fixed = true;
            iterations++;
            
            for (size_t i = 0; i < ops.size() - 1; i++) {
                if (ops[i] == 0 && ops[i + 1] == 0) {
                    for (size_t j = i + 2; j < ops.size(); j++) {
                        if (ops[j] == 1) {
                            std::swap(ops[i + 1], ops[j]);
                            fixed = false;
                            break;
                        }
                    }
                }
            }
        }
    }
};

// Display update function - Enhanced
void update_live_display() {
    if (!g_live_display) return;
    
    std::lock_guard<std::mutex> lock(g_live_display->display_mutex);
    
    // Move cursor to beginning of line and clear it
    std::cout << "\r\033[K";
    
    // Enhanced format showing config progress
    std::cout << "[" << g_live_display->completed_configs.load() << "/" 
              << g_live_display->total_configs.load() << " configs] "
              << g_live_display->current_step.load() << "/" << g_live_display->total_steps.load()
              << " " << g_live_display->current_divs.load() << "/" << g_live_display->current_subs.load()
              << "   " << g_live_display->paths_completed.load() << "/" << g_live_display->paths_quota.load()
              << "     " << g_live_display->current_pubkey.substr(0, 66)
              << "  " << g_live_display->target_divs << "-Div " 
              << g_live_display->target_subs << "-Sub" << std::flush;
}

// Get next path configuration that needs work
PathConfig* get_next_config_needing_work() {
    std::lock_guard<std::mutex> lock(g_config_assignment_mutex);
    
    for (auto& config : g_path_configs) {
        if (!config->quota_reached.load() && 
            config->paths_completed.load() < config->paths_quota.load()) {
            return config.get();
        }
    }
    
    // All configs reached quota - find one with least threads for rotation
    PathConfig* best = nullptr;
    int min_threads = INT_MAX;
    
    for (auto& config : g_path_configs) {
        int threads = config->active_threads.load();
        if (threads < min_threads) {
            min_threads = threads;
            best = config.get();
        }
    }
    
    return best;
}

// Main worker thread function - Enhanced for path distribution
void* thread_worker_division_distributed(void* vargp) {
    ThreadWork* work = (ThreadWork*)vargp;
    Config* config = work->config_ptr;
    OptimizedBloomFilter* bloom = work->bloom_ptr;
    
    Secp256K1* secp = new Secp256K1();
    secp->Init();
    
    PrecomputedPoints precomp;
    precomp.initialize(secp);
    
    BatchPathProcessor processor;
    
    // Register with assigned config
    if (work->assigned_config) {
        work->assigned_config->active_threads.fetch_add(1);
    }
    
    while (!solution_found.load()) {
        // Check if we need to rotate to different config
        if (work->should_rotate.load() || !work->assigned_config) {
            if (work->assigned_config) {
                work->assigned_config->active_threads.fetch_sub(1);
            }
            
            work->assigned_config = get_next_config_needing_work();
            if (!work->assigned_config) {
                // All configs completed - if infinite mode, pick any config
                if (config->infinite_on_completion && !g_path_configs.empty()) {
                    work->assigned_config = g_path_configs[work->thread_id % g_path_configs.size()].get();
                } else {
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    continue;
                }
            }
            
            work->assigned_config->active_threads.fetch_add(1);
            work->should_rotate.store(false);
            work->rotation_batch_count = 0;
        }
        
        if (!work->assigned_config) {
            std::cerr << "[E] Thread " << work->thread_id << " has no assigned config\n";
            break;
        }
        
        // Generate batch for assigned configuration
        auto batch = processor.generate_batch_for_config(PATH_BATCH_SIZE, work->assigned_config);
        
        if (batch.operations.empty()) {
            std::cerr << "[E] Thread " << work->thread_id << " failed to generate batch\n";
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }
        
        global_paths_generated.fetch_add(batch.operations.size());
        
        for (size_t batch_idx = 0; batch_idx < batch.operations.size(); batch_idx++) {
            if (solution_found.load()) break;
            
            const auto& ops = batch.operations[batch_idx];
            
            // Skip empty operations
            if (ops.empty()) {
                std::cerr << "[W] Thread " << work->thread_id << " got empty operations\n";
                continue;
            }
            
            // Update display info for this path - reset counters
            work->current_total_steps = batch.total_steps[batch_idx];
            work->current_divs = 0;
            work->current_subs = 0;
            work->current_step = 0;
            
            for (size_t key_idx = 0; key_idx < config->input_points.size(); key_idx++) {
                if (solution_found.load()) break;
                
                Point current = config->input_points[key_idx];
                work->current_key = config->input_pubkeys_hex[key_idx];
                
                // Update global display
                if (work->thread_id == 0 || (rand() % 100 == 0)) {
                    g_live_display->current_pubkey = work->current_key;
                    g_live_display->total_steps.store(work->current_total_steps);
                    g_live_display->target_divs = work->assigned_config->divisions;
                    g_live_display->target_subs = work->assigned_config->subtractions;
                }
                
                bool valid_path = true;
                for (size_t op_idx = 0; op_idx < ops.size(); op_idx++) {
                    work->current_step = op_idx + 1;
                    
                    if (ops[op_idx] == 0) {
                        // Subtraction
                        if (precomp.GSn.empty() || precomp.GSn[0].isZero()) {
                            valid_path = false;
                            break;
                        }
                        current = secp->AddDirect(current, precomp.GSn[0]);
                        work->current_subs++;
                    } else {
                        // Division by 2
                        Int temp;
                        temp.Set(&precomp.inverse_of_2);
                        
                        Point Q, R;
                        Q.Clear();
                        R.Clear();
                        
                        int bits = temp.GetBitLength();
                        if (!temp.IsZero() && bits > 0) {
                            Q = current;
                            if (temp.GetBit(0)) R = current;
                            
                            for (int i = 1; i < bits; i++) {
                                Q = secp->DoubleDirect(Q);
                                if (temp.GetBit(i)) {
                                    R = R.isZero() ? Q : secp->AddDirect(R, Q);
                                }
                            }
                        }
                        current = R;
                        work->current_divs++;
                    }
                    
                    // Update live display
                    if (work->thread_id == 0 || (op_idx % 10 == 0 && rand() % 10 == 0)) {
                        g_live_display->current_step.store(work->current_step);
                        g_live_display->current_divs.store(work->current_divs);
                        g_live_display->current_subs.store(work->current_subs);
                        
                        if (work->thread_id == 0) {
                            update_live_display();
                        }
                    }
                    
                    if (current.isZero()) {
                        valid_path = false;
                        break;
                    }
                }
                
                if (!valid_path) continue;
                
                global_paths_tested.fetch_add(1);
                work->paths_completed++;
                work->assigned_config->paths_completed.fetch_add(1);
                g_live_display->paths_completed.fetch_add(1);
                
                // Check if config reached quota
                if (work->assigned_config->paths_completed.load() >= 
                    work->assigned_config->paths_quota.load()) {
                    
                    if (!work->assigned_config->quota_reached.exchange(true)) {
                        g_configs_completed.fetch_add(1);
                        g_live_display->completed_configs.fetch_add(1);
                        
                        // Check if all configs completed
                        if ((size_t)g_configs_completed.load() >= g_path_configs.size()) {
                            if (config->infinite_on_completion) {
                                std::cout << "\n[+] All path configurations completed quota - continuing infinitely\n";
                            } else {
                                work->should_rotate.store(true);
                            }
                        } else {
                            // Rotate to help other configs
                            work->should_rotate.store(true);
                        }
                    }
                } else if (!config->infinite_on_completion) {
                    // Rotation mode - after DEFAULT_PATH_BATCH paths, rotate
                    work->rotation_batch_count++;
                    if (work->rotation_batch_count >= DEFAULT_PATH_BATCH / PATH_BATCH_SIZE) {
                        work->should_rotate.store(true);
                    }
                }
                
                if (bloom->check(current)) {
                    global_bloom_checks.fetch_add(1);
                    
                    if (bloom->verify_in_file(current)) {
                        pthread_mutex_lock(&result_mutex);
                        if (!solution_found.exchange(true)) {
                            char final_hex[67];
                            secp->GetPublicKeyHex(true, current, final_hex);
                            
                            std::cout << "\r\033[K";
                            std::cout << "\n\n[!] MATCH FOUND by Thread " << work->thread_id << "!\n";
                            std::cout << "Configuration: " << work->assigned_config->total_steps 
                                     << " steps (" << work->assigned_config->divisions << " divs, "
                                     << work->assigned_config->subtractions << " subs)\n";
                            std::cout << "Original Key #" << (key_idx + 1) << ": " 
                                     << config->input_pubkeys_hex[key_idx] << "\n";
                            std::cout << "Final Point: " << final_hex << "\n";
                            std::cout << "Path: ";
                            for (int op : ops) {
                                std::cout << (op == 0 ? "-1," : "/2,");
                            }
                            std::cout << "\n";
                            
                            std::ofstream out("KEYFOUNDKEYFOUND.txt", std::ios::app);
                            if (out) {
                                out << "Found: " << final_hex << "\n";
                                out << "Original: " << config->input_pubkeys_hex[key_idx] << "\n";
                                out << "Config: " << work->assigned_config->total_steps 
                                    << "-" << work->assigned_config->divisions 
                                    << "-" << work->assigned_config->subtractions << "\n";
                                out << "Path: ";
                                for (int op : ops) {
                                    out << (op == 0 ? "-1," : "/2,");
                                }
                                out << "\n";
                                out << "Thread: " << work->thread_id << "\n";
                                out.close();
                            }
                        }
                        pthread_mutex_unlock(&result_mutex);
                    }
                }
            }
        }
    }
    
    if (work->assigned_config) {
        work->assigned_config->active_threads.fetch_sub(1);
    }
    
    delete secp;
    work->finished.store(true);
    
    return NULL;
}

// Initialize path configurations
void initialize_path_configurations(Config& config) {
    int total_configs = 0;
    
    // Calculate total number of configurations
    for (int steps = config.min_steps; steps <= config.max_steps; steps++) {
        // For fixed divisions, only one config per step size
        if (config.min_divisions == config.max_divisions) {
            int divs = config.min_divisions;
            int subs = steps - divs;
            
            // Make sure it's valid
            if (divs <= steps && subs >= 0) {
                total_configs++;
            }
        } else {
            // Variable divisions - create config for each valid combination
            for (int divs = config.min_divisions; divs <= config.max_divisions && divs <= steps; divs++) {
                int subs = steps - divs;
                if (subs >= 0) {
                    total_configs++;
                }
            }
        }
    }
    
    std::cout << "[+] Creating " << total_configs << " path configurations\n";
    
    // Calculate threads per config
    int base_threads = config.num_threads / total_configs;
    int extra_threads = config.num_threads % total_configs;
    
    std::cout << "[+] Thread distribution: " << base_threads << " base threads per config\n";
    if (extra_threads > 0) {
        std::cout << "[+] " << extra_threads << " configs will have 1 extra thread\n";
    }
    
    // Create configurations
    g_path_configs.clear();
    g_path_configs.reserve(total_configs);
    
    int config_idx = 0;
    for (int steps = config.min_steps; steps <= config.max_steps; steps++) {
        if (config.min_divisions == config.max_divisions) {
            int divs = config.min_divisions;
            int subs = steps - divs;
            
            if (divs <= steps && subs >= 0) {
                // Calculate quota for this config based on thread count
                int threads_for_config = base_threads + (config_idx < extra_threads ? 1 : 0);
                uint64_t quota = (config.paths_per_thread * threads_for_config) / base_threads;
                
                auto path_config = std::make_unique<PathConfig>(steps, divs, subs, quota);
                g_path_configs.push_back(std::move(path_config));
                
                if (config_idx < 5 || config_idx == total_configs - 1) {
                    std::cout << "  Config " << config_idx << ": " 
                             << steps << " steps (" << divs << "D/" << subs << "S) - "
                             << threads_for_config << " threads, quota: " << quota << "\n";
                }
                config_idx++;
            }
        } else {
            for (int divs = config.min_divisions; divs <= config.max_divisions && divs <= steps; divs++) {
                int subs = steps - divs;
                if (subs >= 0) {
                    int threads_for_config = base_threads + (config_idx < extra_threads ? 1 : 0);
                    uint64_t quota = (config.paths_per_thread * threads_for_config) / base_threads;
                    
                    auto path_config = std::make_unique<PathConfig>(steps, divs, subs, quota);
                    g_path_configs.push_back(std::move(path_config));
                    config_idx++;
                }
            }
        }
    }
    
    g_live_display->total_configs.store(total_configs);
    g_live_display->active_configs.store(total_configs);
    
    // Update total quota
    uint64_t total_quota = 0;
    for (const auto& pc : g_path_configs) {
        total_quota += pc->paths_quota.load();
    }
    g_live_display->paths_quota.store(total_quota);
}

// Command-line parser - Enhanced
class ArgumentParser {
public:
    static Config parse(int argc, char* argv[]) {
        if (argc < 2) {
            print_usage(argv[0]);
            exit(1);
        }
        
        Config config;
        config.input_pubkeys_hex.push_back(argv[1]);
        
        for (int i = 2; i < argc; ++i) {
            std::string arg(argv[i]);
            
            if (arg == "-f" && i + 1 < argc) {
                config.bloom_file = argv[++i];
            } else if (arg == "-t" && i + 1 < argc) {
                config.num_threads = std::stoul(argv[++i]);
            } else if (arg == "-s" && i + 1 < argc) {
                config.min_steps = std::stoi(argv[++i]);
            } else if (arg == "-S" && i + 1 < argc) {
                config.max_steps = std::stoi(argv[++i]);
            } else if (arg == "-d" && i + 1 < argc) {
                config.min_divisions = std::stoi(argv[++i]);
            } else if (arg == "-D" && i + 1 < argc) {
                config.max_divisions = std::stoi(argv[++i]);
            } else if (arg == "-p" && i + 1 < argc) {
                config.paths_per_thread = std::stoull(argv[++i]);
            } else if (arg == "-b" && i + 1 < argc) {
                config.bloom_load_threads = std::stoi(argv[++i]);
            } else if (arg == "-w") {
                config.save_paths = true;
            } else if (arg == "--no-distribute") {
                config.enable_path_distribution = false;
            } else if (arg == "--rotate-mode") {
                config.infinite_on_completion = false;
            } else if (arg == "-h" || arg == "--help") {
                print_usage(argv[0]);
                exit(0);
            }
        }
        
        if (config.bloom_file.empty()) {
            std::cerr << "[E] Bloom filter file required (-f)\n";
            exit(1);
        }
        
        return config;
    }
    
private:
    static void print_usage(const char* program) {
        std::cout << "Division Tool v4.0 - Path Distribution System\n\n";
        std::cout << "Usage: " << program << " <pubkey1,pubkey2,...> -f <bloom_file> [options]\n\n";
        std::cout << "Required:\n";
        std::cout << "  -f <file>           Binary file with compressed public keys\n\n";
        std::cout << "Options:\n";
        std::cout << "  -t <threads>        Worker threads (default: hardware concurrency)\n";
        std::cout << "  -b <threads>        Bloom loading threads (default: 4)\n";
        std::cout << "  -s <min_steps>      Minimum total steps (default: 120)\n";
        std::cout << "  -S <max_steps>      Maximum total steps (default: 190)\n";
        std::cout << "  -d <min_divs>       Minimum divisions (default: 100)\n";
        std::cout << "  -D <max_divs>       Maximum divisions (default: 100)\n";
        std::cout << "  -p <paths>          Paths quota per thread (default: 1000000)\n";
        std::cout << "  -w                  Save found paths to file\n";
        std::cout << "  --no-distribute     Disable path distribution (use old random mode)\n";
        std::cout << "  --rotate-mode       Rotate threads between configs (vs infinite on completion)\n\n";
        std::cout << "Path Distribution:\n";
        std::cout << "  When enabled (default), threads are distributed evenly across all\n";
        std::cout << "  step/division combinations for systematic coverage.\n";
        std::cout << "  Example: 96 threads, 140-160 steps, 100 divs = 21 configs\n";
        std::cout << "           Each config gets ~4-5 threads for parallel processing\n\n";
        std::cout << "Examples:\n";
        std::cout << "  " << program << " 02a1b2c3d4... -f keys.bin -t 96 -s 140 -S 160 -d 100 -D 100 -p 1024\n";
    }
};

// Main orchestrator - Enhanced
class DivisionOrchestrator {
public:
    DivisionOrchestrator(Config& config) : config_(config) {}
    
    bool initialize() {
        if (!parse_public_keys()) {
            return false;
        }
        
        // Initialize live display
        g_live_display = new LiveDisplay();
        g_live_display->paths_quota.store(config_.paths_per_thread * config_.num_threads);
        g_live_display->target_divs = config_.min_divisions;
        g_live_display->target_subs = config_.min_steps - config_.min_divisions;
        
        // Initialize path configurations if distribution enabled
        if (config_.enable_path_distribution) {
            initialize_path_configurations(config_);
        }
        
        bloom_ = std::make_unique<OptimizedBloomFilter>();
        if (!bloom_->initialize_parallel(config_.bloom_file, config_.bloom_load_threads)) {
            return false;
        }
        
        return true;
    }
    
    void run() {
        auto start_time = std::chrono::steady_clock::now();
        
        std::cout << "[+] Starting division search with " << config_.num_threads << " workers\n";
        
        if (config_.enable_path_distribution) {
            std::cout << "[+] Path Distribution Mode: ENABLED\n";
            std::cout << "[+] Total configurations: " << g_path_configs.size() << "\n";
            std::cout << "[+] Mode: " << (config_.infinite_on_completion ? "Infinite on completion" : "Rotation mode") << "\n";
        } else {
            std::cout << "[+] Random Mode: " << config_.min_steps << "-" << config_.max_steps << " steps\n";
            std::cout << "[+] Divisions: " << config_.min_divisions << "-" << config_.max_divisions << "\n";
        }
        
        std::cout << "[+] Total paths quota: " << g_live_display->paths_quota.load() << "\n\n";
        
        std::vector<ThreadWork> thread_works(config_.num_threads);
        std::vector<pthread_t> threads(config_.num_threads);
        
        // Assign threads to configurations
        if (config_.enable_path_distribution) {
            // Distribute threads across configs
            size_t config_idx = 0;
            for (size_t i = 0; i < config_.num_threads; i++) {
                memset(&thread_works[i], 0, sizeof(ThreadWork));  // Clear the structure
                thread_works[i].thread_id = i;
                thread_works[i].assigned_config = g_path_configs[config_idx % g_path_configs.size()].get();
                thread_works[i].config_ptr = &config_;
                thread_works[i].bloom_ptr = bloom_.get();
                thread_works[i].paths_completed = 0;
                thread_works[i].finished.store(false);
                thread_works[i].should_rotate.store(false);
                thread_works[i].current_step = 0;
                thread_works[i].current_total_steps = 0;
                thread_works[i].current_divs = 0;
                thread_works[i].current_subs = 0;
                thread_works[i].rotation_batch_count = 0;
                config_idx++;
            }
            
            // Create distributed worker threads
            for (size_t i = 0; i < config_.num_threads; i++) {
                pthread_create(&threads[i], NULL, thread_worker_division_distributed, &thread_works[i]);
            }
        } else {
            // Original random mode - implementation not shown but would be original function
            std::cout << "[+] Random mode not implemented in this version\n";
            return;
        }
        
        // Main display update loop
        while (!solution_found.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            
            // Check if all configs completed and in infinite mode
            if (config_.enable_path_distribution && 
                (size_t)g_configs_completed.load() >= g_path_configs.size() && 
                config_.infinite_on_completion) {
                // Continue infinitely - no action needed
            }
        }
        
        // Signal threads to stop
        solution_found.store(true);
        
        for (size_t i = 0; i < config_.num_threads; i++) {
            pthread_join(threads[i], NULL);
        }
        
        auto end_time = std::chrono::steady_clock::now();
        auto total_elapsed = std::chrono::duration_cast<std::chrono::seconds>(end_time - start_time).count();
        
        std::cout << "\n[+] Search completed in " << total_elapsed << " seconds\n";
        std::cout << "[+] Total paths generated: " << global_paths_generated.load() << "\n";
        std::cout << "[+] Total paths tested: " << global_paths_tested.load() << "\n";
        std::cout << "[+] Bloom filter hits: " << global_bloom_checks.load() << "\n";
        
        if (config_.enable_path_distribution) {
            std::cout << "[+] Configurations completed: " << g_configs_completed.load() 
                     << "/" << g_path_configs.size() << "\n";
        }
        
        delete g_live_display;
        g_live_display = nullptr;
    }
    
private:
    Config config_;
    std::unique_ptr<OptimizedBloomFilter> bloom_;
    
    bool parse_public_keys() {
        std::string keys_str = config_.input_pubkeys_hex[0];
        config_.input_pubkeys_hex.clear();
        config_.input_points.clear();
        
        Secp256K1 secp;
        secp.Init();
        
        std::stringstream ss(keys_str);
        std::string key;
        
        while (std::getline(ss, key, ',')) {
            key.erase(0, key.find_first_not_of(" \t\n\r"));
            key.erase(key.find_last_not_of(" \t\n\r") + 1);
            
            if (key.empty()) continue;
            
            Point point;
            bool compressed;
            char* key_cstr = new char[key.length() + 1];
            std::strcpy(key_cstr, key.c_str());
            
            bool success = secp.ParsePublicKeyHex(key_cstr, point, compressed);
            delete[] key_cstr;
            
            if (!success) {
                std::cerr << "[E] Invalid public key: " << key << "\n";
                return false;
            }
            
            config_.input_points.push_back(point);
            config_.input_pubkeys_hex.push_back(key);
        }
        
        std::cout << "[+] Loaded " << config_.input_points.size() << " public keys\n";
        return !config_.input_points.empty();
    }
};

int main(int argc, char* argv[]) {
    try {
        Config config = ArgumentParser::parse(argc, argv);
        
        if (!config.validate()) {
            std::cerr << "[E] Invalid configuration\n";
            return 1;
        }
        
        DivisionOrchestrator orchestrator(config);
        
        if (!orchestrator.initialize()) {
            std::cerr << "[E] Failed to initialize\n";
            return 1;
        }
        
        orchestrator.run();
        
        return 0;
        
    } catch (const std::exception& e) {
        std::cerr << "[E] Exception: " << e.what() << "\n";
        return 1;
    }
}
