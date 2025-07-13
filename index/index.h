#ifndef INDEX_H
#define INDEX_H

#include <stdint.h>
#include <vector>
#include <time.h>
#include <atomic>
#include "../secp256k1/SECP256k1.h"
#include "../secp256k1/Point.h"
#include "../secp256k1/Int.h"
#include "../bloom/bloom.h"

// Configuration for extreme compression
struct ExtremeConfig {
    Point origin_pubkey;
    Int spacing;
    uint64_t num_keys;
    uint8_t bloom_layers;      // Number of bloom filter layers (2-4)
    double bits_per_key_base;  // Base bits per key
    double fpp_layer1;         // False positive probability for layer 1
    double fpp_layer2;         // False positive probability for layer 2  
    double fpp_layer3;         // False positive probability for layer 3
    bool stop_on_first_find;   // Stop after finding first key
};

// Thread data for parallel bloom loading
struct BloomLoadData {
    uint32_t thread_id;
    uint64_t from;
    uint64_t to;
    uint64_t workload;
    ExtremeConfig* config;
    struct bloom** bloom_filters;
    std::vector<uint32_t>* mini_hashes;  // Changed from uint32_t** to vector*
    uint64_t* mini_hash_count;
    std::atomic<bool>* should_stop;
    uint32_t finished;
    void* mini_hash_mutex;  // Added this field
};

// Multi-layer bloom filter for extreme compression
class ExtremeBloomIndex {
private:
    ExtremeConfig config;
    
    // Multiple bloom filters with decreasing sizes
    struct bloom* layer1;
    struct bloom* layer2;  
    struct bloom* layer3;
    
    // Ultra-minimal verification data
    uint32_t* mini_hashes;     // 4-byte hashes for final verification
    uint64_t mini_hash_count;  // Number of entries in mini_hashes
    
    // Thread synchronization
    void* bloom_mutexes[3][256]; // Mutexes for each bloom layer and byte prefix
    void* mini_hash_mutex;
    
    // Statistics
    struct {
        uint64_t checks;
        uint64_t layer1_hits;
        uint64_t layer2_hits;
        uint64_t layer3_hits;
        uint64_t reconstructions;
        uint64_t found;
        time_t start_time;
    } stats;
    
    bool initialized;
    std::atomic<bool> stop_flag;
    
    // Hash functions for different layers
    uint64_t hash1(const uint8_t* data, uint64_t index);
    uint64_t hash2(const uint8_t* data, uint64_t index);
    uint64_t hash3(const uint8_t* data, uint64_t index);
    uint32_t mini_hash(const uint8_t* data, uint64_t index);
    
    // Thread function for parallel loading
    static void* threadBuildBloom(void* vargp);
    
public:
    ExtremeBloomIndex();
    ~ExtremeBloomIndex();

    Point getOriginPoint() const { return config.origin_pubkey; }
    bool shouldStop() const { return stop_flag; }
    
    // Initialize with extreme settings
    bool initialize(const Point& origin, const Int& spacing, uint64_t num_keys);
    
    // Build the multi-layer index with threading
    bool buildIndex(int num_threads = 1);
    
    // Check with 100% accuracy and recover original key
    bool checkKey(const Point& test_key, uint64_t& found_index, Int* original_private_key = nullptr);
    
    // Get memory usage
    void getMemoryStats(uint64_t& total_bytes, double& bytes_per_key);
    
    // Display statistics
    void displayStats();
    static void displayCapacityTable();
    
    // Set custom false positive rates
    void setFalsePositiveRates(double fpp1, double fpp2, double fpp3);
    
    // Enable/disable stop on first find
    void setStopOnFirstFind(bool stop) { config.stop_on_first_find = stop; }
};

// Global instance
extern ExtremeBloomIndex* g_extreme_index;

// High-level functions
bool initializeExtremeIndex(const char* params, const char* origin_pubkey_hex, int num_threads = 1);
void writeExtremeKey(uint64_t index, const Int& subtract_value, const Point& found_point, const Int* found_private_key, const Point& origin_point);

#endif
