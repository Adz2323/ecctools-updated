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

#ifdef _WIN64
#include <windows.h>
#else
#include <pthread.h>
#include <unistd.h>
#endif

// Forward declarations
class ExtremePatternIndex;
struct PatternBPload;

// Thread function declarations
#ifdef _WIN64
DWORD WINAPI thread_pattern_table_build(LPVOID vargp);
#else
void* thread_pattern_table_build(void* vargp);
#endif

// Configuration for pattern-based key matching
struct PatternConfig {
    Point origin_pubkey;
    Int spacing;
    uint64_t num_keys;
    bool stop_on_first_find;
};

// Pattern table entry - similar to BSGS
struct pattern_table_entry {
    uint8_t value[6];   // 6 bytes from X coordinate (like BSGS)
    uint64_t index;     // Pattern index
};

// Thread structure for pattern table building
struct PatternTableBuildInfo {
    uint32_t threadid;
    uint64_t from;
    uint64_t to;
    uint32_t finished;
    ExtremePatternIndex* parent;
    struct pattern_table_entry* table;
};

// Ultra-efficient pattern-based index for arithmetic progressions
class ExtremePatternIndex {
private:
    PatternConfig config;
    
    // Pattern table for binary search (like BSGS bPtable)
    struct pattern_table_entry* patternTable;
    uint64_t table_size;
    uint64_t step_size;  // Store every Nth point
    
    // Optional bloom filter for large datasets
    struct bloom* quick_filter;
    bool use_bloom;
    
    // Statistics
    struct {
        uint64_t checks;
        uint64_t bloom_hits;
        uint64_t bloom_misses;
        uint64_t found;
        uint64_t false_positives;
        time_t start_time;
    } stats;
    
    bool initialized;
    std::atomic<bool> stop_flag;
    
    // Helper functions
    bool computePatternPoint(uint64_t index, Point& result) const;
    void sortPatternTable();
    int binarySearchPattern(const unsigned char* xpoint_raw, uint64_t* found_indices, int* num_found);
    
    // Friend function for thread access
#ifdef _WIN64
    friend DWORD WINAPI thread_pattern_table_build(LPVOID vargp);
#else
    friend void* thread_pattern_table_build(void* vargp);
#endif
    
public:
    ExtremePatternIndex();
    ~ExtremePatternIndex();

    // Get origin point for external use
    Point getOriginPoint() const { return config.origin_pubkey; }
    bool shouldStop() const { return stop_flag; }
    
    // Initialize with pattern parameters
    bool initialize(const Point& origin, const Int& spacing, uint64_t num_keys);
    
    // Build the pattern table
    bool buildIndex(int num_threads = 1);
    
    // Check if a point matches our pattern
    bool checkKey(const Point& test_key, uint64_t& found_index, Int* original_offset = nullptr);
    
    // Batch checking for better performance
    int checkBatch(Point* test_keys, int batch_size, uint64_t* found_indices);
    
    // Get memory usage
    void getMemoryStats(uint64_t& total_bytes, double& bytes_per_key);
    
    // Display capacity table only
    static void displayCapacityTable();
    
    // Enable/disable stop on first find
    void setStopOnFirstFind(bool stop) { config.stop_on_first_find = stop; }
    
    // Save/Load pattern table for faster startup
    bool saveTable(const char* filename);
    bool loadTable(const char* filename);

    const PatternConfig& getConfig() const { return config; }
};

// Sorting functions for pattern table
void pattern_swap(struct pattern_table_entry *a, struct pattern_table_entry *b);
void pattern_sort(struct pattern_table_entry *arr, int64_t n);
void pattern_introsort(struct pattern_table_entry *arr, uint32_t depthLimit, int64_t n);
void pattern_insertionsort(struct pattern_table_entry *arr, int64_t n);
int64_t pattern_partition(struct pattern_table_entry *arr, int64_t n);
void pattern_heapify(struct pattern_table_entry *arr, int64_t n, int64_t i);
void pattern_heapsort(struct pattern_table_entry *arr, int64_t n);

// Global instance
extern ExtremePatternIndex* g_extreme_pattern_index;
extern Secp256K1* secp;
extern int NTHREADS;

// Global points for faster computation
extern Point* g_spacing_point;
extern Point* g_negated_spacing;


// High-level functions
bool initializeExtremeIndex(const char* params, const char* origin_pubkey_hex, int num_threads = 1);
void writeExtremeKey(uint64_t index, const Int& subtract_value, const Point& found_point, 
                     const Int* found_private_key, const Point& origin_point);

#endif
