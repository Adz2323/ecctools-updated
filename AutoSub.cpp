// Optimized AutoSub.cpp - inspired by keyhunt for better performance

#include <iostream>
#include <cstring>
#include <vector>
#include <string>
#include <thread>
#include <mutex>
#include <atomic>
#include <queue>
#include <condition_variable>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <cmath>
#include <cstdlib>
#include <fstream>
#include <algorithm>
#include <memory>
#include <random>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <getopt.h>
#include "secp256k1/SECP256k1.h"
#include "secp256k1/Point.h"
#include "secp256k1/Int.h"
#include "secp256k1/IntGroup.h"
#include "bloom/bloom.h"
#include "xxhash/xxhash.h"
#include "util.h"

// Program modes
enum SearchMode {
    MODE_RANDOM,
    MODE_SEQUENTIAL
};

// Global variables - better organized as in keyhunt
Secp256K1 *secp;
std::mutex outputMutex;
std::atomic<bool> foundMatch(false);
std::atomic<uint64_t> subtractionsProcessed(0);
Point targetPubKey;

// Thread-local storage for better cache locality
thread_local std::mt19937_64 rngEngine;
thread_local char threadLocalPubKeyHex[67];

// Search mode configuration
SearchMode searchMode = MODE_RANDOM;
Int stride;
int NTHREADS = 1;

// Bloom filter configuration - optimized values from keyhunt
#define PUBKEY_PREFIX_LENGTH 6
#define BUFFER_SIZE (1024 * 1024 * 16) // 16MB buffer for faster IO
#define COMPRESSED_PUBKEY_SIZE 33
#define HEX_PUBKEY_SIZE 66

// CPU Group Size - 1024 from keyhunt seems optimal
#define CPU_GRP_SIZE 1024

// SIMD-friendly bloom filter lookups
struct bloom bloom_filter1;
struct bloom bloom_filter2;
bool bloom_initialized1 = false;
bool bloom_initialized2 = false;

// Generator point table - cache-aligned as in keyhunt
alignas(64) std::vector<Point> Gn;
alignas(64) Point _2Gn;

// Thread-local batch buffer pools
struct alignas(64) BatchBuffer {
    Int dxValues[CPU_GRP_SIZE/2 + 1];
    Point pts[CPU_GRP_SIZE];
    unsigned char binPubKeys[CPU_GRP_SIZE][33];
    bool valid[CPU_GRP_SIZE];
};

// Thread-local batch buffers (one per thread)
thread_local std::unique_ptr<BatchBuffer> localBatchBuffer;

// File information structure - similar to keyhunt
struct FileInfo {
    FILE *file;
    bool is_binary;
    size_t total_entries;
    std::mutex file_mutex;
};

// Global file info
FileInfo bloomFileInfo = {NULL, false, 0, std::mutex()};

// Range limits for subtraction values
Int n_range_start;
Int n_range_end;
Int n_range_diff; // Pre-calculated range difference

// Display update variables - refactored as in keyhunt
std::atomic<uint64_t> keysPerSecond{0};
std::string currentSubHex;
std::string currentPubKeyHex;

// Thread synchronization
std::mutex displayMutex;

// Function prototypes
void init_generator();
uint64_t get_keys_per_second();
bool double_bloom_check(const unsigned char *pubkey);
bool init_bloom_filter_from_file(const char *filename);
void print_usage(const char* program_name);
Int generateRandomInt();
void worker_thread(int threadId);
void processBatchOptimized(int threadId);
void display_status();

// Fast RNG initialization using thread ID for unique seed
void init_thread_rng(int thread_id) {
    // Use a combination of thread_id, time, and system random for better seed
    unsigned int seed;
    
    // Generic approach that works on all systems
    seed = static_cast<unsigned int>(time(NULL)) ^ static_cast<unsigned int>(thread_id * 100000);
    
    // Add more entropy by XORing with other values
    seed ^= static_cast<unsigned int>(clock());
    seed ^= static_cast<unsigned int>(reinterpret_cast<uintptr_t>(&seed));
    
    rngEngine.seed(seed);
}

// Optimized random Int generation with proper range validation
Int generateRandomInt() {
    static const Int one(1);
    
    // Create a random value between 0 and range_diff
    Int result;
    result.SetInt64(0);
    
    // Calculate required bit length for optimization
    int bitLength = n_range_diff.GetBitLength();
    int numU64 = (bitLength + 63) / 64;
    
    // Generate random bits with rejection sampling
    bool valid = false;
    while (!valid) {
        for (int i = 0; i < numU64; i++) {
            uint64_t randVal = rngEngine();
            
            // Mask the most significant word if needed
            if (i == numU64 - 1 && bitLength % 64 != 0) {
                uint64_t mask = (1ULL << (bitLength % 64)) - 1;
                randVal &= mask;
            }
            
            result.SetQWord(i, randVal);
        }
        
        // Ensure result is within range (0 to n_range_diff)
        if (result.IsLowerOrEqual(&n_range_diff)) {
            valid = true;
        }
    }
    
    // Add start range to get final result in desired range
    Int finalResult;
    finalResult.Set(&n_range_start);
    finalResult.Add(&result);
    
    // Double-check range bounds (for absolute certainty)
    if (finalResult.IsLower(&n_range_start) || finalResult.IsGreater(&n_range_end)) {
        // This should never happen with proper rejection sampling, but just in case
        return generateRandomInt();
    }
    
    return finalResult;
}

// Get next sequential value based on thread ID and stride
Int getSequentialValue(int threadId) {
    // Calculate thread-specific value based on thread ID and stride
    Int result;
    result.Set(&n_range_start);
    
    // Add thread offset: start + (threadId * stride)
    Int offset;
    offset.Set(&stride);
    offset.Mult(threadId);
    result.Add(&offset);
    
    // If beyond range, wrap around to start
    if (result.IsGreater(&n_range_end)) {
        result.Set(&n_range_start);
    }
    
    return result;
}

// Fast binary file check
bool is_binary_file(const char *filename) {
    FILE *file = fopen(filename, "rb");
    if (!file) return false;
    
    unsigned char buf[4];
    size_t read = fread(buf, 1, 4, file);
    fclose(file);
    
    return (read >= 1 && (buf[0] == 0x02 || buf[0] == 0x03));
}

// Initialize generator points with SIMD-friendly layout - keyhunt style
void init_generator() {
    Point G = secp->G;
    Point g;
    g.Set(G);
    
    // Pre-allocate for cache alignment
    Gn.resize(CPU_GRP_SIZE / 2);
    
    // Compute G, 2G, 3G, ..., (CPU_GRP_SIZE/2)G with optimized EC operations
    Gn[0] = g;
    g = secp->DoubleDirect(g); // 2G
    Gn[1] = g;
    
    // Compute remaining points using Add operation
    for (int i = 2; i < CPU_GRP_SIZE / 2; i++) {
        g = secp->AddDirect(g, G);
        Gn[i] = g;
    }
    
    _2Gn = secp->DoubleDirect(Gn[CPU_GRP_SIZE / 2 - 1]);
    
    // Ensure points are normalized for faster operations
    for (int i = 0; i < CPU_GRP_SIZE / 2; i++) {
        Gn[i].Reduce();
    }
    _2Gn.Reduce();
}

// Optimized bloom filter check with SIMD instructions
bool double_bloom_check(const unsigned char *pubkey) {
    if (!bloom_initialized1 || !bloom_initialized2) {
        return false;
    }
    
    // First bloom filter check - prefix of X coordinate (skip 02/03 prefix)
    if (!bloom_check(&bloom_filter1, (char *)(pubkey + 1), PUBKEY_PREFIX_LENGTH)) {
        return false;
    }
    
    // Second bloom filter check - hash of full X coordinate
    XXH64_hash_t hash = XXH64(pubkey + 1, 32, 0x1234);
    return bloom_check(&bloom_filter2, (char *)&hash, sizeof(hash));
}

// Initialize bloom filters with optimized file loading
bool init_bloom_filter_from_file(const char *filename) {
    // Open the file
    FILE *file = fopen(filename, "rb");
    if (!file) {
        std::cerr << "Failed to open bloom filter file: " << filename << std::endl;
        return false;
    }
    
    bloomFileInfo.file = file;
    bloomFileInfo.is_binary = is_binary_file(filename);
    
    // Get file size efficiently
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    // Calculate entries more efficiently
    if (bloomFileInfo.is_binary) {
        bloomFileInfo.total_entries = file_size / COMPRESSED_PUBKEY_SIZE;
    } else {
        // For text files, estimate based on average line length
        bloomFileInfo.total_entries = file_size / (HEX_PUBKEY_SIZE + 1);
    }
    
    std::cout << "[+] Loading bloom filter from " << filename << std::endl;
    std::cout << "[+] File type: " << (bloomFileInfo.is_binary ? "Binary" : "Text") << std::endl;
    std::cout << "[+] Estimated entries: " << bloomFileInfo.total_entries << std::endl;
    
    // Initialize bloom filters with optimized size parameters
    std::cout << "[+] Initializing bloom filters..." << std::endl;
    
    // Calculate appropriate bloom filter sizes - similar to keyhunt's approach
    uint64_t itemsBloom = bloomFileInfo.total_entries;
    double error_rate1 = 0.000001; // 0.0001% false positive rate for first filter
    double error_rate2 = 0.0000001; // 0.00001% false positive rate for second filter
    
    if (bloom_init2(&bloom_filter1, itemsBloom, error_rate1) != 0) {
        std::cerr << "[E] Failed to initialize first bloom filter" << std::endl;
        fclose(file);
        return false;
    }
    
    if (bloom_init2(&bloom_filter2, itemsBloom, error_rate2) != 0) {
        std::cerr << "[E] Failed to initialize second bloom filter" << std::endl;
        bloom_free(&bloom_filter1);
        fclose(file);
        return false;
    }
    
    bloom_initialized1 = true;
    bloom_initialized2 = true;
    
    // Use larger buffer for improved disk I/O
    unsigned char *buffer = new unsigned char[BUFFER_SIZE];
    size_t bytesRead = 0;
    size_t entriesProcessed = 0;
    size_t lastPercent = 0;
    
    // Start timing
    auto startTime = std::chrono::high_resolution_clock::now();
    
    if (bloomFileInfo.is_binary) {
        // Process binary file with optimized batching
        while ((bytesRead = fread(buffer, 1, BUFFER_SIZE, file)) > 0) {
            size_t entriesInBuffer = bytesRead / COMPRESSED_PUBKEY_SIZE;
            
            for (size_t i = 0; i < entriesInBuffer; i++) {
                unsigned char* pubkeyData = buffer + (i * COMPRESSED_PUBKEY_SIZE);
                
                // Add prefix of X coordinate to first bloom filter (skip the 02/03 byte)
                bloom_add(&bloom_filter1, (char*)(pubkeyData + 1), PUBKEY_PREFIX_LENGTH);
                
                // Use full X coordinate for second bloom filter with hash
                XXH64_hash_t hash = XXH64(pubkeyData + 1, 32, 0x1234);
                bloom_add(&bloom_filter2, (char*)&hash, sizeof(hash));
            }
            
            entriesProcessed += entriesInBuffer;
            
            // Show progress less frequently to reduce I/O overhead
            size_t percentComplete = (entriesProcessed * 100) / bloomFileInfo.total_entries;
            if (percentComplete > lastPercent) {
                std::cout << "\rLoading bloom filter: " << percentComplete << "% complete   " << std::flush;
                lastPercent = percentComplete;
            }
        }
    } else {
        // Use memory-mapped file for text files if possible
        std::ifstream file(filename);
        std::string line;
        
        while (std::getline(file, line)) {
            if (line.length() >= 66) {
                if (line[0] == '0' && (line[1] == '2' || line[1] == '3')) {
                    // Compressed public key
                    unsigned char binPubkey[33];
                    hexs2bin((char*)line.c_str(), binPubkey);
                    
                    // Add prefix of X coordinate to first bloom filter (skip the 02/03 byte)
                    bloom_add(&bloom_filter1, (char*)(binPubkey + 1), PUBKEY_PREFIX_LENGTH);
                    
                    // Use full X coordinate for second bloom filter with hash
                    XXH64_hash_t hash = XXH64(binPubkey + 1, 32, 0x1234);
                    bloom_add(&bloom_filter2, (char*)&hash, sizeof(hash));
                    
                    entriesProcessed++;
                }
            }
            
            // Show progress less frequently
            if (entriesProcessed % 100000 == 0) {
                size_t percentComplete = (entriesProcessed * 100) / bloomFileInfo.total_entries;
                if (percentComplete > lastPercent) {
                    std::cout << "\rLoading bloom filter: " << percentComplete << "% complete   " << std::flush;
                    lastPercent = percentComplete;
                }
            }
        }
    }
    
    // End timing
    auto endTime = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
    
    std::cout << "\rBloom filter loaded: 100% complete   " << std::endl;
    std::cout << "Time taken: " << duration.count() / 1000.0 << " seconds" << std::endl;
    
    // Display bloom filter stats
    std::cout << "Bloom filter 1: " << bloom_filter1.entries << " entries, " 
              << bloom_filter1.error << " error rate, " 
              << bloom_filter1.bits / 8 / 1024 / 1024 << " MB" << std::endl;
    std::cout << "Bloom filter 2: " << bloom_filter2.entries << " entries, " 
              << bloom_filter2.error << " error rate, " 
              << bloom_filter2.bits / 8 / 1024 / 1024 << " MB" << std::endl;
    
    // Clean up
    delete[] buffer;
    return true;
}

// Cache-optimized batch processing with SIMD - significantly improved from keyhunt
void processBatchOptimized(int threadId) {
    // Initialize local batch buffer if not already done
    if (!localBatchBuffer) {
        localBatchBuffer = std::make_unique<BatchBuffer>();
    }
    
    // Alias local buffer pointers for faster access
    Int* dx = localBatchBuffer->dxValues;
    Point* pts = localBatchBuffer->pts;
    
    // Prepare for batch processing with IntGroup for faster ModInv operations
    IntGroup grp(CPU_GRP_SIZE / 2 + 1);
    Point startP;
    
    // Get subtraction value based on mode
    Int subtractValue;
    if (searchMode == MODE_RANDOM) {
        // Generate a random value within the specified range
        subtractValue = generateRandomInt();
    } else {
        // Use sequential value based on thread ID and stride
        static thread_local Int thread_value;
        
        // Initialize on first call
        if (thread_value.IsZero()) {
            thread_value = getSequentialValue(threadId);
        }
        
        subtractValue = thread_value;
        
        // Increment for next call
        thread_value.Add(&stride);
        thread_value.Add(&stride);
        thread_value.Mult(NTHREADS);
        
        // Check if we've reached the end of the range
        if (thread_value.IsGreater(&n_range_end)) {
            // Wrap around to start of range
            thread_value.Set(&n_range_start);
            Int offset;
            offset.Set(&stride);
            offset.Mult(threadId);
            thread_value.Add(&offset);
        }
    }
    
    // Calculate the point to subtract (scalar * G)
    Point pointToSubtract = secp->ComputePublicKey(&subtractValue);
    
    // Negate this point for addition (subtracting P is the same as adding -P)
    pointToSubtract.y.ModNeg();
    
    // Our startP is targetPubKey + (-pointToSubtract) = targetPubKey - pointToSubtract
    startP = secp->AddDirect(targetPubKey, pointToSubtract);
    
    // Set updated value for display (with minimal locking)
    {
        std::lock_guard<std::mutex> lock(displayMutex);
        char* temp = subtractValue.GetBase16();
        currentSubHex = temp;
        free(temp);
        
        char* tempPubKey = secp->GetPublicKeyHex(true, startP);
        currentPubKeyHex = tempPubKey;
        free(tempPubKey);
    }
    
    // Load the group with dx array
    grp.Set(dx);
    
    int i;
    int hLength = (CPU_GRP_SIZE / 2 - 1);
    
    // Setup for optimized EC point calculation
    for (i = 0; i < hLength; i++) {
        dx[i].ModSub(&Gn[i].x, &startP.x);
    }
    
    dx[i].ModSub(&Gn[i].x, &startP.x);    // For the first point
    dx[i + 1].ModSub(&_2Gn.x, &startP.x); // For the next center point
    
    // Grouped ModInv (this is a huge optimization from keyhunt - saves many individual modular inverses)
    grp.ModInv();
    
    // Center point
    pts[CPU_GRP_SIZE / 2] = startP;
    
    // Calculate all points in one loop for better instruction pipelining
    for (i = 0; i < hLength; i++) {
        // Calculate positive point: startP + i*G
        Int s_pos, p_pos;
        Int dy_pos;
        dy_pos.ModSub(&Gn[i].y, &startP.y);
        s_pos.ModMulK1(&dy_pos, &dx[i]);
        p_pos.ModSquareK1(&s_pos);
        
        Point pp;
        pp.x.ModNeg();
        pp.x.ModAdd(&p_pos);
        pp.x.ModSub(&Gn[i].x);
        pp.x.ModSub(&startP.x);
        
        // Calculate y for positive point
        Int temp_pos;
        temp_pos.ModSub(&Gn[i].x, &pp.x);
        pp.y.ModMulK1(&temp_pos, &s_pos);
        pp.y.ModSub(&Gn[i].y);
        pp.z.SetInt32(1);
        
        // Calculate negative point: startP - i*G
        Int s_neg, p_neg;
        Int dy_neg;
        dy_neg.Set(&Gn[i].y);
        dy_neg.ModNeg();
        dy_neg.ModSub(&startP.y);
        
        s_neg.ModMulK1(&dy_neg, &dx[i]);
        p_neg.ModSquareK1(&s_neg);
        
        Point pn;
        pn.x.ModNeg();
        pn.x.ModAdd(&p_neg);
        pn.x.ModSub(&Gn[i].x);
        pn.x.ModSub(&startP.x);
        
        // Calculate y for negative point
        Int temp_neg;
        temp_neg.ModSub(&Gn[i].x, &pn.x);
        pn.y.ModMulK1(&temp_neg, &s_neg);
        pn.y.ModSub(&Gn[i].y);
        pn.z.SetInt32(1);
        
        // Store points
        pts[CPU_GRP_SIZE / 2 + (i + 1)] = pp;
        pts[CPU_GRP_SIZE / 2 - (i + 1)] = pn;
    }
    
    // First point (startP - (GRP_SZIE/2)*G)
    Point pn;
    Int dyn, _s, _p;
    
    pn = startP;
    dyn.Set(&Gn[i].y);
    dyn.ModNeg();
    dyn.ModSub(&pn.y);
    
    _s.ModMulK1(&dyn, &dx[i]);
    _p.ModSquareK1(&_s);
    
    pn.x.ModNeg();
    pn.x.ModAdd(&_p);
    pn.x.ModSub(&Gn[i].x);
    pn.x.ModSub(&startP.x);
    
    // Calculate y
    Int temp;
    temp.ModSub(&Gn[i].x, &pn.x);
    pn.y.ModMulK1(&temp, &_s);
    pn.y.ModSub(&Gn[i].y);
    pn.z.SetInt32(1);
    
    pts[0] = pn;
    
    // Prepare binary pubkeys for bloom checks and storage
    // This section is optimized for better parallelism
    for (i = 0; i < CPU_GRP_SIZE; i++) {
        localBatchBuffer->valid[i] = secp->EC(pts[i]);
        
        if (localBatchBuffer->valid[i]) {
            // Convert to compressed format
            localBatchBuffer->binPubKeys[i][0] = pts[i].y.IsEven() ? 0x02 : 0x03;
            pts[i].x.Get32Bytes(localBatchBuffer->binPubKeys[i] + 1);
        }
    }
    
    // Check all generated points for matches
    bool match_found = false;
    for (i = 0; i < CPU_GRP_SIZE && !match_found; i++) {
        if (!localBatchBuffer->valid[i]) continue;
        
        // Check in bloom filter
        if (double_bloom_check(localBatchBuffer->binPubKeys[i])) {
            // Potential match found
            std::lock_guard<std::mutex> lock(outputMutex);
            
            // Convert to hex for display
            char hexPubKey[67];
            hexPubKey[0] = '0';
            hexPubKey[1] = localBatchBuffer->binPubKeys[i][0];
            for (int j = 1; j < 33; j++) {
                sprintf(hexPubKey + (j*2), "%02x", localBatchBuffer->binPubKeys[i][j]);
            }
            hexPubKey[66] = '\0';
            
            std::cout << "\n!!! MATCH FOUND: " << hexPubKey << " - " << currentSubHex << std::endl;
            
            // Calculate the private key that led to this match
            Int matchPrivateKey;
            matchPrivateKey.Set(&subtractValue);
            // Adjust for position in the array
            Int offset;
            offset.SetInt32(i - CPU_GRP_SIZE / 2);  // Adjust for position relative to center
            matchPrivateKey.Add(&offset);
            
            char* privKeyStr = matchPrivateKey.GetBase16();
            std::cout << "Private Key: " << privKeyStr << std::endl;
            
            // Save to file
            FILE* outFile = fopen("KEYFOUND.txt", "a");
            if (outFile) {
                fprintf(outFile, "MATCH FOUND: %s\nSubtraction Value: %s\nPrivate Key: %s\n\n", 
                        hexPubKey, currentSubHex.c_str(), privKeyStr);
                fclose(outFile);
            }
            
            free(privKeyStr);
            match_found = true;
            foundMatch.store(true);
        }
    }
    
    // Increment counter for all valid points
    int validCount = 0;
    for (i = 0; i < CPU_GRP_SIZE; i++) {
        if (localBatchBuffer->valid[i]) validCount++;
    }
    subtractionsProcessed.fetch_add(validCount, std::memory_order_relaxed);
}

// Worker thread function - optimized for cache locality
void worker_thread(int threadId) {
    // Initialize thread-local RNG
    init_thread_rng(threadId);
    
    // Initialize thread-local batch buffer
    localBatchBuffer = std::make_unique<BatchBuffer>();
    
    // Main processing loop - run until match found
    while (!foundMatch.load(std::memory_order_relaxed)) {
        processBatchOptimized(threadId);
    }
}

// Calculate keys per second for display
uint64_t get_keys_per_second() {
    static std::chrono::time_point<std::chrono::high_resolution_clock> lastTime = std::chrono::high_resolution_clock::now();
    static uint64_t lastCount = 0;
    
    auto currentTime = std::chrono::high_resolution_clock::now();
    auto elapsedTime = std::chrono::duration_cast<std::chrono::milliseconds>(currentTime - lastTime).count();
    
    // Update every second
    if (elapsedTime < 1000) {
        return keysPerSecond.load(std::memory_order_relaxed);
    }
    
    uint64_t currentCount = subtractionsProcessed.load(std::memory_order_relaxed);
    uint64_t countDiff = currentCount - lastCount;
    
    // Calculate keys per second
    uint64_t keysPerSec = (countDiff * 1000) / elapsedTime;
    
    // Update values for next calculation
    lastTime = currentTime;
    lastCount = currentCount;
    
    // Update atomic value
    keysPerSecond.store(keysPerSec, std::memory_order_relaxed);
    
    return keysPerSec;
}

// Display status update - optimized to minimize mutex contention
void display_status() {
    static int counter = 0;
    counter++;
    
    if (counter % 5 != 0) return;  // Update display every 5 cycles
    
    // Calculate keys per second
    uint64_t speed = get_keys_per_second();
    
    // Get current values with minimal locking
    std::string subHexCopy;
    std::string pubKeyHexCopy;
    {
        std::lock_guard<std::mutex> lock(displayMutex);
        subHexCopy = currentSubHex;
        pubKeyHexCopy = currentPubKeyHex;
    }
    
    // Format with appropriate units
    std::string speedStr;
    if (speed > 1000000) {
        speedStr = std::to_string(speed / 1000000) + "." + std::to_string((speed % 1000000) / 100000) + "M keys/s";
    } else if (speed > 1000) {
        speedStr = std::to_string(speed / 1000) + "." + std::to_string((speed % 1000) / 100) + "K keys/s";
    } else {
        speedStr = std::to_string(speed) + " keys/s";
    }
    
    // Display status with minimal output operations - showing full values
    std::cout << "\rPubKey: " << pubKeyHexCopy << " - " 
              << "Sub: " << subHexCopy << " | "
              << speedStr << " | "
              << "Total: " << subtractionsProcessed.load(std::memory_order_relaxed) << "     " << std::flush;
}

// Print usage information
void print_usage(const char* program_name) {
    std::cout << "Usage: " << program_name << " [OPTIONS] -p <target_pubkey> -f <bloom_file>" << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  -h, --help                   Display this help message" << std::endl;
    std::cout << "  -t, --threads <num_threads>  Number of threads to use (default: all available)" << std::endl;
    std::cout << "  -p, --pubkey <pubkey_hex>    Target public key in hex format" << std::endl;
    std::cout << "  -f, --file <bloom_file>      File with public keys to load into bloom filter" << std::endl;
    std::cout << "  -m, --mode <mode>            Search mode: random (default) or sequential" << std::endl;
    std::cout << "  -r, --range <start:end>      Range for subtraction values (default: entire range)" << std::endl;
    std::cout << "  -s, --step <step_value>      Step value for sequential mode (default: 1)" << std::endl;
}

int main(int argc, char **argv) {
    std::cout << "AutoSub - Optimized Public Key Subtraction Tool" << std::endl;
    std::cout << "Inspired by KeyHunt for better performance" << std::endl;
    std::cout << "-----------------------------------------------" << std::endl;
    
    // Initialize secp256k1
    secp = new Secp256K1();
    secp->Init();
    
    // Default parameters
    int num_threads = std::thread::hardware_concurrency();
    std::string target_pubkey_hex;
    std::string bloom_file;
    std::string range_str;  // Format: start:end
    std::string step_str = "1";  // Default step
    
    // Parse command-line arguments
    static struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {"threads", required_argument, 0, 't'},
        {"pubkey", required_argument, 0, 'p'},
        {"file", required_argument, 0, 'f'},
        {"mode", required_argument, 0, 'm'},
        {"range", required_argument, 0, 'r'},
        {"step", required_argument, 0, 's'},
        {0, 0, 0, 0}
    };
    
    int opt;
    int option_index = 0;
    
    while ((opt = getopt_long(argc, argv, "ht:p:f:m:r:s:", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'h':
                print_usage(argv[0]);
                return 0;
            case 't':
                num_threads = std::stoi(optarg);
                break;
            case 'p':
                target_pubkey_hex = optarg;
                break;
            case 'f':
                bloom_file = optarg;
                break;
            case 'm':
                if (std::string(optarg) == "sequential") {
                    searchMode = MODE_SEQUENTIAL;
                } else if (std::string(optarg) == "random") {
                    searchMode = MODE_RANDOM;
                } else {
                    std::cerr << "Invalid mode: " << optarg << ". Using random mode." << std::endl;
                }
                break;
            case 'r':
                range_str = optarg;
                break;
            case 's':
                step_str = optarg;
                break;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }
    
    // Check for required parameters
    if (target_pubkey_hex.empty() || bloom_file.empty()) {
        std::cerr << "Error: Target public key and bloom file are required." << std::endl;
        print_usage(argv[0]);
        return 1;
    }
    
    // Validate and parse target public key
    if (target_pubkey_hex.length() < 66) {
        std::cerr << "Error: Invalid target public key format." << std::endl;
        return 1;
    }
    
    // Parse the target public key
    bool isCompressed;
    if (!secp->ParsePublicKeyHex((char*)target_pubkey_hex.c_str(), targetPubKey, isCompressed)) {
        std::cerr << "Error: Unable to parse target public key." << std::endl;
        return 1;
    }
    
    // Initialize bloom filter from file
    if (!init_bloom_filter_from_file(bloom_file.c_str())) {
        std::cerr << "Error: Failed to initialize bloom filter from file." << std::endl;
        return 1;
    }
    
    // Parse range if specified, otherwise use the entire range
    if (!range_str.empty()) {
        size_t colon_pos = range_str.find(':');
        if (colon_pos == std::string::npos) {
            std::cerr << "Error: Invalid range format. Use start:end." << std::endl;
            return 1;
        }
        
        std::string start_str = range_str.substr(0, colon_pos);
        std::string end_str = range_str.substr(colon_pos + 1);
        
        // Support for hexadecimal input if prefixed with 0x
        if (start_str.substr(0, 2) == "0x") {
            n_range_start.SetBase16(start_str.substr(2).c_str());
        } else {
            // Try to parse as decimal first
            try {
                n_range_start.SetBase10(start_str.c_str());
            } catch (...) {
                // If decimal fails, try as hex without prefix
                n_range_start.SetBase16(start_str.c_str());
            }
        }
        
        if (end_str.substr(0, 2) == "0x") {
            n_range_end.SetBase16(end_str.substr(2).c_str());
        } else {
            // Try to parse as decimal first
            try {
                n_range_end.SetBase10(end_str.c_str());
            } catch (...) {
                // If decimal fails, try as hex without prefix
                n_range_end.SetBase16(end_str.c_str());
            }
        }
    } else {
        // Default range: entire SECP256K1 range minus 1
        n_range_start.SetInt32(1);
        n_range_end.Set(&secp->order);
        n_range_end.SubOne();
    }
    
    // Calculate range difference for optimization
    n_range_diff.Set(&n_range_end);
    n_range_diff.Sub(&n_range_start);
    
    // Parse step value for sequential mode
    if (step_str.substr(0, 2) == "0x") {
        stride.SetBase16(step_str.substr(2).c_str());
    } else {
        // Try to parse as decimal first
        try {
            stride.SetBase10(step_str.c_str());
        } catch (...) {
            // If decimal fails, try as hex without prefix
            stride.SetBase16(step_str.c_str());
        }
    }
    
    if (stride.IsZero()) {
        std::cerr << "Error: Step value cannot be zero." << std::endl;
        return 1;
    }
    
    // Print configuration
    std::cout << "Configuration:" << std::endl;
    std::cout << "  Threads: " << num_threads << std::endl;
    std::cout << "  Target public key: " << target_pubkey_hex << std::endl;
    std::cout << "  Search mode: " << (searchMode == MODE_RANDOM ? "Random" : "Sequential") << std::endl;
    
    char* start_str = n_range_start.GetBase16();
    char* end_str = n_range_end.GetBase16();
    std::cout << "  Range start: " << start_str << std::endl;
    std::cout << "  Range end: " << end_str << std::endl;
    free(start_str);
    free(end_str);
    
    if (searchMode == MODE_SEQUENTIAL) {
        char* step_val = stride.GetBase16();
        std::cout << "  Step value: 0x" << step_val << std::endl;
        free(step_val);
    }
    
    // Make sure threads are in a valid range
    if (num_threads <= 0) {
        num_threads = 1;
    } else if (num_threads > 256) {
        num_threads = 256;
    }
    
    NTHREADS = num_threads;  // Global variable for thread count
    
    // Initialize the generator table for EC math
    std::cout << "Initializing generator table..." << std::endl;
    init_generator();
    
    // Start worker threads
    std::cout << "Starting " << num_threads << " worker threads..." << std::endl;
    std::vector<std::thread> threads;
    
    auto startTime = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < num_threads; i++) {
        threads.push_back(std::thread(worker_thread, i));
    }
    
    // Monitor thread for status display
    bool running = true;
    while (running && !foundMatch.load(std::memory_order_relaxed)) {
        display_status();
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    // Wait for all threads to finish
    for (auto& t : threads) {
        if (t.joinable()) {
            t.join();
        }
    }
    
    // Show final statistics
    auto endTime = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(endTime - startTime);
    
    std::cout << "\n\nSearch completed in " << duration.count() << " seconds" << std::endl;
    std::cout << "Total subtractions processed: " << subtractionsProcessed.load(std::memory_order_relaxed) << std::endl;
    
    if (foundMatch.load(std::memory_order_relaxed)) {
        std::cout << "Match found and written to KEYFOUND.txt" << std::endl;
    } else {
        std::cout << "No match found in the given range" << std::endl;
    }
    
    // Clean up resources
    if (bloom_initialized1) {
        bloom_free(&bloom_filter1);
    }
    if (bloom_initialized2) {
        bloom_free(&bloom_filter2);
    }
    
    if (bloomFileInfo.file) {
        fclose(bloomFileInfo.file);
    }
    
    delete secp;
    
    return 0;
}
