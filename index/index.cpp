#include "index.h"
#include "util.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <algorithm>
#include <thread>
#include <vector>

#ifdef _WIN64
#include <windows.h>
#else
#include <pthread.h>
#endif

ExtremeBloomIndex* g_extreme_index = nullptr;
extern Secp256K1* secp;
extern int NTHREADS;

// MurmurHash3 helper functions
static inline uint64_t rotl64(uint64_t x, int8_t r) {
    return (x << r) | (x >> (64 - r));
}

static uint64_t fmix64(uint64_t k) {
    k ^= k >> 33;
    k *= 0xff51afd7ed558ccdULL;
    k ^= k >> 33;
    k *= 0xc4ceb9fe1a85ec53ULL;
    k ^= k >> 33;
    return k;
}

ExtremeBloomIndex::ExtremeBloomIndex() 
    : layer1(nullptr), layer2(nullptr), layer3(nullptr), 
      mini_hashes(nullptr), mini_hash_count(0), mini_hash_mutex(nullptr),
      initialized(false), stop_flag(false) {
    memset(&stats, 0, sizeof(stats));
    memset(bloom_mutexes, 0, sizeof(bloom_mutexes));
    
    // Set default false positive rates (much lower than before)
    config.fpp_layer1 = 0.01;   // 1% instead of 25%
    config.fpp_layer2 = 0.001;  // 0.1% instead of 50%
    config.fpp_layer3 = 0.0001; // 0.01% instead of 70%
    config.stop_on_first_find = true;
}

ExtremeBloomIndex::~ExtremeBloomIndex() {
    if (layer1) { bloom_free(layer1); free(layer1); }
    if (layer2) { bloom_free(layer2); free(layer2); }
    if (layer3) { bloom_free(layer3); free(layer3); }
    if (mini_hashes) free(mini_hashes);
    
    // Clean up mutexes
#ifdef _WIN64
    if (mini_hash_mutex) CloseHandle((HANDLE)mini_hash_mutex);
    for (int layer = 0; layer < 3; layer++) {
        for (int i = 0; i < 256; i++) {
            if (bloom_mutexes[layer][i]) 
                CloseHandle((HANDLE)bloom_mutexes[layer][i]);
        }
    }
#else
    if (mini_hash_mutex) {
        pthread_mutex_destroy((pthread_mutex_t*)mini_hash_mutex);
        free(mini_hash_mutex);
    }
    for (int layer = 0; layer < 3; layer++) {
        for (int i = 0; i < 256; i++) {
            if (bloom_mutexes[layer][i]) {
                pthread_mutex_destroy((pthread_mutex_t*)bloom_mutexes[layer][i]);
                free(bloom_mutexes[layer][i]);
            }
        }
    }
#endif
}

void ExtremeBloomIndex::setFalsePositiveRates(double fpp1, double fpp2, double fpp3) {
    config.fpp_layer1 = fpp1;
    config.fpp_layer2 = fpp2;
    config.fpp_layer3 = fpp3;
}

uint64_t ExtremeBloomIndex::hash1(const uint8_t* data, uint64_t index) {
    uint64_t h = 0x9e3779b97f4a7c15ULL;
    h ^= *(uint64_t*)data;
    h ^= index;
    return fmix64(h);
}

uint64_t ExtremeBloomIndex::hash2(const uint8_t* data, uint64_t index) {
    uint64_t h = 0x517cc1b727220a95ULL;
    h ^= *(uint64_t*)(data + 8);
    h ^= rotl64(index, 17);
    return fmix64(h);
}

uint64_t ExtremeBloomIndex::hash3(const uint8_t* data, uint64_t index) {
    uint64_t h = 0x85ebca6b0c1c4e91ULL;
    h ^= *(uint64_t*)(data + 16);
    h ^= rotl64(index, 31);
    return fmix64(h);
}

uint32_t ExtremeBloomIndex::mini_hash(const uint8_t* data, uint64_t index) {
    uint32_t h = 0x9e3779b9;
    h ^= *(uint32_t*)data;
    h ^= (uint32_t)index;
    h *= 0x85ebca6b;
    h ^= h >> 16;
    return h;
}

bool ExtremeBloomIndex::initialize(const Point& origin, const Int& spacing, uint64_t num_keys) {
    config.origin_pubkey = origin;
    config.spacing = spacing;
    config.num_keys = num_keys;
    config.bloom_layers = 3;
    
    // Initialize bloom filters with better false positive rates
    layer1 = (struct bloom*)calloc(1, sizeof(struct bloom));
    if (!layer1) return false;
    
    if (bloom_init2(layer1, num_keys, config.fpp_layer1) != 0) {
        fprintf(stderr, "[E] Failed to initialize layer 1 bloom\n");
        return false;
    }
    
    // Layer 2: Expect fewer keys to pass layer 1
    layer2 = (struct bloom*)calloc(1, sizeof(struct bloom));
    if (!layer2) return false;
    
    uint64_t layer2_size = (uint64_t)(num_keys * config.fpp_layer1);
    if (layer2_size < 1000) layer2_size = 1000;
    
    if (bloom_init2(layer2, layer2_size, config.fpp_layer2) != 0) {
        fprintf(stderr, "[E] Failed to initialize layer 2 bloom\n");
        return false;
    }
    
    // Layer 3: Expect even fewer keys
    layer3 = (struct bloom*)calloc(1, sizeof(struct bloom));
    if (!layer3) return false;
    
    uint64_t layer3_size = (uint64_t)(layer2_size * config.fpp_layer2);
    if (layer3_size < 1000) layer3_size = 1000;
    
    if (bloom_init2(layer3, layer3_size, config.fpp_layer3) != 0) {
        fprintf(stderr, "[E] Failed to initialize layer 3 bloom\n");
        return false;
    }
    
    // Mini hashes for final verification
    mini_hash_count = (uint64_t)(layer3_size * config.fpp_layer3 * 10); // Reserve extra space
    if (mini_hash_count < 10000) mini_hash_count = 10000;
    
    // Don't pre-allocate all mini hashes - we'll collect them during build
    
    // Initialize mutexes
#ifdef _WIN64
    mini_hash_mutex = CreateMutex(NULL, FALSE, NULL);
    for (int layer = 0; layer < 3; layer++) {
        for (int i = 0; i < 256; i++) {
            bloom_mutexes[layer][i] = CreateMutex(NULL, FALSE, NULL);
        }
    }
#else
    mini_hash_mutex = malloc(sizeof(pthread_mutex_t));
    pthread_mutex_init((pthread_mutex_t*)mini_hash_mutex, NULL);
    for (int layer = 0; layer < 3; layer++) {
        for (int i = 0; i < 256; i++) {
            bloom_mutexes[layer][i] = malloc(sizeof(pthread_mutex_t));
            pthread_mutex_init((pthread_mutex_t*)bloom_mutexes[layer][i], NULL);
        }
    }
#endif
    
    printf("[+] Extreme Bloom Index Configuration:\n");
    printf("    Number of keys: %llu\n", num_keys);
    printf("    Layer 1: %.2f MB (FPP: %.2f%%)\n", 
           layer1->bytes / (1024.0 * 1024.0), config.fpp_layer1 * 100);
    printf("    Layer 2: %.2f MB (FPP: %.2f%%)\n", 
           layer2->bytes / (1024.0 * 1024.0), config.fpp_layer2 * 100);
    printf("    Layer 3: %.2f MB (FPP: %.2f%%)\n", 
           layer3->bytes / (1024.0 * 1024.0), config.fpp_layer3 * 100);
    
    uint64_t total = layer1->bytes + layer2->bytes + layer3->bytes;
    printf("    Total bloom memory: %.2f MB\n", total / (1024.0 * 1024.0));
    
    stats.start_time = time(NULL);
    initialized = true;
    stop_flag = false;
    
    return true;
}

// Thread function for building bloom filters
void* ExtremeBloomIndex::threadBuildBloom(void* vargp) {
    BloomLoadData* data = (BloomLoadData*)vargp;
    ExtremeBloomIndex* index = (ExtremeBloomIndex*)data->config;
    std::vector<uint32_t> local_mini_hashes;
    local_mini_hashes.reserve(1000);
    
    Point currentPoint;
    uint8_t x_coord[32];
    uint8_t data1[40], data2[16], data3[12];
    
    // Process assigned range
    for (uint64_t i = data->from; i < data->to && !data->should_stop->load(); i++) {
        // Calculate subtracted point: origin - (i * spacing)
        Int subtract_value;
        subtract_value.SetInt64(i);
        subtract_value.Mult(&data->config->spacing);
        
        Point subtract_pubkey = secp->ComputePublicKey(&subtract_value);
        Point negated = secp->Negation(subtract_pubkey);
        currentPoint = secp->AddDirect(data->config->origin_pubkey, negated);
        
        currentPoint.x.Get32Bytes(x_coord);
        
        // Layer 1
        memcpy(data1, x_coord, 32);
        memcpy(data1 + 32, &i, 8);
        
        uint8_t prefix = x_coord[0];
#ifdef _WIN64
        WaitForSingleObject((HANDLE)index->bloom_mutexes[0][prefix], INFINITE);
        bloom_add(data->bloom_filters[0], data1, 40);
        ReleaseMutex((HANDLE)index->bloom_mutexes[0][prefix]);
#else
        pthread_mutex_lock((pthread_mutex_t*)index->bloom_mutexes[0][prefix]);
        bloom_add(data->bloom_filters[0], data1, 40);
        pthread_mutex_unlock((pthread_mutex_t*)index->bloom_mutexes[0][prefix]);
#endif
        
        // Check if it passes layer 1
        if (bloom_check(data->bloom_filters[0], data1, 40)) {
            // Layer 2
            uint64_t h2 = index->hash2(x_coord, i);
            *(uint64_t*)data2 = h2;
            *(uint64_t*)(data2 + 8) = i;
            
#ifdef _WIN64
            WaitForSingleObject((HANDLE)index->bloom_mutexes[1][prefix], INFINITE);
            bloom_add(data->bloom_filters[1], data2, 16);
            ReleaseMutex((HANDLE)index->bloom_mutexes[1][prefix]);
#else
            pthread_mutex_lock((pthread_mutex_t*)index->bloom_mutexes[1][prefix]);
            bloom_add(data->bloom_filters[1], data2, 16);
            pthread_mutex_unlock((pthread_mutex_t*)index->bloom_mutexes[1][prefix]);
#endif
            
            // Check if it passes layer 2
            if (bloom_check(data->bloom_filters[1], data2, 16)) {
                // Layer 3
                uint64_t h3 = index->hash3(x_coord, i);
                *(uint64_t*)data3 = h3;
                *(uint32_t*)(data3 + 8) = (uint32_t)i;
                
#ifdef _WIN64
                WaitForSingleObject((HANDLE)index->bloom_mutexes[2][prefix], INFINITE);
                bloom_add(data->bloom_filters[2], data3, 12);
                ReleaseMutex((HANDLE)index->bloom_mutexes[2][prefix]);
#else
                pthread_mutex_lock((pthread_mutex_t*)index->bloom_mutexes[2][prefix]);
                bloom_add(data->bloom_filters[2], data3, 12);
                pthread_mutex_unlock((pthread_mutex_t*)index->bloom_mutexes[2][prefix]);
#endif
                
                // Collect mini hash
                uint32_t mh = index->mini_hash(x_coord, i);
                local_mini_hashes.push_back(mh);
            }
        }
        
        // Progress update every 10000 keys
        if (i % 10000 == 0 && data->thread_id == 0) {
            printf("\r[+] Thread %d: Progress %llu/%llu (%.1f%%)", 
                   data->thread_id, i - data->from, data->to - data->from,
                   (double)(i - data->from) * 100.0 / (data->to - data->from));
            fflush(stdout);
        }
    }
    
    // Merge local mini hashes into global array
    if (!local_mini_hashes.empty()) {
#ifdef _WIN64
        WaitForSingleObject((HANDLE)data->mini_hash_mutex, INFINITE);
#else
        pthread_mutex_lock((pthread_mutex_t*)data->mini_hash_mutex);
#endif
        
        // Append to mini hashes vector
        data->mini_hashes->insert(data->mini_hashes->end(), 
                                 local_mini_hashes.begin(), 
                                 local_mini_hashes.end());
        
#ifdef _WIN64
        ReleaseMutex((HANDLE)data->mini_hash_mutex);
#else
        pthread_mutex_unlock((pthread_mutex_t*)data->mini_hash_mutex);
#endif
    }
    
    data->finished = 1;
    return NULL;
}

bool ExtremeBloomIndex::buildIndex(int num_threads) {
    if (!initialized) return false;
    
    if (num_threads <= 0) num_threads = 1;
    if (num_threads > 256) num_threads = 256; // Reasonable limit
    
    printf("[+] Building extreme bloom index for %llu keys using %d threads...\n", 
           config.num_keys, num_threads);
    
    clock_t start = clock();
    
    // Prepare bloom filter array for threads
    struct bloom* bloom_array[3] = { layer1, layer2, layer3 };
    
    // Temporary vector to collect mini hashes
    std::vector<uint32_t> all_mini_hashes;
    
    // Set up thread data
    std::vector<BloomLoadData> thread_data(num_threads);
    uint64_t keys_per_thread = config.num_keys / num_threads;
    uint64_t remainder = config.num_keys % num_threads;
    
#ifdef _WIN64
    std::vector<HANDLE> threads(num_threads);
#else
    std::vector<pthread_t> threads(num_threads);
#endif
    
    // Launch threads
    uint64_t current_from = 0;
    for (int i = 0; i < num_threads; i++) {
        thread_data[i].thread_id = i;
        thread_data[i].from = current_from;
        thread_data[i].workload = keys_per_thread + (i < (int)remainder ? 1 : 0);
        thread_data[i].to = current_from + thread_data[i].workload;
        thread_data[i].config = &config;
        thread_data[i].bloom_filters = bloom_array;
        thread_data[i].mini_hashes = &all_mini_hashes;
        thread_data[i].mini_hash_count = &mini_hash_count;
        thread_data[i].should_stop = &stop_flag;
        thread_data[i].finished = 0;
        thread_data[i].mini_hash_mutex = mini_hash_mutex;
        
        current_from = thread_data[i].to;
        
#ifdef _WIN64
        threads[i] = CreateThread(NULL, 0, 
                                 (LPTHREAD_START_ROUTINE)threadBuildBloom, 
                                 &thread_data[i], 0, NULL);
#else
        pthread_create(&threads[i], NULL, threadBuildBloom, &thread_data[i]);
#endif
    }
    
    // Wait for all threads to complete
    for (int i = 0; i < num_threads; i++) {
#ifdef _WIN64
        WaitForSingleObject(threads[i], INFINITE);
        CloseHandle(threads[i]);
#else
        pthread_join(threads[i], NULL);
#endif
    }
    
    // Sort and store mini hashes
    std::sort(all_mini_hashes.begin(), all_mini_hashes.end());
    mini_hash_count = all_mini_hashes.size();
    
    if (mini_hashes) free(mini_hashes);
    mini_hashes = (uint32_t*)malloc(mini_hash_count * sizeof(uint32_t));
    memcpy(mini_hashes, all_mini_hashes.data(), mini_hash_count * sizeof(uint32_t));
    
    clock_t end = clock();
    double seconds = (double)(end - start) / CLOCKS_PER_SEC;
    
    printf("\n[+] Built index in %.2f seconds (%.2f million keys/sec)\n",
           seconds, config.num_keys / seconds / 1e6);
    printf("[+] Mini hashes collected: %llu\n", mini_hash_count);
    
    displayStats();
    return true;
}

bool ExtremeBloomIndex::checkKey(const Point& test_key, uint64_t& found_index, Int* original_private_key) {
    if (!initialized) return false;
    
    stats.checks++;
    
    Point test_key_copy(test_key);
    uint8_t x_coord[32];
    test_key_copy.x.Get32Bytes(x_coord);
    
    // Try all possible indices with progressive filtering
    for (uint64_t i = 0; i < config.num_keys; i++) {
        // Layer 1 check
        uint8_t data1[40];
        memcpy(data1, x_coord, 32);
        memcpy(data1 + 32, &i, 8);
        
        if (!bloom_check(layer1, data1, 40)) {
            continue;
        }
        
        stats.layer1_hits++;
        
        // Layer 2 check
        uint8_t data2[16];
        *(uint64_t*)data2 = hash2(x_coord, i);
        *(uint64_t*)(data2 + 8) = i;
        
        if (!bloom_check(layer2, data2, 16)) {
            continue;
        }
        
        stats.layer2_hits++;
        
        // Layer 3 check
        uint8_t data3[12];
        *(uint64_t*)data3 = hash3(x_coord, i);
        *(uint32_t*)(data3 + 8) = (uint32_t)i;
        
        if (!bloom_check(layer3, data3, 12)) {
            continue;
        }
        
        stats.layer3_hits++;
        
        // Final verification - check mini hash
        uint32_t mh = mini_hash(x_coord, i);
        if (!std::binary_search(mini_hashes, mini_hashes + mini_hash_count, mh)) {
            continue;
        }
        
        // Ultimate verification - reconstruct and compare
        stats.reconstructions++;
        
        Int subtract_value;
        subtract_value.SetInt64(i);
        subtract_value.Mult(&config.spacing);
        
        Point subtract_pubkey = secp->ComputePublicKey(&subtract_value);
        Point negated = secp->Negation(subtract_pubkey);
        Point reconstructed = secp->AddDirect(config.origin_pubkey, negated);
        
        Int test_x_copy(test_key_copy.x);
        if (reconstructed.x.IsEqual(&test_x_copy)) {
            stats.found++;
            found_index = i;
            
            // Calculate original private key if requested
            if (original_private_key) {
                // The original private key = database_private_key + (index * spacing)
                // Since we found that: origin_pubkey - (index * spacing) = database_pubkey
                // Then: origin_private = database_private + (index * spacing)
                original_private_key->Set(&subtract_value);
            }
            
            // Set stop flag if configured
            if (config.stop_on_first_find) {
                stop_flag = true;
            }
            
            return true;
        }
    }
    
    return false;
}

void ExtremeBloomIndex::getMemoryStats(uint64_t& total_bytes, double& bytes_per_key) {
    total_bytes = 0;
    if (layer1) total_bytes += layer1->bytes;
    if (layer2) total_bytes += layer2->bytes;
    if (layer3) total_bytes += layer3->bytes;
    total_bytes += mini_hash_count * sizeof(uint32_t);
    
    bytes_per_key = (double)total_bytes / config.num_keys;
}

void ExtremeBloomIndex::displayStats() {
    uint64_t total_bytes;
    double bytes_per_key;
    getMemoryStats(total_bytes, bytes_per_key);
    
    printf("\n[+] Extreme Bloom Index Statistics:\n");
    printf("    ================================\n");
    printf("    Total memory: %.2f MB\n", total_bytes / (1024.0 * 1024.0));
    printf("    Bits per key: %.3f\n", bytes_per_key * 8);
    printf("    Bytes per key: %.4f\n", bytes_per_key);
    
    if (stats.checks > 0) {
        printf("\n    Filter cascade performance:\n");
        printf("    Layer 1 hits: %llu (%.2f%% pass rate)\n", 
               stats.layer1_hits, (double)stats.layer1_hits * 100 / stats.checks);
        if (stats.layer1_hits > 0) {
            printf("    Layer 2 hits: %llu (%.2f%% of L1)\n", 
                   stats.layer2_hits, (double)stats.layer2_hits * 100 / stats.layer1_hits);
        }
        if (stats.layer2_hits > 0) {
            printf("    Layer 3 hits: %llu (%.2f%% of L2)\n", 
                   stats.layer3_hits, (double)stats.layer3_hits * 100 / stats.layer2_hits);
        }
        printf("    Reconstructions: %llu\n", stats.reconstructions);
        printf("    Keys found: %llu\n", stats.found);
    }
}

void ExtremeBloomIndex::displayCapacityTable() {
    printf("\n[+] Extreme Bloom Index Capacity Table:\n");
    printf("    ===================================\n");
    printf("    (With improved false positive rates)\n\n");
    
    double bits_per_key = 8.0;  // More realistic with better FPP
    double bytes_per_key = bits_per_key / 8.0;
    
    uint64_t gb = 1024ULL * 1024 * 1024;
    
    printf("    Memory     |  Capacity\n");
    printf("    -----------|-----------------\n");
    for (uint64_t mem_gb = 1; mem_gb <= 512; mem_gb *= 2) {
        uint64_t capacity = (mem_gb * gb) / (uint64_t)(bytes_per_key);
        if (capacity >= 1000000000000) {
            printf("    %3llu GB     |  %.1f trillion keys\n", 
                   mem_gb, capacity / 1000000000000.0);
        } else {
            printf("    %3llu GB     |  %llu billion keys\n", 
                   mem_gb, capacity / 1000000000);
        }
    }
    printf("    1 TB       |  %.1f trillion keys\n", 
           (1024 * gb) / (uint64_t)(bytes_per_key) / 1000000000000.0);
}

// Global functions
bool initializeExtremeIndex(const char* params, const char* origin_pubkey_hex, int num_threads) {
    char* params_copy = strdup(params);
    char* token = strtok(params_copy, " ");
    
    uint64_t count = strtoull(token, NULL, 10);
    token = strtok(NULL, " ");
    
    Int spacing;
    if (token[0] == '0' && token[1] == 'x') {
        spacing.SetBase16(token + 2);
    } else {
        spacing.SetBase10(token);
    }
    
    free(params_copy);
    
    Point origin;
    bool compressed = (strlen(origin_pubkey_hex) == 66);
    if (!secp->ParsePublicKeyHex((char*)origin_pubkey_hex, origin, compressed)) {
        fprintf(stderr, "[E] Failed to parse origin public key\n");
        return false;
    }
    
    if (g_extreme_index) delete g_extreme_index;
    g_extreme_index = new ExtremeBloomIndex();
    
    // You can set custom FPP rates here if needed
    // g_extreme_index->setFalsePositiveRates(0.001, 0.0001, 0.00001);
    
    if (!g_extreme_index->initialize(origin, spacing, count)) {
        delete g_extreme_index;
        g_extreme_index = nullptr;
        return false;
    }
    
    ExtremeBloomIndex::displayCapacityTable();
    
    // Use the provided number of threads
    return g_extreme_index->buildIndex(num_threads > 0 ? num_threads : NTHREADS);
}

void writeExtremeKey(uint64_t index, const Int& subtract_value, const Point& found_point, const Int* found_private_key, const Point& origin_point) {
    FILE* fp = fopen("KEYFOUNDKEYFOUND.txt", "a");
    if (fp) {
        Point point_copy(found_point);
        
        // Make non-const copies for GetBase16()
        Int subtract_copy(subtract_value);
        char* subtract_hex = subtract_copy.GetBase16();
        char* point_hex = secp->GetPublicKeyHex(true, point_copy);
        
        fprintf(fp, "Extreme Bloom Index - KEY FOUND!\n");
        fprintf(fp, "=====================================\n");
        fprintf(fp, "Index: %llu\n", index);
        fprintf(fp, "Subtract value: 0x%s\n", subtract_hex);
        fprintf(fp, "\n");
        
        // If we have the found private key, show the found key pair
        if (found_private_key) {
            Int found_key_copy(*found_private_key);
            char* found_private_hex = found_key_copy.GetBase16();
            fprintf(fp, "FOUND KEY PAIR (from database):\n");
            fprintf(fp, "Private Key: 0x%s\n", found_private_hex);
            fprintf(fp, "Public Key: %s\n", point_hex);
            fprintf(fp, "\n");
            
            // Calculate and show the original key pair
            Int original_private_key;
            original_private_key.Set(&found_key_copy);  // Use the non-const copy
            
            // Make a non-const copy of subtract_value for Add
            Int subtract_for_add(subtract_value);
            original_private_key.Add(&subtract_for_add);
            
            char* original_private_hex = original_private_key.GetBase16();
            Point original_public_key = secp->ComputePublicKey(&original_private_key);
            char* original_public_hex = secp->GetPublicKeyHex(true, original_public_key);
            
            fprintf(fp, "ORIGINAL KEY PAIR (target):\n");
            fprintf(fp, "Private Key: 0x%s\n", original_private_hex);
            fprintf(fp, "Public Key: %s\n", original_public_hex);
            fprintf(fp, "=====================================\n\n");
            
            free(found_private_hex);
            free(original_private_hex);
            free(original_public_hex);
        }
        
        fclose(fp);
        
        // Also print to console
        printf("\n[+] Extreme Bloom Index - KEY FOUND!\n");
        printf("=====================================\n");
        printf("Index: %llu\n", index);
        printf("Subtract value: 0x%s\n", subtract_hex);
        
        if (found_private_key) {
            Int found_key_copy(*found_private_key);
            char* found_private_hex = found_key_copy.GetBase16();
            printf("\nFOUND KEY PAIR (from database):\n");
            printf("Private Key: 0x%s\n", found_private_hex);
            printf("Public Key: %s\n", point_hex);
            
            // Calculate and show the original key pair
            Int original_private_key;
            original_private_key.Set(&found_key_copy);  // Use the non-const copy
            
            // Make a non-const copy of subtract_value for Add
            Int subtract_for_add(subtract_value);
            original_private_key.Add(&subtract_for_add);
            
            char* original_private_hex = original_private_key.GetBase16();
            Point original_public_key = secp->ComputePublicKey(&original_private_key);
            char* original_public_hex = secp->GetPublicKeyHex(true, original_public_key);
            
            printf("\nORIGINAL KEY PAIR (target):\n");
            printf("Private Key: 0x%s\n", original_private_hex);
            printf("Public Key: %s\n", original_public_hex);
            printf("=====================================\n\n");
            
            free(found_private_hex);
            free(original_private_hex);
            free(original_public_hex);
        }
        
        free(subtract_hex);
        free(point_hex);
    }
}
