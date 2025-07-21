#include "index.h"
#include "../util.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <algorithm>
#include <thread>
#include <vector>
#include <math.h>

#ifdef _WIN64
#include <windows.h>
#else
#include <pthread.h>
#endif

ExtremePatternIndex* g_extreme_pattern_index = nullptr;
extern Secp256K1* secp;
extern int NTHREADS;

Point* g_spacing_point = nullptr;
Point* g_negated_spacing = nullptr;

// Pattern table build thread
#ifdef _WIN64
static HANDLE* pattern_mutex = NULL;
#else
static pthread_mutex_t* pattern_mutex = NULL;
#endif

ExtremePatternIndex::ExtremePatternIndex() 
    : quick_filter(nullptr), use_bloom(false), patternTable(nullptr),
      table_size(0), step_size(1), initialized(false), stop_flag(false) {
    memset(&stats, 0, sizeof(stats));
    config.stop_on_first_find = true;
}

ExtremePatternIndex::~ExtremePatternIndex() {
    if (quick_filter) {
        bloom_free(quick_filter);
        free(quick_filter);
        quick_filter = nullptr;
    }
    
    if (patternTable) {
        free(patternTable);
        patternTable = nullptr;
    }
    
    // Clean up global spacing points
    if (g_spacing_point) {
        delete g_spacing_point;
        g_spacing_point = nullptr;
    }
    if (g_negated_spacing) {
        delete g_negated_spacing;
        g_negated_spacing = nullptr;
    }
}

bool ExtremePatternIndex::initialize(const Point& origin, const Int& spacing, uint64_t num_keys) {
    config.origin_pubkey = origin;
    config.spacing = spacing;
    config.num_keys = num_keys;
    
    // Calculate optimal step size based on available memory
    // Target: use at most 100MB for the pattern table
    const uint64_t max_table_bytes = 100 * 1024 * 1024; // 100MB
    const uint64_t bytes_per_entry = sizeof(struct pattern_table_entry);
    uint64_t max_entries = max_table_bytes / bytes_per_entry;
    
    if (num_keys <= max_entries) {
        // We can store every point
        step_size = 1;
        table_size = num_keys;
    } else {
        // Calculate step size to fit in memory
        step_size = (num_keys + max_entries - 1) / max_entries;
        table_size = (num_keys + step_size - 1) / step_size;
    }
    
    // Decide whether to use bloom filter
    use_bloom = (num_keys > 1000000); // Use bloom for > 1M keys
    
    if (use_bloom) {
        quick_filter = (struct bloom*)malloc(sizeof(struct bloom));
        if (!quick_filter) {
            fprintf(stderr, "[E] Failed to allocate bloom filter\n");
            return false;
        }
        
        // High false positive rate for minimal memory
        double fp_rate = 0.9; // 1% false positive rate
        if (bloom_init2(quick_filter, num_keys, fp_rate) != 0) {
            fprintf(stderr, "[E] Failed to initialize bloom filter\n");
            free(quick_filter);
            quick_filter = nullptr;
            return false;
        }
    }
    
    // Pre-compute spacing points for faster computation
    if (!g_spacing_point) {
        g_spacing_point = new Point();
        Int spacing_copy(config.spacing);
        *g_spacing_point = secp->ComputePublicKey(&spacing_copy);
        g_negated_spacing = new Point(secp->Negation(*g_spacing_point));
    }
    
    printf("[+] Extreme Pattern Index Configuration:\n");
    printf("    Number of keys: %llu\n", num_keys);
    printf("    Step size: %llu (storing every %llu points)\n", step_size, step_size);
    printf("    Table entries: %llu\n", table_size);
    
    Int spacing_copy(spacing);
    char* spacing_hex = spacing_copy.GetBase16();
    printf("    Spacing: 0x%s\n", spacing_hex);
    free(spacing_hex);
    
    stats.start_time = time(NULL);
    initialized = true;
    stop_flag = false;
    
    return true;
}

bool ExtremePatternIndex::computePatternPoint(uint64_t index, Point& result) const {
    if (index == 0 || index > config.num_keys) {
        return false;
    }
    
    // Calculate subtract value: index * spacing
    Int subtract_value;
    subtract_value.SetInt64(index);
    Int spacing_copy(config.spacing);
    subtract_value.Mult(&spacing_copy);
    
    // Compute public key for subtract value
    Point subtract_pubkey = secp->ComputePublicKey(&subtract_value);
    
    // Negate for subtraction
    Point negated = secp->Negation(subtract_pubkey);
    
    // Calculate result: origin - (index * spacing)
    Point origin_copy(config.origin_pubkey);
    result = secp->AddDirect(origin_copy, negated);
    
    return true;
}

bool ExtremePatternIndex::buildIndex(int num_threads) {
    if (!initialized) return false;
    
    // Allocate pattern table
    uint64_t bytes_needed = table_size * sizeof(struct pattern_table_entry);
    printf("[+] Allocating %.2f MB for pattern table (%llu entries)\n", 
           bytes_needed / (1024.0 * 1024.0), table_size);
    
    patternTable = (struct pattern_table_entry*)malloc(bytes_needed);
    if (!patternTable) {
        fprintf(stderr, "[E] Failed to allocate pattern table\n");
        return false;
    }
    
    printf("[+] Building pattern table using %d threads...\n", num_threads);
    
    // Initialize mutexes
#ifdef _WIN64
    pattern_mutex = (HANDLE*)calloc(num_threads, sizeof(HANDLE));
    for (int i = 0; i < num_threads; i++) {
        pattern_mutex[i] = CreateMutex(NULL, FALSE, NULL);
    }
#else
    pattern_mutex = (pthread_mutex_t*)calloc(num_threads, sizeof(pthread_mutex_t));
    for (int i = 0; i < num_threads; i++) {
        pthread_mutex_init(&pattern_mutex[i], NULL);
    }
#endif
    
    // Prepare thread data
    PatternTableBuildInfo* thread_info = (PatternTableBuildInfo*)calloc(num_threads, sizeof(PatternTableBuildInfo));
    uint64_t entries_per_thread = table_size / num_threads;
    uint64_t remainder = table_size % num_threads;
    
#ifdef _WIN64
    HANDLE* threads = (HANDLE*)calloc(num_threads, sizeof(HANDLE));
#else
    pthread_t* threads = (pthread_t*)calloc(num_threads, sizeof(pthread_t));
#endif
    
    // Launch threads
    uint64_t current_pos = 0;
    for (int i = 0; i < num_threads; i++) {
        thread_info[i].threadid = i;
        thread_info[i].from = current_pos;
        thread_info[i].to = current_pos + entries_per_thread;
        if (i == num_threads - 1) {
            thread_info[i].to += remainder;
        }
        thread_info[i].finished = 0;
        thread_info[i].parent = this;
        thread_info[i].table = patternTable;
        
        current_pos = thread_info[i].to;
        
#ifdef _WIN64
        DWORD thread_id;
        threads[i] = CreateThread(NULL, 0, thread_pattern_table_build, 
                                &thread_info[i], 0, &thread_id);
#else
        pthread_create(&threads[i], NULL, thread_pattern_table_build, 
                      &thread_info[i]);
#endif
    }
    
    // Wait for all threads to complete
    clock_t start_time = clock();
    uint32_t all_finished = 0;
    while (all_finished < num_threads) {
        all_finished = 0;
        for (int i = 0; i < num_threads; i++) {
#ifdef _WIN64
            WaitForSingleObject(pattern_mutex[i], INFINITE);
            all_finished += thread_info[i].finished;
            ReleaseMutex(pattern_mutex[i]);
#else
            pthread_mutex_lock(&pattern_mutex[i]);
            all_finished += thread_info[i].finished;
            pthread_mutex_unlock(&pattern_mutex[i]);
#endif
        }
        
        // Show progress
        uint64_t total_done = 0;
        for (int i = 0; i < num_threads; i++) {
            if (thread_info[i].finished) {
                total_done += (thread_info[i].to - thread_info[i].from);
            }
        }
        printf("\r[+] Building pattern table: %llu/%llu (%.1f%%)", 
               total_done, table_size, (double)total_done * 100.0 / table_size);
        fflush(stdout);
        
#ifdef _WIN64
        Sleep(100);
#else
        usleep(100000);
#endif
    }
    
    clock_t end_time = clock();
    double seconds = (double)(end_time - start_time) / CLOCKS_PER_SEC;
    printf("\n[+] Built pattern table in %.2f seconds\n", seconds);
    
    // Sort the table
    printf("[+] Sorting pattern table...\n");
    sortPatternTable();
    
    // Cleanup
#ifdef _WIN64
    for (int i = 0; i < num_threads; i++) {
        CloseHandle(threads[i]);
        CloseHandle(pattern_mutex[i]);
    }
#else
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
        pthread_mutex_destroy(&pattern_mutex[i]);
    }
#endif
    
    free(threads);
    free(thread_info);
    free(pattern_mutex);
    
    return true;
}

// Thread function to build pattern table
#ifdef _WIN64
DWORD WINAPI thread_pattern_table_build(LPVOID vargp)
#else
void* thread_pattern_table_build(void* vargp)
#endif
{
    PatternTableBuildInfo* info = (PatternTableBuildInfo*)vargp;
    ExtremePatternIndex* parent = info->parent;
    
    for (uint64_t i = info->from; i < info->to; i++) {
        uint64_t pattern_index = i * parent->step_size;
        if (pattern_index > parent->config.num_keys) break;
        
        Point pattern_point;
        parent->computePatternPoint(pattern_index, pattern_point);
        
        // Get X coordinate bytes
        unsigned char x_bytes[32];
        pattern_point.x.Get32Bytes(x_bytes);
        
        // Store 6 bytes from middle of X coordinate (like BSGS)
        memcpy(info->table[i].value, x_bytes + 16, 6);
        info->table[i].index = pattern_index;
        
        // Add to bloom filter if enabled
        if (parent->use_bloom && parent->quick_filter) {
            bloom_add(parent->quick_filter, x_bytes, 32);
        }
    }
    
    // Mark as finished
#ifdef _WIN64
    WaitForSingleObject(pattern_mutex[info->threadid], INFINITE);
    info->finished = 1;
    ReleaseMutex(pattern_mutex[info->threadid]);
#else
    pthread_mutex_lock(&pattern_mutex[info->threadid]);
    info->finished = 1;
    pthread_mutex_unlock(&pattern_mutex[info->threadid]);
#endif
    
    return NULL;
}

void ExtremePatternIndex::sortPatternTable() {
    pattern_sort(patternTable, table_size);
}

int ExtremePatternIndex::binarySearchPattern(const unsigned char* xpoint_raw, 
                                           uint64_t* found_indices, int* num_found) {
    *num_found = 0;
    
    // Extract search value (6 bytes from position 16)
    unsigned char search_value[6];
    memcpy(search_value, xpoint_raw + 16, 6);
    
    // Binary search
    int64_t left = 0, right = table_size - 1;
    int64_t first_match = -1;
    
    while (left <= right) {
        int64_t mid = (left + right) / 2;
        int cmp = memcmp(search_value, patternTable[mid].value, 6);
        
        if (cmp == 0) {
            first_match = mid;
            // Find first occurrence
            while (first_match > 0 && 
                   memcmp(search_value, patternTable[first_match - 1].value, 6) == 0) {
                first_match--;
            }
            break;
        } else if (cmp < 0) {
            right = mid - 1;
        } else {
            left = mid + 1;
        }
    }
    
    if (first_match == -1) {
        return 0; // Not found
    }
    
    // Collect all matching indices
    int64_t pos = first_match;
    while (pos < table_size && 
           memcmp(search_value, patternTable[pos].value, 6) == 0 && 
           *num_found < 10) { // Limit to 10 candidates
        found_indices[*num_found] = patternTable[pos].index;
        (*num_found)++;
        pos++;
    }
    
    return 1; // Found candidates
}

bool ExtremePatternIndex::checkKey(const Point& test_key, uint64_t& found_index, Int* original_offset) {
    if (!initialized || !patternTable) return false;
    
    stats.checks++;
    
    // Get X coordinate
    unsigned char xpoint_raw[32];
    Point test_key_copy(test_key);
    test_key_copy.x.Get32Bytes(xpoint_raw);
    
    // Quick bloom filter check
    if (use_bloom && quick_filter) {
        if (!bloom_check(quick_filter, xpoint_raw, 32)) {
            stats.bloom_misses++;
            return false;
        }
        stats.bloom_hits++;
    }
    
    // Binary search for candidates
    uint64_t candidate_indices[10];
    int num_candidates = 0;
    
    if (!binarySearchPattern(xpoint_raw, candidate_indices, &num_candidates)) {
        stats.false_positives++;
        return false;
    }
    
    // Check each candidate and nearby points
    for (int i = 0; i < num_candidates; i++) {
        uint64_t base_index = candidate_indices[i];
        
        // Check points around this index (within step_size)
        uint64_t start = (base_index > step_size) ? base_index - step_size : 0;
        uint64_t end = std::min(base_index + step_size, config.num_keys);
        
        for (uint64_t check_index = start; check_index <= end; check_index++) {
            Point check_point;
            if (!computePatternPoint(check_index, check_point)) {
                continue;
            }
            
            if (test_key_copy.x.IsEqual(&check_point.x) && 
                test_key_copy.y.IsEqual(&check_point.y)) {
                found_index = check_index;
                
                if (original_offset) {
                    original_offset->SetInt64(check_index);
                    Int spacing_copy(config.spacing);
                    original_offset->Mult(&spacing_copy);
                }
                
                stats.found++;
                
                if (config.stop_on_first_find) {
                    stop_flag = true;
                }
                
                return true;
            }
        }
    }
    
    stats.false_positives++;
    return false;
}

int ExtremePatternIndex::checkBatch(Point* test_keys, int batch_size, uint64_t* found_indices) {
    int matches = 0;
    
    for (int i = 0; i < batch_size; i++) {
        if (checkKey(test_keys[i], found_indices[i], nullptr)) {
            matches++;
        } else {
            found_indices[i] = 0; // 0 indicates no match
        }
        
        if (stop_flag) {
            break;
        }
    }
    
    return matches;
}

void ExtremePatternIndex::getMemoryStats(uint64_t& total_bytes, double& bytes_per_key) {
    total_bytes = sizeof(*this);
    
    if (patternTable) {
        total_bytes += table_size * sizeof(struct pattern_table_entry);
    }
    
    if (quick_filter) {
        total_bytes += quick_filter->bytes;
    }
    
    bytes_per_key = (double)total_bytes / config.num_keys;
}

void ExtremePatternIndex::displayCapacityTable() {
    printf("\n[+] Extreme Pattern Index Capacity Table:\n");
    printf("    ===================================\n");
    printf("    Pattern matching with binary search\n\n");
    
    printf("    Dataset Size   | Table Memory  | Step Size | Search Speed\n");
    printf("    ---------------|---------------|-----------|-------------\n");
    printf("    1 Million      | 12 MB         | 1         | O(log n)\n");
    printf("    10 Million     | 100 MB        | 1         | O(log n)\n");
    printf("    100 Million    | 100 MB        | 10        | O(log n)\n");
    printf("    1 Billion      | 100 MB        | 100       | O(log n)\n");
    printf("    10 Billion     | 100 MB        | 1000      | O(log n)\n");
    printf("    100 Billion    | 100 MB        | 10000     | O(log n)\n");
    
    printf("\n    Note: Memory usage is capped at ~100MB for the pattern table\n");
    printf("    Larger datasets use larger step sizes\n");
}

bool ExtremePatternIndex::saveTable(const char* filename) {
    FILE* fp = fopen(filename, "wb");
    if (!fp) return false;
    
    // Write header
    fwrite(&table_size, sizeof(uint64_t), 1, fp);
    fwrite(&step_size, sizeof(uint64_t), 1, fp);
    fwrite(&config.num_keys, sizeof(uint64_t), 1, fp);
    
    // Write spacing
    Int spacing_copy(config.spacing);
    char* spacing_hex = spacing_copy.GetBase16();
    uint32_t hex_len = strlen(spacing_hex);
    fwrite(&hex_len, sizeof(uint32_t), 1, fp);
    fwrite(spacing_hex, 1, hex_len, fp);
    free(spacing_hex);
    
    // Write origin point
    unsigned char origin_bytes[65];
    config.origin_pubkey.x.Get32Bytes(origin_bytes);
    config.origin_pubkey.y.Get32Bytes(origin_bytes + 32);
    origin_bytes[64] = config.origin_pubkey.y.IsEven() ? 0 : 1;
    fwrite(origin_bytes, 65, 1, fp);
    
    // Write table
    fwrite(patternTable, sizeof(struct pattern_table_entry), table_size, fp);
    
    fclose(fp);
    return true;
}

bool ExtremePatternIndex::loadTable(const char* filename) {
    FILE* fp = fopen(filename, "rb");
    if (!fp) return false;
    
    // Read header
    fread(&table_size, sizeof(uint64_t), 1, fp);
    fread(&step_size, sizeof(uint64_t), 1, fp);
    fread(&config.num_keys, sizeof(uint64_t), 1, fp);
    
    // Read spacing
    uint32_t hex_len;
    fread(&hex_len, sizeof(uint32_t), 1, fp);
    char* spacing_hex = (char*)malloc(hex_len + 1);
    fread(spacing_hex, 1, hex_len, fp);
    spacing_hex[hex_len] = '\0';
    config.spacing.SetBase16(spacing_hex);
    free(spacing_hex);
    
    // Read origin point
    unsigned char origin_bytes[65];
    fread(origin_bytes, 65, 1, fp);
    config.origin_pubkey.x.Set32Bytes(origin_bytes);
    config.origin_pubkey.y.Set32Bytes(origin_bytes + 32);
    if (origin_bytes[64]) {
        config.origin_pubkey.y.ModNeg();
    }
    
    // Allocate and read table
    uint64_t bytes_needed = table_size * sizeof(struct pattern_table_entry);
    patternTable = (struct pattern_table_entry*)malloc(bytes_needed);
    if (!patternTable) {
        fclose(fp);
        return false;
    }
    
    fread(patternTable, sizeof(struct pattern_table_entry), table_size, fp);
    
    fclose(fp);
    initialized = true;
    return true;
}

// Sorting functions (adapted from BSGS)
void pattern_swap(struct pattern_table_entry *a, struct pattern_table_entry *b) {
    struct pattern_table_entry t;
    t = *a;
    *a = *b;
    *b = t;
}

void pattern_sort(struct pattern_table_entry *arr, int64_t n) {
    uint32_t depthLimit = ((uint32_t)ceil(log(n))) * 2;
    pattern_introsort(arr, depthLimit, n);
}

void pattern_introsort(struct pattern_table_entry *arr, uint32_t depthLimit, int64_t n) {
    int64_t p;
    if (n > 1) {
        if (n <= 16) {
            pattern_insertionsort(arr, n);
        } else {
            if (depthLimit == 0) {
                pattern_heapsort(arr, n);
            } else {
                p = pattern_partition(arr, n);
                if (p > 0)
                    pattern_introsort(arr, depthLimit - 1, p);
                if (p < n)
                    pattern_introsort(&arr[p + 1], depthLimit - 1, n - (p + 1));
            }
        }
    }
}

void pattern_insertionsort(struct pattern_table_entry *arr, int64_t n) {
    int64_t j;
    int64_t i;
    struct pattern_table_entry key;
    for (i = 1; i < n; i++) {
        key = arr[i];
        j = i - 1;
        while (j >= 0 && memcmp(arr[j].value, key.value, 6) > 0) {
            arr[j + 1] = arr[j];
            j--;
        }
        arr[j + 1] = key;
    }
}

int64_t pattern_partition(struct pattern_table_entry *arr, int64_t n) {
    struct pattern_table_entry pivot;
    int64_t r, left, right;
    r = n / 2;
    pivot = arr[r];
    left = 0;
    right = n - 1;
    do {
        while (left < right && memcmp(arr[left].value, pivot.value, 6) <= 0) {
            left++;
        }
        while (right >= left && memcmp(arr[right].value, pivot.value, 6) > 0) {
            right--;
        }
        if (left < right) {
            if (left == r) {
                r = right;
            } else if (right == r) {
                r = left;
            }
            pattern_swap(&arr[right], &arr[left]);
        }
    } while (left < right);
    if (right != r) {
        pattern_swap(&arr[right], &arr[r]);
    }
    return right;
}

void pattern_heapify(struct pattern_table_entry *arr, int64_t n, int64_t i) {
    int64_t largest = i;
    int64_t l = 2 * i + 1;
    int64_t r = 2 * i + 2;
    if (l < n && memcmp(arr[l].value, arr[largest].value, 6) > 0)
        largest = l;
    if (r < n && memcmp(arr[r].value, arr[largest].value, 6) > 0)
        largest = r;
    if (largest != i) {
        pattern_swap(&arr[i], &arr[largest]);
        pattern_heapify(arr, n, largest);
    }
}

void pattern_heapsort(struct pattern_table_entry *arr, int64_t n) {
    int64_t i;
    for (i = (n / 2) - 1; i >= 0; i--) {
        pattern_heapify(arr, n, i);
    }
    for (i = n - 1; i > 0; i--) {
        pattern_swap(&arr[0], &arr[i]);
        pattern_heapify(arr, i, 0);
    }
}

// Global initialization function
bool initializeExtremeIndex(const char* params, const char* origin_pubkey_hex, int num_threads) {
    // Parse parameters
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
    
    // Parse origin public key
    Point origin;
    bool compressed = (strlen(origin_pubkey_hex) == 66);
    if (!secp->ParsePublicKeyHex((char*)origin_pubkey_hex, origin, compressed)) {
        fprintf(stderr, "[E] Failed to parse origin public key\n");
        return false;
    }
    
    // Create new index
    if (g_extreme_pattern_index) delete g_extreme_pattern_index;
    g_extreme_pattern_index = new ExtremePatternIndex();
    
    if (!g_extreme_pattern_index->initialize(origin, spacing, count)) {
        delete g_extreme_pattern_index;
        g_extreme_pattern_index = nullptr;
        return false;
    }
    
    ExtremePatternIndex::displayCapacityTable();
    
    // Build the index
    return g_extreme_pattern_index->buildIndex(num_threads);
}

// Write found key
void writeExtremeKey(uint64_t index, const Int& subtract_value, const Point& found_point, 
                    const Int* found_private_key, const Point& /*origin_point*/) {
    FILE* fp = fopen("KEYFOUNDKEYFOUND.txt", "a");
    if (fp) {
        Point point_copy(found_point);
        
        // Get hex strings
        Int subtract_copy(subtract_value);
        char* subtract_hex = subtract_copy.GetBase16();
        char* point_hex = secp->GetPublicKeyHex(true, point_copy);
        
        fprintf(fp, "Extreme Pattern Index - KEY FOUND!\n");
        fprintf(fp, "=====================================\n");
        fprintf(fp, "Pattern position: %llu\n", index);
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
            original_private_key.Set(&found_key_copy);
            
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
        printf("\n[+] Extreme Pattern Index - KEY FOUND!\n");
        printf("=====================================\n");
        printf("Pattern position: %llu\n", index);
        printf("Subtract value: 0x%s\n", subtract_hex);
        
        if (found_private_key) {
            Int found_key_copy(*found_private_key);
            char* found_private_hex = found_key_copy.GetBase16();
            printf("\nFOUND KEY PAIR (from database):\n");
            printf("Private Key: 0x%s\n", found_private_hex);
            printf("Public Key: %s\n", point_hex);
            
            // Calculate original
            Int original_private_key;
            original_private_key.Set(&found_key_copy);
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
