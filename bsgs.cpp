/*
Developed by Alberto (modified version with multi-target optimization)
email: albertobsd@gmail.com
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <vector>
#include <inttypes.h>
#include "base58/libbase58.h"
#include "rmd160/rmd160.h"
#include "oldbloom/oldbloom.h"
#include "bloom/bloom.h"
#include "sha3/sha3.h"
#include "util.h"

#include "secp256k1/SECP256k1.h"
#include "secp256k1/Point.h"
#include "secp256k1/Int.h"
#include "secp256k1/IntGroup.h"
#include "secp256k1/Random.h"

#include "hash/sha256.h"
#include "hash/ripemd160.h"

#if defined(_WIN64) && !defined(__CYGWIN__)
#include "getopt.h"
#include <windows.h>
#else
#include <unistd.h>
#include <pthread.h>
#include <sys/random.h>
#endif

#ifdef __unix__
#ifdef __CYGWIN__
#else
#include <linux/random.h>
#endif
#endif

#define MODE_BSGS 2

uint32_t  THREADBPWORKLOAD = 1048576;

struct checksumsha256 {
    char data[32];
    char backup[32];
};

struct bsgs_xvalue {
    uint8_t value[6];
    uint64_t index;
};

struct tothread {
    int nt;     // Number thread
    char *rs;   // range start
    char *rpt;  // rng per thread
};

struct bPload {
    uint32_t threadid;
    uint64_t from;
    uint64_t to;
    uint64_t counter;
    uint64_t workload;
    uint32_t aux;
    uint32_t finished;
};

// Multi-target specific structures
struct MultiTargetState {
    std::vector<Point> current_points;      // Current point for each target during giant steps
    std::vector<bool> found;               // Which targets have been found
    std::vector<Int> found_keys;           // Found private keys
};
    
const char *version = "0.3.240516 Satoshi Quest Multi-Target Edition";
const char *default_fileName = "targets.txt";

#define CPU_GRP_SIZE 1024

std::vector<Point> Gn;
Point _2Gn;

std::vector<Point> GSn;
Point _2GSn;

void menu();
void init_generator();
void sleep_ms(int milliseconds);

void bsgs_sort(struct bsgs_xvalue *arr, int64_t n);
void bsgs_myheapsort(struct bsgs_xvalue *arr, int64_t n);
void bsgs_insertionsort(struct bsgs_xvalue *arr, int64_t n);
void bsgs_introsort(struct bsgs_xvalue *arr, uint32_t depthLimit, int64_t n);
void bsgs_swap(struct bsgs_xvalue *a, struct bsgs_xvalue *b);
void bsgs_heapify(struct bsgs_xvalue *arr, int64_t n, int64_t i);
int64_t bsgs_partition(struct bsgs_xvalue *arr, int64_t n);

int bsgs_searchbinary(struct bsgs_xvalue *arr, char *data, int64_t array_length, uint64_t *r_value);
int bsgs_secondcheck_multitarget(Int *start_range, uint32_t a, int target_idx, Int *privatekey);
int bsgs_thirdcheck_multitarget(Int *start_range, uint32_t a, int target_idx, Int *privatekey);

void writekey(bool compressed, Int *key);
void checkpointer(void *ptr, const char *file, const char *function, const char *name, int line);

bool readFileTargets(char *fileName);

bool parsePublicKeyHex(const char *pubKeyHex, Point &pubKey, bool &compressed);

void calcualteindex(int i, Int *key);
void *thread_process_bsgs_multi_target(void *vargp);
void *thread_process_bsgs_random_multi_target(void *vargp);
void *thread_bPload_multi_target(void *vargp);
void *thread_bPload_2blooms_multi_target(void *vargp);
void *thread_process_bsgs_subtract_multi_target(void *vargp);
void *thread_process_bsgs_subtract_random_multi_target(void *vargp);
void writeBloomFilters();

char *publickeytohashrmd160(char *pkey, int length);
void publickeytohashrmd160_dst(char *pkey, int length, char *dst);
char *pubkeytopubaddress(char *pkey, int length);
void pubkeytopubaddress_dst(char *pkey, int length, char *dst);
void rmd160toaddress_dst(char *rmd, char *dst);

int THREADOUTPUT = 0;
char *bit_range_str_min;
char *bit_range_str_max;

const char *bsgs_modes[5] = {"sequential", "backward", "both", "random", "subtract"};

pthread_t *tid = NULL;
pthread_mutex_t write_keys;
pthread_mutex_t write_random;
pthread_mutex_t mutex_bsgs_thread;
pthread_mutex_t *bPload_mutex = NULL;

uint64_t FINISHED_THREADS_COUNTER = 0;
uint64_t FINISHED_THREADS_BP = 0;
uint64_t THREADCYCLES = 0;
uint64_t THREADCOUNTER = 0;
uint64_t FINISHED_ITEMS = 0;
uint64_t OLDFINISHED_ITEMS = -1;

uint8_t byte_encode_crypto = 0x00;        /* Bitcoin  */

struct bloom bloom;

uint64_t N = 0;

uint64_t N_SEQUENTIAL_MAX = 0x100000000;
uint64_t DEBUGCOUNT = 0x400;
uint64_t u64range;

Int BSGSkeyfound;

int FLAGSKIPCHECKSUM = 0;
int FLAGBSGSMODE = 0;
int FLAGDEBUG = 0;
int FLAGQUIET = 0;
int KFACTOR = 1;
int MAXLENGTHADDRESS = 20;
int NTHREADS = 1;
int FLAGMULTITARGET = 1; // Enable multi-target by default

Point ORIGIN_PUBKEY; // To store the origin public key
bool FLAGORIGINSET = 0; // Flag to indicate if origin pubkey is set

int FLAGSAVEREADFILE = 0;
int FLAGREADEDFILE1 = 0;
int FLAGREADEDFILE2 = 0;
int FLAGREADEDFILE3 = 0;
int FLAGREADEDFILE4 = 0;
int FLAGUPDATEFILE1 = 0;

int FLAGBITRANGE = 0;
int FLAGRANGE = 0;
int FLAGMODE = MODE_BSGS;
int FLAG_N = 0;

int bitrange;
char *str_N;
char *range_start;
char *range_end;
char *str_stride;
Int stride;

uint64_t BSGS_XVALUE_RAM = 6;
uint64_t BSGS_BUFFERXPOINTLENGTH = 32;
uint64_t BSGS_BUFFERREGISTERLENGTH = 36;

/*
BSGS Variables
*/
int *bsgs_found;
std::vector<Point> OriginalPointsBSGS;
bool *OriginalPointsBSGScompressed;
uint32_t bsgs_point_number = 0;

// Multi-target state
MultiTargetState *multi_target_state = NULL;

uint64_t bytes;
char checksum[32], checksum_backup[32];
char buffer_bloom_file[1024];
struct bsgs_xvalue *bPtable;

struct oldbloom oldbloom_bP;

struct bloom *bloom_bP;
struct bloom *bloom_bPx2nd; // 2nd Bloom filter check
struct bloom *bloom_bPx3rd; // 3rd Bloom filter check

struct checksumsha256 *bloom_bP_checksums;
struct checksumsha256 *bloom_bPx2nd_checksums;
struct checksumsha256 *bloom_bPx3rd_checksums;

pthread_mutex_t *bloom_bP_mutex;
pthread_mutex_t *bloom_bPx2nd_mutex;
pthread_mutex_t *bloom_bPx3rd_mutex;

uint64_t bloom_bP_totalbytes = 0;
uint64_t bloom_bP2_totalbytes = 0;
uint64_t bloom_bP3_totalbytes = 0;
uint64_t bsgs_m = 4194304;
uint64_t bsgs_m2;
uint64_t bsgs_m3;
uint64_t bsgs_aux;

const char *str_limits_prefixs[7] = {"Mkeys/s", "Gkeys/s", "Tkeys/s", "Pkeys/s", "Ekeys/s", "Zkeys/s", "Ykeys/s"};
const char *str_limits[7] = {"1000000", "1000000000", "1000000000000", "1000000000000000", "1000000000000000000", "1000000000000000000000", "1000000000000000000000000"};
Int int_limits[7];

Int BSGS_GROUP_SIZE;
Int BSGS_CURRENT;
Int BSGS_R;
Int BSGS_AUX;
Int BSGS_N;
Int BSGS_M;                  // M is squareroot(N)
Int BSGS_M_double;
Int BSGS_M2;                // M2 is M/32
Int BSGS_M2_double;          // M2_double is M2 * 2

Int BSGS_M3;                // M3 is M2/32
Int BSGS_M3_double;          // M3_double is M3 * 2

Int ONE;
Int ZERO;
Int MPZAUX;

Point BSGS_P;           // Original P is actually G, but this P value change over time for calculations
Point BSGS_MP;          // MP values this is m * P
Point BSGS_MP2;         // MP2 values this is m2 * P
Point BSGS_MP3;         // MP3 values this is m3 * P

Point BSGS_MP_double;          // MP2 values this is m2 * P * 2
Point BSGS_MP2_double;         // MP2 values this is m2 * P * 2
Point BSGS_MP3_double;         // MP3 values this is m3 * P * 2

std::vector<Point> BSGS_AMP2;
std::vector<Point> BSGS_AMP3;

Point point_temp, point_temp2;    // Temp value for some process

Int n_range_start;
Int n_range_end;
Int n_range_diff;
Int n_range_aux;

Secp256K1 *secp;

uint64_t *steps = NULL;
unsigned int *ends = NULL;

bool parsePublicKeyHex(const char *pubKeyHex, Point &pubKey, bool &compressed) {
    std::string key_str = pubKeyHex;
    
    // Trim whitespace
    key_str.erase(0, key_str.find_first_not_of(" \t"));
    key_str.erase(key_str.find_last_not_of(" \t") + 1);
    
    // Validate key format
    if (key_str.length() == 66) {
        if (key_str[0] != '0' || (key_str[1] != '2' && key_str[1] != '3')) {
            fprintf(stderr, "[E] Invalid compressed public key format\n");
            return false;
        }
        compressed = true;
    } else if (key_str.length() == 130) {
        if (key_str[0] != '0' || key_str[1] != '4') {
            fprintf(stderr, "[E] Invalid uncompressed public key format\n");
            return false;
        }
        compressed = false;
    } else {
        fprintf(stderr, "[E] Invalid public key length: %zu\n", key_str.length());
        return false;
    }
    
    // Parse the public key
    if (!secp->ParsePublicKeyHex((char*)key_str.c_str(), pubKey, compressed)) {
        fprintf(stderr, "[E] Unable to parse public key\n");
        return false;
    }
    
    // Verify the point is on the curve
    if (!secp->EC(pubKey)) {
        fprintf(stderr, "[E] Public key is not a valid point on the curve\n");
        return false;
    }
    
    return true;
}

bool readFileTargets(char *fileName) {
    FILE *fd;
    char buffer[1024];
    Tokenizer t;
    
    // Check if file is binary based on extension
    bool isBinary = false;
    const char *extension = strrchr(fileName, '.');
    if (extension && strcasecmp(extension, ".bin") == 0) {
        isBinary = true;
    }
    
    printf("[+] Opening file %s as %s format\n", fileName, isBinary ? "binary" : "text");
    fd = fopen(fileName, "rb");
    if(fd == NULL) {
        fprintf(stderr, "[E] Can't open file %s\n", fileName);
        return false;
    }
    
    // Count valid entries or determine file size for binary
    int count = 0;
    
    if(isBinary) {
        // For binary files, determine size to allocate memory
        fseek(fd, 0, SEEK_END);
        long fileSize = ftell(fd);
        fseek(fd, 0, SEEK_SET);
        
        // Each compressed public key is 33 bytes
        count = fileSize / 33;
        
        if(count == 0 || fileSize % 33 != 0) {
            fprintf(stderr, "[E] Invalid binary file size: %ld bytes (not a multiple of 33 bytes)\n", fileSize);
            fclose(fd);
            return false;
        }
    } else {
        // Text file - count lines with valid public keys
        while(fgets(buffer, sizeof(buffer), fd)) {
            trim(buffer, " \t\n\r");
            if(strlen(buffer) >= 66) { // At least the length of a compressed public key
                count++;
            }
        }
        
        if(count == 0) {
            fprintf(stderr, "[E] No valid public keys in file\n");
            fclose(fd);
            return false;
        }
        
        // Reset file position
        fseek(fd, 0, SEEK_SET);
    }
    
    // Allocate memory
    OriginalPointsBSGS.reserve(count);
    OriginalPointsBSGScompressed = (bool*)malloc(count * sizeof(bool));
    if (!OriginalPointsBSGScompressed) {
        fprintf(stderr, "[E] Memory allocation failed\n");
        fclose(fd);
        return false;
    }
    
    // Initialize points array with default values
    for (int i = 0; i < count; i++) {
        OriginalPointsBSGS.push_back(Point());
    }
    
    // Read public keys
    int i = 0;
    
    if(isBinary) {
        // Binary format - read 33-byte compressed keys
        unsigned char binBuffer[33];
        char hexBuffer[67]; // 66 chars for hex + null terminator
        
        while(i < count && fread(binBuffer, 1, 33, fd) == 33) {
            // Check if it's a valid compressed key format (starts with 0x02 or 0x03)
            if(binBuffer[0] != 0x02 && binBuffer[0] != 0x03) {
                fprintf(stderr, "[W] Invalid compressed key format at position %d, skipping\n", i);
                continue;
            }
            
            // Convert binary to hex for parsing with existing function
            hexBuffer[0] = '0';
            hexBuffer[1] = (binBuffer[0] == 0x02) ? '2' : '3';
            
            for(int j = 1; j < 33; j++) {
                sprintf(hexBuffer + 2 + (j-1)*2, "%02x", binBuffer[j]);
            }
            hexBuffer[66] = '\0';
            
            OriginalPointsBSGScompressed[i] = true; // All keys in binary format are compressed
            
            if(secp->ParsePublicKeyHex(hexBuffer, OriginalPointsBSGS[i], OriginalPointsBSGScompressed[i])) {
                i++;
            } else {
                fprintf(stderr, "[W] Failed to parse key at position %d, skipping\n", i);
            }
        }
    } else {
        // Text format - read one key per line
        while(fgets(buffer, sizeof(buffer), fd) && i < count) {
            trim(buffer, " \t\n\r");
            if(strlen(buffer) >= 66) {
                if(secp->ParsePublicKeyHex(buffer, OriginalPointsBSGS[i], OriginalPointsBSGScompressed[i])) {
                    i++;
                }
            }
        }
    }
    
    bsgs_point_number = i;
    printf("[+] Added %d points from file\n", bsgs_point_number);
    fclose(fd);
    
    // Allocate bsgs_found array
    bsgs_found = (int*)calloc(bsgs_point_number, sizeof(int));
    if(!bsgs_found) {
        fprintf(stderr, "[E] Memory allocation failed for bsgs_found\n");
        return false;
    }
    
    // Initialize multi-target state
    multi_target_state = new MultiTargetState();
    multi_target_state->current_points.resize(bsgs_point_number);
    multi_target_state->found.resize(bsgs_point_number, false);
    multi_target_state->found_keys.resize(bsgs_point_number);
    
    return true;
}

void writeBloomFilters() {
    FILE *fileDescriptor;
    char fileBloomName[1024];
    
    // Save bloom_bP (first bloom filter)
    snprintf(fileBloomName, 1024, "keyhunt_bsgs_4_%" PRIu64 ".blm", bsgs_m);
    fileDescriptor = fopen(fileBloomName, "wb");
    if(fileDescriptor != NULL) {
        printf("[+] Writing bloom filter to file %s ", fileBloomName);
        fflush(stdout);
        
        // Writing 256 bloom filters
        for(int i = 0; i < 256; i++) {
            // Write bloom filter structure
            fwrite(&bloom_bP[i], sizeof(struct bloom), 1, fileDescriptor);
            
            // Write bloom filter data
            fwrite(bloom_bP[i].bf, bloom_bP[i].bytes, 1, fileDescriptor);
            
            // Calculate and write checksum
            sha256((uint8_t*)bloom_bP[i].bf, bloom_bP[i].bytes, (uint8_t*)bloom_bP_checksums[i].data);
            memcpy(bloom_bP_checksums[i].backup, bloom_bP_checksums[i].data, 32);
            fwrite(&bloom_bP_checksums[i], sizeof(struct checksumsha256), 1, fileDescriptor);
            
            if(i % 64 == 0) {
                printf(".");
                fflush(stdout);
            }
        }
        printf(" Done!\n");
        fclose(fileDescriptor);
    }
    
    // Save bloom_bPx2nd (second bloom filter)
    snprintf(fileBloomName, 1024, "keyhunt_bsgs_6_%" PRIu64 ".blm", bsgs_m2);
    fileDescriptor = fopen(fileBloomName, "wb");
    if(fileDescriptor != NULL) {
        printf("[+] Writing bloom filter to file %s ", fileBloomName);
        fflush(stdout);
        
        for(int i = 0; i < 256; i++) {
            fwrite(&bloom_bPx2nd[i], sizeof(struct bloom), 1, fileDescriptor);
            fwrite(bloom_bPx2nd[i].bf, bloom_bPx2nd[i].bytes, 1, fileDescriptor);
            
            sha256((uint8_t*)bloom_bPx2nd[i].bf, bloom_bPx2nd[i].bytes, (uint8_t*)bloom_bPx2nd_checksums[i].data);
            memcpy(bloom_bPx2nd_checksums[i].backup, bloom_bPx2nd_checksums[i].data, 32);
            fwrite(&bloom_bPx2nd_checksums[i], sizeof(struct checksumsha256), 1, fileDescriptor);
            
            if(i % 64 == 0) {
                printf(".");
                fflush(stdout);
            }
        }
        printf(" Done!\n");
        fclose(fileDescriptor);
    }
    
    // Save bPtable
    snprintf(fileBloomName, 1024, "keyhunt_bsgs_2_%" PRIu64 ".tbl", bsgs_m3);
    fileDescriptor = fopen(fileBloomName, "wb");
    if(fileDescriptor != NULL) {
        printf("[+] Writing bP Table to file %s .. ", fileBloomName);
        fflush(stdout);
        
        fwrite(bPtable, bytes, 1, fileDescriptor);
        
        // Calculate and write checksum
        char checksum[32];
        sha256((uint8_t*)bPtable, bytes, (uint8_t*)checksum);
        fwrite(checksum, 32, 1, fileDescriptor);
        
        printf("Done!\n");
        fclose(fileDescriptor);
    }
    
    // Save bloom_bPx3rd (third bloom filter)
    snprintf(fileBloomName, 1024, "keyhunt_bsgs_7_%" PRIu64 ".blm", bsgs_m3);
    fileDescriptor = fopen(fileBloomName, "wb");
    if(fileDescriptor != NULL) {
        printf("[+] Writing bloom filter to file %s ", fileBloomName);
        fflush(stdout);
        
        for(int i = 0; i < 256; i++) {
            fwrite(&bloom_bPx3rd[i], sizeof(struct bloom), 1, fileDescriptor);
            fwrite(bloom_bPx3rd[i].bf, bloom_bPx3rd[i].bytes, 1, fileDescriptor);
            
            sha256((uint8_t*)bloom_bPx3rd[i].bf, bloom_bPx3rd[i].bytes, (uint8_t*)bloom_bPx3rd_checksums[i].data);
            memcpy(bloom_bPx3rd_checksums[i].backup, bloom_bPx3rd_checksums[i].data, 32);
            fwrite(&bloom_bPx3rd_checksums[i], sizeof(struct checksumsha256), 1, fileDescriptor);
            
            if(i % 64 == 0) {
                printf(".");
                fflush(stdout);
            }
        }
        printf(" Done!\n");
        fclose(fileDescriptor);
    }
}

int main(int argc, char **argv) {
    // File pointers
    FILE *fd_aux1, *fd_aux2, *fd_aux3;

    // Strings
    char *hextemp = NULL;
    char *bf_ptr = NULL;
    char *bPload_threads_available;

    // Buffers
    char rawvalue[32];
    char buffer[1024]; // Buffer for formatted output

    // 64-bit integers
    uint64_t BASE, PERTHREAD_R, itemsbloom, itemsbloom2, itemsbloom3;

    // 32-bit integers
    uint32_t finished;
    int readed, c, salir, i, s, j;

    // Custom integers
    Int total, pretotal, debugcount_mpz, seconds, div_pretotal, int_aux, int_r, int_q, int58;

    // Pointers
    struct bPload *bPload_temp_ptr;

    // Sizes
    size_t rsize;
    
    // File name for targets
    char *fileName = NULL;
    
    // Other variables
    bool continue_flag;
    bool check_flag;
    int index_value;

    pthread_mutex_init(&write_keys, NULL);
    pthread_mutex_init(&write_random, NULL);
    pthread_mutex_init(&mutex_bsgs_thread, NULL);

    srand(time(NULL));

    secp = new Secp256K1();
    secp->Init();
    ZERO.SetInt32(0);
    ONE.SetInt32(1);
    BSGS_GROUP_SIZE.SetInt32(CPU_GRP_SIZE);
    
    // Platform-specific random number generation
#if defined(_WIN64) && !defined(__CYGWIN__)
    rseed(clock() + time(NULL) + rand());
#elif defined(__APPLE__)
    unsigned long rseedvalue;
    arc4random_buf(&rseedvalue, sizeof(rseedvalue));
    rseed(rseedvalue);
#else
    unsigned long rseedvalue;
    int bytes_read = getrandom(&rseedvalue, sizeof(rseedvalue), GRND_NONBLOCK);
    if (bytes_read > 0)
    {
        rseed(rseedvalue);
    }
    else
    {
        fprintf(stderr, "[E] Error using getrandom(). Falling back to less secure seed.\n");
        rseed(clock() + time(NULL) + rand() * rand());
    }
#endif
    
    printf("[+] Version %s, developed by AlbertoBSD (multi-target optimized)\n", version);

    while ((c = getopt(argc, argv, "6hk:n:t:f:r:b:m:qSP:M")) != -1) {
        switch(c) {
            case 'M':
                FLAGMULTITARGET = 1;
                printf("[+] Multi-target BSGS optimization enabled\n");
                break;
            case 'P': {
                // Parse the origin public key
                bool isCompressed;
                if (parsePublicKeyHex(optarg, ORIGIN_PUBKEY, isCompressed)) {
                    FLAGORIGINSET = 1;
                    printf("[+] Origin public key set for subtract mode: %s\n", optarg);
                } else {
                    fprintf(stderr, "[E] Failed to parse origin public key\n");
                    exit(1);
                }
                break;
            }
            case '6':
                FLAGSKIPCHECKSUM = 1;
                fprintf(stderr, "[W] Skipping checksums on files\n");
                break;
            case 'h':
                // Show help menu
                menu();
                break;
            case 'k':
                // Set KFACTOR
                KFACTOR = (int)strtol(optarg, NULL, 10);
                if(KFACTOR <= 0) {
                    KFACTOR = 1;
                }
                printf("[+] K factor %i\n", KFACTOR);
                break;
            case 'n':
                // Set FLAG_N and str_N
                FLAG_N = 1;
                str_N = optarg;
                break;
            case 't':
                // Set number of threads (NTHREADS)
                NTHREADS = strtol(optarg, NULL, 10);
                if(NTHREADS <= 0) {
                    NTHREADS = 1;
                }
                printf((NTHREADS > 1) ? "[+] Threads : %u\n": "[+] Thread : %u\n", NTHREADS);
                break;
            case 'f':
                // Set input file name
                fileName = optarg;
                printf("[+] Using target file: %s\n", fileName);
                break;
            case 'r':
                // Parse range
                {
                    Tokenizer t;
                    stringtokenizer(optarg, &t);
                    if(t.n > 0) {
                        range_start = nextToken(&t);
                        if(t.n > 1) {
                            range_end = nextToken(&t);
                        } else {
                            range_end = (char*)"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140";
                        }
                        
                        if(isValidHex(range_start) && isValidHex(range_end)) {
                            FLAGRANGE = 1;
                            printf("[+] Range set from %s to %s\n", range_start, range_end);
                        } else {
                            fprintf(stderr, "[E] Invalid hex range\n");
                            exit(1);
                        }
                    }
                    freetokenizer(&t);
                }
                break;
            case 'b':
                bitrange = strtol(optarg, NULL, 10);
                if(bitrange > 0 && bitrange <= 256) {
                    MPZAUX.Set(&ONE);
                    MPZAUX.ShiftL(bitrange-1);
                    bit_range_str_min = MPZAUX.GetBase16();
                    checkpointer((void *)bit_range_str_min, __FILE__, "malloc", "bit_range_str_min", __LINE__ -1);
                    MPZAUX.Set(&ONE);
                    MPZAUX.ShiftL(bitrange);
                    if(MPZAUX.IsGreater(&secp->order)) {
                        MPZAUX.Set(&secp->order);
                    }
                    bit_range_str_max = MPZAUX.GetBase16();
                    checkpointer((void *)bit_range_str_max, __FILE__, "malloc", "bit_range_str_min", __LINE__ -1);
                    FLAGBITRANGE = 1;
                    printf("[+] Bit Range %i\n", bitrange);
                    printf("[+] -- from : 0x%s\n", bit_range_str_min);
                    printf("[+] -- to   : 0x%s\n", bit_range_str_max);
                }
                else {
                    fprintf(stderr, "[E] invalid bits param: %s.\n", optarg);
                }
                break;
            case 'm':
                // Parse mode - handle both general mode and BSGS variant
                if(strcmp(optarg, "bsgs") == 0) {
                    FLAGMODE = MODE_BSGS;
                    // Leave FLAGBSGSMODE at default (0 - sequential)
                    printf("[+] Mode BSGS sequential\n");
                }
                else if(strcmp(optarg, "random") == 0) {
                    FLAGMODE = MODE_BSGS;
                    FLAGBSGSMODE = 3; // Random mode
                    printf("[+] Mode BSGS random\n");
                }
                else if(strcmp(optarg, "subtract") == 0) {
                    FLAGMODE = MODE_BSGS;
                    FLAGBSGSMODE = 4; // Subtract mode
                    printf("[+] Mode BSGS subtract\n");
                }
                else if(strcmp(optarg, "sequential") == 0) {
                    FLAGMODE = MODE_BSGS;
                    FLAGBSGSMODE = 0; // Sequential mode
                    printf("[+] Mode BSGS sequential\n");
                }
                else if(strcmp(optarg, "subrand") == 0) {
                    FLAGMODE = MODE_BSGS;
                    FLAGBSGSMODE = 1; // Backward mode
                    printf("[+] Mode BSGS Subtract Random\n");
                }
                else if(strcmp(optarg, "both") == 0) {
                    FLAGMODE = MODE_BSGS;
                    FLAGBSGSMODE = 2; // Both mode
                    printf("[+] Mode BSGS both\n");
                }
                else {
                    fprintf(stderr, "[E] Unknown mode value %s\n", optarg);
                    exit(0);
                }
                break;
            case 'q':
                FLAGQUIET = 1;
                printf("[+] Quiet thread output\n");
                break;
            case 'S':
                FLAGSAVEREADFILE = 1;
                printf("[+] Will save bloom filters to disk\n");
                break;
            default:
                // Handle unknown options
                fprintf(stderr, "[E] Unknown option -%c\n", c);
                exit(0);
                break;
        }
    }

    // If no file specified, use default
    if(fileName == NULL) {
        fileName = (char*)default_fileName;
        printf("[+] Using default target file: %s\n", fileName);
    }

    if (FLAGORIGINSET) {
        // Only force subtract mode if no subtract mode is already selected
        if (FLAGBSGSMODE != 1 && FLAGBSGSMODE != 4) {
            FLAGBSGSMODE = 4;
            printf("[+] Forcing BSGS subtract mode (4) as origin key is set\n");
        } else {
            // User already selected a subtract mode, respect their choice
            printf("[+] Using BSGS %s mode (%d) with origin key\n", 
                   (FLAGBSGSMODE == 1) ? "subtract random" : "subtract", 
                   FLAGBSGSMODE);
        }
    }

    stride.Set(&ONE);
    init_generator();
    
    printf("[+] Mode BSGS %s\n", bsgs_modes[FLAGBSGSMODE]);
    
    if (FLAGMULTITARGET) {
        printf("[+] Using multi-target BSGS optimization (Joux & Lercier)\n");
    }

    // Read target public keys
    if(!readFileTargets(fileName)) {
        fprintf(stderr, "[E] Failed to read target file\n");
        return 1;
    }
    
    // If we have multiple target points, announce the multi-target optimization
    if (FLAGMULTITARGET && bsgs_point_number > 1) {
        printf("[+] Computing optimal parameters for %d target points\n", bsgs_point_number);
        printf("[+] Expected speedup: ~%.2fx (theoretical sqrt(%d))\n", 
               sqrt(bsgs_point_number), bsgs_point_number);
    }

    BSGS_N.SetInt32(0);
    BSGS_M.SetInt32(0);
    
    BSGS_M.SetInt64(bsgs_m);

    if(FLAG_N) {   // Custom N by the -n param
                    
        /* Here we need to validate if the given string is a valid hexadecimal number or a base 10 number*/
        
        /* Now the conversion*/
        if(str_N[0] == '0' && (str_N[1] == 'x' || str_N[1] == 'X')) {    /*We expected a hexadecimal value after 0x  -> str_N +2 */
            BSGS_N.SetBase16((char*)(str_N+2));
        }
        else {
            BSGS_N.SetBase10(str_N);
        }
        
    }
    else {    // Default N
        BSGS_N.SetInt64((uint64_t)0x100000000000);
    }
    
    if(BSGS_N.HasSqrt()) {    // If the root is exact
        BSGS_M.Set(&BSGS_N);
        BSGS_M.ModSqrt();
        
        // Multi-target optimization: The baby-step table is SHARED across all targets
        if (FLAGMULTITARGET && bsgs_point_number > 1) {
            printf("[+] Multi-target optimization: Shared baby-step table for %d targets\n", bsgs_point_number);
            printf("[+] Baby-step table size remains M = sqrt(N) for optimal performance\n");
            printf("[+] Each giant step will check ALL %d targets simultaneously\n", bsgs_point_number);
        }
        
        // Ensure M is divisible by CPU_GRP_SIZE (1024) - this is always required
        Int remainder;
        Int cpu_grp_size;
        cpu_grp_size.SetInt32(CPU_GRP_SIZE);
        remainder.Set(&BSGS_M);
        remainder.Mod(&cpu_grp_size);
        
        if (!remainder.IsZero()) {
            // Calculate adjustment needed to make M divisible by CPU_GRP_SIZE
            Int adjustment;
            adjustment.Set(&cpu_grp_size);
            adjustment.Sub(&remainder);
            
            // Add the adjustment to M
            BSGS_M.Add(&adjustment);
            
            // Verify the adjustment worked
            remainder.Set(&BSGS_M);
            remainder.Mod(&cpu_grp_size);
            if (!remainder.IsZero()) {
                fprintf(stderr, "[E] Failed to make M divisible by %d\n", CPU_GRP_SIZE);
                exit(1);
            }
            
            printf("[+] Adjusted M to be divisible by %d for optimal processing\n", CPU_GRP_SIZE);
        }
        
        // Update bsgs_m value
        bsgs_m = BSGS_M.GetInt64();
        
        char *mStr = BSGS_M.GetBase16();
        printf("[+] Baby-step table size M = 0x%s (%llu entries)\n", mStr, (unsigned long long)bsgs_m);
        free(mStr);
        
        // Final verification that M is divisible by CPU_GRP_SIZE
        BSGS_AUX.Set(&BSGS_M);
        BSGS_AUX.Mod(&BSGS_GROUP_SIZE);    
        
        if(!BSGS_AUX.IsZero()) { // If M is not divisible by BSGS_GROUP_SIZE (1024) 
            hextemp = BSGS_GROUP_SIZE.GetBase10();
            fprintf(stderr, "[E] M value is not divisible by %s\n", hextemp);
            free(hextemp);
            exit(0);
        }
    }
    else {
        fprintf(stderr, "[E] -n param doesn't have exact square root\n");
        exit(0);
    }

    BSGS_AUX.Set(&BSGS_M);
    BSGS_AUX.Mod(&BSGS_GROUP_SIZE);    
    
    if(!BSGS_AUX.IsZero()) { // If M is not divisible by  BSGS_GROUP_SIZE (1024) 
        hextemp = BSGS_GROUP_SIZE.GetBase10();
        fprintf(stderr, "[E] M value is not divisible by %s\n", hextemp);
        exit(0);
    }

    // Set up range
    if(FLAGRANGE) {
        n_range_start.SetBase16(range_start);
        n_range_end.SetBase16(range_end);
    } else if(FLAGBITRANGE) {
        n_range_start.SetBase16(bit_range_str_min);
        n_range_end.SetBase16(bit_range_str_max);
    } else {
        n_range_start.SetInt32(1);
        n_range_end.Set(&secp->order);
    }
    
    n_range_diff.Set(&n_range_end);
    n_range_diff.Sub(&n_range_start);
    
    if(n_range_diff.IsZero() || n_range_start.IsGreater(&n_range_end)) {
        fprintf(stderr, "[E] Invalid range: start must be less than end\n");
        exit(1);
    }
    
    BSGS_CURRENT.Set(&n_range_start);
    
    // Rest of BSGS setup (reuse existing code)
    /*
     M    2199023255552
          109951162777.6
     M2   109951162778
          5497558138.9
     M3   5497558139
    */

    BSGS_M.Mult((uint64_t)KFACTOR);
    BSGS_AUX.SetInt32(32);
    BSGS_R.Set(&BSGS_M);
    BSGS_R.Mod(&BSGS_AUX);
    BSGS_M2.Set(&BSGS_M);
    BSGS_M2.Div(&BSGS_AUX);

    if(!BSGS_R.IsZero()) { /* If BSGS_M modulo 32 is not 0*/
        BSGS_M2.AddOne();
    }
    
    BSGS_M_double.SetInt32(2);
    BSGS_M_double.Mult(&BSGS_M);
    
    BSGS_M2_double.SetInt32(2);
    BSGS_M2_double.Mult(&BSGS_M2);
    
    BSGS_R.Set(&BSGS_M2);
    BSGS_R.Mod(&BSGS_AUX);
    
    BSGS_M3.Set(&BSGS_M2);
    BSGS_M3.Div(&BSGS_AUX);
    
    if(!BSGS_R.IsZero()) { /* If BSGS_M2 modulo 32 is not 0*/
        BSGS_M3.AddOne();
    }
    
    BSGS_M3_double.SetInt32(2);
    BSGS_M3_double.Mult(&BSGS_M3);
    
    bsgs_m2 = BSGS_M2.GetInt64();
    bsgs_m3 = BSGS_M3.GetInt64();
    
    BSGS_AUX.Set(&BSGS_N);
    BSGS_AUX.Div(&BSGS_M);
    
    BSGS_R.Set(&BSGS_N);
    BSGS_R.Mod(&BSGS_M);

    if(!BSGS_R.IsZero()) { /* if BSGS_N modulo BSGS_M is not 0*/
        BSGS_N.Set(&BSGS_M);
        BSGS_N.Mult(&BSGS_AUX);
    }

    bsgs_m = BSGS_M.GetInt64();
    bsgs_aux = BSGS_AUX.GetInt64();
    
    hextemp = BSGS_N.GetBase16();
    printf("[+] N = 0x%s\n", hextemp);
    free(hextemp);

    if(((uint64_t)(bsgs_m/256)) > 10000) {
        itemsbloom = (uint64_t)(bsgs_m / 256);
        if(bsgs_m % 256 != 0) {
            itemsbloom++;
        }
    }
    else {
        itemsbloom = 1000;
    }
    
    if(((uint64_t)(bsgs_m2/256)) > 1000) {
        itemsbloom2 = (uint64_t)(bsgs_m2 / 256);
        if(bsgs_m2 % 256 != 0) {
            itemsbloom2++;
        }
    }
    else {
        itemsbloom2 = 1000;
    }
    
    if(((uint64_t)(bsgs_m3/256)) > 1000) {
        itemsbloom3 = (uint64_t)(bsgs_m3/256);
        if(bsgs_m3 % 256 != 0) {
            itemsbloom3++;
        }
    }
    else {
        itemsbloom3 = 1000;
    }
    
    // Calculate estimated Bloom filter sizes
    uint64_t estimated_bytes_per_bloom = (uint64_t)((-1.0 * itemsbloom * log(0.001)) / (log(2.0) * log(2.0))) / 8;
    uint64_t estimated_bytes_per_bloom2 = (uint64_t)((-1.0 * itemsbloom2 * log(0.001)) / (log(2.0) * log(2.0))) / 8;
    uint64_t estimated_bytes_per_bloom3 = (uint64_t)((-1.0 * itemsbloom3 * log(0.001)) / (log(2.0) * log(2.0))) / 8;

    // Total bloom filter sizes (multiply by 256 for each filter)
    uint64_t total_bloom1_size = estimated_bytes_per_bloom * 256;
    uint64_t total_bloom2_size = estimated_bytes_per_bloom2 * 256;
    uint64_t total_bloom3_size = estimated_bytes_per_bloom3 * 256;

    // Calculate memory requirements
    double bloom_memory = (total_bloom1_size + total_bloom2_size + total_bloom3_size) / (1024.0 * 1024.0);
    
    bytes = (uint64_t)bsgs_m3 * (uint64_t)sizeof(struct bsgs_xvalue);
    double bptable_memory = (bytes) / (1024.0 * 1024.0);
    double total_memory = bloom_memory + bptable_memory;

    printf("\n[+] Memory requirements:\n");
    printf("    Bloom filters : %.2f MB\n", bloom_memory);
    printf("    bPtable      : %.2f MB\n", bptable_memory);
    printf("    Total        : %.2f MB\n", total_memory);
    printf("    SHARED baby-step table serves ALL %d targets\n\n", bsgs_point_number);

    // System memory check for safety
#if defined(_WIN64) && !defined(__CYGWIN__)
    MEMORYSTATUSEX statex;
    statex.dwLength = sizeof(statex);
    GlobalMemoryStatusEx(&statex);
    DWORDLONG available_memory = statex.ullAvailPhysMem / (1024 * 1024);
#else
    long pages = sysconf(_SC_PHYS_PAGES);
    long page_size = sysconf(_SC_PAGE_SIZE);
    uint64_t available_memory = ((uint64_t)pages * (uint64_t)page_size) / (1024 * 1024);
#endif

    printf("[+] Available system memory: %llu MB\n", (unsigned long long)available_memory);
    
    printf("[+] Bloom filter for %" PRIu64 " elements ", bsgs_m);
    bloom_bP = (struct bloom*)calloc(256, sizeof(struct bloom));
    checkpointer((void *)bloom_bP, __FILE__, "calloc", "bloom_bP", __LINE__ -1);
    bloom_bP_checksums = (struct checksumsha256*)calloc(256, sizeof(struct checksumsha256));
    checkpointer((void *)bloom_bP_checksums, __FILE__, "calloc", "bloom_bP_checksums", __LINE__ -1);
    
    bloom_bP_mutex = (pthread_mutex_t*)calloc(256, sizeof(pthread_mutex_t));
    checkpointer((void *)bloom_bP_mutex, __FILE__, "calloc", "bloom_bP_mutex", __LINE__ -1);
    
    fflush(stdout);
    bloom_bP_totalbytes = 0;
    for(i = 0; i < 256; i++) {
        pthread_mutex_init(&bloom_bP_mutex[i], NULL);
        if(bloom_init2(&bloom_bP[i], itemsbloom, 0.001) == 1) {
            fprintf(stderr, "[E] error bloom_init _ %i\n", i);
            exit(0);
        }
        bloom_bP_totalbytes += bloom_bP[i].bytes;
    }
    printf(": %.2f MB\n", (float)((float)(uint64_t)bloom_bP_totalbytes/(float)(uint64_t)1048576));

    printf("[+] Bloom filter for %" PRIu64 " elements ", bsgs_m2);
    
    bloom_bPx2nd_mutex = (pthread_mutex_t*)calloc(256, sizeof(pthread_mutex_t));
    checkpointer((void *)bloom_bPx2nd_mutex, __FILE__, "calloc", "bloom_bPx2nd_mutex", __LINE__ -1);
    bloom_bPx2nd = (struct bloom*)calloc(256, sizeof(struct bloom));
    checkpointer((void *)bloom_bPx2nd, __FILE__, "calloc", "bloom_bPx2nd", __LINE__ -1);
    bloom_bPx2nd_checksums = (struct checksumsha256*)calloc(256, sizeof(struct checksumsha256));
    checkpointer((void *)bloom_bPx2nd_checksums, __FILE__, "calloc", "bloom_bPx2nd_checksums", __LINE__ -1);
    bloom_bP2_totalbytes = 0;
    for(i = 0; i < 256; i++) {
        pthread_mutex_init(&bloom_bPx2nd_mutex[i], NULL);
        if(bloom_init2(&bloom_bPx2nd[i], itemsbloom2, 0.001) == 1) {
            fprintf(stderr, "[E] error bloom_init _ %i\n", i);
            exit(0);
        }
        bloom_bP2_totalbytes += bloom_bPx2nd[i].bytes;
    }
    printf(": %.2f MB\n", (float)((float)(uint64_t)bloom_bP2_totalbytes/(float)(uint64_t)1048576));
    
    bloom_bPx3rd_mutex = (pthread_mutex_t*)calloc(256, sizeof(pthread_mutex_t));
    checkpointer((void *)bloom_bPx3rd_mutex, __FILE__, "calloc", "bloom_bPx3rd_mutex", __LINE__ -1);
    bloom_bPx3rd = (struct bloom*)calloc(256, sizeof(struct bloom));
    checkpointer((void *)bloom_bPx3rd, __FILE__, "calloc", "bloom_bPx3rd", __LINE__ -1);
    bloom_bPx3rd_checksums = (struct checksumsha256*)calloc(256, sizeof(struct checksumsha256));
    checkpointer((void *)bloom_bPx3rd_checksums, __FILE__, "calloc", "bloom_bPx3rd_checksums", __LINE__ -1);
    
    printf("[+] Bloom filter for %" PRIu64 " elements ", bsgs_m3);
    bloom_bP3_totalbytes = 0;
    for(i = 0; i < 256; i++) {
        pthread_mutex_init(&bloom_bPx3rd_mutex[i], NULL);
        if(bloom_init2(&bloom_bPx3rd[i], itemsbloom3, 0.001) == 1) {
            fprintf(stderr, "[E] error bloom_init %i\n", i);
            exit(0);
        }
        bloom_bP3_totalbytes += bloom_bPx3rd[i].bytes;
    }
    printf(": %.2f MB\n", (float)((float)(uint64_t)bloom_bP3_totalbytes/(float)(uint64_t)1048576));

    BSGS_MP = secp->ComputePublicKey(&BSGS_M);
    BSGS_MP_double = secp->ComputePublicKey(&BSGS_M_double);
    BSGS_MP2 = secp->ComputePublicKey(&BSGS_M2);
    BSGS_MP2_double = secp->ComputePublicKey(&BSGS_M2_double);
    BSGS_MP3 = secp->ComputePublicKey(&BSGS_M3);
    BSGS_MP3_double = secp->ComputePublicKey(&BSGS_M3_double);
    
    BSGS_AMP2.reserve(32);
    BSGS_AMP3.reserve(32);
    
    GSn.reserve(CPU_GRP_SIZE/2);

    i = 0;

    /* New aMP table just to keep the same code of JLP */
    /* Auxiliar Points to speed up calculations for the main bloom filter check */
    
    Point bsP = secp->Negation(BSGS_MP_double);
    Point g = bsP;
    GSn[0] = g;
    
    g = secp->DoubleDirect(g);
    GSn[1] = g;
    
    for(int i = 2; i < CPU_GRP_SIZE / 2; i++) {
        g = secp->AddDirect(g, bsP);
        GSn[i] = g;
    }
    
    /* For next center point */
    _2GSn = secp->DoubleDirect(GSn[CPU_GRP_SIZE / 2 - 1]);
    
    i = 0;
    point_temp.Set(BSGS_MP2);
    BSGS_AMP2[0] = secp->Negation(point_temp);
    BSGS_AMP2[0].Reduce();
    point_temp.Set(BSGS_MP2_double);
    point_temp = secp->Negation(point_temp);
    
    for(i = 1; i < 32; i++) {
        BSGS_AMP2[i] = secp->AddDirect(BSGS_AMP2[i-1], point_temp);
        BSGS_AMP2[i].Reduce();
    }
    
    i = 0;
    point_temp.Set(BSGS_MP3);
    BSGS_AMP3[0] = secp->Negation(point_temp);
    BSGS_AMP3[0].Reduce();
    point_temp.Set(BSGS_MP3_double);
    point_temp = secp->Negation(point_temp);

    for(i = 1; i < 32; i++) {
        BSGS_AMP3[i] = secp->AddDirect(BSGS_AMP3[i-1], point_temp);
        BSGS_AMP3[i].Reduce();
    }

    printf("[+] Allocating %.2f MB for %" PRIu64 " bP Points\n", (double)(bytes/1048576), bsgs_m3);
    
    bPtable = (struct bsgs_xvalue*)malloc(bytes);
    checkpointer((void *)bPtable, __FILE__, "malloc", "bPtable", __LINE__ -1);
    memset(bPtable, 0, bytes);
    
    if(FLAGSAVEREADFILE) {
        /*Reading file for 1st bloom filter */
        snprintf(buffer_bloom_file, 1024, "keyhunt_bsgs_4_%" PRIu64 ".blm", bsgs_m);
        fd_aux1 = fopen(buffer_bloom_file, "rb");
        if(fd_aux1 != NULL) {
            printf("[+] Reading bloom filter from file %s ", buffer_bloom_file);
            fflush(stdout);
            for(i = 0; i < 256; i++) {
                bf_ptr = (char*)bloom_bP[i].bf;    /*We need to save the current bf pointer*/
                readed = fread(&bloom_bP[i], sizeof(struct bloom), 1, fd_aux1);
                if(readed != 1) {
                    fprintf(stderr, "[E] Error reading the file %s\n", buffer_bloom_file);
                    exit(0);
                }
                bloom_bP[i].bf = (uint8_t*)bf_ptr;    /* Restoring the bf pointer*/
                readed = fread(bloom_bP[i].bf, bloom_bP[i].bytes, 1, fd_aux1);
                if(readed != 1) {
                    fprintf(stderr, "[E] Error reading the file %s\n", buffer_bloom_file);
                    exit(0);
                }
                readed = fread(&bloom_bP_checksums[i], sizeof(struct checksumsha256), 1, fd_aux1);
                if(readed != 1) {
                    fprintf(stderr, "[E] Error reading the file %s\n", buffer_bloom_file);
                    exit(0);
                }
                memset(rawvalue, 0, 32);
                if(FLAGSKIPCHECKSUM == 0) {
                    sha256((uint8_t*)bloom_bP[i].bf, bloom_bP[i].bytes, (uint8_t*)rawvalue);
                    if(memcmp(bloom_bP_checksums[i].data, rawvalue, 32) != 0 || memcmp(bloom_bP_checksums[i].backup, rawvalue, 32) != 0) {    /* Verification */
                        fprintf(stderr, "[E] Error checksum file mismatch! %s\n", buffer_bloom_file);
                        exit(0);
                    }
                }
                if(i % 64 == 0) {
                    printf(".");
                    fflush(stdout);
                }
            }
            printf(" Done!\n");
            fclose(fd_aux1);
            memset(buffer_bloom_file, 0, 1024);
            snprintf(buffer_bloom_file, 1024, "keyhunt_bsgs_3_%" PRIu64 ".blm", bsgs_m);
            fd_aux1 = fopen(buffer_bloom_file, "rb");
            if(fd_aux1 != NULL) {
                printf("[W] Unused file detected %s you can delete it without worry\n", buffer_bloom_file);
                fclose(fd_aux1);
            }
            FLAGREADEDFILE1 = 1;
        }
        else {    /*Checking for old file    keyhunt_bsgs_3_   */
            snprintf(buffer_bloom_file, 1024, "keyhunt_bsgs_3_%" PRIu64 ".blm", bsgs_m);
            fd_aux1 = fopen(buffer_bloom_file, "rb");
            if(fd_aux1 != NULL) {
                printf("[+] Reading bloom filter from file %s ", buffer_bloom_file);
                fflush(stdout);
                for(i = 0; i < 256; i++) {
                    bf_ptr = (char*)bloom_bP[i].bf;    /*We need to save the current bf pointer*/
                    readed = fread(&oldbloom_bP, sizeof(struct oldbloom), 1, fd_aux1);
                    
                    if(readed != 1) {
                        fprintf(stderr, "[E] Error reading the file %s\n", buffer_bloom_file);
                        exit(0);
                    }
                    memcpy(&bloom_bP[i], &oldbloom_bP, sizeof(struct bloom)); // We only need to copy the part data to the new bloom size, not from the old size
                    bloom_bP[i].bf = (uint8_t*)bf_ptr;    /* Restoring the bf pointer*/
                    
                    readed = fread(bloom_bP[i].bf, bloom_bP[i].bytes, 1, fd_aux1);
                    if(readed != 1) {
                        fprintf(stderr, "[E] Error reading the file %s\n", buffer_bloom_file);
                        exit(0);
                    }
                    memcpy(bloom_bP_checksums[i].data, oldbloom_bP.checksum, 32);
                    memcpy(bloom_bP_checksums[i].backup, oldbloom_bP.checksum_backup, 32);
                    memset(rawvalue, 0, 32);
                    if(FLAGSKIPCHECKSUM == 0) {
                        sha256((uint8_t*)bloom_bP[i].bf, bloom_bP[i].bytes, (uint8_t*)rawvalue);
                        if(memcmp(bloom_bP_checksums[i].data, rawvalue, 32) != 0 || memcmp(bloom_bP_checksums[i].backup, rawvalue, 32) != 0) {    /* Verification */
                            fprintf(stderr, "[E] Error checksum file mismatch! %s\n", buffer_bloom_file);
                            exit(0);
                        }
                    }
                    if(i % 32 == 0) {
                        printf(".");
                        fflush(stdout);
                    }
                }
                printf(" Done!\n");
                fclose(fd_aux1);
                FLAGUPDATEFILE1 = 1;    /* Flag to migrate the data to the new File keyhunt_bsgs_4_ */
                FLAGREADEDFILE1 = 1;
                
            }
            else {
                FLAGREADEDFILE1 = 0;
                // Flag to make the new file
            }
        }
        
        /*Reading file for 2nd bloom filter */
        snprintf(buffer_bloom_file, 1024, "keyhunt_bsgs_6_%" PRIu64 ".blm", bsgs_m2);
        fd_aux2 = fopen(buffer_bloom_file, "rb");
        if(fd_aux2 != NULL) {
            printf("[+] Reading bloom filter from file %s ", buffer_bloom_file);
            fflush(stdout);
            for(i = 0; i < 256; i++) {
                bf_ptr = (char*)bloom_bPx2nd[i].bf;    /*We need to save the current bf pointer*/
                readed = fread(&bloom_bPx2nd[i], sizeof(struct bloom), 1, fd_aux2);
                if(readed != 1) {
                    fprintf(stderr, "[E] Error reading the file %s\n", buffer_bloom_file);
                    exit(0);
                }
                bloom_bPx2nd[i].bf = (uint8_t*)bf_ptr;    /* Restoring the bf pointer*/
                readed = fread(bloom_bPx2nd[i].bf, bloom_bPx2nd[i].bytes, 1, fd_aux2);
                if(readed != 1) {
                    fprintf(stderr, "[E] Error reading the file %s\n", buffer_bloom_file);
                    exit(0);
                }
                readed = fread(&bloom_bPx2nd_checksums[i], sizeof(struct checksumsha256), 1, fd_aux2);
                if(readed != 1) {
                    fprintf(stderr, "[E] Error reading the file %s\n", buffer_bloom_file);
                    exit(0);
                }
                memset(rawvalue, 0, 32);
                if(FLAGSKIPCHECKSUM == 0) {
                    sha256((uint8_t*)bloom_bPx2nd[i].bf, bloom_bPx2nd[i].bytes, (uint8_t*)rawvalue);
                    if(memcmp(bloom_bPx2nd_checksums[i].data, rawvalue, 32) != 0 || memcmp(bloom_bPx2nd_checksums[i].backup, rawvalue, 32) != 0) {        /* Verification */
                        fprintf(stderr, "[E] Error checksum file mismatch! %s\n", buffer_bloom_file);
                        exit(0);
                    }
                }
                if(i % 64 == 0) {
                    printf(".");
                    fflush(stdout);
                }
            }
            fclose(fd_aux2);
            printf(" Done!\n");
            memset(buffer_bloom_file, 0, 1024);
            snprintf(buffer_bloom_file, 1024, "keyhunt_bsgs_5_%" PRIu64 ".blm", bsgs_m2);
            fd_aux2 = fopen(buffer_bloom_file, "rb");
            if(fd_aux2 != NULL) {
                printf("[W] Unused file detected %s you can delete it without worry\n", buffer_bloom_file);
                fclose(fd_aux2);
            }
            memset(buffer_bloom_file, 0, 1024);
            snprintf(buffer_bloom_file, 1024, "keyhunt_bsgs_1_%" PRIu64 ".blm", bsgs_m2);
            fd_aux2 = fopen(buffer_bloom_file, "rb");
            if(fd_aux2 != NULL) {
                printf("[W] Unused file detected %s you can delete it without worry\n", buffer_bloom_file);
                fclose(fd_aux2);
            }
            FLAGREADEDFILE2 = 1;
        }
        else {    
            FLAGREADEDFILE2 = 0;
        }
        
        /*Reading file for bPtable */
        snprintf(buffer_bloom_file, 1024, "keyhunt_bsgs_2_%" PRIu64 ".tbl", bsgs_m3);
        fd_aux3 = fopen(buffer_bloom_file, "rb");
        if(fd_aux3 != NULL) {
            printf("[+] Reading bP Table from file %s .", buffer_bloom_file);
            fflush(stdout);
            rsize = fread(bPtable, bytes, 1, fd_aux3);
            if(rsize != 1) {
                fprintf(stderr, "[E] Error reading the file %s\n", buffer_bloom_file);
                exit(0);
            }
            rsize = fread(checksum, 32, 1, fd_aux3);
            if(rsize != 1) {
                fprintf(stderr, "[E] Error reading the file %s\n", buffer_bloom_file);
                exit(0);
            }
            if(FLAGSKIPCHECKSUM == 0) {
                sha256((uint8_t*)bPtable, bytes, (uint8_t*)checksum_backup);
                if(memcmp(checksum, checksum_backup, 32) != 0) {
                    fprintf(stderr, "[E] Error checksum file mismatch! %s\n", buffer_bloom_file);
                    exit(0);
                }
            }
            printf("... Done!\n");
            fclose(fd_aux3);
            FLAGREADEDFILE3 = 1;
        }
        else {
            FLAGREADEDFILE3 = 0;
        }
        
        /*Reading file for 3rd bloom filter */
        snprintf(buffer_bloom_file, 1024, "keyhunt_bsgs_7_%" PRIu64 ".blm", bsgs_m3);
        fd_aux2 = fopen(buffer_bloom_file, "rb");
        if(fd_aux2 != NULL) {
            printf("[+] Reading bloom filter from file %s ", buffer_bloom_file);
            fflush(stdout);
            for(i = 0; i < 256; i++) {
                bf_ptr = (char*)bloom_bPx3rd[i].bf;    /*We need to save the current bf pointer*/
                readed = fread(&bloom_bPx3rd[i], sizeof(struct bloom), 1, fd_aux2);
                if(readed != 1) {
                    fprintf(stderr, "[E] Error reading the file %s\n", buffer_bloom_file);
                    exit(0);
                }
                bloom_bPx3rd[i].bf = (uint8_t*)bf_ptr;    /* Restoring the bf pointer*/
                readed = fread(bloom_bPx3rd[i].bf, bloom_bPx3rd[i].bytes, 1, fd_aux2);
                if(readed != 1) {
                    fprintf(stderr, "[E] Error reading the file %s\n", buffer_bloom_file);
                    exit(0);
                }
                readed = fread(&bloom_bPx3rd_checksums[i], sizeof(struct checksumsha256), 1, fd_aux2);
                if(readed != 1) {
                    fprintf(stderr, "[E] Error reading the file %s\n", buffer_bloom_file);
                    exit(0);
                }
                memset(rawvalue, 0, 32);
                if(FLAGSKIPCHECKSUM == 0) {
                    sha256((uint8_t*)bloom_bPx3rd[i].bf, bloom_bPx3rd[i].bytes, (uint8_t*)rawvalue);
                    if(memcmp(bloom_bPx3rd_checksums[i].data, rawvalue, 32) != 0 || memcmp(bloom_bPx3rd_checksums[i].backup, rawvalue, 32) != 0) {        /* Verification */
                        fprintf(stderr, "[E] Error checksum file mismatch! %s\n", buffer_bloom_file);
                        exit(0);
                    }
                }
                if(i % 64 == 0) {
                    printf(".");
                    fflush(stdout);
                }
            }
            fclose(fd_aux2);
            printf(" Done!\n");
            FLAGREADEDFILE4 = 1;
        }
        else {
            FLAGREADEDFILE4 = 0;
        }
    }
    
    if(!FLAGREADEDFILE1 || !FLAGREADEDFILE2 || !FLAGREADEDFILE3 || !FLAGREADEDFILE4) {
        // Process for generating Bloom filters if not loaded from files
        
        if(FLAGREADEDFILE1 == 1) {
            /* 
                We need just to make File 2 to File 4 this is
                - Second bloom filter 5%
                - third  bloom fitler 0.25 %
                - bp Table 0.25 %
            */
            printf("[I] We need to recalculate some files, don't worry this is only 3%% of the previous work\n");
            FINISHED_THREADS_COUNTER = 0;
            FINISHED_THREADS_BP = 0;
            FINISHED_ITEMS = 0;
            salir = 0;
            BASE = 0;
            THREADCOUNTER = 0;
            if(THREADBPWORKLOAD >= bsgs_m2) {
                THREADBPWORKLOAD = bsgs_m2;
            }
            THREADCYCLES = bsgs_m2 / THREADBPWORKLOAD;
            PERTHREAD_R = bsgs_m2 % THREADBPWORKLOAD;
            if(PERTHREAD_R != 0) {
                THREADCYCLES++;
            }
            
            printf("\r[+] processing %llu/%llu bP points : %i%%\r", (unsigned long long)FINISHED_ITEMS, (unsigned long long)bsgs_m, (int)(((double)FINISHED_ITEMS/(double)bsgs_m)*100));
            fflush(stdout);
            
            tid = (pthread_t*)calloc(NTHREADS, sizeof(pthread_t));
            bPload_mutex = (pthread_mutex_t*)calloc(NTHREADS, sizeof(pthread_mutex_t));
            checkpointer((void*)bPload_mutex, __FILE__, "calloc", "bPload_mutex", __LINE__ -1);
            bPload_temp_ptr = (struct bPload*)calloc(NTHREADS, sizeof(struct bPload));
            checkpointer((void*)bPload_temp_ptr, __FILE__, "calloc", "bPload_temp_ptr", __LINE__ -1);
            bPload_threads_available = (char*)calloc(NTHREADS, sizeof(char));
            checkpointer((void*)bPload_threads_available, __FILE__, "calloc", "bPload_threads_available", __LINE__ -1);
            
            memset(bPload_threads_available, 1, NTHREADS);
            
            for(i = 0; i < NTHREADS; i++) {
                pthread_mutex_init(&bPload_mutex[i], NULL);
            }
            
            do {
                for(i = 0; i < NTHREADS && !salir; i++) {
                    if(bPload_threads_available[i] && !salir) {
                        bPload_threads_available[i] = 0;
                        bPload_temp_ptr[i].from = BASE;
                        bPload_temp_ptr[i].threadid = i;
                        bPload_temp_ptr[i].finished = 0;
                        if(THREADCOUNTER < THREADCYCLES-1) {
                            bPload_temp_ptr[i].to = BASE + THREADBPWORKLOAD;
                            bPload_temp_ptr[i].workload = THREADBPWORKLOAD;
                        }
                        else {
                            bPload_temp_ptr[i].to = BASE + THREADBPWORKLOAD + PERTHREAD_R;
                            bPload_temp_ptr[i].workload = THREADBPWORKLOAD + PERTHREAD_R;
                            salir = 1;
                        }
                        s = pthread_create(&tid[i], NULL, thread_bPload_2blooms_multi_target, (void*)&bPload_temp_ptr[i]);
                        if(s != 0) {
                            printf("Thread creation failed. Error code: %d\n", s);
                            exit(EXIT_FAILURE);
                        }
                        pthread_detach(tid[i]);
                        BASE += THREADBPWORKLOAD;
                        THREADCOUNTER++;
                    }
                }

                if(OLDFINISHED_ITEMS != FINISHED_ITEMS) {
                    printf("\r[+] processing %llu/%llu bP points : %i%%\r", (unsigned long long)FINISHED_ITEMS, (unsigned long long)bsgs_m2, (int)(((double)FINISHED_ITEMS/(double)bsgs_m2)*100));
                    fflush(stdout);
                    OLDFINISHED_ITEMS = FINISHED_ITEMS;
                }
                
                for(i = 0; i < NTHREADS; i++) {
                    pthread_mutex_lock(&bPload_mutex[i]);
                    finished = bPload_temp_ptr[i].finished;
                    pthread_mutex_unlock(&bPload_mutex[i]);
                    if(finished) {
                        bPload_temp_ptr[i].finished = 0;
                        bPload_threads_available[i] = 1;
                        FINISHED_ITEMS += bPload_temp_ptr[i].workload;
                        FINISHED_THREADS_COUNTER++;
                    }
                }
                
            } while(FINISHED_THREADS_COUNTER < THREADCYCLES);
            printf("\r[+] processing %llu/%llu bP points : 100%%     \n", (unsigned long long)bsgs_m2, (unsigned long long)bsgs_m2);
            
            free(tid);
            free(bPload_mutex);
            free(bPload_temp_ptr);
            free(bPload_threads_available);
        }
        else {    
            /* We need just to do all the files 
                - first  bllom filter 100% 
                - Second bloom filter 5%
                - third  bloom fitler 0.25 %
                - bp Table 0.25 %
            */
            FINISHED_THREADS_COUNTER = 0;
            FINISHED_THREADS_BP = 0;
            FINISHED_ITEMS = 0;
            salir = 0;
            BASE = 0;
            THREADCOUNTER = 0;
            if(THREADBPWORKLOAD >= bsgs_m) {
                THREADBPWORKLOAD = bsgs_m;
            }
            THREADCYCLES = bsgs_m / THREADBPWORKLOAD;
            PERTHREAD_R = bsgs_m % THREADBPWORKLOAD;
            if(PERTHREAD_R != 0) {
                THREADCYCLES++;
            }
            
            printf("\r[+] processing %llu/%llu bP points : %i%%\r", (unsigned long long)FINISHED_ITEMS, (unsigned long long)bsgs_m, (int)(((double)FINISHED_ITEMS/(double)bsgs_m)*100));
            fflush(stdout);
            
            tid = (pthread_t*)calloc(NTHREADS, sizeof(pthread_t));
            bPload_mutex = (pthread_mutex_t*)calloc(NTHREADS, sizeof(pthread_mutex_t));
            checkpointer((void*)tid, __FILE__, "calloc", "tid", __LINE__ -1);
            checkpointer((void*)bPload_mutex, __FILE__, "calloc", "bPload_mutex", __LINE__ -1);
            
            bPload_temp_ptr = (struct bPload*)calloc(NTHREADS, sizeof(struct bPload));
            checkpointer((void*)bPload_temp_ptr, __FILE__, "calloc", "bPload_temp_ptr", __LINE__ -1);
            bPload_threads_available = (char*)calloc(NTHREADS, sizeof(char));
            checkpointer((void*)bPload_threads_available, __FILE__, "calloc", "bPload_threads_available", __LINE__ -1);
            
            memset(bPload_threads_available, 1, NTHREADS);
            
            for(i = 0; i < NTHREADS; i++) {
                pthread_mutex_init(&bPload_mutex[i], NULL);
            }
            
            do {
                for(i = 0; i < NTHREADS && !salir; i++) {
                    if(bPload_threads_available[i] && !salir) {
                        bPload_threads_available[i] = 0;
                        bPload_temp_ptr[i].from = BASE;
                        bPload_temp_ptr[i].threadid = i;
                        bPload_temp_ptr[i].finished = 0;
                        if(THREADCOUNTER < THREADCYCLES-1) {
                            bPload_temp_ptr[i].to = BASE + THREADBPWORKLOAD;
                            bPload_temp_ptr[i].workload = THREADBPWORKLOAD;
                        }
                        else {
                            bPload_temp_ptr[i].to = BASE + THREADBPWORKLOAD + PERTHREAD_R;
                            bPload_temp_ptr[i].workload = THREADBPWORKLOAD + PERTHREAD_R;
                            salir = 1;
                        }

                        s = pthread_create(&tid[i], NULL, thread_bPload_multi_target, (void*)&bPload_temp_ptr[i]);
                        if(s != 0) {
                            printf("Thread creation failed. Error code: %d\n", s);
                            exit(EXIT_FAILURE);
                        }
                        pthread_detach(tid[i]);
                        BASE += THREADBPWORKLOAD;
                        THREADCOUNTER++;
                    }
                }
                if(OLDFINISHED_ITEMS != FINISHED_ITEMS) {
                    printf("\r[+] processing %llu/%llu bP points : %i%%\r", (unsigned long long)FINISHED_ITEMS, (unsigned long long)bsgs_m, (int)(((double)FINISHED_ITEMS/(double)bsgs_m)*100));
                    fflush(stdout);
                    OLDFINISHED_ITEMS = FINISHED_ITEMS;
                }
                
                for(i = 0; i < NTHREADS; i++) {
                    pthread_mutex_lock(&bPload_mutex[i]);
                    finished = bPload_temp_ptr[i].finished;
                    pthread_mutex_unlock(&bPload_mutex[i]);
                    if(finished) {
                        bPload_temp_ptr[i].finished = 0;
                        bPload_threads_available[i] = 1;
                        FINISHED_ITEMS += bPload_temp_ptr[i].workload;
                        FINISHED_THREADS_COUNTER++;
                    }
                }
                
            } while(FINISHED_THREADS_COUNTER < THREADCYCLES);
            printf("\r[+] processing %llu/%llu bP points : 100%%     \n", (unsigned long long)bsgs_m, (unsigned long long)bsgs_m);
            
            free(tid);
            free(bPload_mutex);
            free(bPload_temp_ptr);
            free(bPload_threads_available);
        }
    }
    
    if(!FLAGREADEDFILE1 || !FLAGREADEDFILE2 || !FLAGREADEDFILE4) {
        printf("[+] Making checksums .. ");
        fflush(stdout);
    }    
    if(!FLAGREADEDFILE1) {
        for(i = 0; i < 256; i++) {
            sha256((uint8_t*)bloom_bP[i].bf, bloom_bP[i].bytes, (uint8_t*)bloom_bP_checksums[i].data);
            memcpy(bloom_bP_checksums[i].backup, bloom_bP_checksums[i].data, 32);
        }
        printf(".");
    }
    if(!FLAGREADEDFILE2) {
        for(i = 0; i < 256; i++) {
            sha256((uint8_t*)bloom_bPx2nd[i].bf, bloom_bPx2nd[i].bytes, (uint8_t*)bloom_bPx2nd_checksums[i].data);
            memcpy(bloom_bPx2nd_checksums[i].backup, bloom_bPx2nd_checksums[i].data, 32);
        }
        printf(".");
    }
    if(!FLAGREADEDFILE4) {
        for(i = 0; i < 256; i++) {
            sha256((uint8_t*)bloom_bPx3rd[i].bf, bloom_bPx3rd[i].bytes, (uint8_t*)bloom_bPx3rd_checksums[i].data);
            memcpy(bloom_bPx3rd_checksums[i].backup, bloom_bPx3rd_checksums[i].data, 32);
        }
        printf(".");
    }
    if(!FLAGREADEDFILE1 || !FLAGREADEDFILE2 || !FLAGREADEDFILE4) {
        printf(" done\n");
        fflush(stdout);
    }    
    if(!FLAGREADEDFILE3) {
        printf("[+] Sorting %llu elements... ", (unsigned long long)bsgs_m3);
        fflush(stdout);
        bsgs_sort(bPtable, bsgs_m3);
        sha256((uint8_t*)bPtable, bytes, (uint8_t*)checksum);
        memcpy(checksum_backup, checksum, 32);
        printf("Done!\n");
        fflush(stdout);
    }
    
    // If we've generated new bloom filters and we want to save them
    if(FLAGSAVEREADFILE && (!FLAGREADEDFILE1 || !FLAGREADEDFILE2 || !FLAGREADEDFILE3 || !FLAGREADEDFILE4)) {
        printf("[+] Saving bloom filters to disk...\n");
        writeBloomFilters();
    }

    printf("[+] Multi-Target BSGS Algorithm\n");
    printf("    Shared baby-step table created\n");
    printf("    Processing %d targets with √%d speedup\n", bsgs_point_number, bsgs_point_number);

    // Launch worker threads
    steps = (uint64_t*)calloc(NTHREADS, sizeof(uint64_t));
    checkpointer((void*)steps, __FILE__, "calloc", "steps", __LINE__ -1);
    ends = (unsigned int*)calloc(NTHREADS, sizeof(int));
    checkpointer((void*)ends, __FILE__, "calloc", "ends", __LINE__ -1);
    tid = (pthread_t*)calloc(NTHREADS, sizeof(pthread_t));
    checkpointer((void*)tid, __FILE__, "calloc", "tid", __LINE__ -1);
    
    for(j = 0; j < NTHREADS; j++) {
        struct tothread *tt = (tothread*)malloc(sizeof(struct tothread));
        checkpointer((void*)tt, __FILE__, "malloc", "tt", __LINE__ -1);
        tt->nt = j;
        steps[j] = 0;
        
        // Always use multi-target version if we have multiple targets
        if (FLAGMULTITARGET && bsgs_point_number > 1) {
            switch(FLAGBSGSMODE) {
                case 0: // Sequential
                    s = pthread_create(&tid[j], NULL, thread_process_bsgs_multi_target, (void*)tt);
                    break;
                case 3: // Random
                    s = pthread_create(&tid[j], NULL, thread_process_bsgs_random_multi_target, (void*)tt);
                    break;
                case 4: // Subtract
                    if (!FLAGORIGINSET) {
                        fprintf(stderr, "[E] Subtract mode requires an origin public key (-P)\n");
                        exit(1);
                    }
                    s = pthread_create(&tid[j], NULL, thread_process_bsgs_subtract_multi_target, (void*)tt);
                    break;
                case 1: // Subtract random
                    if (!FLAGORIGINSET) {
                        fprintf(stderr, "[E] Subtract mode requires an origin public key (-P)\n");
                        exit(1);
                    }
                    s = pthread_create(&tid[j], NULL, thread_process_bsgs_subtract_random_multi_target, (void*)tt);
                    break;
                default:
                    // Default to sequential multi-target
                    s = pthread_create(&tid[j], NULL, thread_process_bsgs_multi_target, (void*)tt);
                    break;
            }
        } else {
            // Single target - use optimized single target versions
            switch(FLAGBSGSMODE) {
                case 0: // Sequential
                    s = pthread_create(&tid[j], NULL, thread_process_bsgs_multi_target, (void*)tt);
                    break;
                case 1: // Subtract random
                    if (!FLAGORIGINSET) {
                        fprintf(stderr, "[E] Subtract mode requires an origin public key (-P)\n");
                        exit(1);
                    }
                    s = pthread_create(&tid[j], NULL, thread_process_bsgs_subtract_random_multi_target, (void*)tt);
                    break;
                case 3: // Random
                    s = pthread_create(&tid[j], NULL, thread_process_bsgs_random_multi_target, (void*)tt);
                    break;
                case 4: // Subtract
                    if (!FLAGORIGINSET) {
                        fprintf(stderr, "[E] Subtract mode requires an origin public key (-P)\n");
                        exit(1);
                    }
                    s = pthread_create(&tid[j], NULL, thread_process_bsgs_subtract_multi_target, (void*)tt);
                    break;
                default:
                    // Default to sequential
                    s = pthread_create(&tid[j], NULL, thread_process_bsgs_multi_target, (void*)tt);
                    break;
            }
        }
        
        if(s != 0) {
            fprintf(stderr, "[E] pthread_create thread_process\n");
            exit(EXIT_FAILURE);
        }
    }
    
    // Initialize limits for stats display
    for(j = 0; j < 7; j++) {
        int_limits[j].SetBase10((char*)str_limits[j]);
    }

    // Monitor thread progress
    continue_flag = true;
    total.SetInt32(0);
    pretotal.SetInt32(0);
    debugcount_mpz.Set(&BSGS_N);
    seconds.SetInt32(0);

    do {
        sleep_ms(1000);
        seconds.AddOne();
        check_flag = true;
        for(j = 0; j < NTHREADS && check_flag; j++) {
            check_flag &= ends[j];
        }
        if(check_flag) {
            continue_flag = false;
        }
        
        // Display stats every 30 seconds
        Int thirty(30);
        Int secondsMod(seconds);
        secondsMod.Mod(&thirty);
        if(seconds.IsEqual(&thirty) || secondsMod.IsZero()) {
            total.SetInt32(0);
            for(j = 0; j < NTHREADS; j++) {
                pretotal.Set(&debugcount_mpz);
                pretotal.Mult(steps[j]);                    
                total.Add(&pretotal);
            }
            
            pthread_mutex_lock(&mutex_bsgs_thread);
            pretotal.Set(&total);
            pretotal.Div(&seconds);
            char *str_seconds = seconds.GetBase10();
            char *str_pretotal = pretotal.GetBase10();
            char *str_total = total.GetBase10();
            
            // Create extended buffer for better display
            char extended_buffer[512];
            
            if(pretotal.IsLower(&int_limits[0])) {
                // Add multi-target info and extensive padding
                if(FLAGMULTITARGET && bsgs_point_number > 1) {
                    sprintf(extended_buffer, "\r[+] Total %s keys in %s seconds: %s keys/s | MT: %d targets | Mode: %s | √%d speedup%*s\r", 
                            str_total, str_seconds, str_pretotal, bsgs_point_number,
                            bsgs_modes[FLAGBSGSMODE], bsgs_point_number, 100, "");
                } else {
                    sprintf(extended_buffer, "\r[+] Total %s keys in %s seconds: %s keys/s | Mode: %s%*s\r", 
                            str_total, str_seconds, str_pretotal, bsgs_modes[FLAGBSGSMODE], 120, "");
                }
            }
            else {
                i = 0;
                salir = 0;
                while(i < 6 && !salir) {
                    if(pretotal.IsLower(&int_limits[i+1])) {
                        salir = 1;
                    }
                    else {
                        i++;
                    }
                }

                div_pretotal.Set(&pretotal);
                div_pretotal.Div(&int_limits[salir ? i : i-1]);
                char *str_divpretotal = div_pretotal.GetBase10();
                
                // Enhanced display with multi-target info and extensive padding
                if(FLAGMULTITARGET && bsgs_point_number > 1) {
                    sprintf(extended_buffer, "\r[+] Total %s keys in %s seconds: ~%s %s (%s keys/s) | MT: %d targets | Mode: %s | √%d speedup%*s\r", 
                            str_total, str_seconds, str_divpretotal, 
                            str_limits_prefixs[salir ? i : i-1], str_pretotal,
                            bsgs_point_number, bsgs_modes[FLAGBSGSMODE], 
                            bsgs_point_number, 80, "");
                } else {
                    sprintf(extended_buffer, "\r[+] Total %s keys in %s seconds: ~%s %s (%s keys/s) | Mode: %s | Threads: %d%*s\r", 
                            str_total, str_seconds, str_divpretotal, 
                            str_limits_prefixs[salir ? i : i-1], str_pretotal,
                            bsgs_modes[FLAGBSGSMODE], NTHREADS, 100, "");
                }
                
                free(str_divpretotal);
            }
            
            printf("%s", extended_buffer);
            fflush(stdout);
            THREADOUTPUT = 0;
            
            pthread_mutex_unlock(&mutex_bsgs_thread);

            free(str_seconds);
            free(str_pretotal);
            free(str_total);
        }
    } while(continue_flag);

    printf("\nSearch completed\n");

    // Clean up
    for(i = 0; i < NTHREADS; i++) {
        pthread_join(tid[i], NULL);
    }

    free(tid);
    free(steps);
    free(ends);

    return 0;
}

// Multi-target optimized BSGS search thread - sequential mode
void *thread_process_bsgs_multi_target(void *vargp) {
    FILE *filekey;
    struct tothread *tt = (struct tothread*)vargp;
    char xpoint_raw[32], *aux_c, *hextemp;
    Int base_key, keyfound;
    Point base_point, point_aux;
    uint32_t r, cycles;
    
    IntGroup *grp = new IntGroup(CPU_GRP_SIZE / 2 + 1);
    Point startP;
    
    int hLength = (CPU_GRP_SIZE / 2 - 1);
    
    Int dx[CPU_GRP_SIZE / 2 + 1];
    Point pts[CPU_GRP_SIZE];

    Int dy;
    Int dyn;
    Int _s;
    Int _p;
    Int km, intaux;
    Point pp;
    Point pn;
    grp->Set(dx);
    
    cycles = bsgs_aux / 1024;
    if(bsgs_aux % 1024 != 0) {
        cycles++;
    }

    intaux.Set(&BSGS_M_double);
    intaux.Mult(CPU_GRP_SIZE/2);
    intaux.Add(&BSGS_M);
    
    // Pre-compute transformed targets for subtract mode if needed
    std::vector<Point> transformed_targets;
    if(FLAGBSGSMODE == 4 || FLAGBSGSMODE == 1) { // Subtract mode
        transformed_targets.resize(bsgs_point_number);
        for(int i = 0; i < bsgs_point_number; i++) {
            Point negatedTarget = secp->Negation(OriginalPointsBSGS[i]);
            transformed_targets[i] = secp->AddDirect(ORIGIN_PUBKEY, negatedTarget);
        }
    }
    
    do {
        pthread_mutex_lock(&mutex_bsgs_thread);
        base_key.Set(&BSGS_CURRENT);
        BSGS_CURRENT.Add(&BSGS_N);
        BSGS_CURRENT.Add(&BSGS_N);
        pthread_mutex_unlock(&mutex_bsgs_thread);

        if(base_key.IsGreaterOrEqual(&n_range_end))
            break;

        if(FLAGQUIET == 0) {
            aux_c = base_key.GetBase16();
            printf("\r[+] Thread 0x%s MT:%d  \r", aux_c, bsgs_point_number);
            fflush(stdout);
            free(aux_c);
            THREADOUTPUT = 1;
        }

        // Compute base point for this giant step
        base_point = secp->ComputePublicKey(&base_key);
        
        // MULTI-TARGET OPTIMIZATION: Check all targets with this base_point
        for(int target_idx = 0; target_idx < bsgs_point_number; target_idx++) {
            if(multi_target_state->found[target_idx]) continue;
            
            // Direct hit check
            if(FLAGBSGSMODE == 4 || FLAGBSGSMODE == 1) { // Subtract mode
                if(base_point.equals(transformed_targets[target_idx])) {
                    hextemp = base_key.GetBase16();
                    printf("[+] Thread Key found privkey %s for target %d (MT Direct) \n", hextemp, target_idx);
                    Point negatedBasePoint = secp->Negation(base_point);
                    Point calculated_point = secp->AddDirect(ORIGIN_PUBKEY, negatedBasePoint);
                    aux_c = secp->GetPublicKeyHex(OriginalPointsBSGScompressed[target_idx], calculated_point);
                    printf("[+] Target %d Calculated point (O - k*G) %s\n", target_idx, aux_c);
                    
                    pthread_mutex_lock(&write_keys);
                    filekey = fopen("KEYFOUNDKEYFOUND.txt", "a");
                    if(filekey != NULL) {
                        fprintf(filekey, "Key found privkey %s for target %d (Multi-Target)\n", hextemp, target_idx);
                        fprintf(filekey, "Target pubkey: %s\n", secp->GetPublicKeyHex(OriginalPointsBSGScompressed[target_idx], OriginalPointsBSGS[target_idx]));
                        fclose(filekey);
                    }
                    multi_target_state->found[target_idx] = true;
                    multi_target_state->found_keys[target_idx].Set(&base_key);
                    pthread_mutex_unlock(&write_keys);

                    free(hextemp);
                    free(aux_c);
                    
                    // Check if all found
                    bool all_found = true;
                    for(int i = 0; i < bsgs_point_number; i++) {
                        if(!multi_target_state->found[i]) {
                            all_found = false;
                            break;
                        }
                    }
                    if(all_found) {
                        printf("All keys found!\n");
                        exit(0);
                    }
                    continue;
                }
            } else { // Regular mode
                if(base_point.equals(OriginalPointsBSGS[target_idx])) {
                    hextemp = base_key.GetBase16();
                    printf("[+] Thread Key found privkey %s for target %d (MT Direct) \n", hextemp, target_idx);
                    aux_c = secp->GetPublicKeyHex(OriginalPointsBSGScompressed[target_idx], base_point);
                    printf("[+] Target %d Publickey %s\n", target_idx, aux_c);
                    
                    pthread_mutex_lock(&write_keys);
                    filekey = fopen("KEYFOUNDKEYFOUND.txt", "a");
                    if(filekey != NULL) {
                        fprintf(filekey, "Key found privkey %s for target %d (Multi-Target)\nPublickey %s\n", hextemp, target_idx, aux_c);
                        fclose(filekey);
                    }
                    multi_target_state->found[target_idx] = true;
                    multi_target_state->found_keys[target_idx].Set(&base_key);
                    pthread_mutex_unlock(&write_keys);

                    free(hextemp);
                    free(aux_c);
                    
                    // Check if all found
                    bool all_found = true;
                    for(int i = 0; i < bsgs_point_number; i++) {
                        if(!multi_target_state->found[i]) {
                            all_found = false;
                            break;
                        }
                    }
                    if(all_found) {
                        printf("All keys found!\n");
                        exit(0);
                    }
                    continue;
                }
            }
        }

        // Compute auxiliary point for baby-step giant-step
        km.Set(&base_key);
        km.Neg();
        km.Add(&secp->order);
        km.Sub(&intaux);
        point_aux = secp->ComputePublicKey(&km);
        
        // MULTI-TARGET GIANT STEPS: Process all targets in this giant step
        for(int target_idx = 0; target_idx < bsgs_point_number; target_idx++) {
            if(multi_target_state->found[target_idx]) continue;
            
            // Set up starting point for this target
            if(FLAGBSGSMODE == 4 || FLAGBSGSMODE == 1) { // Subtract mode
                startP = secp->AddDirect(transformed_targets[target_idx], point_aux);
            } else {
                startP = secp->AddDirect(OriginalPointsBSGS[target_idx], point_aux);
            }
            
            uint32_t j = 0;
            while(j < cycles && !multi_target_state->found[target_idx]) {
                int i;
                
                // Compute batch points
                for(i = 0; i < hLength; i++) {
                    dx[i].ModSub(&GSn[i].x, &startP.x);
                }
                dx[i].ModSub(&GSn[i].x, &startP.x);
                dx[i+1].ModSub(&_2GSn.x, &startP.x);

                grp->ModInv();
                
                pts[CPU_GRP_SIZE / 2] = startP;
                
                for(i = 0; i<hLength; i++) {
                    pp = startP;
                    pn = startP;

                    dy.ModSub(&GSn[i].y, &pp.y);
                    _s.ModMulK1(&dy, &dx[i]);
                    _p.ModSquareK1(&_s);
                    pp.x.ModNeg();
                    pp.x.ModAdd(&_p);
                    pp.x.ModSub(&GSn[i].x);
                    
                    dyn.Set(&GSn[i].y);
                    dyn.ModNeg();
                    dyn.ModSub(&pn.y);
                    _s.ModMulK1(&dyn, &dx[i]);
                    _p.ModSquareK1(&_s);
                    pn.x.ModNeg();
                    pn.x.ModAdd(&_p);
                    pn.x.ModSub(&GSn[i].x);

                    pts[CPU_GRP_SIZE / 2 + (i + 1)] = pp;
                    pts[CPU_GRP_SIZE / 2 - (i + 1)] = pn;
                }

                pn = startP;
                dyn.Set(&GSn[i].y);
                dyn.ModNeg();
                dyn.ModSub(&pn.y);
                _s.ModMulK1(&dyn, &dx[i]);
                _p.ModSquareK1(&_s);
                pn.x.ModNeg();
                pn.x.ModAdd(&_p);
                pn.x.ModSub(&GSn[i].x);
                pts[0] = pn;
                
                // Check computed points against baby-step table
                for(int i = 0; i<CPU_GRP_SIZE && !multi_target_state->found[target_idx]; i++) {
                    pts[i].x.Get32Bytes((unsigned char*)xpoint_raw);
                    r = bloom_check(&bloom_bP[((unsigned char)xpoint_raw[0])], xpoint_raw, 32);
                    if(r) {
                        r = bsgs_secondcheck_multitarget(&base_key, ((j*1024) + i), target_idx, &keyfound);
                        if(r) {
                            hextemp = keyfound.GetBase16();
                            printf("[+] Thread Key found privkey %s for target %d (Multi-Target) \n", hextemp, target_idx);
                            
                            Point point_found = secp->ComputePublicKey(&keyfound);
                            if(FLAGBSGSMODE == 4 || FLAGBSGSMODE == 1) { // Subtract mode
                                Point negatedFound = secp->Negation(point_found);
                                Point calculated_point = secp->AddDirect(ORIGIN_PUBKEY, negatedFound);
                                aux_c = secp->GetPublicKeyHex(OriginalPointsBSGScompressed[target_idx], calculated_point);
                                printf("[+] Target %d Calculated point (O - k*G) %s\n", target_idx, aux_c);
                            } else {
                                aux_c = secp->GetPublicKeyHex(OriginalPointsBSGScompressed[target_idx], point_found);
                                printf("[+] Target %d Publickey %s\n", target_idx, aux_c);
                            }
                            
                            pthread_mutex_lock(&write_keys);
                            filekey = fopen("KEYFOUNDKEYFOUND.txt", "a");
                            if(filekey != NULL) {
                                fprintf(filekey, "Key found privkey %s for target %d (Multi-Target)\n", hextemp, target_idx);
                                if(FLAGBSGSMODE == 4 || FLAGBSGSMODE == 1) {
                                    fprintf(filekey, "Calculated point: %s\n", aux_c);
                                } else {
                                    fprintf(filekey, "Publickey %s\n", aux_c);
                                }
                                fclose(filekey);
                            }
                            multi_target_state->found[target_idx] = true;
                            multi_target_state->found_keys[target_idx].Set(&keyfound);
                            pthread_mutex_unlock(&write_keys);
                            
                            free(hextemp);
                            free(aux_c);
                            
                            // Check if all found
                            bool all_found = true;
                            for(int i = 0; i < bsgs_point_number; i++) {
                                if(!multi_target_state->found[i]) {
                                    all_found = false;
                                    break;
                                }
                            }
                            if(all_found) {
                                printf("All keys found!\n");
                                exit(0);
                            }
                        }
                    }
                }
                
                // Next start point
                pp = startP;
                dy.ModSub(&_2GSn.y, &pp.y);
                _s.ModMulK1(&dy, &dx[i + 1]);
                _p.ModSquareK1(&_s);
                pp.x.ModNeg();
                pp.x.ModAdd(&_p);
                pp.x.ModSub(&_2GSn.x);
                pp.y.ModSub(&_2GSn.x, &pp.x);
                pp.y.ModMulK1(&_s);
                pp.y.ModSub(&_2GSn.y);
                startP = pp;
                
                j++;
            }
        }
        
        steps[tt->nt]+=2;
    } while(base_key.IsLower(&n_range_end));
    
    ends[tt->nt] = 1;
    delete grp;
    pthread_exit(NULL);
}

// Multi-target optimized BSGS search thread - random mode
void *thread_process_bsgs_random_multi_target(void *vargp) {
    FILE *filekey;
    struct tothread *tt = (struct tothread*)vargp;
    char xpoint_raw[32], *aux_c, *hextemp;
    Int base_key, keyfound;
    Point base_point, point_aux;
    uint32_t r, thread_number, cycles;
    
    IntGroup *grp = new IntGroup(CPU_GRP_SIZE / 2 + 1);
    Point startP;
    
    int hLength = (CPU_GRP_SIZE / 2 - 1);
    
    Int dx[CPU_GRP_SIZE / 2 + 1];
    Point pts[CPU_GRP_SIZE];

    Int dy;
    Int dyn;
    Int _s;
    Int _p;
    Int km, intaux;
    Point pp;
    Point pn;
    grp->Set(dx);

    thread_number = tt->nt;
    free(tt);
    
    cycles = bsgs_aux / 1024;
    if(bsgs_aux % 1024 != 0) {
        cycles++;
    }
    
    intaux.Set(&BSGS_M_double);
    intaux.Mult(CPU_GRP_SIZE/2);
    intaux.Add(&BSGS_M);
    
    // Pre-compute transformed targets for subtract mode if needed
    std::vector<Point> transformed_targets;
    if(FLAGBSGSMODE == 4 || FLAGBSGSMODE == 1) { // Subtract mode
        transformed_targets.resize(bsgs_point_number);
        for(int i = 0; i < bsgs_point_number; i++) {
            Point negatedTarget = secp->Negation(OriginalPointsBSGS[i]);
            transformed_targets[i] = secp->AddDirect(ORIGIN_PUBKEY, negatedTarget);
        }
    }

    do {
        // Get a random key within the range
        pthread_mutex_lock(&mutex_bsgs_thread);
        base_key.Rand(&n_range_start, &n_range_end);
        pthread_mutex_unlock(&mutex_bsgs_thread);

        if(FLAGQUIET == 0) {
            aux_c = base_key.GetBase16();
            printf("\r[+] Thread 0x%s MT:%d  \r", aux_c, bsgs_point_number);
            fflush(stdout);
            free(aux_c);
            THREADOUTPUT = 1;
        }
        
        // Compute base point for this giant step
        base_point = secp->ComputePublicKey(&base_key);

        // MULTI-TARGET OPTIMIZATION: Check all targets with this base_point
        for(int target_idx = 0; target_idx < bsgs_point_number; target_idx++) {
            if(multi_target_state->found[target_idx]) continue;
            
            // Direct hit check
            if(FLAGBSGSMODE == 4 || FLAGBSGSMODE == 1) { // Subtract mode
                if(base_point.equals(transformed_targets[target_idx])) {
                    hextemp = base_key.GetBase16();
                    printf("[+] Thread Key found privkey %s for target %d (MT Random Direct) \n", hextemp, target_idx);
                    Point negatedBasePoint = secp->Negation(base_point);
                    Point calculated_point = secp->AddDirect(ORIGIN_PUBKEY, negatedBasePoint);
                    aux_c = secp->GetPublicKeyHex(OriginalPointsBSGScompressed[target_idx], calculated_point);
                    printf("[+] Target %d Calculated point (O - k*G) %s\n", target_idx, aux_c);
                    
                    pthread_mutex_lock(&write_keys);
                    filekey = fopen("KEYFOUNDKEYFOUND.txt", "a");
                    if(filekey != NULL) {
                        fprintf(filekey, "Key found privkey %s for target %d (Multi-Target Random)\n", hextemp, target_idx);
                        fprintf(filekey, "Target pubkey: %s\n", secp->GetPublicKeyHex(OriginalPointsBSGScompressed[target_idx], OriginalPointsBSGS[target_idx]));
                        fclose(filekey);
                    }
                    multi_target_state->found[target_idx] = true;
                    multi_target_state->found_keys[target_idx].Set(&base_key);
                    pthread_mutex_unlock(&write_keys);

                    free(hextemp);
                    free(aux_c);
                    
                    // Check if all found
                    bool all_found = true;
                    for(int i = 0; i < bsgs_point_number; i++) {
                        if(!multi_target_state->found[i]) {
                            all_found = false;
                            break;
                        }
                    }
                    if(all_found) {
                        printf("All keys found!\n");
                        exit(0);
                    }
                    continue;
                }
            } else { // Regular mode
                if(base_point.equals(OriginalPointsBSGS[target_idx])) {
                    hextemp = base_key.GetBase16();
                    printf("[+] Thread Key found privkey %s for target %d (MT Random Direct) \n", hextemp, target_idx);
                    aux_c = secp->GetPublicKeyHex(OriginalPointsBSGScompressed[target_idx], base_point);
                    printf("[+] Target %d Publickey %s\n", target_idx, aux_c);
                    
                    pthread_mutex_lock(&write_keys);
                    filekey = fopen("KEYFOUNDKEYFOUND.txt", "a");
                    if(filekey != NULL) {
                        fprintf(filekey, "Key found privkey %s for target %d (Multi-Target Random)\nPublickey %s\n", hextemp, target_idx, aux_c);
                        fclose(filekey);
                    }
                    multi_target_state->found[target_idx] = true;
                    multi_target_state->found_keys[target_idx].Set(&base_key);
                    pthread_mutex_unlock(&write_keys);

                    free(hextemp);
                    free(aux_c);
                    
                    // Check if all found
                    bool all_found = true;
                    for(int i = 0; i < bsgs_point_number; i++) {
                        if(!multi_target_state->found[i]) {
                            all_found = false;
                            break;
                        }
                    }
                    if(all_found) {
                        printf("All keys found!\n");
                        exit(0);
                    }
                    continue;
                }
            }
        }

        km.Set(&base_key);
        km.Neg();
        km.Add(&secp->order);
        km.Sub(&intaux);
        point_aux = secp->ComputePublicKey(&km);

        // MULTI-TARGET GIANT STEPS: Process all targets in this giant step
        for(int target_idx = 0; target_idx < bsgs_point_number; target_idx++) {
            if(multi_target_state->found[target_idx]) continue;
            
            // Set up starting point for this target
            if(FLAGBSGSMODE == 4 || FLAGBSGSMODE == 1) { // Subtract mode
                startP = secp->AddDirect(transformed_targets[target_idx], point_aux);
            } else {
                startP = secp->AddDirect(OriginalPointsBSGS[target_idx], point_aux);
            }
            
            uint32_t j = 0;
            while(j < cycles && !multi_target_state->found[target_idx]) {
                int i;
                
                // Compute batch points
                for(i = 0; i < hLength; i++) {
                    dx[i].ModSub(&GSn[i].x, &startP.x);
                }
                dx[i].ModSub(&GSn[i].x, &startP.x);
                dx[i+1].ModSub(&_2GSn.x, &startP.x);

                grp->ModInv();
                
                pts[CPU_GRP_SIZE / 2] = startP;
                
                for(i = 0; i < hLength; i++) {
                    pp = startP;
                    pn = startP;

                    dy.ModSub(&GSn[i].y, &pp.y);
                    _s.ModMulK1(&dy, &dx[i]);
                    _p.ModSquareK1(&_s);
                    pp.x.ModNeg();
                    pp.x.ModAdd(&_p);
                    pp.x.ModSub(&GSn[i].x);

                    dyn.Set(&GSn[i].y);
                    dyn.ModNeg();
                    dyn.ModSub(&pn.y);
                    _s.ModMulK1(&dyn, &dx[i]);
                    _p.ModSquareK1(&_s);
                    pn.x.ModNeg();
                    pn.x.ModAdd(&_p);
                    pn.x.ModSub(&GSn[i].x);

                    pts[CPU_GRP_SIZE / 2 + (i + 1)] = pp;
                    pts[CPU_GRP_SIZE / 2 - (i + 1)] = pn;
                }

                pn = startP;
                dyn.Set(&GSn[i].y);
                dyn.ModNeg();
                dyn.ModSub(&pn.y);
                _s.ModMulK1(&dyn, &dx[i]);
                _p.ModSquareK1(&_s);
                pn.x.ModNeg();
                pn.x.ModAdd(&_p);
                pn.x.ModSub(&GSn[i].x);
                pts[0] = pn;
                
                // Check computed points against baby-step table
                for(int i = 0; i < CPU_GRP_SIZE && !multi_target_state->found[target_idx]; i++) {
                    pts[i].x.Get32Bytes((unsigned char*)xpoint_raw);
                    r = bloom_check(&bloom_bP[((unsigned char)xpoint_raw[0])], xpoint_raw, 32);
                    
                    if(r) {
                        r = bsgs_secondcheck_multitarget(&base_key, ((j*1024) + i), target_idx, &keyfound);
                        if(r) {
                            hextemp = keyfound.GetBase16();
                            printf("[+] Thread Key found privkey %s for target %d (Multi-Target Random) \n", hextemp, target_idx);
                            
                            Point point_found = secp->ComputePublicKey(&keyfound);
                            if(FLAGBSGSMODE == 4 || FLAGBSGSMODE == 1) { // Subtract mode
                                Point negatedFound = secp->Negation(point_found);
                                Point calculated_point = secp->AddDirect(ORIGIN_PUBKEY, negatedFound);
                                aux_c = secp->GetPublicKeyHex(OriginalPointsBSGScompressed[target_idx], calculated_point);
                                printf("[+] Target %d Calculated point (O - k*G) %s\n", target_idx, aux_c);
                            } else {
                                aux_c = secp->GetPublicKeyHex(OriginalPointsBSGScompressed[target_idx], point_found);
                                printf("[+] Target %d Publickey %s\n", target_idx, aux_c);
                            }
                            
                            pthread_mutex_lock(&write_keys);
                            filekey = fopen("KEYFOUNDKEYFOUND.txt", "a");
                            if(filekey != NULL) {
                                fprintf(filekey, "Key found privkey %s for target %d (Multi-Target Random)\n", hextemp, target_idx);
                                if(FLAGBSGSMODE == 4 || FLAGBSGSMODE == 1) {
                                    fprintf(filekey, "Calculated point: %s\n", aux_c);
                                } else {
                                    fprintf(filekey, "Publickey %s\n", aux_c);
                                }
                                fclose(filekey);
                            }
                            multi_target_state->found[target_idx] = true;
                            multi_target_state->found_keys[target_idx].Set(&keyfound);
                            pthread_mutex_unlock(&write_keys);
                            
                            free(hextemp);
                            free(aux_c);
                            
                            // Check if all found
                            bool all_found = true;
                            for(int i = 0; i < bsgs_point_number; i++) {
                                if(!multi_target_state->found[i]) {
                                    all_found = false;
                                    break;
                                }
                            }
                            if(all_found) {
                                printf("All keys found!\n");
                                exit(0);
                            }
                        }
                    }
                }
                
                // Next start point
                pp = startP;
                dy.ModSub(&_2GSn.y, &pp.y);
                _s.ModMulK1(&dy, &dx[i + 1]);
                _p.ModSquareK1(&_s);
                pp.x.ModNeg();
                pp.x.ModAdd(&_p);
                pp.x.ModSub(&_2GSn.x);
                pp.y.ModSub(&_2GSn.x, &pp.x);
                pp.y.ModMulK1(&_s);
                pp.y.ModSub(&_2GSn.y);
                startP = pp;
                
                j++;
            }
        }
        
        steps[thread_number] += 2;
    } while(1);
    
    ends[thread_number] = 1;
    delete grp;
    return NULL;
}

// Multi-target optimized BSGS search thread - subtract mode
void *thread_process_bsgs_subtract_multi_target(void *vargp) {
    FILE *filekey;
    struct tothread *tt = (struct tothread*)vargp;
    char xpoint_raw[32], *aux_c, *hextemp;
    Int base_key, keyfound;
    Point base_point, point_aux;
    uint32_t r, cycles;
    
    IntGroup *grp = new IntGroup(CPU_GRP_SIZE / 2 + 1);
    Point startP;
    
    int hLength = (CPU_GRP_SIZE / 2 - 1);
    
    Int dx[CPU_GRP_SIZE / 2 + 1];
    Point pts[CPU_GRP_SIZE];

    Int dy;
    Int dyn;
    Int _s;
    Int _p;
    Int km, intaux;
    Point pp;
    Point pn;
    grp->Set(dx);
    
    cycles = bsgs_aux / 1024;
    if(bsgs_aux % 1024 != 0) {
        cycles++;
    }

    intaux.Set(&BSGS_M_double);
    intaux.Mult(CPU_GRP_SIZE/2);
    intaux.Add(&BSGS_M);
    
    // Pre-compute transformed targets (O - Q) for all targets
    std::vector<Point> transformed_targets(bsgs_point_number);
    for(int i = 0; i < bsgs_point_number; i++) {
        Point negatedTarget = secp->Negation(OriginalPointsBSGS[i]);
        transformed_targets[i] = secp->AddDirect(ORIGIN_PUBKEY, negatedTarget);
    }
    
    do {
        pthread_mutex_lock(&mutex_bsgs_thread);
        base_key.Set(&BSGS_CURRENT);
        BSGS_CURRENT.Add(&BSGS_M); // Use M instead of N for step size
        pthread_mutex_unlock(&mutex_bsgs_thread);

        if(base_key.IsGreaterOrEqual(&n_range_end))
            break;

        if(FLAGQUIET == 0) {
            aux_c = base_key.GetBase16();
            printf("\r[+] Thread 0x%s MT:%d Sub  \r", aux_c, bsgs_point_number);
            fflush(stdout);
            free(aux_c);
            THREADOUTPUT = 1;
        }

        // Compute k*G
        base_point = secp->ComputePublicKey(&base_key);
        
        // MULTI-TARGET OPTIMIZATION: Check all targets with this base_point
        for(int target_idx = 0; target_idx < bsgs_point_number; target_idx++) {
            if(multi_target_state->found[target_idx]) continue;
            
            // Direct check with transformed target: k*G = (O - Q)
            if(base_point.equals(transformed_targets[target_idx])) {
                hextemp = base_key.GetBase16();
                printf("[+] Thread Key found privkey %s for target %d (MT Subtract Direct) \n", hextemp, target_idx);
                
                // Calculate O - k*G for display
                Point negatedBasePoint = secp->Negation(base_point);
                Point calculated_point = secp->AddDirect(ORIGIN_PUBKEY, negatedBasePoint);
                
                aux_c = secp->GetPublicKeyHex(OriginalPointsBSGScompressed[target_idx], calculated_point);
                printf("[+] Target %d Calculated point (O - k*G) %s\n", target_idx, aux_c);
                printf("[+] Target %d Original pubkey %s\n", target_idx, secp->GetPublicKeyHex(OriginalPointsBSGScompressed[target_idx], OriginalPointsBSGS[target_idx]));
                
                pthread_mutex_lock(&write_keys);
                filekey = fopen("KEYFOUNDKEYFOUND.txt", "a");
                if(filekey != NULL) {
                    fprintf(filekey, "Key found privkey %s for target %d (Multi-Target Subtract)\n", hextemp, target_idx);
                    fprintf(filekey, "Origin pubkey: %s\n", secp->GetPublicKeyHex(true, ORIGIN_PUBKEY));
                    fprintf(filekey, "Private key pubkey: %s\n", secp->GetPublicKeyHex(true, base_point));
                    fprintf(filekey, "Calculated point (O - k*G): %s\n", aux_c);
                    fprintf(filekey, "Target pubkey: %s\n", secp->GetPublicKeyHex(OriginalPointsBSGScompressed[target_idx], OriginalPointsBSGS[target_idx]));
                    fclose(filekey);
                }
                multi_target_state->found[target_idx] = true;
                multi_target_state->found_keys[target_idx].Set(&base_key);
                pthread_mutex_unlock(&write_keys);

                free(hextemp);
                free(aux_c);
                
                // Check if all found
                bool all_found = true;
                for(int i = 0; i < bsgs_point_number; i++) {
                    if(!multi_target_state->found[i]) {
                        all_found = false;
                        break;
                    }
                }
                if(all_found) {
                    printf("All keys found!\n");
                    exit(0);
                }
                continue;
            }
        }
        
        // Compute auxiliary point for BSGS
        km.Set(&base_key);
        km.Neg();
        km.Add(&secp->order);
        km.Sub(&intaux);
        point_aux = secp->ComputePublicKey(&km);
        
        // MULTI-TARGET GIANT STEPS: Process all targets in this giant step
        for(int target_idx = 0; target_idx < bsgs_point_number; target_idx++) {
            if(multi_target_state->found[target_idx]) continue;
            
            // Use transformed targets for BSGS search
            startP = secp->AddDirect(transformed_targets[target_idx], point_aux);
            
            uint32_t j = 0;
            while(j < cycles && !multi_target_state->found[target_idx]) {
                int i;
                
                for(i = 0; i < hLength; i++) {
                    dx[i].ModSub(&GSn[i].x, &startP.x);
                }
                dx[i].ModSub(&GSn[i].x, &startP.x);
                dx[i+1].ModSub(&_2GSn.x, &startP.x);

                grp->ModInv();
                
                pts[CPU_GRP_SIZE / 2] = startP;
                
                for(i = 0; i<hLength; i++) {
                    pp = startP;
                    pn = startP;

                    dy.ModSub(&GSn[i].y, &pp.y);
                    _s.ModMulK1(&dy, &dx[i]);
                    _p.ModSquareK1(&_s);
                    pp.x.ModNeg();
                    pp.x.ModAdd(&_p);
                    pp.x.ModSub(&GSn[i].x);
                    
                    dyn.Set(&GSn[i].y);
                    dyn.ModNeg();
                    dyn.ModSub(&pn.y);
                    _s.ModMulK1(&dyn, &dx[i]);
                    _p.ModSquareK1(&_s);
                    pn.x.ModNeg();
                    pn.x.ModAdd(&_p);
                    pn.x.ModSub(&GSn[i].x);

                    pts[CPU_GRP_SIZE / 2 + (i + 1)] = pp;
                    pts[CPU_GRP_SIZE / 2 - (i + 1)] = pn;
                }

                pn = startP;
                dyn.Set(&GSn[i].y);
                dyn.ModNeg();
                dyn.ModSub(&pn.y);
                _s.ModMulK1(&dyn, &dx[i]);
                _p.ModSquareK1(&_s);
                pn.x.ModNeg();
                pn.x.ModAdd(&_p);
                pn.x.ModSub(&GSn[i].x);
                pts[0] = pn;
                
                for(int i = 0; i<CPU_GRP_SIZE && !multi_target_state->found[target_idx]; i++) {
                    pts[i].x.Get32Bytes((unsigned char*)xpoint_raw);
                    r = bloom_check(&bloom_bP[((unsigned char)xpoint_raw[0])], xpoint_raw, 32);
                    
                    if(r) {
                        r = bsgs_secondcheck_multitarget(&base_key, ((j*1024) + i), target_idx, &keyfound);
                        if(r) {
                            Point point_found = secp->ComputePublicKey(&keyfound);
                            
                            // Verify with transformed target
                            if(point_found.equals(transformed_targets[target_idx])) {
                                hextemp = keyfound.GetBase16();
                                printf("[+] Thread Key found privkey %s for target %d (Multi-Target Subtract) \n", hextemp, target_idx);
                                
                                // Calculate O - k*G for display
                                Point negatedFound = secp->Negation(point_found);
                                Point calculated_point = secp->AddDirect(ORIGIN_PUBKEY, negatedFound);
                                
                                aux_c = secp->GetPublicKeyHex(OriginalPointsBSGScompressed[target_idx], calculated_point);
                                printf("[+] Target %d Calculated point (O - k*G) %s\n", target_idx, aux_c);
                                printf("[+] Target %d Original pubkey %s\n", target_idx, secp->GetPublicKeyHex(OriginalPointsBSGScompressed[target_idx], OriginalPointsBSGS[target_idx]));
                                
                                pthread_mutex_lock(&write_keys);
                                filekey = fopen("KEYFOUNDKEYFOUND.txt", "a");
                                if(filekey != NULL) {
                                    fprintf(filekey, "Key found privkey %s for target %d (Multi-Target Subtract)\n", hextemp, target_idx);
                                    fprintf(filekey, "Origin pubkey: %s\n", secp->GetPublicKeyHex(true, ORIGIN_PUBKEY));
                                    fprintf(filekey, "Private key pubkey: %s\n", secp->GetPublicKeyHex(true, point_found));
                                    fprintf(filekey, "Calculated point (O - k*G): %s\n", aux_c);
                                    fprintf(filekey, "Target pubkey: %s\n", secp->GetPublicKeyHex(OriginalPointsBSGScompressed[target_idx], OriginalPointsBSGS[target_idx]));
                                    fclose(filekey);
                                }
                                multi_target_state->found[target_idx] = true;
                                multi_target_state->found_keys[target_idx].Set(&keyfound);
                                pthread_mutex_unlock(&write_keys);
                                
                                free(hextemp);
                                free(aux_c);
                                
                                // Check if all found
                                bool all_found = true;
                                for(int i = 0; i < bsgs_point_number; i++) {
                                    if(!multi_target_state->found[i]) {
                                        all_found = false;
                                        break;
                                    }
                                }
                                if(all_found) {
                                    printf("All keys found!\n");
                                    exit(0);
                                }
                            }
                        }
                    }
                }
                
                pp = startP;
                dy.ModSub(&_2GSn.y, &pp.y);
                _s.ModMulK1(&dy, &dx[i + 1]);
                _p.ModSquareK1(&_s);
                pp.x.ModNeg();
                pp.x.ModAdd(&_p);
                pp.x.ModSub(&_2GSn.x);
                pp.y.ModSub(&_2GSn.x, &pp.x);
                pp.y.ModMulK1(&_s);
                pp.y.ModSub(&_2GSn.y);
                startP = pp;
                
                j++;
            }
        }
        steps[tt->nt]++;
    } while(base_key.IsLower(&n_range_end));
    
    ends[tt->nt] = 1;
    delete grp;
    pthread_exit(NULL);
}

// Multi-target optimized BSGS search thread - subtract random mode
void *thread_process_bsgs_subtract_random_multi_target(void *vargp) {
    FILE *filekey;
    struct tothread *tt = (struct tothread*)vargp;
    char xpoint_raw[32], *aux_c, *hextemp;
    Int base_key, keyfound;
    Point base_point, point_aux;
    uint32_t r, thread_number, cycles;
    
    IntGroup *grp = new IntGroup(CPU_GRP_SIZE / 2 + 1);
    Point startP;
    
    int hLength = (CPU_GRP_SIZE / 2 - 1);
    
    Int dx[CPU_GRP_SIZE / 2 + 1];
    Point pts[CPU_GRP_SIZE];

    Int dy;
    Int dyn;
    Int _s;
    Int _p;
    Int km, intaux;
    Point pp;
    Point pn;
    grp->Set(dx);

    thread_number = tt->nt;
    free(tt);
    
    cycles = bsgs_aux / 1024;
    if(bsgs_aux % 1024 != 0) {
        cycles++;
    }
    
    intaux.Set(&BSGS_M_double);
    intaux.Mult(CPU_GRP_SIZE/2);
    intaux.Add(&BSGS_M);
    
    // Pre-compute transformed targets (O - Q)
    std::vector<Point> transformed_targets(bsgs_point_number);
    for(int i = 0; i < bsgs_point_number; i++) {
        Point negatedTarget = secp->Negation(OriginalPointsBSGS[i]);
        transformed_targets[i] = secp->AddDirect(ORIGIN_PUBKEY, negatedTarget);
    }

    do {
        // Get a random key within the range
        pthread_mutex_lock(&mutex_bsgs_thread);
        base_key.Rand(&n_range_start, &n_range_end);
        pthread_mutex_unlock(&mutex_bsgs_thread);

        if(FLAGQUIET == 0) {
            aux_c = base_key.GetBase16();
            printf("\r[+] Thread 0x%s MT:%d SubR  \r", aux_c, bsgs_point_number);
            fflush(stdout);
            free(aux_c);
            THREADOUTPUT = 1;
        }
        
        // Compute k*G
        base_point = secp->ComputePublicKey(&base_key);
        
        // MULTI-TARGET OPTIMIZATION: Check all targets with this base_point
        for(int target_idx = 0; target_idx < bsgs_point_number; target_idx++) {
            if(multi_target_state->found[target_idx]) continue;
            
            // Direct check with transformed target: k*G = (O - Q)
            if(base_point.equals(transformed_targets[target_idx])) {
                hextemp = base_key.GetBase16();
                printf("[+] Thread Key found privkey %s for target %d (MT Subtract Random Direct) \n", hextemp, target_idx);
                
                Point negatedBasePoint = secp->Negation(base_point);
                Point calculated_point = secp->AddDirect(ORIGIN_PUBKEY, negatedBasePoint);
                
                aux_c = secp->GetPublicKeyHex(OriginalPointsBSGScompressed[target_idx], calculated_point);
                printf("[+] Target %d Calculated point (O - k*G) %s\n", target_idx, aux_c);
                printf("[+] Target %d Target pubkey %s\n", target_idx, secp->GetPublicKeyHex(OriginalPointsBSGScompressed[target_idx], OriginalPointsBSGS[target_idx]));
                
                pthread_mutex_lock(&write_keys);
                filekey = fopen("KEYFOUNDKEYFOUND.txt", "a");
                if(filekey != NULL) {
                    fprintf(filekey, "Key found privkey %s for target %d (Multi-Target Subtract Random)\n", hextemp, target_idx);
                    fprintf(filekey, "Origin pubkey: %s\n", secp->GetPublicKeyHex(true, ORIGIN_PUBKEY));
                    fprintf(filekey, "Private key pubkey: %s\n", secp->GetPublicKeyHex(true, base_point));
                    fprintf(filekey, "Calculated point (O - k*G): %s\n", aux_c);
                    fprintf(filekey, "Target pubkey: %s\n", secp->GetPublicKeyHex(OriginalPointsBSGScompressed[target_idx], OriginalPointsBSGS[target_idx]));
                    fclose(filekey);
                }
                multi_target_state->found[target_idx] = true;
                multi_target_state->found_keys[target_idx].Set(&base_key);
                pthread_mutex_unlock(&write_keys);

                free(hextemp);
                free(aux_c);
                
                // Check if all found
                bool all_found = true;
                for(int i = 0; i < bsgs_point_number; i++) {
                    if(!multi_target_state->found[i]) {
                        all_found = false;
                        break;
                    }
                }
                if(all_found) {
                    printf("All keys found!\n");
                    exit(0);
                }
                continue;
            }
        }

        // Compute auxiliary point for BSGS
        km.Set(&base_key);
        km.Neg();
        km.Add(&secp->order);
        km.Sub(&intaux);
        point_aux = secp->ComputePublicKey(&km);

        // MULTI-TARGET GIANT STEPS: Process all targets in this giant step
        for(int target_idx = 0; target_idx < bsgs_point_number; target_idx++) {
            if(multi_target_state->found[target_idx]) continue;
            
            // Use transformed target for BSGS search
            startP = secp->AddDirect(transformed_targets[target_idx], point_aux);
            
            uint32_t j = 0;
            while(j < cycles && !multi_target_state->found[target_idx]) {
                int i;
                
                for(i = 0; i < hLength; i++) {
                    dx[i].ModSub(&GSn[i].x, &startP.x);
                }
                dx[i].ModSub(&GSn[i].x, &startP.x);
                dx[i+1].ModSub(&_2GSn.x, &startP.x);

                grp->ModInv();
                
                pts[CPU_GRP_SIZE / 2] = startP;
                
                for(i = 0; i < hLength; i++) {
                    pp = startP;
                    pn = startP;

                    dy.ModSub(&GSn[i].y, &pp.y);
                    _s.ModMulK1(&dy, &dx[i]);
                    _p.ModSquareK1(&_s);
                    pp.x.ModNeg();
                    pp.x.ModAdd(&_p);
                    pp.x.ModSub(&GSn[i].x);

                    dyn.Set(&GSn[i].y);
                    dyn.ModNeg();
                    dyn.ModSub(&pn.y);
                    _s.ModMulK1(&dyn, &dx[i]);
                    _p.ModSquareK1(&_s);
                    pn.x.ModNeg();
                    pn.x.ModAdd(&_p);
                    pn.x.ModSub(&GSn[i].x);

                    pts[CPU_GRP_SIZE / 2 + (i + 1)] = pp;
                    pts[CPU_GRP_SIZE / 2 - (i + 1)] = pn;
                }

                pn = startP;
                dyn.Set(&GSn[i].y);
                dyn.ModNeg();
                dyn.ModSub(&pn.y);
                _s.ModMulK1(&dyn, &dx[i]);
                _p.ModSquareK1(&_s);
                pn.x.ModNeg();
                pn.x.ModAdd(&_p);
                pn.x.ModSub(&GSn[i].x);
                pts[0] = pn;
                
                for(int i = 0; i < CPU_GRP_SIZE && !multi_target_state->found[target_idx]; i++) {
                    pts[i].x.Get32Bytes((unsigned char*)xpoint_raw);
                    r = bloom_check(&bloom_bP[((unsigned char)xpoint_raw[0])], xpoint_raw, 32);
                    
                    if(r) {
                        r = bsgs_secondcheck_multitarget(&base_key, ((j*1024) + i), target_idx, &keyfound);
                        if(r) {
                            Point point_found = secp->ComputePublicKey(&keyfound);
                            
                            if(point_found.equals(transformed_targets[target_idx])) {
                                hextemp = keyfound.GetBase16();
                                printf("[+] Thread Key found privkey %s for target %d (Multi-Target Subtract Random) \n", hextemp, target_idx);
                                
                                Point negatedFound = secp->Negation(point_found);
                                Point calculated_point = secp->AddDirect(ORIGIN_PUBKEY, negatedFound);
                                
                                aux_c = secp->GetPublicKeyHex(OriginalPointsBSGScompressed[target_idx], calculated_point);
                                printf("[+] Target %d Calculated point (O - k*G) %s\n", target_idx, aux_c);
                                printf("[+] Target %d Target pubkey %s\n", target_idx, secp->GetPublicKeyHex(OriginalPointsBSGScompressed[target_idx], OriginalPointsBSGS[target_idx]));
                                
                                pthread_mutex_lock(&write_keys);
                                filekey = fopen("KEYFOUNDKEYFOUND.txt", "a");
                                if(filekey != NULL) {
                                    fprintf(filekey, "Key found privkey %s for target %d (Multi-Target Subtract Random)\n", hextemp, target_idx);
                                    fprintf(filekey, "Origin pubkey: %s\n", secp->GetPublicKeyHex(true, ORIGIN_PUBKEY));
                                    fprintf(filekey, "Private key pubkey: %s\n", secp->GetPublicKeyHex(true, point_found));
                                    fprintf(filekey, "Calculated point (O - k*G): %s\n", aux_c);
                                    fprintf(filekey, "Target pubkey: %s\n", secp->GetPublicKeyHex(OriginalPointsBSGScompressed[target_idx], OriginalPointsBSGS[target_idx]));
                                    fclose(filekey);
                                }
                                multi_target_state->found[target_idx] = true;
                                multi_target_state->found_keys[target_idx].Set(&keyfound);
                                pthread_mutex_unlock(&write_keys);
                                
                                free(hextemp);
                                free(aux_c);
                                
                                // Check if all found
                                bool all_found = true;
                                for(int idx = 0; idx < bsgs_point_number; idx++) {
                                    if(!multi_target_state->found[idx]) {
                                        all_found = false;
                                        break;
                                    }
                                }
                                if(all_found) {
                                    printf("All keys found!\n");
                                    exit(0);
                                }
                            }
                        }
                    }
                }
                
                pp = startP;
                dy.ModSub(&_2GSn.y, &pp.y);
                _s.ModMulK1(&dy, &dx[i + 1]);
                _p.ModSquareK1(&_s);
                pp.x.ModNeg();
                pp.x.ModAdd(&_p);
                pp.x.ModSub(&_2GSn.x);
                pp.y.ModSub(&_2GSn.x, &pp.x);
                pp.y.ModMulK1(&_s);
                pp.y.ModSub(&_2GSn.y);
                startP = pp;
                
                j++;
            }
        }
        
        steps[thread_number]++;
    } while(1); 
    
    ends[thread_number] = 1;
    delete grp;
    return NULL;
}

// Multi-target second check function
int bsgs_secondcheck_multitarget(Int *start_range, uint32_t a, int target_idx, Int *privatekey) {
    int i = 0, found = 0, r = 0;
    Int base_key;
    Point base_point, point_aux;
    Point BSGS_Q, BSGS_S, BSGS_Q_AMP;
    char xpoint_raw[32];
    
    // Calculate the base key for this BSGS block
    base_key.Set(&BSGS_M_double);
    base_key.Mult((uint64_t)a);
    base_key.Add(start_range);

    // Compute the corresponding point
    base_point = secp->ComputePublicKey(&base_key);
    
    // Compute negated point for BSGS search
    point_aux = secp->Negation(base_point);
    
    // Pre-compute transformed target for subtract mode if needed
    Point target_point;
    if(FLAGBSGSMODE == 4 || FLAGBSGSMODE == 1) { // Subtract mode
        Point negatedTarget = secp->Negation(OriginalPointsBSGS[target_idx]);
        target_point = secp->AddDirect(ORIGIN_PUBKEY, negatedTarget);
    } else {
        target_point = OriginalPointsBSGS[target_idx];
    }
    
    // Direct check
    if(base_point.equals(target_point)) {
        privatekey->Set(&base_key);
        return 1;
    }
    
    BSGS_S = secp->AddDirect(target_point, point_aux);
    BSGS_Q.Set(BSGS_S);
    i = 0;
    found = 0;
    
    // Search through second-level points
    do {
        BSGS_Q_AMP = secp->AddDirect(BSGS_Q, BSGS_AMP2[i]);
        BSGS_S.Set(BSGS_Q_AMP);
        BSGS_S.x.Get32Bytes((unsigned char*)xpoint_raw);
        
        r = bloom_check(&bloom_bPx2nd[(uint8_t)xpoint_raw[0]], xpoint_raw, 32);
        if(r) {
            found = bsgs_thirdcheck_multitarget(start_range, i, target_idx, privatekey);
            if(found) {
                // Verify the result
                Point test_point = secp->ComputePublicKey(privatekey);
                
                if(test_point.equals(target_point)) {
                    return found;
                }
                
                // If we get here, the match was a false positive
                found = 0;
            }
        }
        i++;
    } while(i < 32 && !found);
    
    return found;
}

// Multi-target third check function
int bsgs_thirdcheck_multitarget(Int *start_range, uint32_t a, int target_idx, Int *privatekey) {
    uint64_t j = 0;
    int i = 0, found = 0, r = 0;
    Int base_key, calculatedkey;
    Point base_point, point_aux;
    Point BSGS_Q, BSGS_S, BSGS_Q_AMP;
    char xpoint_raw[32];

    // Calculate the base key for this BSGS block
    base_key.SetInt32(a);
    base_key.Mult(&BSGS_M2_double);
    base_key.Add(start_range);

    // Compute the corresponding point
    base_point = secp->ComputePublicKey(&base_key);
    
    // Compute negated point for BSGS search
    point_aux = secp->Negation(base_point);
    
    // Pre-compute transformed target for subtract mode if needed
    Point target_point;
    if(FLAGBSGSMODE == 4 || FLAGBSGSMODE == 1) { // Subtract mode
        Point negatedTarget = secp->Negation(OriginalPointsBSGS[target_idx]);
        target_point = secp->AddDirect(ORIGIN_PUBKEY, negatedTarget);
    } else {
        target_point = OriginalPointsBSGS[target_idx];
    }
    
    // Direct check
    if(base_point.equals(target_point)) {
        privatekey->Set(&base_key);
        return 1;
    }
    
    BSGS_S = secp->AddDirect(target_point, point_aux);
    BSGS_Q.Set(BSGS_S);
    i = 0;
    found = 0;
    
    // Search through third-level points
    do {
        BSGS_Q_AMP = secp->AddDirect(BSGS_Q, BSGS_AMP3[i]);
        BSGS_S.Set(BSGS_Q_AMP);
        BSGS_S.x.Get32Bytes((unsigned char*)xpoint_raw);
        
        r = bloom_check(&bloom_bPx3rd[(uint8_t)xpoint_raw[0]], xpoint_raw, 32);
        if(r) {
            r = bsgs_searchbinary(bPtable, xpoint_raw, bsgs_m3, &j);
            if(r) {
                // Try addition first
                calcualteindex(i, &calculatedkey);
                privatekey->Set(&calculatedkey);
                privatekey->Add((uint64_t)(j+1));
                privatekey->Add(&base_key);
                
                Point test_point = secp->ComputePublicKey(privatekey);
                
                // Verify with appropriate target
                if(test_point.equals(target_point)) {
                    found = 1;
                    break;
                }
                
                // Try subtraction if addition didn't work
                calcualteindex(i, &calculatedkey);
                privatekey->Set(&calculatedkey);
                privatekey->Sub((uint64_t)(j+1));
                privatekey->Add(&base_key);
                
                test_point = secp->ComputePublicKey(privatekey);
                
                // Verify with appropriate target
                if(test_point.equals(target_point)) {
                    found = 1;
                    break;
                }
            }
        }
        else {
            // Special case for curves
            if(BSGS_Q.x.IsEqual(&BSGS_AMP3[i].x)) {
                calcualteindex(i, &calculatedkey);
                privatekey->Set(&calculatedkey);
                privatekey->Add(&base_key);
                
                Point test_point = secp->ComputePublicKey(privatekey);
                
                // Verify special case
                if(test_point.equals(target_point)) {
                    found = 1;
                    break;
                }
            }
        }
        i++;
    } while(i < 32 && !found);
    
    return found;
}

// Multi-target optimized bPload thread
void *thread_bPload_multi_target(void *vargp) {
    char rawvalue[32];
    struct bPload *tt;
    uint64_t i_counter, j, nbStep, to;
    
    IntGroup *grp = new IntGroup(CPU_GRP_SIZE / 2 + 1);
    Point startP;
    Int dx[CPU_GRP_SIZE / 2 + 1];
    Point pts[CPU_GRP_SIZE];
    Int dy, dyn, _s, _p;
    Point pp, pn;
    
    int i, bloom_bP_index, hLength = (CPU_GRP_SIZE / 2 - 1), threadid;
    tt = (struct bPload*)vargp;
    Int km((uint64_t)(tt->from + 1));
    threadid = tt->threadid;
    
    i_counter = tt->from;

    nbStep = (tt->to - tt->from) / CPU_GRP_SIZE;
    
    if(((tt->to - tt->from) % CPU_GRP_SIZE) != 0) {
        nbStep++;
    }
    to = tt->to;
    
    km.Add((uint64_t)(CPU_GRP_SIZE / 2));
    
    // Always compute standard k*G points for bloom filters, regardless of mode
    startP = secp->ComputePublicKey(&km);
    
    grp->Set(dx);
    for(uint64_t s=0; s<nbStep; s++) {
        for(i = 0; i < hLength; i++) {
            dx[i].ModSub(&Gn[i].x, &startP.x);
        }
        dx[i].ModSub(&Gn[i].x, &startP.x);
        dx[i + 1].ModSub(&_2Gn.x, &startP.x);
        
        grp->ModInv();

        pts[CPU_GRP_SIZE / 2] = startP;

        for(i = 0; i<hLength; i++) {
            pp = startP;
            pn = startP;

            dy.ModSub(&Gn[i].y, &pp.y);
            _s.ModMulK1(&dy, &dx[i]);
            _p.ModSquareK1(&_s);
            pp.x.ModNeg();
            pp.x.ModAdd(&_p);
            pp.x.ModSub(&Gn[i].x);

            dyn.Set(&Gn[i].y);
            dyn.ModNeg();
            dyn.ModSub(&pn.y);
            _s.ModMulK1(&dyn, &dx[i]);
            _p.ModSquareK1(&_s);
            pn.x.ModNeg();
            pn.x.ModAdd(&_p);
            pn.x.ModSub(&Gn[i].x);

            pts[CPU_GRP_SIZE / 2 + (i + 1)] = pp;
            pts[CPU_GRP_SIZE / 2 - (i + 1)] = pn;
        }

        pn = startP;
        dyn.Set(&Gn[i].y);
        dyn.ModNeg();
        dyn.ModSub(&pn.y);
        _s.ModMulK1(&dyn, &dx[i]);
        _p.ModSquareK1(&_s);
        pn.x.ModNeg();
        pn.x.ModAdd(&_p);
        pn.x.ModSub(&Gn[i].x);
        pts[0] = pn;
        
        // Add points to bloom filters and bPtable
        for(j=0; j<CPU_GRP_SIZE; j++) {
            pts[j].x.Get32Bytes((unsigned char*)rawvalue);
            bloom_bP_index = (uint8_t)rawvalue[0];

            if(i_counter < bsgs_m3) {
                if(!FLAGREADEDFILE3) {
                    memcpy(bPtable[i_counter].value, rawvalue+16, BSGS_XVALUE_RAM);
                    bPtable[i_counter].index = i_counter;
                }
                if(!FLAGREADEDFILE4) {
                    pthread_mutex_lock(&bloom_bPx3rd_mutex[bloom_bP_index]);
                    bloom_add(&bloom_bPx3rd[bloom_bP_index], rawvalue, BSGS_BUFFERXPOINTLENGTH);
                    pthread_mutex_unlock(&bloom_bPx3rd_mutex[bloom_bP_index]);
                }
            }
            if(i_counter < bsgs_m2 && !FLAGREADEDFILE2) {
                pthread_mutex_lock(&bloom_bPx2nd_mutex[bloom_bP_index]);
                bloom_add(&bloom_bPx2nd[bloom_bP_index], rawvalue, BSGS_BUFFERXPOINTLENGTH);
                pthread_mutex_unlock(&bloom_bPx2nd_mutex[bloom_bP_index]);
            }
            if(i_counter < to && !FLAGREADEDFILE1) {
                pthread_mutex_lock(&bloom_bP_mutex[bloom_bP_index]);
                bloom_add(&bloom_bP[bloom_bP_index], rawvalue, BSGS_BUFFERXPOINTLENGTH);
                pthread_mutex_unlock(&bloom_bP_mutex[bloom_bP_index]);
            }
            i_counter++;
        }

        pp = startP;
        dy.ModSub(&_2Gn.y, &pp.y);
        _s.ModMulK1(&dy, &dx[i + 1]);
        _p.ModSquareK1(&_s);
        pp.x.ModNeg();
        pp.x.ModAdd(&_p);
        pp.x.ModSub(&_2Gn.x);
        pp.y.ModSub(&_2Gn.x, &pp.x);
        pp.y.ModMulK1(&_s);
        pp.y.ModSub(&_2Gn.y);
        startP = pp;
    }
    
    delete grp;
    pthread_mutex_lock(&bPload_mutex[threadid]);
    tt->finished = 1;
    pthread_mutex_unlock(&bPload_mutex[threadid]);
    pthread_exit(NULL);
    return NULL;
}

// Multi-target optimized bPload_2blooms thread
void *thread_bPload_2blooms_multi_target(void *vargp) {
    char rawvalue[32];
    struct bPload *tt;
    uint64_t i_counter, j, nbStep;
    IntGroup *grp = new IntGroup(CPU_GRP_SIZE / 2 + 1);
    Point startP;
    Int dx[CPU_GRP_SIZE / 2 + 1];
    Point pts[CPU_GRP_SIZE];
    Int dy, dyn, _s, _p;
    Point pp, pn;
    int i, bloom_bP_index, hLength = (CPU_GRP_SIZE / 2 - 1), threadid;
    tt = (struct bPload*)vargp;
    Int km((uint64_t)(tt->from + 1));
    threadid = tt->threadid;
    
    i_counter = tt->from;

    nbStep = (tt->to - (tt->from)) / CPU_GRP_SIZE;
    
    if(((tt->to - (tt->from)) % CPU_GRP_SIZE) != 0) {
        nbStep++;
    }
    
    km.Add((uint64_t)(CPU_GRP_SIZE / 2));
    
    // Always compute standard k*G points for bloom filters, regardless of mode
    startP = secp->ComputePublicKey(&km);
    
    grp->Set(dx);
    for(uint64_t s=0; s<nbStep; s++) {
        for(i = 0; i < hLength; i++) {
            dx[i].ModSub(&Gn[i].x, &startP.x);
        }
        dx[i].ModSub(&Gn[i].x, &startP.x);
        dx[i + 1].ModSub(&_2Gn.x, &startP.x);
        
        grp->ModInv();

        pts[CPU_GRP_SIZE / 2] = startP;

        for(i = 0; i<hLength; i++) {
            pp = startP;
            pn = startP;

            dy.ModSub(&Gn[i].y, &pp.y);
            _s.ModMulK1(&dy, &dx[i]);
            _p.ModSquareK1(&_s);
            pp.x.ModNeg();
            pp.x.ModAdd(&_p);
            pp.x.ModSub(&Gn[i].x);

            dyn.Set(&Gn[i].y);
            dyn.ModNeg();
            dyn.ModSub(&pn.y);
            _s.ModMulK1(&dyn, &dx[i]);
            _p.ModSquareK1(&_s);
            pn.x.ModNeg();
            pn.x.ModAdd(&_p);
            pn.x.ModSub(&Gn[i].x);

            pts[CPU_GRP_SIZE / 2 + (i + 1)] = pp;
            pts[CPU_GRP_SIZE / 2 - (i + 1)] = pn;
        }

        pn = startP;
        dyn.Set(&Gn[i].y);
        dyn.ModNeg();
        dyn.ModSub(&pn.y);
        _s.ModMulK1(&dyn, &dx[i]);
        _p.ModSquareK1(&_s);
        pn.x.ModNeg();
        pn.x.ModAdd(&_p);
        pn.x.ModSub(&Gn[i].x);
        pts[0] = pn;
        
        for(j=0; j<CPU_GRP_SIZE; j++) {
            pts[j].x.Get32Bytes((unsigned char*)rawvalue);
            bloom_bP_index = (uint8_t)rawvalue[0];
            if(i_counter < bsgs_m3) {
                if(!FLAGREADEDFILE3) {
                    memcpy(bPtable[i_counter].value, rawvalue+16, BSGS_XVALUE_RAM);
                    bPtable[i_counter].index = i_counter;
                }
                if(!FLAGREADEDFILE4) {
                    pthread_mutex_lock(&bloom_bPx3rd_mutex[bloom_bP_index]);
                    bloom_add(&bloom_bPx3rd[bloom_bP_index], rawvalue, BSGS_BUFFERXPOINTLENGTH);
                    pthread_mutex_unlock(&bloom_bPx3rd_mutex[bloom_bP_index]);
                }
            }
            if(i_counter < bsgs_m2 && !FLAGREADEDFILE2) {
                pthread_mutex_lock(&bloom_bPx2nd_mutex[bloom_bP_index]);
                bloom_add(&bloom_bPx2nd[bloom_bP_index], rawvalue, BSGS_BUFFERXPOINTLENGTH);
                pthread_mutex_unlock(&bloom_bPx2nd_mutex[bloom_bP_index]);
            }
            i_counter++;
        }
        
        pp = startP;
        dy.ModSub(&_2Gn.y, &pp.y);
        _s.ModMulK1(&dy, &dx[i + 1]);
        _p.ModSquareK1(&_s);
        pp.x.ModNeg();
        pp.x.ModAdd(&_p);
        pp.x.ModSub(&_2Gn.x);
        pp.y.ModSub(&_2Gn.x, &pp.x);
        pp.y.ModMulK1(&_s);
        pp.y.ModSub(&_2Gn.y);
        startP = pp;
    }
    
    delete grp;
    pthread_mutex_lock(&bPload_mutex[threadid]);
    tt->finished = 1;
    pthread_mutex_unlock(&bPload_mutex[threadid]);
    pthread_exit(NULL);
    return NULL;
}

// BSGS search binary function
int bsgs_searchbinary(struct bsgs_xvalue *buffer, char *data, int64_t array_length, uint64_t *r_value) {
    int64_t min, max, half, current;
    int r = 0, rcmp;
    min = 0;
    current = 0;
    max = array_length;
    half = array_length;
    while(!r && half >= 1) {
        half = (max - min)/2;
        rcmp = memcmp(data+16, buffer[current+half].value, BSGS_XVALUE_RAM);
        if(rcmp == 0) {
            *r_value = buffer[current+half].index;
            r = 1;
        }
        else {
            if(rcmp < 0) {
                max = (max-half);
            }
            else {
                min = (min+half);
            }
            current = min;
        }
    }
    return r;
}

void calcualteindex(int i, Int *key) {
    if(i == 0) {
        key->Set(&BSGS_M3);
    }
    else {
        key->SetInt32(i);
        key->Mult(&BSGS_M3_double);
        key->Add(&BSGS_M3);
    }
}

void writekey(bool compressed, Int *key) {
    Point publickey;
    FILE *keys;
    char *hextemp, *hexrmd, public_key_hex[132], address[50], rmdhash[20];
    memset(address, 0, 50);
    memset(public_key_hex, 0, 132);
    hextemp = key->GetBase16();
    publickey = secp->ComputePublicKey(key);
    secp->GetPublicKeyHex(compressed, publickey, public_key_hex);
    secp->GetHash160(P2PKH, compressed, publickey, (uint8_t*)rmdhash);
    hexrmd = tohex(rmdhash, 20);
    rmd160toaddress_dst(rmdhash, address);

    pthread_mutex_lock(&write_keys);
    keys = fopen("KEYFOUNDKEYFOUND.txt", "a+");
    if(keys != NULL) {
        if (FLAGBSGSMODE == 4) { // Subtract mode
            // Calculate O - k*G
            Point negPoint = secp->Negation(publickey);
            Point resultPoint = secp->AddDirect(ORIGIN_PUBKEY, negPoint);
            char result_key_hex[132];
            bool resultCompressed = compressed;
            secp->GetPublicKeyHex(resultCompressed, resultPoint, result_key_hex);
            
            fprintf(keys, "Private Key: %s\npubkey: %s\nAddress %s\nrmd160 %s\n", 
                   hextemp, public_key_hex, address, hexrmd);
            fprintf(keys, "Subtract mode result (O - k*G): %s\n", result_key_hex);
            printf("\nHit! Private Key: %s\npubkey: %s\nAddress %s\nrmd160 %s\n", 
                   hextemp, public_key_hex, address, hexrmd);
            printf("Subtract mode result (O - k*G): %s\n", result_key_hex);
        } else {
            fprintf(keys, "Private Key: %s\npubkey: %s\nAddress %s\nrmd160 %s\n", 
                   hextemp, public_key_hex, address, hexrmd);
            printf("\nHit! Private Key: %s\npubkey: %s\nAddress %s\nrmd160 %s\n", 
                   hextemp, public_key_hex, address, hexrmd);
        }
        fclose(keys);
    }
    
    pthread_mutex_unlock(&write_keys);
    free(hextemp);
    free(hexrmd);
}

void checkpointer(void *ptr, const char *file, const char *function, const char *name, int line) {
    if(ptr == NULL) {
        fprintf(stderr, "[E] error in file %s, %s pointer %s on line %i\n", file, function, name, line); 
        exit(EXIT_FAILURE);
    }
}

void init_generator() {
    Point G = secp->ComputePublicKey(&stride);
    Point g;
    g.Set(G);
    Gn.reserve(CPU_GRP_SIZE / 2);
    Gn[0] = g;
    g = secp->DoubleDirect(g);
    Gn[1] = g;
    for(int i = 2; i < CPU_GRP_SIZE / 2; i++) {
        g = secp->AddDirect(g, G);
        Gn[i] = g;
    }
    _2Gn = secp->DoubleDirect(Gn[CPU_GRP_SIZE / 2 - 1]);
}

void bsgs_swap(struct bsgs_xvalue *a, struct bsgs_xvalue *b) {
    struct bsgs_xvalue t;
    t = *a;
    *a = *b;
    *b = t;
}

void bsgs_sort(struct bsgs_xvalue *arr, int64_t n) {
    uint32_t depthLimit = ((uint32_t)ceil(log(n))) * 2;
    bsgs_introsort(arr, depthLimit, n);
}

void bsgs_introsort(struct bsgs_xvalue *arr, uint32_t depthLimit, int64_t n) {
    int64_t p;
    if(n > 1) {
        if(n <= 16) {
            bsgs_insertionsort(arr, n);
        }
        else {
            if(depthLimit == 0) {
                bsgs_myheapsort(arr, n);
            }
            else {
                p = bsgs_partition(arr, n);
                if(p > 0) bsgs_introsort(arr, depthLimit-1, p);
                if(p < n) bsgs_introsort(&arr[p+1], depthLimit-1, n-(p+1));
            }
        }
    }
}

void bsgs_insertionsort(struct bsgs_xvalue *arr, int64_t n) {
    int64_t j;
    int64_t i;
    struct bsgs_xvalue key;
    for(i = 1; i < n; i++) {
        key = arr[i];
        j = i-1;
        while(j >= 0 && memcmp(arr[j].value, key.value, BSGS_XVALUE_RAM) > 0) {
            arr[j+1] = arr[j];
            j--;
        }
        arr[j+1] = key;
    }
}

int64_t bsgs_partition(struct bsgs_xvalue *arr, int64_t n) {
    struct bsgs_xvalue pivot;
    int64_t r, left, right;
    r = n/2;
    pivot = arr[r];
    left = 0;
    right = n-1;
    do {
        while(left < right && memcmp(arr[left].value, pivot.value, BSGS_XVALUE_RAM) <= 0) {
            left++;
        }
        while(right >= left && memcmp(arr[right].value, pivot.value, BSGS_XVALUE_RAM) > 0) {
            right--;
        }
        if(left < right) {
            if(left == r || right == r) {
                if(left == r) {
                    r = right;
                }
                if(right == r) {
                    r = left;
                }
            }
            bsgs_swap(&arr[right], &arr[left]);
        }
    } while(left < right);
    if(right != r) {
        bsgs_swap(&arr[right], &arr[r]);
    }
    return right;
}

void bsgs_heapify(struct bsgs_xvalue *arr, int64_t n, int64_t i) {
    int64_t largest = i;
    int64_t l = 2 * i + 1;
    int64_t r = 2 * i + 2;
    if(l < n && memcmp(arr[l].value, arr[largest].value, BSGS_XVALUE_RAM) > 0)
        largest = l;
    if(r < n && memcmp(arr[r].value, arr[largest].value, BSGS_XVALUE_RAM) > 0)
        largest = r;
    if(largest != i) {
        bsgs_swap(&arr[i], &arr[largest]);
        bsgs_heapify(arr, n, largest);
    }
}

void bsgs_myheapsort(struct bsgs_xvalue *arr, int64_t n) {
    int64_t i;
    for(i = (n / 2) - 1; i >= 0; i--) {
        bsgs_heapify(arr, n, i);
    }
    for(i = n - 1; i > 0; i--) {
        bsgs_swap(&arr[0], &arr[i]);
        bsgs_heapify(arr, i, 0);
    }
}

void sleep_ms(int milliseconds) {
#if defined(_WIN64) && !defined(__CYGWIN__)
    Sleep(milliseconds);
#elif _POSIX_C_SOURCE >= 199309L
    struct timespec ts;
    ts.tv_sec = milliseconds / 1000;
    ts.tv_nsec = (milliseconds % 1000) * 1000000;
    nanosleep(&ts, NULL);
#else
    if (milliseconds >= 1000)
      sleep(milliseconds / 1000);
    usleep((milliseconds % 1000) * 1000);
#endif
}

void menu() {
    printf("\nUsage:\n");
    printf("-h          show this help\n");
    printf("-6          to skip sha256 Checksum on data files\n");
    printf("-k value    Use this only with bsgs mode, k value is factor for M, more speed but more RAM use wisely\n");
    printf("-n number   Check for N sequential numbers before the random chosen, this only works with -R option\n");
    printf("-t tn       Threads number, must be a positive integer\n");
    printf("-f file     Specify file with target public key(s)\n");
    printf("-r SR:EN    StartRange:EndRange\n");
    printf("-b bits     Bit range for search (sets min and max range automatically)\n");
    printf("-m mode     BSGS search mode <sequential, backward, both, random, subtract>\n");
    printf("-q          Quiet thread output\n");
    printf("-S          Save bloom filters to disk\n");
    printf("-P pubkey   Set origin public key for subtract mode\n");
    printf("-M          Enable Multi-target BSGS optimization (√T speedup with T targets)\n");
    printf("\nExample:\n\n");
    printf("./bsgs -f targets.txt -r 8000000000:9000000000 -t 8 -m sequential -M\n\n");
    printf("Developed by AlbertoBSD (multi-target optimized)\n");
    exit(EXIT_FAILURE);
}

char *pubkeytopubaddress(char *pkey, int length) {
    char *pubaddress = (char*)calloc(MAXLENGTHADDRESS+10, 1);
    char *digest = (char*)calloc(60, 1);
    size_t pubaddress_size = MAXLENGTHADDRESS+10;
    checkpointer((void*)pubaddress, __FILE__, "malloc", "pubaddress", __LINE__ -1);
    checkpointer((void*)digest, __FILE__, "malloc", "digest", __LINE__ -1);
    
    sha256((uint8_t*)pkey, length, (uint8_t*)digest);
    RMD160Data((const unsigned char*)digest, 32, digest+1);
    digest[0] = 0;
    sha256((uint8_t*)digest, 21, (uint8_t*)digest+21);
    sha256((uint8_t*)digest+21, 32, (uint8_t*)digest+21);
    if(!b58enc(pubaddress, &pubaddress_size, digest, 25)) {
        fprintf(stderr, "error b58enc\n");
    }
    free(digest);
    return pubaddress;
}

void pubkeytopubaddress_dst(char *pkey, int length, char *dst) {
    char digest[60];
    size_t pubaddress_size = 40;
    sha256((uint8_t*)pkey, length, (uint8_t*)digest);
    RMD160Data((const unsigned char*)digest, 32, digest+1);
    digest[0] = 0;
    sha256((uint8_t*)digest, 21, (uint8_t*)digest+21);
    sha256((uint8_t*)digest+21, 32, (uint8_t*)digest+21);
    if(!b58enc(dst, &pubaddress_size, digest, 25)) {
        fprintf(stderr, "error b58enc\n");
    }
}

void rmd160toaddress_dst(char *rmd, char *dst) {
    char digest[60];
    size_t pubaddress_size = 40;
    digest[0] = byte_encode_crypto;
    memcpy(digest+1, rmd, 20);
    sha256((uint8_t*)digest, 21, (uint8_t*)digest+21);
    sha256((uint8_t*)digest+21, 32, (uint8_t*)digest+21);
    if(!b58enc(dst, &pubaddress_size, digest, 25)) {
        fprintf(stderr, "error b58enc\n");
    }
}

char *publickeytohashrmd160(char *pkey, int length) {
    char *hash160 = (char*)malloc(20);
    char *digest = (char*)malloc(32);
    checkpointer((void*)hash160, __FILE__, "malloc", "hash160", __LINE__ -1);
    checkpointer((void*)digest, __FILE__, "malloc", "digest", __LINE__ -1);
    
    sha256((uint8_t*)pkey, length, (uint8_t*)digest);
    RMD160Data((const unsigned char*)digest, 32, hash160);
    free(digest);
    return hash160;
}

void publickeytohashrmd160_dst(char *pkey, int length, char *dst) {
    char digest[32];
    sha256((uint8_t*)pkey, length, (uint8_t*)digest);
    RMD160Data((const unsigned char*)digest, 32, dst);
}
