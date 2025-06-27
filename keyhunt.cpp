/*
Develop by Alberto
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

#define CRYPTO_NONE 0
#define CRYPTO_BTC 1
#define CRYPTO_ETH 2
#define CRYPTO_ALL 3

#define MODE_XPOINT 0
#define MODE_ADDRESS 1
#define MODE_BSGS 2
#define MODE_RMD160 3
#define MODE_PUB2RMD 4
#define MODE_MINIKEYS 5
#define MODE_VANITY 6
#define MODE_SUBTRACT 7

#define PUBKEY_BUFFER_SIZE 10000 // Number of keys per batch
#define NUM_BUFFERS 256          // One per thread

#define SEARCH_UNCOMPRESS 0
#define SEARCH_COMPRESS 1
#define SEARCH_BOTH 2

uint32_t THREADBPWORKLOAD = 1048576;

struct subtractBPload {
    uint32_t threadid;
    uint64_t from;
    uint64_t to;
    uint64_t workload;
    uint32_t finished;
};

struct checksumsha256
{
    char data[32];
    char backup[32];
};

struct PubkeyBuffer
{
    unsigned char *keys;
    size_t count;
    bool ready;


#if defined(_WIN64) && !defined(__CYGWIN__)
    HANDLE mutex;
#else
    pthread_mutex_t mutex;
#endif
};


PubkeyBuffer *thread_buffers;
volatile bool writer_running = true;
uint64_t total_keys_written = 0;


struct bsgs_xvalue
{
    uint8_t value[6];
    uint64_t index;
};

struct address_value
{
    uint8_t value[20];
};

struct tothread
{
    int nt;    // Number thread
    char *rs;  // range start
    char *rpt; // rng per thread
};

struct bPload
{
    uint32_t threadid;
    uint64_t from;
    uint64_t to;
    uint64_t counter;
    uint64_t workload;
    uint32_t aux;
    uint32_t finished;
};

#if defined(_WIN64) && !defined(__CYGWIN__)
#define PACK(__Declaration__) __pragma(pack(push, 1)) __Declaration__ __pragma(pack(pop))
PACK(struct publickey {
    uint8_t parity;
    union
    {
        uint8_t data8[32];
        uint32_t data32[8];
        uint64_t data64[4];
    } X;
});
#else
struct __attribute__((__packed__)) publickey
{
    uint8_t parity;
    union
    {
        uint8_t data8[32];
        uint32_t data32[8];
        uint64_t data64[4];
    } X;
};
#endif

const char *Ccoinbuffer_default = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

char *Ccoinbuffer = (char *)Ccoinbuffer_default;
char *str_baseminikey = NULL;
char *raw_baseminikey = NULL;
char *minikeyN = NULL;
int minikey_n_limit;

const char *version = "0.2.230519 Satoshi Quest";

#define CPU_GRP_SIZE 1024

std::vector<Point> Gn;
Point _2Gn;

std::vector<Point> GSn;
Point _2GSn;

// Public key buffering system function declarations
void init_pubkey_buffers();
void start_pubkey_writer();
void cleanup_pubkey_writer();
void add_pubkey_to_buffer(const unsigned char *pubkey, int thread_id);
#if defined(_WIN64) && !defined(__CYGWIN__)
DWORD WINAPI writer_thread_func(LPVOID vargp);
#else
void *writer_thread_func(void *vargp);
#endif

void menu();
void init_generator();

int searchbinary(struct address_value *buffer, char *data, int64_t array_length);
void sleep_ms(int milliseconds);

void write_pubkey_binary(unsigned char *pubkey_bytes);
void convert_bin_to_txt(const char *bin_file, const char *txt_file);

void _sort(struct address_value *arr, int64_t N);
void _insertionsort(struct address_value *arr, int64_t n);
void _introsort(struct address_value *arr, uint32_t depthLimit, int64_t n);
void _swap(struct address_value *a, struct address_value *b);
int64_t _partition(struct address_value *arr, int64_t n);
void _myheapsort(struct address_value *arr, int64_t n);
void _heapify(struct address_value *arr, int64_t n, int64_t i);

void bsgs_sort(struct bsgs_xvalue *arr, int64_t n);
void bsgs_myheapsort(struct bsgs_xvalue *arr, int64_t n);
void bsgs_insertionsort(struct bsgs_xvalue *arr, int64_t n);
void bsgs_introsort(struct bsgs_xvalue *arr, uint32_t depthLimit, int64_t n);
void bsgs_swap(struct bsgs_xvalue *a, struct bsgs_xvalue *b);
void bsgs_heapify(struct bsgs_xvalue *arr, int64_t n, int64_t i);
int64_t bsgs_partition(struct bsgs_xvalue *arr, int64_t n);

int bsgs_searchbinary(struct bsgs_xvalue *arr, char *data, int64_t array_length, uint64_t *r_value);
int bsgs_secondcheck(Int *start_range, uint32_t a, uint32_t k_index, Int *privatekey);
int bsgs_thirdcheck(Int *start_range, uint32_t a, uint32_t k_index, Int *privatekey);

void sha256sse_22(uint8_t *src0, uint8_t *src1, uint8_t *src2, uint8_t *src3, uint8_t *dst0, uint8_t *dst1, uint8_t *dst2, uint8_t *dst3);
void sha256sse_23(uint8_t *src0, uint8_t *src1, uint8_t *src2, uint8_t *src3, uint8_t *dst0, uint8_t *dst1, uint8_t *dst2, uint8_t *dst3);

bool vanityrmdmatch(unsigned char *rmdhash);
void writevanitykey(bool compress, Int *key);
int addvanity(char *target);
int minimum_same_bytes(unsigned char *A, unsigned char *B, int length);

void writekey(bool compressed, Int *key);
void writekeyeth(Int *key);

void checkpointer(void *ptr, const char *file, const char *function, const char *name, int line);

bool isBase58(char c);
bool isValidBase58String(char *str);

void displayBloomEstimate(uint64_t num_items);
bool generateSubtractedKeysToBloom(const char* params, const char* originPubkeyHex);
bool loadSubtractedKeysToBloom();

bool readFileAddress(char *fileName);
bool readFileVanity(char *fileName);
bool forceReadFileAddress(char *fileName);
bool forceReadFileAddressEth(char *fileName);
bool forceReadFileXPoint(char *fileName);
bool processOneVanity();

bool initBloomFilter(struct bloom *bloom_arg, uint64_t items_bloom);

void writeFileIfNeeded(const char *fileName);

void calcualteindex(int i, Int *key);

void write_subtract_key(Int &subtractValue, size_t keyIndex);
bool parse_target_subtract_keys();
bool init_subtract_bloom_filter(const char *filename);
bool init_subtract_bloom_filter(const char *filename);
uint64_t estimate_subtract_bloom_size(uint64_t items, double fp_rate);
void calculate_prime_stride(Int &range_diff, Int &current_prime_int, Int &stride);
uint64_t next_prime(uint64_t n);
bool is_prime(uint64_t n);
bool verify_pubkey_in_file(Point &resultPoint);
void generate_evenly_distributed_keys();


#if defined(_WIN64) && !defined(__CYGWIN__)
DWORD WINAPI thread_process_vanity(LPVOID vargp);
DWORD WINAPI thread_process_minikeys(LPVOID vargp);
DWORD WINAPI thread_process(LPVOID vargp);
DWORD WINAPI thread_process_bsgs(LPVOID vargp);
DWORD WINAPI thread_process_bsgs_backward(LPVOID vargp);
DWORD WINAPI thread_process_bsgs_both(LPVOID vargp);
DWORD WINAPI thread_process_bsgs_random(LPVOID vargp);
DWORD WINAPI thread_process_bsgs_dance(LPVOID vargp);
DWORD WINAPI thread_process_bsgs_levy(LPVOID vargp);
DWORD WINAPI thread_process_subtract(LPVOID vargp);
DWORD WINAPI thread_bPload(LPVOID vargp);
DWORD WINAPI thread_bPload_2blooms(LPVOID vargp);
DWORD WINAPI thread_subtract_bloom_load(LPVOID vargp);
#else
void *thread_process_vanity(void *vargp);
void *thread_process_minikeys(void *vargp);
void *thread_process(void *vargp);
void *thread_process_bsgs(void *vargp);
void *thread_process_bsgs_backward(void *vargp);
void *thread_process_bsgs_both(void *vargp);
void *thread_process_bsgs_random(void *vargp);
void *thread_process_bsgs_dance(void *vargp);
void *thread_process_bsgs_levy(void *vargp);
void *thread_process_subtract(void *vargp);
void *thread_bPload(void *vargp);
void *thread_bPload_2blooms(void *vargp);
void *thread_subtract_bloom_load(void *vargp);
#endif

char *pubkeytopubaddress(char *pkey, int length);
void pubkeytopubaddress_dst(char *pkey, int length, char *dst);
void rmd160toaddress_dst(char *rmd, char *dst);
void set_minikey(char *buffer, char *rawbuffer, int length);
bool increment_minikey_index(char *buffer, char *rawbuffer, int index);
void increment_minikey_N(char *rawbuffer);

void KECCAK_256(uint8_t *source, size_t size, uint8_t *dst);
void generate_binaddress_eth(Point &publickey, unsigned char *dst_address);

int THREADOUTPUT = 0;
char *bit_range_str_min;
char *bit_range_str_max;

const char *bsgs_modes[6] = {"sequential", "backward", "both", "random", "dance", "levy"};
const char *modes[8] = {"xpoint", "address", "bsgs", "rmd160", "pub2rmd", "minikeys", "vanity", "subtract"};
const char *cryptos[3] = {"btc", "eth", "all"};
const char *publicsearch[3] = {"uncompress", "compress", "both"};
const char *default_fileName = "addresses.txt";

#if defined(_WIN64) && !defined(__CYGWIN__)
HANDLE *tid = NULL;
HANDLE write_keys;
HANDLE write_random;
HANDLE bsgs_thread;
HANDLE *bPload_mutex = NULL;
HANDLE writer_thread;
HANDLE buffer_ready_event;
HANDLE *subtract_bloom_mutex = NULL;
#else
pthread_t writer_thread;
pthread_cond_t buffer_ready_cond;
pthread_mutex_t buffer_ready_mutex;
pthread_mutex_t *subtract_bloom_mutex = NULL;
pthread_t *tid = NULL;
pthread_mutex_t write_keys;
pthread_mutex_t write_random;
pthread_mutex_t bsgs_thread;
pthread_mutex_t *bPload_mutex = NULL;
#endif

uint64_t FINISHED_THREADS_COUNTER = 0;
uint64_t FINISHED_THREADS_BP = 0;
uint64_t THREADCYCLES = 0;
uint64_t THREADCOUNTER = 0;
uint64_t FINISHED_ITEMS = 0;
uint64_t OLDFINISHED_ITEMS = -1;

uint8_t byte_encode_crypto = 0x00; /* Bitcoin  */

int vanity_rmd_targets = 0;
int vanity_rmd_total = 0;
int *vanity_rmd_limits = NULL;
uint8_t ***vanity_rmd_limit_values_A = NULL, ***vanity_rmd_limit_values_B = NULL;
int vanity_rmd_minimun_bytes_check_length = 999999;
char **vanity_address_targets = NULL;
struct bloom *vanity_bloom = NULL;

struct bloom bloom;

uint64_t *steps = NULL;
unsigned int *ends = NULL;
uint64_t N = 0;

uint64_t N_SEQUENTIAL_MAX = 0x100000000;
uint64_t DEBUGCOUNT = 0x400;
uint64_t u64range;

Int OUTPUTSECONDS;

// For subtract mode
std::vector<Point> targetSubtractKeys;
std::vector<std::string> targetSubtractKeyStrs;
std::vector<bool> subtractKeyFound;
Int subtractStride;
int FLAGSUBTRACTKEY = 0;
struct bloom bloom_subtract;
bool bloom_subtract_initialized = false;

int FLAGOPTIMIZEDPRIME = 0;  // Flag for optimized prime mode
uint64_t current_prime = 2;   // Start with first prime
uint64_t steps_taken = 0;     // Count steps taken with current prime
uint64_t starting_prime = 2;
uint64_t global_steps_taken = 0;  // Global step counter for optimized prime mode
Int global_base_key;              // Base key for the current prime cycle


//Xpoint Bloom Load
bool FLAGSUBTRACTBLOOM = false;
uint64_t subtract_bloom_count = 0;
Int subtract_bloom_spacing;
Point subtract_bloom_origin;

int FLAGSKIPCHECKSUM = 0;
int FLAGENDOMORPHISM = 0;

int FLAGBLOOMMULTIPLIER = 1;
int FLAGVANITY = 0;
int FLAGBASEMINIKEY = 0;
int FLAGBSGSMODE = 0;
int FLAGDEBUG = 0;
int FLAGQUIET = 0;
int FLAGMATRIX = 0;
int KFACTOR = 1;
int MAXLENGTHADDRESS = -1;
int NTHREADS = 1;
int FLAGRANDOMMULTIPLE = 0;
int FLAGEVENLYDISTRIBUTE = 0;

int FLAGSAVEREADFILE = 0;
int FLAGREADEDFILE1 = 0;
int FLAGREADEDFILE2 = 0;
int FLAGREADEDFILE3 = 0;
int FLAGREADEDFILE4 = 0;
int FLAGUPDATEFILE1 = 0;

int FLAGSTRIDE = 0;
int FLAGSEARCH = 2;
int FLAGBITRANGE = 0;
int FLAGRANGE = 0;
int FLAGFILE = 0;
int FLAGMODE = MODE_ADDRESS;
int FLAGCRYPTO = 0;
int FLAGRAWDATA = 0;
int FLAGRANDOM = 0;
int FLAG_N = 0;
int FLAGPRECALCUTED_P_FILE = 0;
// publickey Print
int FLAGPRINTPUBKEYS = 0;
FILE *pubkeyfile = NULL;
FILE *pubkeyfile_bin = NULL;
uint64_t max_pubkeys_to_generate = 0;
uint64_t pubkeys_generated = 0;
const char *pubkeyfile_name = "134.bin";

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

uint64_t bytes;
char checksum[32], checksum_backup[32];
char buffer_bloom_file[1024];
struct bsgs_xvalue *bPtable;
struct address_value *addressTable;

struct oldbloom oldbloom_bP;

struct bloom *bloom_bP;
struct bloom *bloom_bPx2nd; // 2nd Bloom filter check
struct bloom *bloom_bPx3rd; // 3rd Bloom filter check

struct checksumsha256 *bloom_bP_checksums;
struct checksumsha256 *bloom_bPx2nd_checksums;
struct checksumsha256 *bloom_bPx3rd_checksums;

#if defined(_WIN64) && !defined(__CYGWIN__)
std::vector<HANDLE> bloom_bP_mutex;
std::vector<HANDLE> bloom_bPx2nd_mutex;
std::vector<HANDLE> bloom_bPx3rd_mutex;
#else
pthread_mutex_t *bloom_bP_mutex;
pthread_mutex_t *bloom_bPx2nd_mutex;
pthread_mutex_t *bloom_bPx3rd_mutex;
#endif

uint64_t bloom_bP_totalbytes = 0;
uint64_t bloom_bP2_totalbytes = 0;
uint64_t bloom_bP3_totalbytes = 0;
uint64_t bsgs_m = 4194304;
uint64_t bsgs_m2;
uint64_t bsgs_m3;
uint64_t bsgs_aux;
uint32_t bsgs_point_number;

const char *str_limits_prefixs[7] = {"Mkeys/s", "Gkeys/s", "Tkeys/s", "Pkeys/s", "Ekeys/s", "Zkeys/s", "Ykeys/s"};
const char *str_limits[7] = {"1000000", "1000000000", "1000000000000", "1000000000000000", "1000000000000000000", "1000000000000000000000", "1000000000000000000000000"};
Int int_limits[7];

Int BSGS_GROUP_SIZE;
Int BSGS_CURRENT;
Int BSGS_R;
Int BSGS_AUX;
Int BSGS_N;
Int BSGS_N_double;
Int BSGS_M; // M is squareroot(N)
Int BSGS_M_double;
Int BSGS_M2;        // M2 is M/32
Int BSGS_M2_double; // M2_double is M2 * 2
Int BSGS_M3;        // M3 is M2/32
Int BSGS_M3_double; // M3_double is M3 * 2

Int ONE;
Int ZERO;
Int MPZAUX;

Point BSGS_P;   // Original P is actually G, but this P value change over time for calculations
Point BSGS_MP;  // MP values this is m * P
Point BSGS_MP2; // MP2 values this is m2 * P
Point BSGS_MP3; // MP3 values this is m3 * P

Point BSGS_MP_double;  // MP2 values this is m2 * P * 2
Point BSGS_MP2_double; // MP2 values this is m2 * P * 2
Point BSGS_MP3_double; // MP3 values this is m3 * P * 2

std::vector<Point> BSGS_AMP2;
std::vector<Point> BSGS_AMP3;

Point point_temp, point_temp2; // Temp value for some process

Int n_range_start;
Int n_range_end;
Int n_range_diff;
Int n_range_aux;

Int lambda, lambda2, beta, beta2;

Secp256K1 *secp;

// Lévy flight parameters
double LEVY_ALPHA = 1.5; // Default value
double LEVY_SCALE = 1e9; // Default scale factor

int main(int argc, char **argv)
{
    char buffer[2048];
    char rawvalue[32];
    struct tothread *tt;
    Tokenizer t, tokenizerbsgs;
    char *fileName = NULL;
    char *hextemp = NULL;
    char *aux = NULL;
    char *aux2 = NULL;
    char *pointx_str = NULL;
    char *pointy_str = NULL;
    char *str_seconds = NULL;
    char *str_total = NULL;
    char *str_pretotal = NULL;
    char *str_divpretotal = NULL;
    char *bf_ptr = NULL;
    char *bPload_threads_available;
    FILE *fd, *fd_aux1, *fd_aux2, *fd_aux3;
    uint64_t i, BASE, PERTHREAD_R, itemsbloom, itemsbloom2, itemsbloom3;
    uint32_t finished;
    int readed, continue_flag, check_flag, c, salir, index_value, j;
    Int total, pretotal, debugcount_mpz, seconds, div_pretotal, int_aux, int_r, int_q, int58;
    struct bPload *bPload_temp_ptr;
    size_t rsize;

#if defined(_WIN64) && !defined(__CYGWIN__)
    DWORD s;
    write_keys = CreateMutex(NULL, FALSE, NULL);
    write_random = CreateMutex(NULL, FALSE, NULL);
    bsgs_thread = CreateMutex(NULL, FALSE, NULL);
#else
    pthread_mutex_init(&write_keys, NULL);
    pthread_mutex_init(&write_random, NULL);
    pthread_mutex_init(&bsgs_thread, NULL);
    int s;
#endif

    srand(time(NULL));

    secp = new Secp256K1();
    secp->Init();
    OUTPUTSECONDS.SetInt32(30);
    ZERO.SetInt32(0);
    ONE.SetInt32(1);
    BSGS_GROUP_SIZE.SetInt32(CPU_GRP_SIZE);

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

    printf("[+] Version %s, developed by AlbertoBSD\n", version);
    
    while ((c = getopt(argc, argv, "deh6MoqRSEB:b:c:C:E:f:I:k:L:l:m:N:n:p:P:r:s:t:v:V:G:8:z:O:X")) != -1)
{
    switch (c)
    {
         case 'E':
            FLAGEVENLYDISTRIBUTE = 1;
            printf("[+] Evenly distributed pubkey generation mode enabled\n");
            break;
        case 'X':  // Use 'X' for random multiple mode
            FLAGRANDOMMULTIPLE = 1;
            printf("[+] Random Multiple mode enabled\n");
            break;
            case 'O':
    starting_prime = strtoull(optarg, NULL, 10);
    if (starting_prime < 2) {
        starting_prime = 2;
    }
    printf("[+] Starting with prime: %llu\n", starting_prime);
    break;
            case 'o':
    FLAGOPTIMIZEDPRIME = 1;
    printf("[+] Using optimized prime step mode\n");
    break;
            case 'P': {
                // Handle comma-separated list of target public keys
                std::string pubkeys_input = optarg;
                
                // Parse comma-separated pubkeys
                size_t start_pos = 0;
                size_t comma_pos;
                
                while ((comma_pos = pubkeys_input.find(',', start_pos)) != std::string::npos) {
                    std::string one_key = pubkeys_input.substr(start_pos, comma_pos - start_pos);
                    // Trim whitespace
                    one_key.erase(0, one_key.find_first_not_of(" \t"));
                    one_key.erase(one_key.find_last_not_of(" \t") + 1);
                    
                    targetSubtractKeyStrs.push_back(one_key);
                    start_pos = comma_pos + 1;
                }
                
                // Add the last part
                std::string last_key = pubkeys_input.substr(start_pos);
                // Trim whitespace
                last_key.erase(0, last_key.find_first_not_of(" \t"));
                last_key.erase(last_key.find_last_not_of(" \t") + 1);
                
                targetSubtractKeyStrs.push_back(last_key);
                FLAGSUBTRACTKEY = 1;
                break;
            }
            case 'V':
                // Parse the step size for subtraction mode
                if (optarg[0] == '0' && optarg[1] == 'x') {
                    subtractStride.SetBase16(optarg + 2);
                } else {
                    subtractStride.SetBase10(optarg);
                }
                if (subtractStride.IsZero()) {
                    subtractStride.SetInt32(1); // Default to 1 if invalid
                }
                printf("[+] Subtract stride: %s\n", subtractStride.GetBase10());
                break;
        case 'L': // Add this to getopt string
            LEVY_ALPHA = strtod(optarg, NULL);
            if (LEVY_ALPHA <= 1.0 || LEVY_ALPHA > 2.0)
            {
                fprintf(stderr, "[W] Invalid Lévy alpha (must be 1 < alpha <= 2), using default 1.5\n");
                LEVY_ALPHA = 1.5;
            }
            break;
        case 'h':
            menu();
            break;
        case '6':
            FLAGSKIPCHECKSUM = 1;
            fprintf(stderr, "[W] Skipping checksums on files\n");
            break;
        case 'B':
            index_value = indexOf(optarg, bsgs_modes, 6); // Change from 5 to 6
            if (index_value >= 0 && index_value <= 5)
            { // Change from 4 to 5
                FLAGBSGSMODE = index_value;
            }
            else
            {
                fprintf(stderr, "[W] Ignoring unknown bsgs mode %s\n", optarg);
            }
            break;
        case 'b':
            bitrange = strtol(optarg, NULL, 10);
            if (bitrange > 0 && bitrange <= 256)
            {
                MPZAUX.Set(&ONE);
                MPZAUX.ShiftL(bitrange - 1);
                bit_range_str_min = MPZAUX.GetBase16();
                checkpointer((void *)bit_range_str_min, __FILE__, "malloc", "bit_range_str_min", __LINE__ - 1);
                MPZAUX.Set(&ONE);
                MPZAUX.ShiftL(bitrange);
                if (MPZAUX.IsGreater(&secp->order))
                {
                    MPZAUX.Set(&secp->order);
                }
                bit_range_str_max = MPZAUX.GetBase16();
                checkpointer((void *)bit_range_str_max, __FILE__, "malloc", "bit_range_str_min", __LINE__ - 1);
                FLAGBITRANGE = 1;
            }
            else
            {
                fprintf(stderr, "[E] invalid bits param: %s.\n", optarg);
            }
            break;
        case 'c':
            index_value = indexOf(optarg, cryptos, 3);
            switch (index_value)
            {
            case 0:
                FLAGCRYPTO = CRYPTO_BTC;
                break;
            case 1:
                FLAGCRYPTO = CRYPTO_ETH;
                printf("[+] Setting search for ETH address.\n");
                break;
            default:
                FLAGCRYPTO = CRYPTO_NONE;
                fprintf(stderr, "[E] Unknown crypto value %s\n", optarg);
                exit(EXIT_FAILURE);
                break;
            }
            break;
        case 'C':
            if (strlen(optarg) == 22)
            {
                FLAGBASEMINIKEY = 1;
                str_baseminikey = (char *)malloc(23);
                checkpointer((void *)str_baseminikey, __FILE__, "malloc", "str_baseminikey", __LINE__ - 1);
                raw_baseminikey = (char *)malloc(23);
                checkpointer((void *)raw_baseminikey, __FILE__, "malloc", "raw_baseminikey", __LINE__ - 1);
                strncpy(str_baseminikey, optarg, 22);
                for (i = 0; i < 21; i++)
                {
                    if (strchr(Ccoinbuffer, str_baseminikey[i + 1]) != NULL)
                    {
                        raw_baseminikey[i] = (int)(strchr(Ccoinbuffer, str_baseminikey[i + 1]) - Ccoinbuffer) % 58;
                    }
                    else
                    {
                        fprintf(stderr, "[E] invalid character in minikey\n");
                        exit(EXIT_FAILURE);
                    }
                }
            }
            else
            {
                fprintf(stderr, "[E] Invalid Minikey length %li : %s\n", strlen(optarg), optarg);
                exit(EXIT_FAILURE);
            }
            break;
        case 'd':
            FLAGDEBUG = 1;
            printf("[+] Flag DEBUG enabled\n");
            break;
        case 'e':
            FLAGENDOMORPHISM = 1;
            printf("[+] Endomorphism enabled\n");
            lambda.SetBase16("5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72");
            lambda2.SetBase16("ac9c52b33fa3cf1f5ad9e3fd77ed9ba4a880b9fc8ec739c2e0cfc810b51283ce");
            beta.SetBase16("7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee");
            beta2.SetBase16("851695d49a83f8ef919bb86153cbcb16630fb68aed0a766a3ec693d68e6afa40");
            break;
        case 'f':
            FLAGFILE = 1;
            fileName = optarg;
            break;
        case 'I':
            FLAGSTRIDE = 1;
            str_stride = optarg;
            break;
        case 'k':
            KFACTOR = (int)strtol(optarg, NULL, 10);
            if (KFACTOR <= 0)
            {
                KFACTOR = 1;
            }
            printf("[+] K factor %i\n", KFACTOR);
            break;
        case 'l':
            switch (indexOf(optarg, publicsearch, 3))
            {
            case SEARCH_UNCOMPRESS:
                FLAGSEARCH = SEARCH_UNCOMPRESS;
                printf("[+] Search uncompress only\n");
                break;
            case SEARCH_COMPRESS:
                FLAGSEARCH = SEARCH_COMPRESS;
                printf("[+] Search compress only\n");
                break;
            case SEARCH_BOTH:
                FLAGSEARCH = SEARCH_BOTH;
                printf("[+] Search both compress and uncompress\n");
                break;
            }
            break;
        case 'M':
            FLAGMATRIX = 1;
            printf("[+] Matrix screen\n");
            break;
            case 'm':
            switch (indexOf(optarg, modes, 8)) // Change from 7 to 8
            {
            case MODE_XPOINT:
                FLAGMODE = MODE_XPOINT;
                printf("[+] Mode xpoint\n");
                break;
            case MODE_ADDRESS:
                FLAGMODE = MODE_ADDRESS;
                printf("[+] Mode address\n");
                break;
            case MODE_BSGS:
                FLAGMODE = MODE_BSGS;
                break;
            case MODE_RMD160:
                FLAGMODE = MODE_RMD160;
                FLAGCRYPTO = CRYPTO_BTC;
                printf("[+] Mode rmd160\n");
                break;
            case MODE_PUB2RMD:
                FLAGMODE = MODE_PUB2RMD;
                printf("[+] Mode pub2rmd was removed\n");
                exit(0);
                break;
            case MODE_MINIKEYS:
                FLAGMODE = MODE_MINIKEYS;
                printf("[+] Mode minikeys\n");
                break;
            case MODE_VANITY:
                FLAGMODE = MODE_VANITY;
                printf("[+] Mode vanity\n");
                if (vanity_bloom == NULL)
                {
                    vanity_bloom = (struct bloom *)calloc(1, sizeof(struct bloom));
                    checkpointer((void *)vanity_bloom, __FILE__, "calloc", "vanity_bloom", __LINE__ - 1);
                }
                break;
            case MODE_SUBTRACT:
                FLAGMODE = MODE_SUBTRACT;
                printf("[+] Mode subtract\n");
                break;
            default:
                fprintf(stderr, "[E] Unknown mode value %s\n", optarg);
                exit(EXIT_FAILURE);
                break;
            }
            break;;
        case 'n':
            FLAG_N = 1;
            str_N = optarg;
            break;
        case 'p':
            FLAGPRINTPUBKEYS = 1;
            max_pubkeys_to_generate = strtoull(optarg, NULL, 10);
            pubkeyfile = fopen("134.bin", "wb");
            if (pubkeyfile == NULL)
            {
                fprintf(stderr, "[E] Unable to open file for writing scanned public keys\n");
                exit(EXIT_FAILURE);
            }
            printf("[+] Scanned compressed public keys will be saved to scanned_pubkeys.bin\n");
            printf("[+] Will stop after generating %llu public keys\n", max_pubkeys_to_generate);
            printf("[+] Each key uses 33 bytes (1 byte prefix + 32 bytes X coordinate)\n");
            printf("[+] Estimated file size: %.2f GB\n", (double)(max_pubkeys_to_generate * 33) / (1024.0 * 1024.0 * 1024.0));
            start_pubkey_writer(); // Initialize the buffering system
            break;
        case 'q':
            FLAGQUIET = 1;
            printf("[+] Quiet thread output\n");
            break;
        case 'R':
            printf("[+] Random mode\n");
            FLAGRANDOM = 1;
            FLAGBSGSMODE = 3;
            break;
        case 'r':
            if (optarg != NULL)
            {
                stringtokenizer(optarg, &t);
                switch (t.n)
                {
                case 1:
                    range_start = nextToken(&t);
                    if (isValidHex(range_start))
                    {
                        FLAGRANGE = 1;
                        range_end = secp->order.GetBase16();
                    }
                    else
                    {
                        fprintf(stderr, "[E] Invalid hexstring : %s.\n", range_start);
                    }
                    break;
                case 2:
                    range_start = nextToken(&t);
                    range_end = nextToken(&t);
                    if (isValidHex(range_start) && isValidHex(range_end))
                    {
                        FLAGRANGE = 1;
                    }
                    else
                    {
                        if (isValidHex(range_start))
                        {
                            fprintf(stderr, "[E] Invalid hexstring : %s\n", range_start);
                        }
                        else
                        {
                            fprintf(stderr, "[E] Invalid hexstring : %s\n", range_end);
                        }
                    }
                    break;
                default:
                    printf("[E] Unknown number of Range Params: %i\n", t.n);
                    break;
                }
            }
            break;
        case 's':
            OUTPUTSECONDS.SetBase10(optarg);
            if (OUTPUTSECONDS.IsLower(&ZERO))
            {
                OUTPUTSECONDS.SetInt32(30);
            }
            if (OUTPUTSECONDS.IsZero())
            {
                printf("[+] Turn off stats output\n");
            }
            else
            {
                hextemp = OUTPUTSECONDS.GetBase10();
                printf("[+] Stats output every %s seconds\n", hextemp);
                free(hextemp);
            }
            break;
        case 'S':
            FLAGSAVEREADFILE = 1;
            break;
        case 't':
            NTHREADS = strtol(optarg, NULL, 10);
            if (NTHREADS <= 0)
            {
                NTHREADS = 1;
            }
            printf((NTHREADS > 1) ? "[+] Threads : %u\n" : "[+] Thread : %u\n", NTHREADS);
            break;
        case 'v':
            FLAGVANITY = 1;
            if (vanity_bloom == NULL)
            {
                vanity_bloom = (struct bloom *)calloc(1, sizeof(struct bloom));
                checkpointer((void *)vanity_bloom, __FILE__, "calloc", "vanity_bloom", __LINE__ - 1);
            }
            if (isValidBase58String(optarg))
            {
                if (addvanity(optarg) > 0)
                {
                    printf("[+] Added Vanity search : %s\n", optarg);
                }
                else
                {
                    printf("[+] Vanity search \"%s\" was NOT Added\n", optarg);
                }
            }
            else
            {
                fprintf(stderr, "[+] The string \"%s\" is not Valid Base58\n", optarg);
            }
            break;
        case '8':
            if (strlen(optarg) == 58)
            {
                Ccoinbuffer = optarg;
                printf("[+] Base58 for Minikeys %s\n", Ccoinbuffer);
            }
            else
            {
                fprintf(stderr, "[E] The base58 alphabet must be 58 characters long.\n");
                exit(EXIT_FAILURE);
            }
            break;
        case 'z':
            FLAGBLOOMMULTIPLIER = strtol(optarg, NULL, 10);
            if (FLAGBLOOMMULTIPLIER <= 0)
            {
                FLAGBLOOMMULTIPLIER = 1;
            }
            printf("[+] Bloom Size Multiplier %i\n", FLAGBLOOMMULTIPLIER);
            break;
        default:
            fprintf(stderr, "[E] Unknown option -%c\n", c);
            exit(EXIT_FAILURE);
            break;
        }
    }

    if (FLAGFILE && FLAGMODE == MODE_XPOINT && strncmp(fileName, "subtract", 8) == 0) {
    // Find the -p parameter from targetSubtractKeyStrs
    if (targetSubtractKeyStrs.empty()) {
        fprintf(stderr, "[E] Subtract bloom mode requires -p parameter with origin public key\n");
        exit(EXIT_FAILURE);
    }
    
    if (!generateSubtractedKeysToBloom(fileName, targetSubtractKeyStrs[0].c_str())) {
        fprintf(stderr, "[E] Failed to parse subtract bloom parameters\n");
        exit(EXIT_FAILURE);
    }
}


    if (FLAGBSGSMODE == MODE_BSGS && FLAGENDOMORPHISM)
    {
        fprintf(stderr, "[E] Endomorphism doesn't work with BSGS\n");
        exit(EXIT_FAILURE);
    }

    if (FLAGBSGSMODE == MODE_BSGS && FLAGSTRIDE)
    {
        fprintf(stderr, "[E] Stride doesn't work with BSGS\n");
        exit(EXIT_FAILURE);
    }
    if (FLAGSTRIDE)
    {
        if (str_stride[0] == '0' && str_stride[1] == 'x')
        {
            stride.SetBase16(str_stride + 2);
        }
        else
        {
            stride.SetBase10(str_stride);
        }
        printf("[+] Stride : %s\n", stride.GetBase10());
    }
    else
    {
        FLAGSTRIDE = 1;
        stride.Set(&ONE);
    }
    init_generator();
    if (FLAGMODE == MODE_BSGS)
    {
        printf("[+] Mode BSGS %s\n", bsgs_modes[FLAGBSGSMODE]);
    }

    if (FLAGFILE == 0)
    {
        fileName = (char *)default_fileName;
    }

    if (FLAGMODE == MODE_ADDRESS && FLAGCRYPTO == CRYPTO_NONE)
    {
        FLAGCRYPTO = CRYPTO_BTC;
        printf("[+] Setting search for btc address\n");
    }
    if (FLAGRANGE)
    {
        n_range_start.SetBase16(range_start);
        if (n_range_start.IsZero())
        {
            n_range_start.AddOne();
        }
        n_range_end.SetBase16(range_end);
        if (n_range_start.IsEqual(&n_range_end) == false)
        {
            if (n_range_start.IsLower(&secp->order) && n_range_end.IsLowerOrEqual(&secp->order))
            {
                if (n_range_start.IsGreater(&n_range_end))
                {
                    fprintf(stderr, "[W] Opps, start range can't be great than end range. Swapping them\n");
                    n_range_aux.Set(&n_range_start);
                    n_range_start.Set(&n_range_end);
                    n_range_end.Set(&n_range_aux);
                }
                n_range_diff.Set(&n_range_end);
                n_range_diff.Sub(&n_range_start);
            }
            else
            {
                fprintf(stderr, "[E] Start and End range can't be great than N\nFallback to random mode!\n");
                FLAGRANGE = 0;
            }
        }
        else
        {
            fprintf(stderr, "[E] Start and End range can't be the same\nFallback to random mode!\n");
            FLAGRANGE = 0;
        }
    }
    if (FLAGMODE != MODE_BSGS && FLAGMODE != MODE_MINIKEYS)
    {
        BSGS_N.SetInt32(DEBUGCOUNT);
        if (FLAGRANGE == 0 && FLAGBITRANGE == 0)
        {
            n_range_start.SetInt32(1);
            n_range_end.Set(&secp->order);
            n_range_diff.Set(&n_range_end);
            n_range_diff.Sub(&n_range_start);
        }
        else
        {
            if (FLAGBITRANGE)
            {
                n_range_start.SetBase16(bit_range_str_min);
                n_range_end.SetBase16(bit_range_str_max);
                n_range_diff.Set(&n_range_end);
                n_range_diff.Sub(&n_range_start);
            }
            else
            {
                if (FLAGRANGE == 0)
                {
                    fprintf(stderr, "[W] WTF!\n");
                }
            }
        }
    }
    N = 0;

    if (FLAGMODE != MODE_BSGS)
    {
        if (FLAG_N)
        {
            if (str_N[0] == '0' && str_N[1] == 'x')
            {
                N_SEQUENTIAL_MAX = strtol(str_N, NULL, 16);
            }
            else
            {
                N_SEQUENTIAL_MAX = strtol(str_N, NULL, 10);
            }

            if (N_SEQUENTIAL_MAX < 1024)
            {
                fprintf(stderr, "[I] n value need to be equal or great than 1024, back to defaults\n");
                FLAG_N = 0;
                N_SEQUENTIAL_MAX = 0x100000000;
            }
            if (N_SEQUENTIAL_MAX % 1024 != 0)
            {
                fprintf(stderr, "[I] n value need to be multiplier of  1024\n");
                FLAG_N = 0;
                N_SEQUENTIAL_MAX = 0x100000000;
            }
        }
        printf("[+] N = %p\n", (void *)N_SEQUENTIAL_MAX);
        if (FLAGMODE == MODE_MINIKEYS)
        {
            BSGS_N.SetInt32(DEBUGCOUNT);
            if (FLAGBASEMINIKEY)
            {
                printf("[+] Base Minikey : %s\n", str_baseminikey);
            }
            minikeyN = (char *)malloc(22);
            checkpointer((void *)minikeyN, __FILE__, "malloc", "minikeyN", __LINE__ - 1);
            i = 0;
            int58.SetInt32(58);
            int_aux.SetInt64(N_SEQUENTIAL_MAX);
            int_aux.Mult(253);
            i = 20;
            salir = 0;
            do
            {
                if (!int_aux.IsZero())
                {
                    int_r.Set(&int_aux);
                    int_r.Mod(&int58);
                    int_q.Set(&int_aux);
                    minikeyN[i] = (uint8_t)int_r.GetInt64();
                    int_q.Sub(&int_r);
                    int_q.Div(&int58);
                    int_aux.Set(&int_q);
                    i--;
                }
                else
                {
                    salir = 1;
                }
            } while (!salir && i > 0);
            minikey_n_limit = 21 - i;
        }
        else
        {
            if (FLAGBITRANGE)
            {
                printf("[+] Bit Range %i\n", bitrange);
            }
            else
            {
                printf("[+] Range \n");
            }
        }
        if (FLAGMODE != MODE_MINIKEYS)
        {
            hextemp = n_range_start.GetBase16();
            printf("[+] -- from : 0x%s\n", hextemp);
            free(hextemp);
            hextemp = n_range_end.GetBase16();
            printf("[+] -- to   : 0x%s\n", hextemp);
            free(hextemp);
        }

        switch (FLAGMODE)
{
case MODE_MINIKEYS:
case MODE_RMD160:
case MODE_ADDRESS:
case MODE_XPOINT:
    if (!readFileAddress(fileName))
    {
        fprintf(stderr, "[E] Unexpected error\n");
        exit(EXIT_FAILURE);
    }
    break;
case MODE_VANITY:
    if (!readFileVanity(fileName))
    {
        fprintf(stderr, "[E] Unexpected error\n");
        exit(EXIT_FAILURE);
    }
    break;
case MODE_SUBTRACT:
    // We'll initialize the bloom filter when handling this mode
    // So do nothing here
    break;
}

        if (FLAGMODE != MODE_VANITY && !FLAGREADEDFILE1)
        {
            printf("[+] Sorting data ...");
            _sort(addressTable, N);
            printf(" done! %" PRIu64 " values were loaded and sorted\n", N);
            writeFileIfNeeded(fileName);
        }
    }

    if (FLAGPRINTPUBKEYS && FLAGEVENLYDISTRIBUTE) {
        // Skip the normal thread processing and generate evenly distributed keys instead
        generate_evenly_distributed_keys();
        exit(EXIT_SUCCESS);
    }
    // Add this after processing all options
if (FLAGOPTIMIZEDPRIME && FLAGSTRIDE && !stride.IsOne()) {
    fprintf(stderr, "[E] Cannot use both -o (optimized prime) and -V (fixed stride) together\n");
    exit(EXIT_FAILURE);
}

current_prime = starting_prime;

    if (FLAGMODE == MODE_SUBTRACT) {
        if (FLAGSUBTRACTKEY == 0) {
            fprintf(stderr, "[E] Subtract mode requires target public key(s). Use -P option.\n");
            exit(EXIT_FAILURE);
        }
        
        if (!parse_target_subtract_keys()) {
            fprintf(stderr, "[E] Failed to parse target public keys.\n");
            exit(EXIT_FAILURE);
        }
        
        if (subtractStride.IsZero()) {
            subtractStride.SetInt32(1); // Default stride to 1
            printf("[+] Using default subtract stride: 1\n");
        }
        
        if (!init_subtract_bloom_filter(fileName)) {
            fprintf(stderr, "[E] Failed to initialize bloom filter for subtract mode.\n");
            exit(EXIT_FAILURE);
        }
    }

    if (FLAGRANDOMMULTIPLE && !FLAGMODE == MODE_SUBTRACT) {
    fprintf(stderr, "[W] Random Multiple mode is only supported for subtract mode. Ignoring flag.\n");
    FLAGRANDOMMULTIPLE = 0;
}

if (FLAGRANDOMMULTIPLE && FLAGOPTIMIZEDPRIME) {
    fprintf(stderr, "[W] Random Multiple mode cannot be used with optimized prime mode. Using Random Multiple only.\n");
    FLAGOPTIMIZEDPRIME = 0;
}

// In the main function:
if (FLAGMODE == MODE_SUBTRACT && FLAGRANDOMMULTIPLE) {
    // Calculate and display the random multiple information using GLOBAL range
    Int total_range;
    Int max_steps;
    
    // Calculate total range - from n_range_start to n_range_end
    total_range.Set(&n_range_end);
    total_range.Sub(&n_range_start);
    
    // Calculate how many steps it takes to traverse the range
    max_steps.Set(&total_range);
    max_steps.Div(&subtractStride);
    
    // Print this information to console
    char *range_str = total_range.GetBase10();
    char *step_str = subtractStride.GetBase10();
    char *max_steps_str = max_steps.GetBase10();
    char *start_hex = n_range_start.GetBase16();
    char *end_hex = n_range_end.GetBase16();
    
    printf("\n[+] Random Multiple Mode Information:\n");
    printf("    Full range: 0x%s to 0x%s\n", start_hex, end_hex);
    printf("    Total range size: %s\n", range_str);
    printf("    Step value: %s (0x%s)\n", step_str, subtractStride.GetBase16());
    printf("    Maximum steps to complete range: %s\n", max_steps_str);
    printf("    Random selection will span the entire range\n\n");
    
    free(range_str);
    free(step_str);
    free(max_steps_str);
    free(start_hex);
    free(end_hex);
}

    if (FLAGMODE == MODE_BSGS)
{
    printf("[+] Opening file %s\n", fileName);
    
    // Check if it's subtract mode
    if (strncmp(fileName, "subtract", 8) == 0) {
        // Subtract mode for BSGS
        if (targetSubtractKeyStrs.empty()) {
            fprintf(stderr, "[E] Subtract mode requires -P parameter with origin public key\n");
            exit(EXIT_FAILURE);
        }
        
        // Parse subtract parameters using existing function
        if (!generateSubtractedKeysToBloom(fileName, targetSubtractKeyStrs[0].c_str())) {
            fprintf(stderr, "[E] Failed to parse subtract parameters\n");
            exit(EXIT_FAILURE);
        }
        
        // Generate subtracted points as BSGS targets
        printf("[+] Generating %llu subtracted points as BSGS targets\n", subtract_bloom_count);
        
        N = subtract_bloom_count;
        bsgs_point_number = subtract_bloom_count;
        
        // Allocate BSGS arrays
        bsgs_found = (int *)calloc(N, sizeof(int));
        checkpointer((void *)bsgs_found, __FILE__, "calloc", "bsgs_found", __LINE__ - 1);
        OriginalPointsBSGS.reserve(N);
        OriginalPointsBSGScompressed = (bool *)malloc(N * sizeof(bool));
        checkpointer((void *)OriginalPointsBSGScompressed, __FILE__, "malloc", "OriginalPointsBSGScompressed", __LINE__ - 1);
        
        // Generate each subtracted point
        Int currentSubtract;
        for (uint64_t i = 0; i < N; i++) {
            // Calculate subtract value: i * spacing
            currentSubtract.SetInt64(i);
            currentSubtract.Mult(&subtract_bloom_spacing);
            
            // Compute the public key for this subtract value
            Point subtractPubKey = secp->ComputePublicKey(&currentSubtract);
            
            // Negate for subtraction
            Point negatedSubtractPubKey = secp->Negation(subtractPubKey);
            
            // Calculate result: origin - (i * spacing)
            OriginalPointsBSGS[i] = secp->AddDirect(subtract_bloom_origin, negatedSubtractPubKey);
            OriginalPointsBSGScompressed[i] = true; // Assume compressed
            
            // Progress indicator
            if (i % 100000 == 0 && i > 0) {
                printf("\r[+] Generated %llu/%llu target points", i, N);
                fflush(stdout);
            }
        }
        printf("\r[+] Generated %llu target points for BSGS search\n", N);
        printf("[+] Added %u points from subtract mode\n", bsgs_point_number);
        
    } else {
        // Original file reading code
        fd = fopen(fileName, "rb");
        if (fd == NULL)
        {
            fprintf(stderr, "[E] Can't open file %s\n", fileName);
            exit(EXIT_FAILURE);
        }
        aux = (char *)malloc(1024);
        checkpointer((void *)aux, __FILE__, "malloc", "aux", __LINE__ - 1);
        while (!feof(fd))
        {
            if (fgets(aux, 1022, fd) == aux)
            {
                trim(aux, " \t\n\r");
                if (strlen(aux) >= 128)
                {
                    N++;
                }
                else
                {
                    if (strlen(aux) >= 66)
                    {
                        N++;
                    }
                }
            }
        }
        if (N == 0)
        {
            fprintf(stderr, "[E] There is no valid data in the file\n");
            exit(EXIT_FAILURE);
        }
        bsgs_found = (int *)calloc(N, sizeof(int));
        checkpointer((void *)bsgs_found, __FILE__, "calloc", "bsgs_found", __LINE__ - 1);
        OriginalPointsBSGS.reserve(N);
        OriginalPointsBSGScompressed = (bool *)malloc(N * sizeof(bool));
        checkpointer((void *)OriginalPointsBSGScompressed, __FILE__, "malloc", "OriginalPointsBSGScompressed", __LINE__ - 1);
        pointx_str = (char *)malloc(65);
        checkpointer((void *)pointx_str, __FILE__, "malloc", "pointx_str", __LINE__ - 1);
        pointy_str = (char *)malloc(65);
        checkpointer((void *)pointy_str, __FILE__, "malloc", "pointy_str", __LINE__ - 1);
        fseek(fd, 0, SEEK_SET);
        i = 0;
        while (!feof(fd))
        {
            if (fgets(aux, 1022, fd) == aux)
            {
                trim(aux, " \t\n\r");
                if (strlen(aux) >= 66)
                {
                    stringtokenizer(aux, &tokenizerbsgs);
                    aux2 = nextToken(&tokenizerbsgs);
                    memset(pointx_str, 0, 65);
                    memset(pointy_str, 0, 65);
                    switch (strlen(aux2))
                    {
                    case 66:
                        if (secp->ParsePublicKeyHex(aux2, OriginalPointsBSGS[i], OriginalPointsBSGScompressed[i]))
                        {
                            i++;
                        }
                        else
                        {
                            N--;
                        }
                        break;
                    case 130:
                        if (secp->ParsePublicKeyHex(aux2, OriginalPointsBSGS[i], OriginalPointsBSGScompressed[i]))
                        {
                            i++;
                        }
                        else
                        {
                            N--;
                        }
                        break;
                    default:
                        printf("Invalid length: %s\n", aux2);
                        N--;
                        break;
                    }
                    freetokenizer(&tokenizerbsgs);
                }
            }
        }
        fclose(fd);
        bsgs_point_number = N;
        if (bsgs_point_number > 0)
        {
            printf("[+] Added %u points from file\n", bsgs_point_number);
        }
        else
        {
            fprintf(stderr, "[E] The file don't have any valid publickeys\n");
            exit(EXIT_FAILURE);
        }
    }
        BSGS_N.SetInt32(0);
        BSGS_M.SetInt32(0);

        BSGS_M.SetInt64(bsgs_m);

        if (FLAG_N)
        {

            if (str_N[0] == '0' && str_N[1] == 'x')
            {
                BSGS_N.SetBase16((char *)(str_N + 2));
            }
            else
            {
                BSGS_N.SetBase10(str_N);
            }
        }
        else
        {
            BSGS_N.SetInt64((uint64_t)0x100000000000);
        }

        if (BSGS_N.HasSqrt())
        {
            BSGS_M.Set(&BSGS_N);
            BSGS_M.ModSqrt();
        }
        else
        {
            fprintf(stderr, "[E] -n param doesn't have exact square root\n");
            exit(EXIT_FAILURE);
        }

        BSGS_AUX.Set(&BSGS_M);
        BSGS_AUX.Mod(&BSGS_GROUP_SIZE);

        if (!BSGS_AUX.IsZero())
        {
            hextemp = BSGS_GROUP_SIZE.GetBase10();
            fprintf(stderr, "[E] M value is not divisible by %s\n", hextemp);
            exit(EXIT_FAILURE);
        }

        bsgs_m = BSGS_M.GetInt64();

        if (FLAGRANGE || FLAGBITRANGE)
        {
            if (FLAGBITRANGE)
            {
                n_range_start.SetBase16(bit_range_str_min);
                n_range_end.SetBase16(bit_range_str_max);

                n_range_diff.Set(&n_range_end);
                n_range_diff.Sub(&n_range_start);
                printf("[+] Bit Range %i\n", bitrange);
                printf("[+] -- from : 0x%s\n", bit_range_str_min);
                printf("[+] -- to   : 0x%s\n", bit_range_str_max);
            }
            else
            {
                printf("[+] Range \n");
                printf("[+] -- from : 0x%s\n", range_start);
                printf("[+] -- to   : 0x%s\n", range_end);
            }
        }
        else
        {

            n_range_start.SetInt32(1);
            n_range_end.Set(&secp->order);
            n_range_diff.Rand(&n_range_start, &n_range_end);
            n_range_start.Set(&n_range_diff);
        }
        BSGS_CURRENT.Set(&n_range_start);

        if (n_range_diff.IsLower(&BSGS_N))
        {
            fprintf(stderr, "[E] the given range is small\n");
            exit(EXIT_FAILURE);
        }

        BSGS_M.Mult((uint64_t)KFACTOR);
        BSGS_AUX.SetInt32(32);
        BSGS_R.Set(&BSGS_M);
        BSGS_R.Mod(&BSGS_AUX);
        BSGS_M2.Set(&BSGS_M);
        BSGS_M2.Div(&BSGS_AUX);

        if (!BSGS_R.IsZero())
        {
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

        if (!BSGS_R.IsZero())
        {
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

        if (!BSGS_R.IsZero())
        {
            BSGS_N.Set(&BSGS_M);
            BSGS_N.Mult(&BSGS_AUX);
        }

        bsgs_m = BSGS_M.GetInt64();
        bsgs_aux = BSGS_AUX.GetInt64();

        BSGS_N_double.SetInt32(2);
        BSGS_N_double.Mult(&BSGS_N);

        hextemp = BSGS_N.GetBase16();
        printf("[+] N = 0x%s\n", hextemp);
        free(hextemp);
        if (((uint64_t)(bsgs_m / 256)) > 10000)
        {
            itemsbloom = (uint64_t)(bsgs_m / 256);
            if (bsgs_m % 256 != 0)
            {
                itemsbloom++;
            }
        }
        else
        {
            itemsbloom = 1000;
        }

        if (((uint64_t)(bsgs_m2 / 256)) > 1000)
        {
            itemsbloom2 = (uint64_t)(bsgs_m2 / 256);
            if (bsgs_m2 % 256 != 0)
            {
                itemsbloom2++;
            }
        }
        else
        {
            itemsbloom2 = 1000;
        }

        if (((uint64_t)(bsgs_m3 / 256)) > 1000)
        {
            itemsbloom3 = (uint64_t)(bsgs_m3 / 256);
            if (bsgs_m3 % 256 != 0)
            {
                itemsbloom3++;
            }
        }
        else
        {
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
        double bptable_memory = (bytes) / (1024.0 * 1024.0);
        double total_memory = bloom_memory + bptable_memory;

        printf("\n[+] Memory requirements:\n");
        printf("    Bloom filters : %.2f MB\n", bloom_memory);
        printf("    bPtable      : %.2f MB\n", bptable_memory);
        printf("    Total        : %.2f MB\n\n", total_memory);

// Add a safety check
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

        printf("[+] Available system memory: %llu MB\n", available_memory);

        /*if (total_memory > available_memory * 0.95)
        { // Allow using up to 95% of available memory
            fprintf(stderr, "[E] Insufficient memory available! Required: %.2f MB, Available: %llu MB\n",
                    total_memory, available_memory);
            fprintf(stderr, "[I] Try reducing the bloom filter size multiplier (-z option)\n");
            fprintf(stderr, "[I] Or reduce the number of elements being processed\n");
            exit(EXIT_FAILURE);
        }*/
        // Original code continues here
        printf("[+] Bloom filter for %" PRIu64 " elements ", bsgs_m);
        bloom_bP = (struct bloom *)calloc(256, sizeof(struct bloom));
        checkpointer((void *)bloom_bP, __FILE__, "calloc", "bloom_bP", __LINE__ - 1);
        bloom_bP_checksums = (struct checksumsha256 *)calloc(256, sizeof(struct checksumsha256));
        checkpointer((void *)bloom_bP_checksums, __FILE__, "calloc", "bloom_bP_checksums", __LINE__ - 1);

#if defined(_WIN64) && !defined(__CYGWIN__)
        bloom_bP_mutex = (HANDLE *)calloc(256, sizeof(HANDLE));
#else
        bloom_bP_mutex = (pthread_mutex_t *)calloc(256, sizeof(pthread_mutex_t));
#endif
        checkpointer((void *)bloom_bP_mutex, __FILE__, "calloc", "bloom_bP_mutex", __LINE__ - 1);

        fflush(stdout);
        bloom_bP_totalbytes = 0;
        for (i = 0; i < 256; i++)
        {
#if defined(_WIN64) && !defined(__CYGWIN__)
            bloom_bP_mutex[i] = CreateMutex(NULL, FALSE, NULL);
#else
            pthread_mutex_init(&bloom_bP_mutex[i], NULL);
#endif
            if (bloom_init2(&bloom_bP[i], itemsbloom, 0.001) == 1)
            {
                fprintf(stderr, "[E] error bloom_init _ [%" PRIu64 "]\n", i);
                exit(EXIT_FAILURE);
            }
            bloom_bP_totalbytes += bloom_bP[i].bytes;
        }
        printf(": %.2f MB\n", (float)((float)(uint64_t)bloom_bP_totalbytes / (float)(uint64_t)1048576));

        printf("[+] Bloom filter for %" PRIu64 " elements ", bsgs_m2);

#if defined(_WIN64) && !defined(__CYGWIN__)
        bloom_bPx2nd_mutex = (HANDLE *)calloc(256, sizeof(HANDLE));
#else
        bloom_bPx2nd_mutex = (pthread_mutex_t *)calloc(256, sizeof(pthread_mutex_t));
#endif
        checkpointer((void *)bloom_bPx2nd_mutex, __FILE__, "calloc", "bloom_bPx2nd_mutex", __LINE__ - 1);
        bloom_bPx2nd = (struct bloom *)calloc(256, sizeof(struct bloom));
        checkpointer((void *)bloom_bPx2nd, __FILE__, "calloc", "bloom_bPx2nd", __LINE__ - 1);
        bloom_bPx2nd_checksums = (struct checksumsha256 *)calloc(256, sizeof(struct checksumsha256));
        checkpointer((void *)bloom_bPx2nd_checksums, __FILE__, "calloc", "bloom_bPx2nd_checksums", __LINE__ - 1);
        bloom_bP2_totalbytes = 0;
        for (i = 0; i < 256; i++)
        {
#if defined(_WIN64) && !defined(__CYGWIN__)
            bloom_bPx2nd_mutex[i] = CreateMutex(NULL, FALSE, NULL);
#else
            pthread_mutex_init(&bloom_bPx2nd_mutex[i], NULL);
#endif
            if (bloom_init2(&bloom_bPx2nd[i], itemsbloom2, 0.001) == 1)
            {
                fprintf(stderr, "[E] error bloom_init _ [%" PRIu64 "]\n", i);
                exit(EXIT_FAILURE);
            }
            bloom_bP2_totalbytes += bloom_bPx2nd[i].bytes;
        }
        printf(": %.2f MB\n", (float)((float)(uint64_t)bloom_bP2_totalbytes / (float)(uint64_t)1048576));

#if defined(_WIN64) && !defined(__CYGWIN__)
        bloom_bPx3rd_mutex = (HANDLE *)calloc(256, sizeof(HANDLE));
#else
        bloom_bPx3rd_mutex = (pthread_mutex_t *)calloc(256, sizeof(pthread_mutex_t));
#endif
        checkpointer((void *)bloom_bPx3rd_mutex, __FILE__, "calloc", "bloom_bPx3rd_mutex", __LINE__ - 1);
        bloom_bPx3rd = (struct bloom *)calloc(256, sizeof(struct bloom));
        checkpointer((void *)bloom_bPx3rd, __FILE__, "calloc", "bloom_bPx3rd", __LINE__ - 1);
        bloom_bPx3rd_checksums = (struct checksumsha256 *)calloc(256, sizeof(struct checksumsha256));
        checkpointer((void *)bloom_bPx3rd_checksums, __FILE__, "calloc", "bloom_bPx3rd_checksums", __LINE__ - 1);

        printf("[+] Bloom filter for %" PRIu64 " elements ", bsgs_m3);
        bloom_bP3_totalbytes = 0;
        for (i = 0; i < 256; i++)
        {
#if defined(_WIN64) && !defined(__CYGWIN__)
            bloom_bPx3rd_mutex[i] = CreateMutex(NULL, FALSE, NULL);
#else
            pthread_mutex_init(&bloom_bPx3rd_mutex[i], NULL);
#endif
            if (bloom_init2(&bloom_bPx3rd[i], itemsbloom3, 0.001) == 1)
            {
                fprintf(stderr, "[E] error bloom_init [%" PRIu64 "]\n", i);
                exit(EXIT_FAILURE);
            }
            bloom_bP3_totalbytes += bloom_bPx3rd[i].bytes;
        }
        printf(": %.2f MB\n", (float)((float)(uint64_t)bloom_bP3_totalbytes / (float)(uint64_t)1048576));

        BSGS_MP = secp->ComputePublicKey(&BSGS_M);
        BSGS_MP_double = secp->ComputePublicKey(&BSGS_M_double);
        BSGS_MP2 = secp->ComputePublicKey(&BSGS_M2);
        BSGS_MP2_double = secp->ComputePublicKey(&BSGS_M2_double);
        BSGS_MP3 = secp->ComputePublicKey(&BSGS_M3);
        BSGS_MP3_double = secp->ComputePublicKey(&BSGS_M3_double);

        BSGS_AMP2.reserve(32);
        BSGS_AMP3.reserve(32);
        GSn.reserve(CPU_GRP_SIZE / 2);

        i = 0;

        Point bsP = secp->Negation(BSGS_MP_double);
        Point g = bsP;
        GSn[0] = g;

        g = secp->DoubleDirect(g);
        GSn[1] = g;

        for (int i = 2; i < CPU_GRP_SIZE / 2; i++)
        {
            g = secp->AddDirect(g, bsP);
            GSn[i] = g;
        }

        _2GSn = secp->DoubleDirect(GSn[CPU_GRP_SIZE / 2 - 1]);

        i = 0;
        point_temp.Set(BSGS_MP2);
        BSGS_AMP2[0] = secp->Negation(point_temp);
        BSGS_AMP2[0].Reduce();
        point_temp.Set(BSGS_MP2_double);
        point_temp = secp->Negation(point_temp);
        point_temp.Reduce();

        for (i = 1; i < 32; i++)
        {
            BSGS_AMP2[i] = secp->AddDirect(BSGS_AMP2[i - 1], point_temp);
            BSGS_AMP2[i].Reduce();
        }

        i = 0;
        point_temp.Set(BSGS_MP3);
        BSGS_AMP3[0] = secp->Negation(point_temp);
        BSGS_AMP3[0].Reduce();
        point_temp.Set(BSGS_MP3_double);
        point_temp = secp->Negation(point_temp);
        point_temp.Reduce();

        for (i = 1; i < 32; i++)
        {
            BSGS_AMP3[i] = secp->AddDirect(BSGS_AMP3[i - 1], point_temp);
            BSGS_AMP3[i].Reduce();
        }

        bytes = (uint64_t)bsgs_m3 * (uint64_t)sizeof(struct bsgs_xvalue);
        printf("[+] Allocating %.2f MB for %" PRIu64 " bP Points\n", (double)(bytes / 1048576), bsgs_m3);

        bPtable = (struct bsgs_xvalue *)malloc(bytes);
        checkpointer((void *)bPtable, __FILE__, "malloc", "bPtable", __LINE__ - 1);
        memset(bPtable, 0, bytes);

        if (FLAGSAVEREADFILE)
        {
            snprintf(buffer_bloom_file, 1024, "keyhunt_bsgs_4_%" PRIu64 ".blm", bsgs_m);
            fd_aux1 = fopen(buffer_bloom_file, "rb");
            if (fd_aux1 != NULL)
            {
                printf("[+] Reading bloom filter from file %s ", buffer_bloom_file);
                fflush(stdout);
                for (i = 0; i < 256; i++)
                {
                    bf_ptr = (char *)bloom_bP[i].bf;
                    readed = fread(&bloom_bP[i], sizeof(struct bloom), 1, fd_aux1);
                    if (readed != 1)
                    {
                        fprintf(stderr, "[E] Error reading the file %s\n", buffer_bloom_file);
                        exit(EXIT_FAILURE);
                    }
                    bloom_bP[i].bf = (uint8_t *)bf_ptr;
                    readed = fread(bloom_bP[i].bf, bloom_bP[i].bytes, 1, fd_aux1);
                    if (readed != 1)
                    {
                        fprintf(stderr, "[E] Error reading the file %s\n", buffer_bloom_file);
                        exit(EXIT_FAILURE);
                    }
                    readed = fread(&bloom_bP_checksums[i], sizeof(struct checksumsha256), 1, fd_aux1);
                    if (readed != 1)
                    {
                        fprintf(stderr, "[E] Error reading the file %s\n", buffer_bloom_file);
                        exit(EXIT_FAILURE);
                    }
                    if (FLAGSKIPCHECKSUM == 0)
                    {
                        sha256((uint8_t *)bloom_bP[i].bf, bloom_bP[i].bytes, (uint8_t *)rawvalue);
                        if (memcmp(bloom_bP_checksums[i].data, rawvalue, 32) != 0 || memcmp(bloom_bP_checksums[i].backup, rawvalue, 32) != 0)
                        {
                            fprintf(stderr, "[E] Error checksum file mismatch! %s\n", buffer_bloom_file);
                            exit(EXIT_FAILURE);
                        }
                    }
                    if (i % 64 == 0)
                    {
                        printf(".");
                        fflush(stdout);
                    }
                }
                printf(" Done!\n");
                fclose(fd_aux1);
                memset(buffer_bloom_file, 0, 1024);
                snprintf(buffer_bloom_file, 1024, "keyhunt_bsgs_3_%" PRIu64 ".blm", bsgs_m);
                fd_aux1 = fopen(buffer_bloom_file, "rb");
                if (fd_aux1 != NULL)
                {
                    printf("[W] Unused file detected %s you can delete it without worry\n", buffer_bloom_file);
                    fclose(fd_aux1);
                }
                FLAGREADEDFILE1 = 1;
            }
            else
            {
                snprintf(buffer_bloom_file, 1024, "keyhunt_bsgs_3_%" PRIu64 ".blm", bsgs_m);
                fd_aux1 = fopen(buffer_bloom_file, "rb");
                if (fd_aux1 != NULL)
                {
                    printf("[+] Reading bloom filter from file %s ", buffer_bloom_file);
                    fflush(stdout);
                    for (i = 0; i < 256; i++)
                    {
                        bf_ptr = (char *)bloom_bP[i].bf;
                        readed = fread(&oldbloom_bP, sizeof(struct oldbloom), 1, fd_aux1);

                        if (readed != 1)
                        {
                            fprintf(stderr, "[E] Error reading the file %s\n", buffer_bloom_file);
                            exit(EXIT_FAILURE);
                        }
                        memcpy(&bloom_bP[i], &oldbloom_bP, sizeof(struct bloom));
                        bloom_bP[i].bf = (uint8_t *)bf_ptr;

                        readed = fread(bloom_bP[i].bf, bloom_bP[i].bytes, 1, fd_aux1);
                        if (readed != 1)
                        {
                            fprintf(stderr, "[E] Error reading the file %s\n", buffer_bloom_file);
                            exit(EXIT_FAILURE);
                        }
                        memcpy(bloom_bP_checksums[i].data, oldbloom_bP.checksum, 32);
                        memcpy(bloom_bP_checksums[i].backup, oldbloom_bP.checksum_backup, 32);
                        memset(rawvalue, 0, 32);
                        if (FLAGSKIPCHECKSUM == 0)
                        {
                            sha256((uint8_t *)bloom_bP[i].bf, bloom_bP[i].bytes, (uint8_t *)rawvalue);
                            if (memcmp(bloom_bP_checksums[i].data, rawvalue, 32) != 0 || memcmp(bloom_bP_checksums[i].backup, rawvalue, 32) != 0)
                            {
                                fprintf(stderr, "[E] Error checksum file mismatch! %s\n", buffer_bloom_file);
                                exit(EXIT_FAILURE);
                            }
                        }
                        if (i % 32 == 0)
                        {
                            printf(".");
                            fflush(stdout);
                        }
                    }
                    printf(" Done!\n");
                    fclose(fd_aux1);
                    FLAGUPDATEFILE1 = 1;
                    FLAGREADEDFILE1 = 1;
                }
                else
                {
                    FLAGREADEDFILE1 = 0;
                }
            }

            snprintf(buffer_bloom_file, 1024, "keyhunt_bsgs_6_%" PRIu64 ".blm", bsgs_m2);
            fd_aux2 = fopen(buffer_bloom_file, "rb");
            if (fd_aux2 != NULL)
            {
                printf("[+] Reading bloom filter from file %s ", buffer_bloom_file);
                fflush(stdout);
                for (i = 0; i < 256; i++)
                {
                    bf_ptr = (char *)bloom_bPx2nd[i].bf;
                    readed = fread(&bloom_bPx2nd[i], sizeof(struct bloom), 1, fd_aux2);
                    if (readed != 1)
                    {
                        fprintf(stderr, "[E] Error reading the file %s\n", buffer_bloom_file);
                        exit(EXIT_FAILURE);
                    }
                    bloom_bPx2nd[i].bf = (uint8_t *)bf_ptr;
                    readed = fread(bloom_bPx2nd[i].bf, bloom_bPx2nd[i].bytes, 1, fd_aux2);
                    if (readed != 1)
                    {
                        fprintf(stderr, "[E] Error reading the file %s\n", buffer_bloom_file);
                        exit(EXIT_FAILURE);
                    }
                    readed = fread(&bloom_bPx2nd_checksums[i], sizeof(struct checksumsha256), 1, fd_aux2);
                    if (readed != 1)
                    {
                        fprintf(stderr, "[E] Error reading the file %s\n", buffer_bloom_file);
                        exit(EXIT_FAILURE);
                    }
                    memset(rawvalue, 0, 32);
                    if (FLAGSKIPCHECKSUM == 0)
                    {
                        sha256((uint8_t *)bloom_bPx2nd[i].bf, bloom_bPx2nd[i].bytes, (uint8_t *)rawvalue);
                        if (memcmp(bloom_bPx2nd_checksums[i].data, rawvalue, 32) != 0 || memcmp(bloom_bPx2nd_checksums[i].backup, rawvalue, 32) != 0)
                        {
                            fprintf(stderr, "[E] Error checksum file mismatch! %s\n", buffer_bloom_file);
                            exit(EXIT_FAILURE);
                        }
                    }
                    if (i % 64 == 0)
                    {
                        printf(".");
                        fflush(stdout);
                    }
                }
                fclose(fd_aux2);
                printf(" Done!\n");
                memset(buffer_bloom_file, 0, 1024);
                snprintf(buffer_bloom_file, 1024, "keyhunt_bsgs_5_%" PRIu64 ".blm", bsgs_m2);
                fd_aux2 = fopen(buffer_bloom_file, "rb");
                if (fd_aux2 != NULL)
                {
                    printf("[W] Unused file detected %s you can delete it without worry\n", buffer_bloom_file);
                    fclose(fd_aux2);
                }
                memset(buffer_bloom_file, 0, 1024);
                snprintf(buffer_bloom_file, 1024, "keyhunt_bsgs_1_%" PRIu64 ".blm", bsgs_m2);
                fd_aux2 = fopen(buffer_bloom_file, "rb");
                if (fd_aux2 != NULL)
                {
                    printf("[W] Unused file detected %s you can delete it without worry\n", buffer_bloom_file);
                    fclose(fd_aux2);
                }
                FLAGREADEDFILE2 = 1;
            }
            else
            {
                FLAGREADEDFILE2 = 0;
            }

            snprintf(buffer_bloom_file, 1024, "keyhunt_bsgs_2_%" PRIu64 ".tbl", bsgs_m3);
            fd_aux3 = fopen(buffer_bloom_file, "rb");
            if (fd_aux3 != NULL)
            {
                printf("[+] Reading bP Table from file %s .", buffer_bloom_file);
                fflush(stdout);
                rsize = fread(bPtable, bytes, 1, fd_aux3);
                if (rsize != 1)
                {
                    fprintf(stderr, "[E] Error reading the file %s\n", buffer_bloom_file);
                    exit(EXIT_FAILURE);
                }
                rsize = fread(checksum, 32, 1, fd_aux3);
                if (rsize != 1)
                {
                    fprintf(stderr, "[E] Error reading the file %s\n", buffer_bloom_file);
                    exit(EXIT_FAILURE);
                }
                if (FLAGSKIPCHECKSUM == 0)
                {
                    sha256((uint8_t *)bPtable, bytes, (uint8_t *)checksum_backup);
                    if (memcmp(checksum, checksum_backup, 32) != 0)
                    {
                        fprintf(stderr, "[E] Error checksum file mismatch! %s\n", buffer_bloom_file);
                        exit(EXIT_FAILURE);
                    }
                }
                printf("... Done!\n");
                fclose(fd_aux3);
                FLAGREADEDFILE3 = 1;
            }
            else
            {
                FLAGREADEDFILE3 = 0;
            }

            snprintf(buffer_bloom_file, 1024, "keyhunt_bsgs_7_%" PRIu64 ".blm", bsgs_m3);
            fd_aux2 = fopen(buffer_bloom_file, "rb");
            if (fd_aux2 != NULL)
            {
                printf("[+] Reading bloom filter from file %s ", buffer_bloom_file);
                fflush(stdout);
                for (i = 0; i < 256; i++)
                {
                    bf_ptr = (char *)bloom_bPx3rd[i].bf;
                    readed = fread(&bloom_bPx3rd[i], sizeof(struct bloom), 1, fd_aux2);
                    if (readed != 1)
                    {
                        fprintf(stderr, "[E] Error reading the file %s\n", buffer_bloom_file);
                        exit(EXIT_FAILURE);
                    }
                    bloom_bPx3rd[i].bf = (uint8_t *)bf_ptr;
                    readed = fread(bloom_bPx3rd[i].bf, bloom_bPx3rd[i].bytes, 1, fd_aux2);
                    if (readed != 1)
                    {
                        fprintf(stderr, "[E] Error reading the file %s\n", buffer_bloom_file);
                        exit(EXIT_FAILURE);
                    }
                    readed = fread(&bloom_bPx3rd_checksums[i], sizeof(struct checksumsha256), 1, fd_aux2);
                    if (readed != 1)
                    {
                        fprintf(stderr, "[E] Error reading the file %s\n", buffer_bloom_file);
                        exit(EXIT_FAILURE);
                    }
                    memset(rawvalue, 0, 32);
                    if (FLAGSKIPCHECKSUM == 0)
                    {
                        sha256((uint8_t *)bloom_bPx3rd[i].bf, bloom_bPx3rd[i].bytes, (uint8_t *)rawvalue);
                        if (memcmp(bloom_bPx3rd_checksums[i].data, rawvalue, 32) != 0 || memcmp(bloom_bPx3rd_checksums[i].backup, rawvalue, 32) != 0)
                        {
                            fprintf(stderr, "[E] Error checksum file mismatch! %s\n", buffer_bloom_file);
                            exit(EXIT_FAILURE);
                        }
                    }
                    if (i % 64 == 0)
                    {
                        printf(".");
                        fflush(stdout);
                    }
                }
                fclose(fd_aux2);
                printf(" Done!\n");
                FLAGREADEDFILE4 = 1;
            }
            else
            {
                FLAGREADEDFILE4 = 0;
            }
        }

        if (!FLAGREADEDFILE1 || !FLAGREADEDFILE2 || !FLAGREADEDFILE3 || !FLAGREADEDFILE4)
        {
            if (FLAGREADEDFILE1 == 1)
            {
                printf("[I] We need to recalculate some files, don't worry this is only 3%% of the previous work\n");
                FINISHED_THREADS_COUNTER = 0;
                FINISHED_THREADS_BP = 0;
                FINISHED_ITEMS = 0;
                salir = 0;
                BASE = 0;
                THREADCOUNTER = 0;
                if (THREADBPWORKLOAD >= bsgs_m2)
                {
                    THREADBPWORKLOAD = bsgs_m2;
                }
                THREADCYCLES = bsgs_m2 / THREADBPWORKLOAD;
                PERTHREAD_R = bsgs_m2 % THREADBPWORKLOAD;
                if (PERTHREAD_R != 0)
                {
                    THREADCYCLES++;
                }

                printf("\r[+] processing %lu/%lu bP points : %i%%\r", FINISHED_ITEMS, bsgs_m, (int)(((double)FINISHED_ITEMS / (double)bsgs_m) * 100));
                fflush(stdout);

#if defined(_WIN64) && !defined(__CYGWIN__)
                tid = (HANDLE *)calloc(NTHREADS, sizeof(HANDLE));
                checkpointer((void *)tid, __FILE__, "calloc", "tid", __LINE__ - 1);
                bPload_mutex = (HANDLE *)calloc(NTHREADS, sizeof(HANDLE));
#else
                tid = (pthread_t *)calloc(NTHREADS, sizeof(pthread_t));
                bPload_mutex = (pthread_mutex_t *)calloc(NTHREADS, sizeof(pthread_mutex_t));
#endif
                checkpointer((void *)bPload_mutex, __FILE__, "calloc", "bPload_mutex", __LINE__ - 1);
                bPload_temp_ptr = (struct bPload *)calloc(NTHREADS, sizeof(struct bPload));
                checkpointer((void *)bPload_temp_ptr, __FILE__, "calloc", "bPload_temp_ptr", __LINE__ - 1);
                bPload_threads_available = (char *)calloc(NTHREADS, sizeof(char));
                checkpointer((void *)bPload_threads_available, __FILE__, "calloc", "bPload_threads_available", __LINE__ - 1);

                memset(bPload_threads_available, 1, NTHREADS);

                for (j = 0; j < NTHREADS; j++)
                {
#if defined(_WIN64) && !defined(__CYGWIN__)
                    bPload_mutex[j] = CreateMutex(NULL, FALSE, NULL);
#else
                    pthread_mutex_init(&bPload_mutex[j], NULL);
#endif
                }

                do
                {
                    for (j = 0; j < NTHREADS && !salir; j++)
                    {
                        if (bPload_threads_available[j] && !salir)
                        {
                            bPload_threads_available[j] = 0;
                            bPload_temp_ptr[j].from = BASE;
                            bPload_temp_ptr[j].threadid = j;
                            bPload_temp_ptr[j].finished = 0;
                            if (THREADCOUNTER < THREADCYCLES - 1)
                            {
                                bPload_temp_ptr[j].to = BASE + THREADBPWORKLOAD;
                                bPload_temp_ptr[j].workload = THREADBPWORKLOAD;
                            }
                            else
                            {
                                bPload_temp_ptr[j].to = BASE + THREADBPWORKLOAD + PERTHREAD_R;
                                bPload_temp_ptr[j].workload = THREADBPWORKLOAD + PERTHREAD_R;
                                salir = 1;
                            }
#if defined(_WIN64) && !defined(__CYGWIN__)
                            tid[j] = CreateThread(NULL, 0, thread_bPload_2blooms, (void *)&bPload_temp_ptr[j], 0, &s);
#else
                            s = pthread_create(&tid[j], NULL, thread_bPload_2blooms, (void *)&bPload_temp_ptr[j]);
                            pthread_detach(tid[j]);
#endif
                            BASE += THREADBPWORKLOAD;
                            THREADCOUNTER++;
                        }
                    }

                    if (OLDFINISHED_ITEMS != FINISHED_ITEMS)
                    {
                        printf("\r[+] processing %lu/%lu bP points : %i%%\r", FINISHED_ITEMS, bsgs_m2, (int)(((double)FINISHED_ITEMS / (double)bsgs_m2) * 100));
                        fflush(stdout);
                        OLDFINISHED_ITEMS = FINISHED_ITEMS;
                    }

                    for (j = 0; j < NTHREADS; j++)
                    {
#if defined(_WIN64) && !defined(__CYGWIN__)
                        WaitForSingleObject(bPload_mutex[j], INFINITE);
                        finished = bPload_temp_ptr[j].finished;
                        ReleaseMutex(bPload_mutex[j]);
#else
                        pthread_mutex_lock(&bPload_mutex[j]);
                        finished = bPload_temp_ptr[j].finished;
                        pthread_mutex_unlock(&bPload_mutex[j]);
#endif
                        if (finished)
                        {
                            bPload_temp_ptr[j].finished = 0;
                            bPload_threads_available[j] = 1;
                            FINISHED_ITEMS += bPload_temp_ptr[j].workload;
                            FINISHED_THREADS_COUNTER++;
                        }
                    }
                } while (FINISHED_THREADS_COUNTER < THREADCYCLES);
                printf("\r[+] processing %lu/%lu bP points : 100%%     \n", bsgs_m2, bsgs_m2);

                free(tid);
                free(bPload_mutex);
                free(bPload_temp_ptr);
                free(bPload_threads_available);
            }
            else
            {
                FINISHED_THREADS_COUNTER = 0;
                FINISHED_THREADS_BP = 0;
                FINISHED_ITEMS = 0;
                salir = 0;
                BASE = 0;
                THREADCOUNTER = 0;
                if (THREADBPWORKLOAD >= bsgs_m)
                {
                    THREADBPWORKLOAD = bsgs_m;
                }
                THREADCYCLES = bsgs_m / THREADBPWORKLOAD;
                PERTHREAD_R = bsgs_m % THREADBPWORKLOAD;
                if (PERTHREAD_R != 0)
                {
                    THREADCYCLES++;
                }

                printf("\r[+] processing %lu/%lu bP points : %i%%\r", FINISHED_ITEMS, bsgs_m, (int)(((double)FINISHED_ITEMS / (double)bsgs_m) * 100));
                fflush(stdout);

#if defined(_WIN64) && !defined(__CYGWIN__)
                tid = (HANDLE *)calloc(NTHREADS, sizeof(HANDLE));
                bPload_mutex = (HANDLE *)calloc(NTHREADS, sizeof(HANDLE));
#else
                tid = (pthread_t *)calloc(NTHREADS, sizeof(pthread_t));
                bPload_mutex = (pthread_mutex_t *)calloc(NTHREADS, sizeof(pthread_mutex_t));
#endif
                checkpointer((void *)tid, __FILE__, "calloc", "tid", __LINE__ - 1);
                checkpointer((void *)bPload_mutex, __FILE__, "calloc", "bPload_mutex", __LINE__ - 1);

                bPload_temp_ptr = (struct bPload *)calloc(NTHREADS, sizeof(struct bPload));
                checkpointer((void *)bPload_temp_ptr, __FILE__, "calloc", "bPload_temp_ptr", __LINE__ - 1);
                bPload_threads_available = (char *)calloc(NTHREADS, sizeof(char));
                checkpointer((void *)bPload_threads_available, __FILE__, "calloc", "bPload_threads_available", __LINE__ - 1);

                memset(bPload_threads_available, 1, NTHREADS);

                for (j = 0; j < NTHREADS; j++)
                {
#if defined(_WIN64) && !defined(__CYGWIN__)
                    bPload_mutex[j] = CreateMutex(NULL, FALSE, NULL);
#else
                    pthread_mutex_init(&bPload_mutex[j], NULL);
#endif
                }

                do
                {
                    for (j = 0; j < NTHREADS && !salir; j++)
                    {
                        if (bPload_threads_available[j] && !salir)
                        {
                            bPload_threads_available[j] = 0;
                            bPload_temp_ptr[j].from = BASE;
                            bPload_temp_ptr[j].threadid = j;
                            bPload_temp_ptr[j].finished = 0;
                            if (THREADCOUNTER < THREADCYCLES - 1)
                            {
                                bPload_temp_ptr[j].to = BASE + THREADBPWORKLOAD;
                                bPload_temp_ptr[j].workload = THREADBPWORKLOAD;
                            }
                            else
                            {
                                bPload_temp_ptr[j].to = BASE + THREADBPWORKLOAD + PERTHREAD_R;
                                bPload_temp_ptr[j].workload = THREADBPWORKLOAD + PERTHREAD_R;
                                salir = 1;
                            }
#if defined(_WIN64) && !defined(__CYGWIN__)
                            tid[j] = CreateThread(NULL, 0, thread_bPload, (void *)&bPload_temp_ptr[j], 0, &s);
#else
                            s = pthread_create(&tid[j], NULL, thread_bPload, (void *)&bPload_temp_ptr[j]);
                            pthread_detach(tid[j]);
#endif
                            BASE += THREADBPWORKLOAD;
                            THREADCOUNTER++;
                        }
                    }
                    if (OLDFINISHED_ITEMS != FINISHED_ITEMS)
                    {
                        printf("\r[+] processing %lu/%lu bP points : %i%%\r", FINISHED_ITEMS, bsgs_m, (int)(((double)FINISHED_ITEMS / (double)bsgs_m) * 100));
                        fflush(stdout);
                        OLDFINISHED_ITEMS = FINISHED_ITEMS;
                    }

                    for (j = 0; j < NTHREADS; j++)
                    {
#if defined(_WIN64) && !defined(__CYGWIN__)
                        WaitForSingleObject(bPload_mutex[j], INFINITE);
                        finished = bPload_temp_ptr[j].finished;
                        ReleaseMutex(bPload_mutex[j]);
#else
                        pthread_mutex_lock(&bPload_mutex[j]);
                        finished = bPload_temp_ptr[j].finished;
                        pthread_mutex_unlock(&bPload_mutex[j]);
#endif
                        if (finished)
                        {
                            bPload_temp_ptr[j].finished = 0;
                            bPload_threads_available[j] = 1;
                            FINISHED_ITEMS += bPload_temp_ptr[j].workload;
                            FINISHED_THREADS_COUNTER++;
                        }
                    }
                } while (FINISHED_THREADS_COUNTER < THREADCYCLES);
                printf("\r[+] processing %lu/%lu bP points : 100%%     \n", bsgs_m, bsgs_m);

                free(tid);
                free(bPload_mutex);
                free(bPload_temp_ptr);
                free(bPload_threads_available);
            }
        }

        if (!FLAGREADEDFILE1 || !FLAGREADEDFILE2 || !FLAGREADEDFILE4)
        {
            printf("[+] Making checksums .. ");
            fflush(stdout);
        }
        if (!FLAGREADEDFILE1)
        {
            for (i = 0; i < 256; i++)
            {
                sha256((uint8_t *)bloom_bP[i].bf, bloom_bP[i].bytes, (uint8_t *)bloom_bP_checksums[i].data);
                memcpy(bloom_bP_checksums[i].backup, bloom_bP_checksums[i].data, 32);
            }
            printf(".");
        }
        if (!FLAGREADEDFILE2)
        {
            for (i = 0; i < 256; i++)
            {
                sha256((uint8_t *)bloom_bPx2nd[i].bf, bloom_bPx2nd[i].bytes, (uint8_t *)bloom_bPx2nd_checksums[i].data);
                memcpy(bloom_bPx2nd_checksums[i].backup, bloom_bPx2nd_checksums[i].data, 32);
            }
            printf(".");
        }
        if (!FLAGREADEDFILE4)
        {
            for (i = 0; i < 256; i++)
            {
                sha256((uint8_t *)bloom_bPx3rd[i].bf, bloom_bPx3rd[i].bytes, (uint8_t *)bloom_bPx3rd_checksums[i].data);
                memcpy(bloom_bPx3rd_checksums[i].backup, bloom_bPx3rd_checksums[i].data, 32);
            }
            printf(".");
        }
        if (!FLAGREADEDFILE1 || !FLAGREADEDFILE2 || !FLAGREADEDFILE4)
        {
            printf(" done\n");
            fflush(stdout);
        }
        if (!FLAGREADEDFILE3)
        {
            printf("[+] Sorting %lu elements... ", bsgs_m3);
            fflush(stdout);
            bsgs_sort(bPtable, bsgs_m3);
            sha256((uint8_t *)bPtable, bytes, (uint8_t *)checksum);
            memcpy(checksum_backup, checksum, 32);
            printf("Done!\n");
            fflush(stdout);
        }
        if (FLAGSAVEREADFILE || FLAGUPDATEFILE1)
        {
            if (!FLAGREADEDFILE1 || FLAGUPDATEFILE1)
            {
                snprintf(buffer_bloom_file, 1024, "keyhunt_bsgs_4_%" PRIu64 ".blm", bsgs_m);

                if (FLAGUPDATEFILE1)
                {
                    printf("[W] Updating old file into a new one\n");
                }

                fd_aux1 = fopen(buffer_bloom_file, "wb");
                if (fd_aux1 != NULL)
                {
                    printf("[+] Writing bloom filter to file %s ", buffer_bloom_file);
                    fflush(stdout);
                    for (i = 0; i < 256; i++)
                    {
                        readed = fwrite(&bloom_bP[i], sizeof(struct bloom), 1, fd_aux1);
                        if (readed != 1)
                        {
                            fprintf(stderr, "[E] Error writing the file %s please delete it\n", buffer_bloom_file);
                            exit(EXIT_FAILURE);
                        }
                        readed = fwrite(bloom_bP[i].bf, bloom_bP[i].bytes, 1, fd_aux1);
                        if (readed != 1)
                        {
                            fprintf(stderr, "[E] Error writing the file %s please delete it\n", buffer_bloom_file);
                            exit(EXIT_FAILURE);
                        }
                        readed = fwrite(&bloom_bP_checksums[i], sizeof(struct checksumsha256), 1, fd_aux1);
                        if (readed != 1)
                        {
                            fprintf(stderr, "[E] Error writing the file %s please delete it\n", buffer_bloom_file);
                            exit(EXIT_FAILURE);
                        }
                        if (i % 64 == 0)
                        {
                            printf(".");
                            fflush(stdout);
                        }
                    }
                    printf(" Done!\n");
                    fclose(fd_aux1);
                }
                else
                {
                    fprintf(stderr, "[E] Error can't create the file %s\n", buffer_bloom_file);
                    exit(EXIT_FAILURE);
                }
            }
            if (!FLAGREADEDFILE2)
            {
                snprintf(buffer_bloom_file, 1024, "keyhunt_bsgs_6_%" PRIu64 ".blm", bsgs_m2);

                fd_aux2 = fopen(buffer_bloom_file, "wb");
                if (fd_aux2 != NULL)
                {
                    printf("[+] Writing bloom filter to file %s ", buffer_bloom_file);
                    fflush(stdout);
                    for (i = 0; i < 256; i++)
                    {
                        readed = fwrite(&bloom_bPx2nd[i], sizeof(struct bloom), 1, fd_aux2);
                        if (readed != 1)
                        {
                            fprintf(stderr, "[E] Error writing the file %s\n", buffer_bloom_file);
                            exit(EXIT_FAILURE);
                        }
                        readed = fwrite(bloom_bPx2nd[i].bf, bloom_bPx2nd[i].bytes, 1, fd_aux2);
                        if (readed != 1)
                        {
                            fprintf(stderr, "[E] Error writing the file %s\n", buffer_bloom_file);
                            exit(EXIT_FAILURE);
                        }
                        readed = fwrite(&bloom_bPx2nd_checksums[i], sizeof(struct checksumsha256), 1, fd_aux2);
                        if (readed != 1)
                        {
                            fprintf(stderr, "[E] Error writing the file %s please delete it\n", buffer_bloom_file);
                            exit(EXIT_FAILURE);
                        }
                        if (i % 64 == 0)
                        {
                            printf(".");
                            fflush(stdout);
                        }
                    }
                    printf(" Done!\n");
                    fclose(fd_aux2);
                }
                else
                {
                    fprintf(stderr, "[E] Error can't create the file %s\n", buffer_bloom_file);
                    exit(EXIT_FAILURE);
                }
            }

            if (!FLAGREADEDFILE3)
            {
                snprintf(buffer_bloom_file, 1024, "keyhunt_bsgs_2_%" PRIu64 ".tbl", bsgs_m3);
                fd_aux3 = fopen(buffer_bloom_file, "wb");
                if (fd_aux3 != NULL)
                {
                    printf("[+] Writing bP Table to file %s .. ", buffer_bloom_file);
                    fflush(stdout);
                    readed = fwrite(bPtable, bytes, 1, fd_aux3);
                    if (readed != 1)
                    {
                        fprintf(stderr, "[E] Error writing the file %s\n", buffer_bloom_file);
                        exit(EXIT_FAILURE);
                    }
                    readed = fwrite(checksum, 32, 1, fd_aux3);
                    if (readed != 1)
                    {
                        fprintf(stderr, "[E] Error writing the file %s\n", buffer_bloom_file);
                        exit(EXIT_FAILURE);
                    }
                    printf("Done!\n");
                    fclose(fd_aux3);
                }
                else
                {
                    fprintf(stderr, "[E] Error can't create the file %s\n", buffer_bloom_file);
                    exit(EXIT_FAILURE);
                }
            }
            if (!FLAGREADEDFILE4)
            {
                snprintf(buffer_bloom_file, 1024, "keyhunt_bsgs_7_%" PRIu64 ".blm", bsgs_m3);

                fd_aux2 = fopen(buffer_bloom_file, "wb");
                if (fd_aux2 != NULL)
                {
                    printf("[+] Writing bloom filter to file %s ", buffer_bloom_file);
                    fflush(stdout);
                    for (i = 0; i < 256; i++)
                    {
                        readed = fwrite(&bloom_bPx3rd[i], sizeof(struct bloom), 1, fd_aux2);
                        if (readed != 1)
                        {
                            fprintf(stderr, "[E] Error writing the file %s\n", buffer_bloom_file);
                            exit(EXIT_FAILURE);
                        }
                        readed = fwrite(bloom_bPx3rd[i].bf, bloom_bPx3rd[i].bytes, 1, fd_aux2);
                        if (readed != 1)
                        {
                            fprintf(stderr, "[E] Error writing the file %s\n", buffer_bloom_file);
                            exit(EXIT_FAILURE);
                        }
                        readed = fwrite(&bloom_bPx3rd_checksums[i], sizeof(struct checksumsha256), 1, fd_aux2);
                        if (readed != 1)
                        {
                            fprintf(stderr, "[E] Error writing the file %s please delete it\n", buffer_bloom_file);
                            exit(EXIT_FAILURE);
                        }
                        if (i % 64 == 0)
                        {
                            printf(".");
                            fflush(stdout);
                        }
                    }
                    printf(" Done!\n");
                    fclose(fd_aux2);
                }
                else
                {
                    fprintf(stderr, "[E] Error can't create the file %s\n", buffer_bloom_file);
                    exit(EXIT_FAILURE);
                }
            }
        }

        i = 0;

        steps = (uint64_t *)calloc(NTHREADS, sizeof(uint64_t));
        checkpointer((void *)steps, __FILE__, "calloc", "steps", __LINE__ - 1);
        ends = (unsigned int *)calloc(NTHREADS, sizeof(int));
        checkpointer((void *)ends, __FILE__, "calloc", "ends", __LINE__ - 1);
#if defined(_WIN64) && !defined(__CYGWIN__)
        tid = (HANDLE *)calloc(NTHREADS, sizeof(HANDLE));
#else
        tid = (pthread_t *)calloc(NTHREADS, sizeof(pthread_t));
#endif
        checkpointer((void *)tid, __FILE__, "calloc", "tid", __LINE__ - 1);

        for (j = 0; j < NTHREADS; j++)
        {
            tt = (tothread *)malloc(sizeof(struct tothread));
            checkpointer((void *)tt, __FILE__, "malloc", "tt", __LINE__ - 1);
            tt->nt = j;
            steps[j] = 0;
            s = 0;
            switch (FLAGBSGSMODE)
            {
#if defined(_WIN64) && !defined(__CYGWIN__)
            case 0:
                tid[j] = CreateThread(NULL, 0, thread_process_bsgs, (void *)tt, 0, &s);
                break;
            case 1:
                tid[j] = CreateThread(NULL, 0, thread_process_bsgs_backward, (void *)tt, 0, &s);
                break;
            case 2:
                tid[j] = CreateThread(NULL, 0, thread_process_bsgs_both, (void *)tt, 0, &s);
                break;
            case 3:
                tid[j] = CreateThread(NULL, 0, thread_process_bsgs_random, (void *)tt, 0, &s);
                break;
            case 4:
                tid[j] = CreateThread(NULL, 0, thread_process_bsgs_dance, (void *)tt, 0, &s);
                break;
            case 5:
                tid[j] = CreateThread(NULL, 0, thread_process_bsgs_levy, (void *)tt, 0, &s);
                break;
#else
            case 0:
                s = pthread_create(&tid[j], NULL, thread_process_bsgs, (void *)tt);
                break;
            case 1:
                s = pthread_create(&tid[j], NULL, thread_process_bsgs_backward, (void *)tt);
                break;
            case 2:
                s = pthread_create(&tid[j], NULL, thread_process_bsgs_both, (void *)tt);
                break;
            case 3:
                s = pthread_create(&tid[j], NULL, thread_process_bsgs_random, (void *)tt);
                break;
            case 4:
                s = pthread_create(&tid[j], NULL, thread_process_bsgs_dance, (void *)tt);
                break;
            case 5:
                s = pthread_create(&tid[j], NULL, thread_process_bsgs_levy, (void *)tt);
                break;
#endif
            }
#if defined(_WIN64) && !defined(__CYGWIN__)
            if (tid[j] == NULL)
            {
#else
            if (s != 0)
            {
#endif
                fprintf(stderr, "[E] thread thread_process\n");
                exit(EXIT_FAILURE);
            }
        }
        free(aux);
    }
    if (FLAGMODE != MODE_BSGS)
    {
        steps = (uint64_t *)calloc(NTHREADS, sizeof(uint64_t));
        checkpointer((void *)steps, __FILE__, "calloc", "steps", __LINE__ - 1);
        ends = (unsigned int *)calloc(NTHREADS, sizeof(int));
        checkpointer((void *)ends, __FILE__, "calloc", "ends", __LINE__ - 1);
#if defined(_WIN64) && !defined(__CYGWIN__)
        tid = (HANDLE *)calloc(NTHREADS, sizeof(HANDLE));
#else
        tid = (pthread_t *)calloc(NTHREADS, sizeof(pthread_t));
#endif
        checkpointer((void *)tid, __FILE__, "calloc", "tid", __LINE__ - 1);
        for (j = 0; j < NTHREADS; j++)
        {
            tt = (tothread *)malloc(sizeof(struct tothread));
            checkpointer((void *)tt, __FILE__, "malloc", "tt", __LINE__ - 1);
            tt->nt = j;
            steps[j] = 0;
            s = 0;
            switch (FLAGMODE)
{
#if defined(_WIN64) && !defined(__CYGWIN__)
case MODE_ADDRESS:
case MODE_XPOINT:
case MODE_RMD160:
    tid[j] = CreateThread(NULL, 0, thread_process, (void *)tt, 0, &s);
    break;
case MODE_MINIKEYS:
    tid[j] = CreateThread(NULL, 0, thread_process_minikeys, (void *)tt, 0, &s);
    break;
case MODE_VANITY:
    tid[j] = CreateThread(NULL, 0, thread_process_vanity, (void *)tt, 0, &s);
    break;
case MODE_SUBTRACT:
    tid[j] = CreateThread(NULL, 0, thread_process_subtract, (void *)tt, 0, &s);
    break;
#else
case MODE_ADDRESS:
case MODE_XPOINT:
case MODE_RMD160:
    s = pthread_create(&tid[j], NULL, thread_process, (void *)tt);
    break;
case MODE_MINIKEYS:
    s = pthread_create(&tid[j], NULL, thread_process_minikeys, (void *)tt);
    break;
case MODE_VANITY:
    s = pthread_create(&tid[j], NULL, thread_process_vanity, (void *)tt);
    break;
case MODE_SUBTRACT:
    s = pthread_create(&tid[j], NULL, thread_process_subtract, (void *)tt);
    break;
#endif
            }
            if (s != 0)
            {
                fprintf(stderr, "[E] pthread_create thread_process\n");
                exit(EXIT_FAILURE);
            }
        }
    }

    for (j = 0; j < 7; j++)
    {
        int_limits[j].SetBase10((char *)str_limits[j]);
    }

    continue_flag = 1;
    total.SetInt32(0);
    pretotal.SetInt32(0);
    debugcount_mpz.Set(&BSGS_N);
    seconds.SetInt32(0);
    do
    {
        sleep_ms(1000);
        seconds.AddOne();
        check_flag = 1;
        for (j = 0; j < NTHREADS && check_flag; j++)
        {
            check_flag &= ends[j];
        }
        if (check_flag)
        {
            continue_flag = 0;
        }
        if (OUTPUTSECONDS.IsGreater(&ZERO))
        {
            MPZAUX.Set(&seconds);
            MPZAUX.Mod(&OUTPUTSECONDS);
            if (MPZAUX.IsZero())
            {
                total.SetInt32(0);
                for (j = 0; j < NTHREADS; j++)
                {
                    pretotal.Set(&debugcount_mpz);
                    pretotal.Mult(steps[j]);
                    total.Add(&pretotal);
                }

                if (FLAGENDOMORPHISM)
                {
                    if (FLAGMODE == MODE_XPOINT)
                    {
                        total.Mult(3);
                    }
                    else
                    {
                        total.Mult(6);
                    }
                }
                else
                {
                    if (FLAGSEARCH == SEARCH_COMPRESS)
                    {
                        total.Mult(2);
                    }
                }

#ifdef _WIN64
                WaitForSingleObject(bsgs_thread, INFINITE);
#else
                pthread_mutex_lock(&bsgs_thread);
#endif
                pretotal.Set(&total);
                pretotal.Div(&seconds);
                str_seconds = seconds.GetBase10();
                str_pretotal = pretotal.GetBase10();
                str_total = total.GetBase10();

                if (pretotal.IsLower(&int_limits[0]))
                {
                    if (FLAGMATRIX)
                    {
                        sprintf(buffer, "[+] Total %s keys in %s seconds: %s keys/s | Pubkeys written: %llu\n",
                                str_total, str_seconds, str_pretotal, total_keys_written);
                    }
                    else
                    {
                        sprintf(buffer, "\r[+] Total %s keys in %s seconds: %s keys/s | Pubkeys written: %llu\r",
                                str_total, str_seconds, str_pretotal, total_keys_written);
                    }
                }
                else
                {
                    i = 0;
                    salir = 0;
                    while (i < 6 && !salir)
                    {
                        if (pretotal.IsLower(&int_limits[i + 1]))
                        {
                            salir = 1;
                        }
                        else
                        {
                            i++;
                        }
                    }

                    div_pretotal.Set(&pretotal);
                    div_pretotal.Div(&int_limits[salir ? i : i - 1]);
                    str_divpretotal = div_pretotal.GetBase10();
                    if (FLAGMATRIX)
                    {
                        sprintf(buffer, "[+] Total %s keys in %s seconds: ~%s %s (%s keys/s) | Pubkeys written: %llu\n",
                                str_total, str_seconds, str_divpretotal, str_limits_prefixs[salir ? i : i - 1],
                                str_pretotal, total_keys_written);
                    }
                    else
                    {
                        if (THREADOUTPUT == 1)
                        {
                            sprintf(buffer, "\r[+] Total %s keys in %s seconds: ~%s %s (%s keys/s) | Pubkeys written: %llu\r",
                                    str_total, str_seconds, str_divpretotal, str_limits_prefixs[salir ? i : i - 1],
                                    str_pretotal, total_keys_written);
                        }
                        else
                        {
                            sprintf(buffer, "\r[+] Total %s keys in %s seconds: ~%s %s (%s keys/s) | Pubkeys written: %llu\r",
                                    str_total, str_seconds, str_divpretotal, str_limits_prefixs[salir ? i : i - 1],
                                    str_pretotal, total_keys_written);
                        }
                    }
                    free(str_divpretotal);
                }
                printf("%s", buffer);
                fflush(stdout);
                THREADOUTPUT = 0;
#ifdef _WIN64
                ReleaseMutex(bsgs_thread);
#else
                pthread_mutex_unlock(&bsgs_thread);
#endif

                free(str_seconds);
                free(str_pretotal);
                free(str_total);
            }
        }
    } while (continue_flag);
    printf("\nEnd\n");

    if (pubkeyfile != NULL)
    {
        fclose(pubkeyfile);
    }

#ifdef _WIN64
    CloseHandle(write_keys);
    CloseHandle(write_random);
    CloseHandle(bsgs_thread);
#endif

    // Free allocated memory
    free(steps);
    free(ends);
    free(tid);

    if (FLAGMODE == MODE_BSGS)
    {
        free(bsgs_found);
        free(OriginalPointsBSGScompressed);
        free(pointx_str);
        free(pointy_str);
        free(bPtable);

        for (i = 0; i < 256; i++)
        {
            bloom_free(&bloom_bP[i]);
            bloom_free(&bloom_bPx2nd[i]);
            bloom_free(&bloom_bPx3rd[i]);
        }

        free(bloom_bP);
        free(bloom_bPx2nd);
        free(bloom_bPx3rd);
        free(bloom_bP_checksums);
        free(bloom_bPx2nd_checksums);
        free(bloom_bPx3rd_checksums);

#if defined(_WIN64) && !defined(__CYGWIN__)
        for (i = 0; i < 256; i++)
        {
            CloseHandle(bloom_bP_mutex[i]);
            CloseHandle(bloom_bPx2nd_mutex[i]);
            CloseHandle(bloom_bPx3rd_mutex[i]);
        }
#else
        for (i = 0; i < 256; i++)
        {
            pthread_mutex_destroy(&bloom_bP_mutex[i]);
            pthread_mutex_destroy(&bloom_bPx2nd_mutex[i]);
            pthread_mutex_destroy(&bloom_bPx3rd_mutex[i]);
        }
#endif

        free(bloom_bP_mutex);
        free(bloom_bPx2nd_mutex);
        free(bloom_bPx3rd_mutex);
    }
    else
    {
        if (addressTable != NULL)
        {
            free(addressTable);
        }
        if (FLAGMODE == MODE_VANITY)
        {
            if (vanity_bloom != NULL)
            {
                bloom_free(vanity_bloom);
                free(vanity_bloom);
            }
            for (i = 0; i < vanity_rmd_targets; i++)
            {
                free(vanity_address_targets[i]);
                for (j = 0; j < vanity_rmd_limits[i]; j++)
                {
                    free(vanity_rmd_limit_values_A[i][j]);
                    free(vanity_rmd_limit_values_B[i][j]);
                }
                free(vanity_rmd_limit_values_A[i]);
                free(vanity_rmd_limit_values_B[i]);
            }
            free(vanity_address_targets);
            free(vanity_rmd_limits);
            free(vanity_rmd_limit_values_A);
            free(vanity_rmd_limit_values_B);
        }
        bloom_free(&bloom);
    }

    if (FLAGBASEMINIKEY)
    {
        free(str_baseminikey);
        free(raw_baseminikey);
    }

    if (FLAGBITRANGE)
    {
        free(bit_range_str_min);
        free(bit_range_str_max);
    }

    if (FLAGMODE == MODE_SUBTRACT && bloom_subtract_initialized) {
        bloom_free(&bloom_subtract);
    }

    delete secp;

    return 0;
}

// Function to display bloom filter size estimate
void displayBloomEstimate(uint64_t num_items) {
    // Calculate bloom filter size using the same formula as bloom_init2
    double fp_rate = (num_items <= 10000) ? 0.001 : 0.001;
    uint64_t bits_needed = (uint64_t)((-1.0 * num_items * FLAGBLOOMMULTIPLIER * log(fp_rate)) / (log(2.0) * log(2.0)));
    uint64_t bytes_needed = bits_needed / 8;
    
    double mb_size = bytes_needed / (1024.0 * 1024.0);
    double gb_size = mb_size / 1024.0;
    
    printf("[+] Estimated bloom filter size for %llu elements:\n", num_items);
    if (gb_size >= 1.0) {
        printf("    %.2f GB (%.2f MB)\n", gb_size, mb_size);
    } else {
        printf("    %.2f MB\n", mb_size);
    }
    
    // Check available memory
#if defined(_WIN64) && !defined(__CYGWIN__)
    MEMORYSTATUSEX statex;
    statex.dwLength = sizeof(statex);
    GlobalMemoryStatusEx(&statex);
    DWORDLONG available_memory = statex.ullAvailPhysMem / (1024 * 1024);
    printf("[+] Available system memory: %llu MB\n", available_memory);
    
    if (mb_size > available_memory * 0.95) {
        fprintf(stderr, "[W] Warning: Bloom filter size exceeds available memory!\n");
        fprintf(stderr, "[W] Consider reducing the number of keys or using -z option\n");
    }
#else
    long pages = sysconf(_SC_PHYS_PAGES);
    long page_size = sysconf(_SC_PAGE_SIZE);
    uint64_t available_memory = ((uint64_t)pages * (uint64_t)page_size) / (1024 * 1024);
    printf("[+] Available system memory: %lu MB\n", available_memory);
    
    if (mb_size > available_memory * 0.95) {
        fprintf(stderr, "[W] Warning: Bloom filter size exceeds available memory!\n");
        fprintf(stderr, "[W] Consider reducing the number of keys or using -z option\n");
    }
#endif
}

// Function to parse subtract bloom parameters
bool generateSubtractedKeysToBloom(const char* params, const char* originPubkeyHex) {
    // Parse the parameters: "subtract count spacing"
    char* paramsCopy = strdup(params);
    char* token = strtok(paramsCopy, " ");
    
    if (!token || strcmp(token, "subtract") != 0) {
        fprintf(stderr, "[E] Invalid subtract bloom format. Expected: -f \"subtract count spacing\"\n");
        free(paramsCopy);
        return false;
    }
    
    // Get count
    token = strtok(NULL, " ");
    if (!token) {
        fprintf(stderr, "[E] Missing count in subtract bloom parameters\n");
        free(paramsCopy);
        return false;
    }
    subtract_bloom_count = strtoull(token, NULL, 10);
    
    // Get spacing
    token = strtok(NULL, " ");
    if (!token) {
        fprintf(stderr, "[E] Missing spacing in subtract bloom parameters\n");
        free(paramsCopy);
        return false;
    }
    
    // Parse spacing (handle hex with 0x prefix)
    if (token[0] == '0' && token[1] == 'x') {
        subtract_bloom_spacing.SetBase16(token + 2);
    } else {
        subtract_bloom_spacing.SetBase10(token);
    }
    
    free(paramsCopy);
    
    // Parse the origin public key
    if (!originPubkeyHex || strlen(originPubkeyHex) == 0) {
        fprintf(stderr, "[E] Origin public key required for subtract bloom mode\n");
        return false;
    }
    
    bool isCompressed = false;
    size_t len = strlen(originPubkeyHex);
    
    if (len == 66) {
        isCompressed = true;
    } else if (len == 130) {
        isCompressed = false;
    } else {
        fprintf(stderr, "[E] Invalid public key length: %zu\n", len);
        return false;
    }
    
    if (!secp->ParsePublicKeyHex((char*)originPubkeyHex, subtract_bloom_origin, isCompressed)) {
        fprintf(stderr, "[E] Failed to parse origin public key\n");
        return false;
    }
    
    printf("[+] Subtract bloom mode configuration:\n");
    printf("    Origin pubkey: %s\n", originPubkeyHex);
    printf("    Number of keys: %llu\n", subtract_bloom_count);
    printf("    Spacing: %s\n", subtract_bloom_spacing.GetBase16());
    
    // Calculate and show the range that will be covered
    Int total_range;
    total_range.Set(&subtract_bloom_spacing);
    total_range.Mult(subtract_bloom_count);
    
    printf("    Total range covered: %s\n", total_range.GetBase16());
    
    // Show bloom multiplier effect if set
    if (FLAGBLOOMMULTIPLIER > 1) {
        printf("    Bloom multiplier: %d (size will be %dx larger)\n", 
               FLAGBLOOMMULTIPLIER, FLAGBLOOMMULTIPLIER);
    }
    
    FLAGSUBTRACTBLOOM = true;
    return true;
}

bool loadSubtractedKeysToBloom() {
    printf("[+] Generating %llu subtracted keys with spacing %s\n", 
           subtract_bloom_count, subtract_bloom_spacing.GetBase16());
    
    // Display bloom filter estimate BEFORE creating it
    displayBloomEstimate(subtract_bloom_count);
    
    // Ask for confirmation if it's a large amount
    if (subtract_bloom_count > 1000000000) { // More than 1 billion
        printf("\n[!] This will generate over 1 billion keys. Continue? (y/n): ");
        fflush(stdout);
        char response = getchar();
        if (response != 'y' && response != 'Y') {
            printf("[+] Operation cancelled by user\n");
            return false;
        }
        // Clear the newline
        while (getchar() != '\n');
    }
    
    printf("\n[+] Proceeding with key generation using %d threads...\n", NTHREADS);
    
    // For xpoint mode, we need 32 bytes for X coordinate
    MAXLENGTHADDRESS = 32;
    
    // For subtract bloom mode, always use bloom-filter-only mode
    printf("[+] Subtract bloom mode - using bloom filter only (no addressTable)\n");
    printf("[+] Note: There may be occasional false positives.\n");
    
    // Allocate minimal addressTable (just to keep code structure intact)
    addressTable = (struct address_value *)malloc(sizeof(struct address_value) * 1);
    N = 0;  // Set to 0 so binary search is skipped, forcing bloom-only mode
    
    if (!addressTable) {
        fprintf(stderr, "[E] Failed to allocate memory\n");
        return false;
    }
    
    // Initialize bloom filter
    if (!initBloomFilter(&bloom, subtract_bloom_count)) {
        free(addressTable);
        return false;
    }
    
    // Initialize mutexes for bloom filter access
#if defined(_WIN64) && !defined(__CYGWIN__)
    subtract_bloom_mutex = (HANDLE *)calloc(256, sizeof(HANDLE));
    for (int i = 0; i < 256; i++) {
        subtract_bloom_mutex[i] = CreateMutex(NULL, FALSE, NULL);
    }
    bPload_mutex = (HANDLE *)calloc(NTHREADS, sizeof(HANDLE));
    for (int i = 0; i < NTHREADS; i++) {
        bPload_mutex[i] = CreateMutex(NULL, FALSE, NULL);
    }
#else
    subtract_bloom_mutex = (pthread_mutex_t *)calloc(256, sizeof(pthread_mutex_t));
    for (int i = 0; i < 256; i++) {
        pthread_mutex_init(&subtract_bloom_mutex[i], NULL);
    }
    bPload_mutex = (pthread_mutex_t *)calloc(NTHREADS, sizeof(pthread_mutex_t));
    for (int i = 0; i < NTHREADS; i++) {
        pthread_mutex_init(&bPload_mutex[i], NULL);
    }
#endif
    
    uint64_t WORKLOAD = 1048576; // 1M keys per batch
    // If total keys is less than workload, adjust workload
    if (subtract_bloom_count < WORKLOAD) {
        WORKLOAD = subtract_bloom_count;
    }
    uint64_t THREADCYCLES = subtract_bloom_count / WORKLOAD;
    uint64_t PERTHREAD_R = subtract_bloom_count % WORKLOAD;
    if (PERTHREAD_R != 0) {
        THREADCYCLES++;
    }
    
    struct subtractBPload *bPload_temp_ptr = (struct subtractBPload *)calloc(NTHREADS, sizeof(struct subtractBPload));
    char *bPload_threads_available = (char *)calloc(NTHREADS, sizeof(char));
    memset(bPload_threads_available, 1, NTHREADS);
    
#if defined(_WIN64) && !defined(__CYGWIN__)
    HANDLE *tid = (HANDLE *)calloc(NTHREADS, sizeof(HANDLE));
#else
    pthread_t *tid = (pthread_t *)calloc(NTHREADS, sizeof(pthread_t));
#endif
    
    uint64_t BASE = 0;
    uint64_t FINISHED_ITEMS = 0;
    uint64_t FINISHED_THREADS_COUNTER = 0;
    uint32_t THREADCOUNTER = 0;
    int salir = 0;
    
    clock_t start_time = clock();
    clock_t last_update = start_time;
    
    printf("\r[+] Processing 0/%llu keys (0.0%%)\r", subtract_bloom_count);
    fflush(stdout);
    
    do {
        for (int j = 0; j < NTHREADS && !salir; j++) {
            if (bPload_threads_available[j] && !salir) {
                bPload_threads_available[j] = 0;
                bPload_temp_ptr[j].from = BASE;
                bPload_temp_ptr[j].threadid = j;
                bPload_temp_ptr[j].finished = 0;
                
                if (THREADCOUNTER < THREADCYCLES - 1) {
                    bPload_temp_ptr[j].to = BASE + WORKLOAD;
                    bPload_temp_ptr[j].workload = WORKLOAD;
                } else {
                    // For the last thread, only assign remaining keys
                    uint64_t remaining = subtract_bloom_count - BASE;
                    bPload_temp_ptr[j].to = BASE + remaining;
                    bPload_temp_ptr[j].workload = remaining;
                    salir = 1;
                }
                
#if defined(_WIN64) && !defined(__CYGWIN__)
                DWORD thread_id;
                tid[j] = CreateThread(NULL, 0, thread_subtract_bloom_load, 
                                    (void *)&bPload_temp_ptr[j], 0, &thread_id);
#else
                pthread_create(&tid[j], NULL, thread_subtract_bloom_load, 
                             (void *)&bPload_temp_ptr[j]);
                pthread_detach(tid[j]);
#endif
                
                BASE += WORKLOAD;
                THREADCOUNTER++;
            }
        }
        
        // Check thread completion
        for (int j = 0; j < NTHREADS; j++) {
            uint32_t finished;
#if defined(_WIN64) && !defined(__CYGWIN__)
            WaitForSingleObject(bPload_mutex[j], INFINITE);
            finished = bPload_temp_ptr[j].finished;
            ReleaseMutex(bPload_mutex[j]);
#else
            pthread_mutex_lock(&bPload_mutex[j]);
            finished = bPload_temp_ptr[j].finished;
            pthread_mutex_unlock(&bPload_mutex[j]);
#endif
            if (finished) {
                bPload_temp_ptr[j].finished = 0;
                bPload_threads_available[j] = 1;
                FINISHED_ITEMS += bPload_temp_ptr[j].workload;
                FINISHED_THREADS_COUNTER++;
            }
        }
        
        // Update progress
        clock_t current_time = clock();
        if ((current_time - last_update) / CLOCKS_PER_SEC >= 1 || FINISHED_THREADS_COUNTER >= THREADCYCLES) {
            double progress = (double)FINISHED_ITEMS * 100.0 / subtract_bloom_count;
            double elapsed = (double)(current_time - start_time) / CLOCKS_PER_SEC;
            double rate = (elapsed > 0) ? FINISHED_ITEMS / elapsed : 0;
            
            printf("\r[+] Generated %llu/%llu keys (%.1f%%) at %.0f keys/sec", 
                   FINISHED_ITEMS, subtract_bloom_count, progress, rate);
            fflush(stdout);
            
            last_update = current_time;
        }
        
    } while (FINISHED_THREADS_COUNTER < THREADCYCLES);
    
    clock_t end_time = clock();
    double total_seconds = (double)(end_time - start_time) / CLOCKS_PER_SEC;
    
    printf("\n[+] Generated %llu subtracted keys in %.2f seconds (%.0f keys/sec)\n", 
           subtract_bloom_count, total_seconds, subtract_bloom_count / total_seconds);
    printf("[+] Bloom filter size: %.2f MB\n", 
           (float)bloom.bytes / (1024.0 * 1024.0));
    
    // Cleanup
    free(tid);
    free(bPload_mutex);
    free(bPload_temp_ptr);
    free(bPload_threads_available);
    
#if defined(_WIN64) && !defined(__CYGWIN__)
    for (int i = 0; i < 256; i++) {
        CloseHandle(subtract_bloom_mutex[i]);
    }
#else
    for (int i = 0; i < 256; i++) {
        pthread_mutex_destroy(&subtract_bloom_mutex[i]);
    }
#endif
    free(subtract_bloom_mutex);
    
    FLAGREADEDFILE1 = 1;
    
    return true;
}

// Improved function with batched processing
void generate_evenly_distributed_keys() {
    if (!FLAGPRINTPUBKEYS || max_pubkeys_to_generate == 0) {
        printf("[E] Evenly distributed mode requires -p option with a value\n");
        return;
    }
    
    if (!FLAGRANGE) {
        printf("[E] Evenly distributed mode requires a range (-r option)\n");
        return;
    }
    
    printf("[+] Generating %llu evenly distributed public keys across the specified range\n", max_pubkeys_to_generate);
    
    // Calculate the step size
    Int step_size;
    step_size.Set(&n_range_diff);
    Int num_keys;
    num_keys.SetInt64(max_pubkeys_to_generate);
    step_size.Div(&num_keys);
    
    // For very large ranges, ensure we don't have a step size of 0
    if (step_size.IsZero()) {
        printf("[W] Range is too large relative to number of keys - using minimum step size\n");
        step_size.SetInt32(1);
    }
    
    // Display information about the generation
    char *start_hex = n_range_start.GetBase16();
    char *end_hex = n_range_end.GetBase16();
    char *step_hex = step_size.GetBase16();
    printf("[+] Range: 0x%s to 0x%s\n", start_hex, end_hex);
    printf("[+] Step size: 0x%s\n", step_hex);
    free(start_hex);
    free(end_hex);
    free(step_hex);
    
    // Define batch size - adjust based on memory constraints
    // For very large jobs, use smaller batches
    uint64_t batch_size = 1000000; // 1 million keys per batch
    if (max_pubkeys_to_generate > 100000000) { // For really large jobs (> 100M)
        batch_size = 100000; // Use smaller batches of 100K
    }
    
    // Initialize progress tracking
    uint64_t total_keys_generated = 0;
    time_t start_time = time(NULL);
    time_t last_update_time = start_time;
    
    // Generate keys in batches
    Int current_key;
    current_key.Set(&n_range_start);
    Point publicKey;
    unsigned char binPubKey[33];
    
    while (total_keys_generated < max_pubkeys_to_generate) {
        // Calculate how many keys to generate in this batch
        uint64_t keys_in_this_batch = batch_size;
        if (total_keys_generated + batch_size > max_pubkeys_to_generate) {
            keys_in_this_batch = max_pubkeys_to_generate - total_keys_generated;
        }
        
        // Process this batch
        for (uint64_t i = 0; i < keys_in_this_batch; i++) {
            // Check if we've reached the end of the range
            if (current_key.IsGreaterOrEqual(&n_range_end)) {
                printf("[+] Reached end of range after %llu keys\n", total_keys_generated);
                break;
            }
            
            // Generate the public key for the current private key
            publicKey = secp->ComputePublicKey(&current_key);
            
            // Create 33-byte binary compressed public key
            binPubKey[0] = publicKey.y.IsEven() ? 0x02 : 0x03;
            publicKey.x.Get32Bytes(binPubKey + 1);
            
            // Write to the binary file directly
            fwrite(binPubKey, 1, 33, pubkeyfile);
            
            // Move to the next key
            current_key.Add(&step_size);
            
            // Increment counters
            total_keys_generated++;
            pubkeys_generated++;
        }
        
        // Update progress after each batch
        time_t current_time = time(NULL);
        double elapsed_time = difftime(current_time, start_time);
        double batch_time = difftime(current_time, last_update_time);
        
        // Calculate rates
        double overall_rate = (elapsed_time > 0) ? total_keys_generated / elapsed_time : 0;
        double batch_rate = (batch_time > 0) ? keys_in_this_batch / batch_time : 0;
        
        // Format progress information
        printf("\r[+] Generated %llu/%llu keys (%.2f%%) | ", 
               total_keys_generated, max_pubkeys_to_generate, 
               (float)total_keys_generated * 100.0 / max_pubkeys_to_generate);
        
        // Format rates with appropriate unit (keys/s, keys/min, etc.)
        if (overall_rate > 1000000) {
            printf("Overall: %.2f M keys/s", overall_rate / 1000000);
        } else if (overall_rate > 1000) {
            printf("Overall: %.2f K keys/s", overall_rate / 1000);
        } else {
            printf("Overall: %.2f keys/s", overall_rate);
        }
        
        if (batch_rate > 1000000) {
            printf(" | Current: %.2f M keys/s", batch_rate / 1000000);
        } else if (batch_rate > 1000) {
            printf(" | Current: %.2f K keys/s", batch_rate / 1000);
        } else {
            printf(" | Current: %.2f keys/s", batch_rate);
        }
        
        // If we have enough information, estimate time remaining
        if (elapsed_time > 10 && overall_rate > 0) {
            uint64_t keys_remaining = max_pubkeys_to_generate - total_keys_generated;
            double seconds_remaining = keys_remaining / overall_rate;
            
            // Format time remaining
            if (seconds_remaining > 86400) { // > 1 day
                printf(" | ETA: %.1f days", seconds_remaining / 86400);
            } else if (seconds_remaining > 3600) { // > 1 hour
                printf(" | ETA: %.1f hours", seconds_remaining / 3600);
            } else if (seconds_remaining > 60) { // > 1 minute
                printf(" | ETA: %.1f mins", seconds_remaining / 60);
            } else {
                printf(" | ETA: %.1f secs", seconds_remaining);
            }
        }
        
        fflush(stdout);
        last_update_time = current_time;
        
        // Flush to disk periodically to avoid losing data
        fflush(pubkeyfile);
    }
    
    // Final status update
    time_t end_time = time(NULL);
    double total_time = difftime(end_time, start_time);
    printf("\n[+] Completed generating %llu evenly distributed public keys\n", pubkeys_generated);
    printf("[+] Total time: %.2f seconds (%.2f keys/sec)\n", total_time, pubkeys_generated / total_time);
    printf("[+] Keys saved to %s\n", pubkeyfile_name);
    
    // Close the file
    fclose(pubkeyfile);
    pubkeyfile = NULL;
    
    // Cleanup
    cleanup_pubkey_writer();
}

bool verify_pubkey_in_file(Point &resultPoint) {
    // Use hardcoded filename - simple and reliable
    const char* hardcoded_filename = "134.bin";
    
    FILE *file = fopen(hardcoded_filename, "rb");
    if (file == NULL) {
        printf("[W] Cannot open verification file %s - accepting hit without verification\n", hardcoded_filename);
        return true; // Accept the hit if file can't be opened
    }
    
    // Get the X coordinate of the result point
    unsigned char result_x[32];
    resultPoint.x.Get32Bytes(result_x);
    
    // Since we know it's a binary file (134.bin), we can assume the format
    // Read each compressed public key (33 bytes) and check for a match
    unsigned char pubkey_buffer[33];
    
    while (fread(pubkey_buffer, 33, 1, file) == 1) {
        // Compare X coordinate (skip the first byte which is the compression flag)
        if (memcmp(result_x, pubkey_buffer + 1, 32) == 0) {
            fclose(file);
            return true;  // Found a match
        }
    }
    
    fclose(file);
    printf("[I] False positive: Point not found in verification file\n");
    return false;  // No match found
}
void init_pubkey_buffers()
{
    thread_buffers = (PubkeyBuffer *)calloc(NUM_BUFFERS, sizeof(PubkeyBuffer));
    for (int i = 0; i < NUM_BUFFERS; i++)
    {
        thread_buffers[i].keys = (unsigned char *)malloc(PUBKEY_BUFFER_SIZE * 33);
        thread_buffers[i].count = 0;
        thread_buffers[i].ready = false;

#if defined(_WIN64) && !defined(__CYGWIN__)
        thread_buffers[i].mutex = CreateMutex(NULL, FALSE, NULL);
#else
        pthread_mutex_init(&thread_buffers[i].mutex, NULL);
#endif
    }

#if defined(_WIN64) && !defined(__CYGWIN__)
    buffer_ready_event = CreateEvent(NULL, TRUE, FALSE, NULL);
#else
    pthread_mutex_init(&buffer_ready_mutex, NULL);
    pthread_cond_init(&buffer_ready_cond, NULL);
#endif
}

// Writer thread function
#if defined(_WIN64) && !defined(__CYGWIN__)
DWORD WINAPI writer_thread_func(LPVOID vargp)
{
#else
void *writer_thread_func(void *vargp)
{
#endif
    while (writer_running || total_keys_written < max_pubkeys_to_generate)
    {
        bool found_buffer = false;

        // Check all buffers for ready data
        for (int i = 0; i < NUM_BUFFERS && total_keys_written < max_pubkeys_to_generate; i++)
        {
#if defined(_WIN64) && !defined(__CYGWIN__)
            WaitForSingleObject(thread_buffers[i].mutex, INFINITE);
#else
            pthread_mutex_lock(&thread_buffers[i].mutex);
#endif

            if (thread_buffers[i].ready)
            {
                // Write the entire buffer at once
                if (thread_buffers[i].count > 0)
                {
                    size_t keys_to_write = thread_buffers[i].count;
                    if (total_keys_written + keys_to_write > max_pubkeys_to_generate)
                    {
                        keys_to_write = max_pubkeys_to_generate - total_keys_written;
                    }

                    fwrite(thread_buffers[i].keys, 33, keys_to_write, pubkeyfile);
                    total_keys_written += keys_to_write;
                }

                thread_buffers[i].count = 0;
                thread_buffers[i].ready = false;
                found_buffer = true;
            }

#if defined(_WIN64) && !defined(__CYGWIN__)
            ReleaseMutex(thread_buffers[i].mutex);
#else
            pthread_mutex_unlock(&thread_buffers[i].mutex);
#endif

            if (total_keys_written >= max_pubkeys_to_generate)
            {
                printf("\n[+] Generated %llu public keys. Stopping as requested.\n", total_keys_written);
                fclose(pubkeyfile);
                writer_running = false;
                return NULL;
            }
        }

        if (!found_buffer && writer_running)
        {
#if defined(_WIN64) && !defined(__CYGWIN__)
            WaitForSingleObject(buffer_ready_event, 100);
            ResetEvent(buffer_ready_event);
#else
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_nsec += 100000000; // 100ms
            pthread_mutex_lock(&buffer_ready_mutex);
            pthread_cond_timedwait(&buffer_ready_cond, &buffer_ready_mutex, &ts);
            pthread_mutex_unlock(&buffer_ready_mutex);
#endif
        }
    }
    return NULL;
}

void add_pubkey_to_buffer(const unsigned char *pubkey, int thread_id)
{
    if (total_keys_written >= max_pubkeys_to_generate)
        return;

    PubkeyBuffer *buffer = &thread_buffers[thread_id];

#if defined(_WIN64) && !defined(__CYGWIN__)
    WaitForSingleObject(buffer->mutex, INFINITE);
#else
    pthread_mutex_lock(&buffer->mutex);
#endif

    if (buffer->count < PUBKEY_BUFFER_SIZE)
    {
        memcpy(buffer->keys + (buffer->count * 33), pubkey, 33);
        buffer->count++;

        if (buffer->count >= PUBKEY_BUFFER_SIZE)
        {
            buffer->ready = true;
#if defined(_WIN64) && !defined(__CYGWIN__)
            SetEvent(buffer_ready_event);
#else
            pthread_mutex_lock(&buffer_ready_mutex);
            pthread_cond_signal(&buffer_ready_cond);
            pthread_mutex_unlock(&buffer_ready_mutex);
#endif
        }
    }

#if defined(_WIN64) && !defined(__CYGWIN__)
    ReleaseMutex(buffer->mutex);
#else
    pthread_mutex_unlock(&buffer->mutex);
#endif
}

void start_pubkey_writer()
{
    init_pubkey_buffers();

#if defined(_WIN64) && !defined(__CYGWIN__)
    writer_thread = CreateThread(NULL, 0, writer_thread_func, NULL, 0, NULL);
    if (writer_thread == NULL)
    {
        fprintf(stderr, "Error creating writer thread\n");
        exit(EXIT_FAILURE);
    }
#else
    if (pthread_create(&writer_thread, NULL, writer_thread_func, NULL) != 0)
    {
        fprintf(stderr, "Error creating writer thread\n");
        exit(EXIT_FAILURE);
    }
#endif
}

void cleanup_pubkey_writer()
{
    writer_running = false;

#if defined(_WIN64) && !defined(__CYGWIN__)
    SetEvent(buffer_ready_event);
    WaitForSingleObject(writer_thread, INFINITE);
    CloseHandle(writer_thread);
    CloseHandle(buffer_ready_event);
#else
    pthread_mutex_lock(&buffer_ready_mutex);
    pthread_cond_signal(&buffer_ready_cond);
    pthread_mutex_unlock(&buffer_ready_mutex);
    pthread_join(writer_thread, NULL);
    pthread_mutex_destroy(&buffer_ready_mutex);
    pthread_cond_destroy(&buffer_ready_cond);
#endif

    // Clean up thread buffers
    if (thread_buffers)
    {
        for (int i = 0; i < NUM_BUFFERS; i++)
        {
            if (thread_buffers[i].count > 0)
            {
                // Write any remaining keys
                size_t keys_to_write = thread_buffers[i].count;
                if (total_keys_written + keys_to_write > max_pubkeys_to_generate)
                {
                    keys_to_write = max_pubkeys_to_generate - total_keys_written;
                }
                if (keys_to_write > 0)
                {
                    fwrite(thread_buffers[i].keys, 33, keys_to_write, pubkeyfile);
                    total_keys_written += keys_to_write;
                }
            }

            free(thread_buffers[i].keys);
#if defined(_WIN64) && !defined(__CYGWIN__)
            CloseHandle(thread_buffers[i].mutex);
#else
            pthread_mutex_destroy(&thread_buffers[i].mutex);
#endif
        }
        free(thread_buffers);
        thread_buffers = NULL;
    }

    if (pubkeyfile)
    {
        fclose(pubkeyfile);
        pubkeyfile = NULL;
    }
}

void pubkeytopubaddress_dst(char *pkey, int length, char *dst)
{
    char digest[60];
    size_t pubaddress_size = 40;
    sha256((uint8_t *)pkey, length, (uint8_t *)digest);
    RMD160Data((const unsigned char *)digest, 32, digest + 1);
    digest[0] = 0;
    sha256((uint8_t *)digest, 21, (uint8_t *)digest + 21);
    sha256((uint8_t *)digest + 21, 32, (uint8_t *)digest + 21);
    if (!b58enc(dst, &pubaddress_size, digest, 25))
    {
        fprintf(stderr, "error b58enc\n");
    }
}

void rmd160toaddress_dst(char *rmd, char *dst)
{
    char digest[60];
    size_t pubaddress_size = 40;
    digest[0] = byte_encode_crypto;
    memcpy(digest + 1, rmd, 20);
    sha256((uint8_t *)digest, 21, (uint8_t *)digest + 21);
    sha256((uint8_t *)digest + 21, 32, (uint8_t *)digest + 21);
    if (!b58enc(dst, &pubaddress_size, digest, 25))
    {
        fprintf(stderr, "error b58enc\n");
    }
}

char *pubkeytopubaddress(char *pkey, int length)
{
    char *pubaddress = (char *)calloc(MAXLENGTHADDRESS + 10, 1);
    char *digest = (char *)calloc(60, 1);
    size_t pubaddress_size = MAXLENGTHADDRESS + 10;
    checkpointer((void *)pubaddress, __FILE__, "malloc", "pubaddress", __LINE__ - 1);
    checkpointer((void *)digest, __FILE__, "malloc", "digest", __LINE__ - 1);
    // digest [000...0]
    sha256((uint8_t *)pkey, length, (uint8_t *)digest);
    // digest [SHA256 32 bytes+000....0]
    RMD160Data((const unsigned char *)digest, 32, digest + 1);
    // digest [? +RMD160 20 bytes+????000....0]
    digest[0] = 0;
    // digest [0 +RMD160 20 bytes+????000....0]
    sha256((uint8_t *)digest, 21, (uint8_t *)digest + 21);
    // digest [0 +RMD160 20 bytes+SHA256 32 bytes+....0]
    sha256((uint8_t *)digest + 21, 32, (uint8_t *)digest + 21);
    // digest [0 +RMD160 20 bytes+SHA256 32 bytes+....0]
    if (!b58enc(pubaddress, &pubaddress_size, digest, 25))
    {
        fprintf(stderr, "error b58enc\n");
    }
    free(digest);
    return pubaddress; // pubaddress need to be free by te caller funtion
}

int searchbinary(struct address_value *buffer, char *data, int64_t array_length)
{
    int64_t half, min, max, current;
    int r = 0, rcmp;
    min = 0;
    current = 0;
    max = array_length;
    half = array_length;
    while (!r && half >= 1)
    {
        half = (max - min) / 2;
        rcmp = memcmp(data, buffer[current + half].value, 20);
        if (rcmp == 0)
        {
            r = 1; // Found!!
        }
        else
        {
            if (rcmp < 0)
            { // data < temp_read
                max = (max - half);
            }
            else
            { // data > temp_read
                min = (min + half);
            }
            current = min;
        }
    }
    return r;
}

#if defined(_WIN64) && !defined(__CYGWIN__)
DWORD WINAPI thread_process_minikeys(LPVOID vargp)
{
#else
void *thread_process_minikeys(void *vargp)
{
#endif
    FILE *keys;
    Point publickey[4];
    Int key_mpz[4];
    struct tothread *tt;
    uint64_t count;
    char publickeyhashrmd160_uncompress[4][20];
    char public_key_uncompressed_hex[131];
    char address[4][40], minikey[4][24], minikeys[8][24], buffer_b58[21], minikey2check[24], rawvalue[4][32];
    char *hextemp, *rawbuffer;
    int r, thread_number, continue_flag = 1, k, j, count_valid;
    Int counter;
    tt = (struct tothread *)vargp;
    thread_number = tt->nt;
    free(tt);
    rawbuffer = (char *)&counter.bits64;
    count_valid = 0;
    for (k = 0; k < 4; k++)
    {
        minikey[k][0] = 'S';
        minikey[k][22] = '?';
        minikey[k][23] = 0x00;
    }
    minikey2check[0] = 'S';
    minikey2check[22] = '?';
    minikey2check[23] = 0x00;

    do
    {
        if (FLAGRANDOM)
        {
            counter.Rand(256);
            for (k = 0; k < 21; k++)
            {
                buffer_b58[k] = (uint8_t)((uint8_t)rawbuffer[k] % 58);
            }
        }
        else
        {
            if (FLAGBASEMINIKEY)
            {
#if defined(_WIN64) && !defined(__CYGWIN__)
                WaitForSingleObject(write_random, INFINITE);
                memcpy(buffer_b58, raw_baseminikey, 21);
                increment_minikey_N(raw_baseminikey);
                ReleaseMutex(write_random);
#else
                pthread_mutex_lock(&write_random);
                memcpy(buffer_b58, raw_baseminikey, 21);
                increment_minikey_N(raw_baseminikey);
                pthread_mutex_unlock(&write_random);
#endif
            }
            else
            {
#if defined(_WIN64) && !defined(__CYGWIN__)
                WaitForSingleObject(write_random, INFINITE);
#else
                pthread_mutex_lock(&write_random);
#endif
                if (raw_baseminikey == NULL)
                {
                    raw_baseminikey = (char *)malloc(22);
                    checkpointer((void *)raw_baseminikey, __FILE__, "malloc", "raw_baseminikey", __LINE__ - 1);
                    counter.Rand(256);
                    for (k = 0; k < 21; k++)
                    {
                        raw_baseminikey[k] = (uint8_t)((uint8_t)rawbuffer[k] % 58);
                    }
                    memcpy(buffer_b58, raw_baseminikey, 21);
                    increment_minikey_N(raw_baseminikey);
                }
                else
                {
                    memcpy(buffer_b58, raw_baseminikey, 21);
                    increment_minikey_N(raw_baseminikey);
                }
#if defined(_WIN64) && !defined(__CYGWIN__)
                ReleaseMutex(write_random);
#else
                pthread_mutex_unlock(&write_random);
#endif
            }
        }
        set_minikey(minikey2check + 1, buffer_b58, 21);
        if (continue_flag)
        {
            count = 0;
            if (FLAGMATRIX)
            {
                printf("[+] Base minikey: %s     \n", minikey2check);
                fflush(stdout);
            }
            else
            {
                if (!FLAGQUIET)
                {
                    printf("\r[+] Base minikey: %s     \r", minikey2check);
                    fflush(stdout);
                }
            }
            do
            {
                for (j = 0; j < 256; j++)
                {

                    if (count_valid > 0)
                    {
                        for (k = 0; k < count_valid; k++)
                        {
                            memcpy(minikeys[k], minikeys[4 + k], 22);
                        }
                    }
                    do
                    {
                        increment_minikey_index(minikey2check + 1, buffer_b58, 20);
                        memcpy(minikey[0] + 1, minikey2check + 1, 21);
                        increment_minikey_index(minikey2check + 1, buffer_b58, 20);
                        memcpy(minikey[1] + 1, minikey2check + 1, 21);
                        increment_minikey_index(minikey2check + 1, buffer_b58, 20);
                        memcpy(minikey[2] + 1, minikey2check + 1, 21);
                        increment_minikey_index(minikey2check + 1, buffer_b58, 20);
                        memcpy(minikey[3] + 1, minikey2check + 1, 21);

                        sha256sse_23((uint8_t *)minikey[0], (uint8_t *)minikey[1], (uint8_t *)minikey[2], (uint8_t *)minikey[3], (uint8_t *)rawvalue[0], (uint8_t *)rawvalue[1], (uint8_t *)rawvalue[2], (uint8_t *)rawvalue[3]);
                        for (k = 0; k < 4; k++)
                        {
                            if (rawvalue[k][0] == 0x00)
                            {
                                memcpy(minikeys[count_valid], minikey[k], 22);
                                count_valid++;
                            }
                        }
                    } while (count_valid < 4);
                    count_valid -= 4;
                    sha256sse_22((uint8_t *)minikeys[0], (uint8_t *)minikeys[1], (uint8_t *)minikeys[2], (uint8_t *)minikeys[3], (uint8_t *)rawvalue[0], (uint8_t *)rawvalue[1], (uint8_t *)rawvalue[2], (uint8_t *)rawvalue[3]);

                    for (k = 0; k < 4; k++)
                    {
                        key_mpz[k].Set32Bytes((uint8_t *)rawvalue[k]);
                        publickey[k] = secp->ComputePublicKey(&key_mpz[k]);
                    }

                    secp->GetHash160(P2PKH, false, publickey[0], publickey[1], publickey[2], publickey[3], (uint8_t *)publickeyhashrmd160_uncompress[0], (uint8_t *)publickeyhashrmd160_uncompress[1], (uint8_t *)publickeyhashrmd160_uncompress[2], (uint8_t *)publickeyhashrmd160_uncompress[3]);

                    for (k = 0; k < 4; k++)
                    {
                        r = bloom_check(&bloom, publickeyhashrmd160_uncompress[k], 20);
                        if (r)
                        {
                            r = searchbinary(addressTable, publickeyhashrmd160_uncompress[k], N);
                            if (r)
                            {
                                /* hit */
                                hextemp = key_mpz[k].GetBase16();
                                secp->GetPublicKeyHex(false, publickey[k], public_key_uncompressed_hex);
#if defined(_WIN64) && !defined(__CYGWIN__)
                                WaitForSingleObject(write_keys, INFINITE);
#else
                                pthread_mutex_lock(&write_keys);
#endif

                                keys = fopen("KEYFOUNDKEYFOUND.txt", "a+");
                                rmd160toaddress_dst(publickeyhashrmd160_uncompress[k], address[k]);
                                minikeys[k][22] = '\0';
                                if (keys != NULL)
                                {
                                    fprintf(keys, "Private Key: %s\npubkey: %s\nminikey: %s\naddress: %s\n", hextemp, public_key_uncompressed_hex, minikeys[k], address[k]);
                                    fclose(keys);
                                }
                                printf("\nHIT!! Private Key: %s\npubkey: %s\nminikey: %s\naddress: %s\n", hextemp, public_key_uncompressed_hex, minikeys[k], address[k]);
#if defined(_WIN64) && !defined(__CYGWIN__)
                                ReleaseMutex(write_keys);
#else
                                pthread_mutex_unlock(&write_keys);
#endif

                                free(hextemp);
                            }
                        }
                    }
                }
                steps[thread_number]++;
                count += 1024;
            } while (count < N_SEQUENTIAL_MAX && continue_flag);
        }
    } while (continue_flag);
    return NULL;
}

#if defined(_WIN64) && !defined(__CYGWIN__)
DWORD WINAPI thread_process_subtract(LPVOID vargp)
{
#else
void *thread_process_subtract(void *vargp)
{
#endif
    struct tothread *tt;
    Point pts[CPU_GRP_SIZE];
    Point endomorphism_beta[CPU_GRP_SIZE];
    Point endomorphism_beta2[CPU_GRP_SIZE];
    Point endomorphism_negeted_point[4];

    Int dx[CPU_GRP_SIZE / 2 + 1];

    IntGroup *grp = new IntGroup(CPU_GRP_SIZE / 2 + 1);
    Point startP;
    Int dy;
    Int dyn;
    Int _s;
    Int _p;
    Point pp; // point positive
    Point pn; // point negative
    int i, hLength = (CPU_GRP_SIZE / 2 - 1);
    uint64_t count;
    unsigned char xpoint_raw[32];
    
    int r, thread_number, continue_flag = 1;
    size_t k;
    bool match_found = false;
    
    Int key_mpz, subtractValue, keyfound;
    
    // For range splitting approach
    Int thread_start_range, thread_end_range;
    
    // For optimized prime mode
    Int current_prime_int;
    
    // For random multiple mode - use GLOBAL range, not thread range
    Int max_steps_global;
    Int random_step;
    Int temp_step;
    
    tt = (struct tothread *)vargp;
    thread_number = tt->nt;
    free(tt);
    
    grp->Set(dx);
    
    // Calculate range size for each thread - proper Int division
    Int range_size;
    range_size.Set(&n_range_diff);
    
    Int nThreads;
    nThreads.SetInt32(NTHREADS);
    
    Int section_size;
    section_size.Set(&range_size);
    section_size.Div(&nThreads);  // Fixed: Using Int division with Int object
    
    // Calculate start range for this thread
    thread_start_range.Set(&n_range_start);
    Int thread_offset;
    thread_offset.Set(&section_size);
    
    Int threadNum;
    threadNum.SetInt32(thread_number);
    thread_offset.Mult(&threadNum);
    
    thread_start_range.Add(&thread_offset);
    
    // Calculate end range for this thread
    thread_end_range.Set(&thread_start_range);
    thread_end_range.Add(&section_size);
    
    // Make sure we don't exceed the global end range
    if (thread_end_range.IsGreater(&n_range_end)) {
        thread_end_range.Set(&n_range_end);
    }
    
    if (FLAGDEBUG) {
        char *start_hex = thread_start_range.GetBase16();
        char *end_hex = thread_end_range.GetBase16();
        printf("[D] Thread %d range: 0x%s to 0x%s\n", thread_number, start_hex, end_hex);
        free(start_hex);
        free(end_hex);
    }

    // Set thread-specific stride
    Int thread_specific_stride;
    
    if (FLAGOPTIMIZEDPRIME) {
        // Different starting points for different threads in prime mode
        // Each thread uses a different prime in the sequence
        uint64_t thread_prime = starting_prime;
        for (int i = 0; i < thread_number; i++) {
            thread_prime = next_prime(thread_prime);
        }
        current_prime = thread_prime;
        current_prime_int.SetInt64(current_prime);
        
        // Calculate initial stride based on range and prime
        calculate_prime_stride(range_size, current_prime_int, thread_specific_stride);
        
        if (FLAGDEBUG) {
            char *prime_str = current_prime_int.GetBase10();
            char *stride_str = thread_specific_stride.GetBase10();
            printf("[D] Thread %d using prime %s with stride %s\n", 
                   thread_number, prime_str, stride_str);
            free(prime_str);
            free(stride_str);
        }
    } else {
        thread_specific_stride.Set(&subtractStride);
    }
    
    // For RANDOM MULTIPLE mode: Use the GLOBAL range, not thread range
    if (FLAGRANDOMMULTIPLE) {
        // Calculate how many steps it takes to traverse the GLOBAL range
        max_steps_global.Set(&n_range_diff);
        max_steps_global.Div(&thread_specific_stride);
    }
    
    // Set key to thread's starting position  
    key_mpz.Set(&thread_start_range);
    
    // For debugging, output the thread's starting position
    if (FLAGDEBUG) {
        char *hextemp = key_mpz.GetBase16();
        printf("[D] Thread %d starting at: 0x%s with stride: %s\n", 
               thread_number, hextemp, thread_specific_stride.GetBase10());
        free(hextemp);
    }
    
    // Main processing loop
    do {
        // For random multiple mode, generate a random value across the ENTIRE range
        if (FLAGRANDOMMULTIPLE) {
            #if defined(_WIN64) && !defined(__CYGWIN__)
            WaitForSingleObject(bsgs_thread, INFINITE);
            #else
            pthread_mutex_lock(&bsgs_thread);
            #endif
            
            // Generate a truly random number within the global range
            random_step.Rand(256);  // Generate a random 256-bit number
            random_step.Mod(&max_steps_global);  // Reduce it to our range
            
            // Calculate the actual key: min_range + (step_value * random_multiple)
            temp_step.Set(&thread_specific_stride);
            temp_step.Mult(&random_step);
            
            key_mpz.Set(&n_range_start);
            key_mpz.Add(&temp_step);
            
            // Make sure we don't exceed the end range
            if (key_mpz.IsGreater(&n_range_end)) {
                // If we exceed, try again
                random_step.Rand(256);
                random_step.Mod(&max_steps_global);
                temp_step.Set(&thread_specific_stride);
                temp_step.Mult(&random_step);
                key_mpz.Set(&n_range_start);
                key_mpz.Add(&temp_step);
            }
            
            #if defined(_WIN64) && !defined(__CYGWIN__)
            ReleaseMutex(bsgs_thread);
            #else
            pthread_mutex_unlock(&bsgs_thread);
            #endif
        }
        
        // Store our current subtract value
        subtractValue.Set(&key_mpz);
        
        // Display current progress
        if (!FLAGQUIET) {
            char *hextemp = subtractValue.GetBase16();
            
            // Compute the public key for subtract value
            Point subPubKey = secp->ComputePublicKey(&subtractValue);
            
            // Negate the public key (for subtraction)
            Point negatedSubtractPubKey = secp->Negation(subPubKey);
            
            // Calculate the result of target - subtractValue (what we're actually checking)
            Point resultPoint = secp->AddDirect(targetSubtractKeys[0], negatedSubtractPubKey);
            
            // Get the display strings for both keys
            char *subPubKeyHex = secp->GetPublicKeyHex(true, subPubKey);
            char *resultPubKeyHex = secp->GetPublicKeyHex(true, resultPoint);
            
            if (FLAGOPTIMIZEDPRIME) {
                printf("\rT%d SubVal:0x%s -> Result: %s (Prime: %llu)     ", 
                       thread_number, hextemp, resultPubKeyHex, current_prime);
            } else if (FLAGRANDOMMULTIPLE) {
                printf("\rT%d SubVal:0x%s -> Result: %s (Random Multiple)     ", 
                       thread_number, hextemp, resultPubKeyHex);
            } else {
                printf("\rT%d SubVal:0x%s -> Result: %s (Steps: %lu)     ", 
                       thread_number, hextemp, resultPubKeyHex, steps[thread_number]);
            }
            
            fflush(stdout);
            free(hextemp);
            free(subPubKeyHex);
            free(resultPubKeyHex);
            THREADOUTPUT = 1;
        }
        
        // Check if we've exceeded the thread's range - for normal mode only
        if (!FLAGOPTIMIZEDPRIME && !FLAGRANDOMMULTIPLE && subtractValue.IsGreater(&thread_end_range)) {
            if (FLAGDEBUG) {
                printf("[D] Thread %d exceeded its range, stopping\n", thread_number);
            }
            continue_flag = 0;
            break;
        }
            
        // Compute the corresponding public key for subtractValue
        Point subtractPubKey = secp->ComputePublicKey(&subtractValue);
        
        // Negate the public key (for subtraction)
        Point negatedSubtractPubKey = secp->Negation(subtractPubKey);
        
        // Process each target public key
        for (k = 0; k < targetSubtractKeys.size(); k++) {
            if (subtractKeyFound[k]) {
                continue;
            }
            
            // Calculate result of target - subtractValue (as points on the curve)
            // This is equivalent to target + (-subtractValue)
            Point resultPoint = secp->AddDirect(targetSubtractKeys[k], negatedSubtractPubKey);
            
            // Get the X coordinate bytes for bloom filter check
            resultPoint.x.Get32Bytes(xpoint_raw);
            
            // Check if X coordinate exists in our bloom filter
            r = bloom_check(&bloom_subtract, xpoint_raw, 32);
            
            if (r) {
                // If found, verify the result against the file
                if (verify_pubkey_in_file(resultPoint)) {
                    printf("\n[+] Thread %d found verified matching public key using subtract value!\n", thread_number);
                    write_subtract_key(subtractValue, k);
                    subtractKeyFound[k] = true;
                    match_found = true;
                    
                    // Check if all keys have been found
                    bool all_keys_found = true;
                    for (size_t j = 0; j < subtractKeyFound.size(); j++) {
                        if (!subtractKeyFound[j]) {
                            all_keys_found = false;
                            break;
                        }
                    }
                    
                    if (all_keys_found) {
                        printf("[+] All target keys have been found!\n");
                        delete grp;
                        ends[thread_number] = 1;
                        return NULL;
                    }
                } else {
                    // False positive detected
                    if (FLAGDEBUG) {
                        printf("\n[I] Thread %d found Bloom filter match BUT VERIFICATION FAILED\n", thread_number);
                    }
                }
            }
            
            // Now check a batch of points around the current key
            if (!subtractKeyFound[k]) {
                // Starting point: Compute target + (-subtractBase) where subtractBase is key_mpz adjusted by CPU_GRP_SIZE/2
                Int adjustedSubtract(subtractValue);
                adjustedSubtract.Add(CPU_GRP_SIZE / 2);
                Point adjustedSubtractPubKey = secp->ComputePublicKey(&adjustedSubtract);
                Point negatedAdjustedPubKey = secp->Negation(adjustedSubtractPubKey);
                
                // This is our starting point for the batch
                startP = secp->AddDirect(targetSubtractKeys[k], negatedAdjustedPubKey);
                
                // Using the group operations for efficiency
                for (i = 0; i < hLength; i++) {
                    dx[i].ModSub(&Gn[i].x, &startP.x);
                }
                dx[i].ModSub(&Gn[i].x, &startP.x);
                dx[i + 1].ModSub(&_2Gn.x, &startP.x);
                
                // Group inversion
                grp->ModInv();
                
                // Center point
                pts[CPU_GRP_SIZE / 2] = startP;
                
                // Calculate points in both directions from the center
                for (i = 0; i < hLength; i++) {
                    // Point in positive direction
                    pp = startP;
                    
                    // Point in negative direction
                    pn = startP;
                    
                    // P = startP + i*G
                    dy.ModSub(&Gn[i].y, &pp.y);
                    _s.ModMulK1(&dy, &dx[i]);
                    _p.ModSquareK1(&_s);
                    pp.x.ModNeg();
                    pp.x.ModAdd(&_p);
                    pp.x.ModSub(&Gn[i].x);
                    
                    // P = startP - i*G
                    dyn.Set(&Gn[i].y);
                    dyn.ModNeg();
                    dyn.ModSub(&pn.y);
                    _s.ModMulK1(&dyn, &dx[i]);
                    _p.ModSquareK1(&_s);
                    pn.x.ModNeg();
                    pn.x.ModAdd(&_p);
                    pn.x.ModSub(&Gn[i].x);
                    
                    // Store points in array
                    pts[CPU_GRP_SIZE / 2 + (i + 1)] = pp;
                    pts[CPU_GRP_SIZE / 2 - (i + 1)] = pn;
                }
                
                // First point (startP - (GRP_SIZE/2)*G)
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
                
                // Check all points in the batch
                for (int j = 0; j < CPU_GRP_SIZE && !subtractKeyFound[k]; j++) {
                    // Get X coordinate bytes
                    pts[j].x.Get32Bytes(xpoint_raw);
                    
                    // Check against bloom filter
                    r = bloom_check(&bloom_subtract, xpoint_raw, 32);
                    
                    if (r) {
                        // Verify against the file before accepting
                        if (verify_pubkey_in_file(pts[j])) {
                            // Calculate the actual subtract value
                            Int actualSubtractVal(subtractValue);
                            actualSubtractVal.Sub(CPU_GRP_SIZE / 2);
                            actualSubtractVal.Add(j);
                            
                            printf("\n[+] Thread %d found verified matching public key using subtract value!\n", thread_number);
                            write_subtract_key(actualSubtractVal, k);
                            subtractKeyFound[k] = true;
                            match_found = true;
                            
                            // Check if all keys have been found
                            bool all_keys_found = true;
                            for (size_t j = 0; j < subtractKeyFound.size(); j++) {
                                if (!subtractKeyFound[j]) {
                                    all_keys_found = false;
                                    break;
                                }
                            }
                            
                            if (all_keys_found) {
                                printf("[+] All target keys have been found!\n");
                                delete grp;
                                ends[thread_number] = 1;
                                return NULL;
                            }
                        } else {
                            // False positive
                            if (FLAGDEBUG) {
                                printf("\n[I] Thread %d found Bloom filter match BUT VERIFICATION FAILED\n", thread_number);
                            }
                        }
                    }
                }
            }
        }
        
        // Increment for next iteration
        if (FLAGOPTIMIZEDPRIME) {
            #if defined(_WIN64) && !defined(__CYGWIN__)
            WaitForSingleObject(bsgs_thread, INFINITE);
            #else
            pthread_mutex_lock(&bsgs_thread);
            #endif
            
            // Each thread processes its own step count
            steps_taken++;
            
            // Check if it's time to move to next prime
            if (steps_taken >= current_prime) {
                // Find next prime number for this thread
                // Skip NTHREADS prime numbers to avoid overlap with other threads
                for (int i = 0; i < NTHREADS; i++) {
                    current_prime = next_prime(current_prime);
                }
                
                steps_taken = 0;
                
                if (!FLAGQUIET) {
                    printf("\r[+] Thread %d moving to prime: %llu  \r", thread_number, current_prime);
                    fflush(stdout);
                }
                
                // Update current_prime_int
                current_prime_int.SetInt64(current_prime);
                
                // Recalculate stride for this prime
                calculate_prime_stride(range_size, current_prime_int, thread_specific_stride);
            }
            
            // Increment based on the current stride
            key_mpz.Add(&thread_specific_stride);
            
            // Wrap around if we exceed the thread's range
            if (key_mpz.IsGreater(&thread_end_range)) {
                key_mpz.Set(&thread_start_range);
                
                if (FLAGDEBUG) {
                    printf("[D] Thread %d wrapped around to start of range\n", thread_number);
                }
            }
            
            #if defined(_WIN64) && !defined(__CYGWIN__)
            ReleaseMutex(bsgs_thread);
            #else
            pthread_mutex_unlock(&bsgs_thread);
            #endif
        } else if (!FLAGRANDOMMULTIPLE) {
            // Regular non-optimized mode - increment by stride
            key_mpz.Add(&thread_specific_stride);
            
            // If we've reached the end of our range and not in optimized prime mode, we're done
            if (key_mpz.IsGreater(&thread_end_range)) {
                continue_flag = 0;
            }
        }
        
        steps[thread_number]++;
        
    } while (continue_flag);
    
    ends[thread_number] = 1;
    delete grp;
    return NULL;
}

#if defined(_WIN64) && !defined(__CYGWIN__)
DWORD WINAPI thread_process(LPVOID vargp)
{
#else
void *thread_process(void *vargp)
{
#endif
    struct tothread *tt;
    Point pts[CPU_GRP_SIZE];
    Point endomorphism_beta[CPU_GRP_SIZE];
    Point endomorphism_beta2[CPU_GRP_SIZE];
    Point endomorphism_negeted_point[4];

    Int dx[CPU_GRP_SIZE / 2 + 1];
    IntGroup *grp = new IntGroup(CPU_GRP_SIZE / 2 + 1);
    Point startP;
    Int dy;
    Int dyn;
    Int _s;
    Int _p;
    Point pp;
    Point pn;
    int i, l, pp_offset, pn_offset, hLength = (CPU_GRP_SIZE / 2 - 1);
    uint64_t j, count;
    Point R, temporal, publickey;
    int r, thread_number, continue_flag = 1, k;
    char *hextemp = NULL;

    char publickeyhashrmd160[20];
    char publickeyhashrmd160_uncompress[4][20];
    char rawvalue[32];
    char publickeyhashrmd160_endomorphism[12][4][20];

    bool calculate_y = FLAGSEARCH == SEARCH_UNCOMPRESS || FLAGSEARCH == SEARCH_BOTH || FLAGCRYPTO == CRYPTO_ETH;
    Int key_mpz, keyfound, temp_stride;
    tt = (struct tothread *)vargp;
    thread_number = tt->nt;
    free(tt);
    grp->Set(dx);

    // Evenly Distributed Mode implementation
    if (FLAGEVENLYDISTRIBUTE && FLAGPRINTPUBKEYS && max_pubkeys_to_generate > 0) {
        // Calculate thread-specific range
        Int thread_range_size, thread_step_size, thread_start, thread_end;
        Int num_keys_per_thread;
        
        // Total keys divided by number of threads
        Int total_keys;
        total_keys.SetInt64(max_pubkeys_to_generate);
        Int nThreadsInt;
        nThreadsInt.SetInt32(NTHREADS);
        num_keys_per_thread.Set(&total_keys);
        num_keys_per_thread.Div(&nThreadsInt);
        
        if (thread_number == NTHREADS - 1) {
            // Last thread gets any remainder keys
            Int keys_assigned;
            keys_assigned.Set(&num_keys_per_thread);
            keys_assigned.Mult(NTHREADS - 1);
            num_keys_per_thread.Set(&total_keys);
            num_keys_per_thread.Sub(&keys_assigned);
        }
        
        // Calculate this thread's range
        thread_range_size.Set(&n_range_diff);
        thread_range_size.Div(&nThreadsInt);
        
        thread_start.Set(&n_range_start);
        Int thread_offset;
        thread_offset.Set(&thread_range_size);
        Int threadNumInt;
        threadNumInt.SetInt32(thread_number);
        thread_offset.Mult(&threadNumInt);
        thread_start.Add(&thread_offset);
        
        thread_end.Set(&thread_start);
        thread_end.Add(&thread_range_size);
        
        // Ensure last thread goes to end of range
        if (thread_number == NTHREADS - 1) {
            thread_end.Set(&n_range_end);
        }
        
        // Calculate key step size for this thread
        thread_step_size.Set(&thread_range_size);
        thread_step_size.Div(&num_keys_per_thread);
        
        // For very large ranges, ensure we don't have a step size of 0
        if (thread_step_size.IsZero()) {
            thread_step_size.SetInt32(1);
        }
        
        // Display thread-specific information
        char *start_hex = thread_start.GetBase16();
        char *end_hex = thread_end.GetBase16();
        char *step_hex = thread_step_size.GetBase16();
        printf("[+] Thread %d: Range 0x%s to 0x%s, Step 0x%s (%llu keys)\n", 
               thread_number, start_hex, end_hex, step_hex, 
               num_keys_per_thread.GetInt64());
        free(start_hex);
        free(end_hex);
        free(step_hex);
        
        // Initialize batching and progress tracking
        uint64_t batch_size = 10000; // Keys per progress update
        uint64_t total_keys_generated = 0;
        time_t start_time = time(NULL);
        time_t last_update_time = start_time;
        
        // Generate keys evenly across thread's range
        Int current_key;
        current_key.Set(&thread_start);
        Point publicKey;
        unsigned char binPubKey[33];
        
        uint64_t thread_max_keys = num_keys_per_thread.GetInt64();
        
        while (total_keys_generated < thread_max_keys) {
            // Check if we've reached the end of the range
            if (current_key.IsGreaterOrEqual(&thread_end)) {
                printf("[+] Thread %d reached end of range after %llu keys\n", 
                       thread_number, total_keys_generated);
                break;
            }
            
            // Generate the public key for the current private key
            publicKey = secp->ComputePublicKey(&current_key);
            
            // Create 33-byte binary compressed public key
            binPubKey[0] = publicKey.y.IsEven() ? 0x02 : 0x03;
            publicKey.x.Get32Bytes(binPubKey + 1);
            
            // Add to thread's buffer
            add_pubkey_to_buffer(binPubKey, thread_number);
            
            // Move to the next key
            current_key.Add(&thread_step_size);
            
            // Increment counters
            total_keys_generated++;
            
            // Update progress periodically
            if (total_keys_generated % batch_size == 0 || total_keys_generated == thread_max_keys) {
                time_t current_time = time(NULL);
                double elapsed_time = difftime(current_time, start_time);
                
                if (elapsed_time > 0) {
                    double keys_per_sec = total_keys_generated / elapsed_time;
                    double percent_complete = (thread_max_keys > 0) ? 100.0 * total_keys_generated / thread_max_keys : 0.0;
                    
                    // Only one thread (thread 0) should print to avoid messy output
                    if (thread_number == 0 || FLAGQUIET == 0) {
                        printf("\r[+] Thread %d: %llu/%llu keys (%.1f%%) at %.1f keys/sec%s", 
                               thread_number, total_keys_generated, thread_max_keys, 
                               percent_complete, keys_per_sec, 
                               thread_number == 0 ? "                    " : "");
                        fflush(stdout);
                    }
                }
            }
            
            // Check if should continue or if requested number is reached
            if (total_keys_written >= max_pubkeys_to_generate) {
                break;
            }
            
            // Increment step counter for stats
            steps[thread_number]++;
        }
        
        // Final stats for this thread
        time_t end_time = time(NULL);
        double total_time = difftime(end_time, start_time);
        if (total_time > 0 && !FLAGQUIET) {
            printf("\n[+] Thread %d completed: %llu keys in %.1f seconds (%.1f keys/sec)\n", 
                   thread_number, total_keys_generated, total_time, 
                   total_keys_generated / total_time);
        }
        
        ends[thread_number] = 1;
        delete grp;
        return NULL;
    }

    // Original thread_process code for non-evenly distributed mode
    do
    {
        if (FLAGRANDOM)
        {
            key_mpz.Rand(&n_range_start, &n_range_end);
        }
        else
        {
            if (n_range_start.IsLower(&n_range_end))
            {
#if defined(_WIN64) && !defined(__CYGWIN__)
                WaitForSingleObject(write_random, INFINITE);
                key_mpz.Set(&n_range_start);
                n_range_start.Add(N_SEQUENTIAL_MAX);
                ReleaseMutex(write_random);
#else
                pthread_mutex_lock(&write_random);
                key_mpz.Set(&n_range_start);
                n_range_start.Add(N_SEQUENTIAL_MAX);
                pthread_mutex_unlock(&write_random);
#endif
            }
            else
            {
                continue_flag = 0;
            }
        }

        if (continue_flag)
        {
            count = 0;
            if (FLAGMATRIX)
            {
                hextemp = key_mpz.GetBase16();
                printf("Base key: %s thread %i\n", hextemp, thread_number);
                fflush(stdout);
                free(hextemp);
            }
            else
            {
                if (FLAGQUIET == 0)
                {
                    hextemp = key_mpz.GetBase16();
                    printf("\rBase key: %s     \r", hextemp);
                    fflush(stdout);
                    free(hextemp);
                    THREADOUTPUT = 1;
                }
            }

            do
            {
                temp_stride.SetInt32(CPU_GRP_SIZE / 2);
                temp_stride.Mult(&stride);
                key_mpz.Add(&temp_stride);
                startP = secp->ComputePublicKey(&key_mpz);
                key_mpz.Sub(&temp_stride);

                for (i = 0; i < hLength; i++)
                {
                    dx[i].ModSub(&Gn[i].x, &startP.x);
                }

                dx[i].ModSub(&Gn[i].x, &startP.x);    // For the first point
                dx[i + 1].ModSub(&_2Gn.x, &startP.x); // For the next center point
                grp->ModInv();

                pts[CPU_GRP_SIZE / 2] = startP;

                for (i = 0; i < hLength; i++)
                {
                    pp = startP;
                    pn = startP;

                    // P = startP + i*G
                    dy.ModSub(&Gn[i].y, &pp.y);

                    _s.ModMulK1(&dy, &dx[i]); // s = (p2.y-p1.y)*inverse(p2.x-p1.x);
                    _p.ModSquareK1(&_s);      // _p = pow2(s)

                    pp.x.ModNeg();
                    pp.x.ModAdd(&_p);
                    pp.x.ModSub(&Gn[i].x); // rx = pow2(s) - p1.x - p2.x;

                    if (calculate_y)
                    {
                        pp.y.ModSub(&Gn[i].x, &pp.x);
                        pp.y.ModMulK1(&_s);
                        pp.y.ModSub(&Gn[i].y); // ry = - p2.y - s*(ret.x-p2.x);
                    }

                    // P = startP - i*G  , if (x,y) = i*G then (x,-y) = -i*G
                    dyn.Set(&Gn[i].y);
                    dyn.ModNeg();
                    dyn.ModSub(&pn.y);

                    _s.ModMulK1(&dyn, &dx[i]); // s = (p2.y-p1.y)*inverse(p2.x-p1.x);
                    _p.ModSquareK1(&_s);       // _p = pow2(s)
                    pn.x.ModNeg();
                    pn.x.ModAdd(&_p);
                    pn.x.ModSub(&Gn[i].x); // rx = pow2(s) - p1.x - p2.x;

                    if (calculate_y)
                    {
                        pn.y.ModSub(&Gn[i].x, &pn.x);
                        pn.y.ModMulK1(&_s);
                        pn.y.ModAdd(&Gn[i].y); // ry = - p2.y - s*(ret.x-p2.x);
                    }

                    pp_offset = CPU_GRP_SIZE / 2 + (i + 1);
                    pn_offset = CPU_GRP_SIZE / 2 - (i + 1);

                    pts[pp_offset] = pp;
                    pts[pn_offset] = pn;

                    if (FLAGENDOMORPHISM)
                    {
                        if (calculate_y)
                        {
                            endomorphism_beta[pp_offset].y.Set(&pp.y);
                            endomorphism_beta[pn_offset].y.Set(&pn.y);
                            endomorphism_beta2[pp_offset].y.Set(&pp.y);
                            endomorphism_beta2[pn_offset].y.Set(&pn.y);
                        }
                        endomorphism_beta[pp_offset].x.ModMulK1(&pp.x, &beta);
                        endomorphism_beta[pn_offset].x.ModMulK1(&pn.x, &beta);
                        endomorphism_beta2[pp_offset].x.ModMulK1(&pp.x, &beta2);
                        endomorphism_beta2[pn_offset].x.ModMulK1(&pn.x, &beta2);
                    }
                }

                if (FLAGENDOMORPHISM)
                {
                    if (calculate_y)
                    {
                        endomorphism_beta[CPU_GRP_SIZE / 2].y.Set(&pts[CPU_GRP_SIZE / 2].y);
                        endomorphism_beta2[CPU_GRP_SIZE / 2].y.Set(&pts[CPU_GRP_SIZE / 2].y);
                    }
                    endomorphism_beta[CPU_GRP_SIZE / 2].x.ModMulK1(&pts[CPU_GRP_SIZE / 2].x, &beta);
                    endomorphism_beta2[CPU_GRP_SIZE / 2].x.ModMulK1(&pts[CPU_GRP_SIZE / 2].x, &beta2);
                }

                // First point (startP - (GRP_SZIE/2)*G)
                pn = startP;
                dyn.Set(&Gn[i].y);
                dyn.ModNeg();
                dyn.ModSub(&pn.y);

                _s.ModMulK1(&dyn, &dx[i]);
                _p.ModSquareK1(&_s);

                pn.x.ModNeg();
                pn.x.ModAdd(&_p);
                pn.x.ModSub(&Gn[i].x);

                if (calculate_y)
                {
                    pn.y.ModSub(&Gn[i].x, &pn.x);
                    pn.y.ModMulK1(&_s);
                    pn.y.ModAdd(&Gn[i].y);
                }

                pts[0] = pn;

                if (FLAGENDOMORPHISM)
                {
                    if (calculate_y)
                    {
                        endomorphism_beta[0].y.Set(&pn.y);
                        endomorphism_beta2[0].y.Set(&pn.y);
                    }
                    endomorphism_beta[0].x.ModMulK1(&pn.x, &beta);
                    endomorphism_beta2[0].x.ModMulK1(&pn.x, &beta2);
                }

                for (j = 0; j < CPU_GRP_SIZE / 4; j++)
                {
                    switch (FLAGMODE)
                    {
                    case MODE_RMD160:
                    case MODE_ADDRESS:
                        if (FLAGCRYPTO == CRYPTO_BTC)
                        {
                            if (FLAGSEARCH == SEARCH_COMPRESS || FLAGSEARCH == SEARCH_BOTH)
                            {
                                if (FLAGENDOMORPHISM)
                                {
                                    secp->GetHash160_fromX(P2PKH, 0x02, &pts[(j * 4)].x, &pts[(j * 4) + 1].x, &pts[(j * 4) + 2].x, &pts[(j * 4) + 3].x, (uint8_t *)publickeyhashrmd160_endomorphism[0][0], (uint8_t *)publickeyhashrmd160_endomorphism[0][1], (uint8_t *)publickeyhashrmd160_endomorphism[0][2], (uint8_t *)publickeyhashrmd160_endomorphism[0][3]);
                                    secp->GetHash160_fromX(P2PKH, 0x03, &pts[(j * 4)].x, &pts[(j * 4) + 1].x, &pts[(j * 4) + 2].x, &pts[(j * 4) + 3].x, (uint8_t *)publickeyhashrmd160_endomorphism[1][0], (uint8_t *)publickeyhashrmd160_endomorphism[1][1], (uint8_t *)publickeyhashrmd160_endomorphism[1][2], (uint8_t *)publickeyhashrmd160_endomorphism[1][3]);

                                    secp->GetHash160_fromX(P2PKH, 0x02, &endomorphism_beta[(j * 4)].x, &endomorphism_beta[(j * 4) + 1].x, &endomorphism_beta[(j * 4) + 2].x, &endomorphism_beta[(j * 4) + 3].x, (uint8_t *)publickeyhashrmd160_endomorphism[2][0], (uint8_t *)publickeyhashrmd160_endomorphism[2][1], (uint8_t *)publickeyhashrmd160_endomorphism[2][2], (uint8_t *)publickeyhashrmd160_endomorphism[2][3]);
                                    secp->GetHash160_fromX(P2PKH, 0x03, &endomorphism_beta[(j * 4)].x, &endomorphism_beta[(j * 4) + 1].x, &endomorphism_beta[(j * 4) + 2].x, &endomorphism_beta[(j * 4) + 3].x, (uint8_t *)publickeyhashrmd160_endomorphism[3][0], (uint8_t *)publickeyhashrmd160_endomorphism[3][1], (uint8_t *)publickeyhashrmd160_endomorphism[3][2], (uint8_t *)publickeyhashrmd160_endomorphism[3][3]);

                                    secp->GetHash160_fromX(P2PKH, 0x02, &endomorphism_beta2[(j * 4)].x, &endomorphism_beta2[(j * 4) + 1].x, &endomorphism_beta2[(j * 4) + 2].x, &endomorphism_beta2[(j * 4) + 3].x, (uint8_t *)publickeyhashrmd160_endomorphism[4][0], (uint8_t *)publickeyhashrmd160_endomorphism[4][1], (uint8_t *)publickeyhashrmd160_endomorphism[4][2], (uint8_t *)publickeyhashrmd160_endomorphism[4][3]);
                                    secp->GetHash160_fromX(P2PKH, 0x03, &endomorphism_beta2[(j * 4)].x, &endomorphism_beta2[(j * 4) + 1].x, &endomorphism_beta2[(j * 4) + 2].x, &endomorphism_beta2[(j * 4) + 3].x, (uint8_t *)publickeyhashrmd160_endomorphism[5][0], (uint8_t *)publickeyhashrmd160_endomorphism[5][1], (uint8_t *)publickeyhashrmd160_endomorphism[5][2], (uint8_t *)publickeyhashrmd160_endomorphism[5][3]);
                                }
                                else
                                {
                                    secp->GetHash160_fromX(P2PKH, 0x02, &pts[(j * 4)].x, &pts[(j * 4) + 1].x, &pts[(j * 4) + 2].x, &pts[(j * 4) + 3].x, (uint8_t *)publickeyhashrmd160_endomorphism[0][0], (uint8_t *)publickeyhashrmd160_endomorphism[0][1], (uint8_t *)publickeyhashrmd160_endomorphism[0][2], (uint8_t *)publickeyhashrmd160_endomorphism[0][3]);
                                    secp->GetHash160_fromX(P2PKH, 0x03, &pts[(j * 4)].x, &pts[(j * 4) + 1].x, &pts[(j * 4) + 2].x, &pts[(j * 4) + 3].x, (uint8_t *)publickeyhashrmd160_endomorphism[1][0], (uint8_t *)publickeyhashrmd160_endomorphism[1][1], (uint8_t *)publickeyhashrmd160_endomorphism[1][2], (uint8_t *)publickeyhashrmd160_endomorphism[1][3]);
                                }
                            }
                            if (FLAGSEARCH == SEARCH_UNCOMPRESS || FLAGSEARCH == SEARCH_BOTH)
                            {
                                if (FLAGENDOMORPHISM)
                                {
                                    for (l = 0; l < 4; l++)
                                    {
                                        endomorphism_negeted_point[l] = secp->Negation(pts[(j * 4) + l]);
                                    }
                                    secp->GetHash160(P2PKH, false, pts[(j * 4)], pts[(j * 4) + 1], pts[(j * 4) + 2], pts[(j * 4) + 3], (uint8_t *)publickeyhashrmd160_endomorphism[6][0], (uint8_t *)publickeyhashrmd160_endomorphism[6][1], (uint8_t *)publickeyhashrmd160_endomorphism[6][2], (uint8_t *)publickeyhashrmd160_endomorphism[6][3]);
                                    secp->GetHash160(P2PKH, false, endomorphism_negeted_point[0], endomorphism_negeted_point[1], endomorphism_negeted_point[2], endomorphism_negeted_point[3], (uint8_t *)publickeyhashrmd160_endomorphism[7][0], (uint8_t *)publickeyhashrmd160_endomorphism[7][1], (uint8_t *)publickeyhashrmd160_endomorphism[7][2], (uint8_t *)publickeyhashrmd160_endomorphism[7][3]);
                                    for (l = 0; l < 4; l++)
                                    {
                                        endomorphism_negeted_point[l] = secp->Negation(endomorphism_beta[(j * 4) + l]);
                                    }
                                    secp->GetHash160(P2PKH, false, endomorphism_beta[(j * 4)], endomorphism_beta[(j * 4) + 1], endomorphism_beta[(j * 4) + 2], endomorphism_beta[(j * 4) + 3], (uint8_t *)publickeyhashrmd160_endomorphism[8][0], (uint8_t *)publickeyhashrmd160_endomorphism[8][1], (uint8_t *)publickeyhashrmd160_endomorphism[8][2], (uint8_t *)publickeyhashrmd160_endomorphism[8][3]);
                                    secp->GetHash160(P2PKH, false, endomorphism_negeted_point[0], endomorphism_negeted_point[1], endomorphism_negeted_point[2], endomorphism_negeted_point[3], (uint8_t *)publickeyhashrmd160_endomorphism[9][0], (uint8_t *)publickeyhashrmd160_endomorphism[9][1], (uint8_t *)publickeyhashrmd160_endomorphism[9][2], (uint8_t *)publickeyhashrmd160_endomorphism[9][3]);

                                    for (l = 0; l < 4; l++)
                                    {
                                        endomorphism_negeted_point[l] = secp->Negation(endomorphism_beta2[(j * 4) + l]);
                                    }
                                    secp->GetHash160(P2PKH, false, endomorphism_beta2[(j * 4)], endomorphism_beta2[(j * 4) + 1], endomorphism_beta2[(j * 4) + 2], endomorphism_beta2[(j * 4) + 3], (uint8_t *)publickeyhashrmd160_endomorphism[10][0], (uint8_t *)publickeyhashrmd160_endomorphism[10][1], (uint8_t *)publickeyhashrmd160_endomorphism[10][2], (uint8_t *)publickeyhashrmd160_endomorphism[10][3]);
                                    secp->GetHash160(P2PKH, false, endomorphism_negeted_point[0], endomorphism_negeted_point[1], endomorphism_negeted_point[2], endomorphism_negeted_point[3], (uint8_t *)publickeyhashrmd160_endomorphism[11][0], (uint8_t *)publickeyhashrmd160_endomorphism[11][1], (uint8_t *)publickeyhashrmd160_endomorphism[11][2], (uint8_t *)publickeyhashrmd160_endomorphism[11][3]);
                                }
                                else
                                {
                                    secp->GetHash160(P2PKH, false, pts[(j * 4)], pts[(j * 4) + 1], pts[(j * 4) + 2], pts[(j * 4) + 3], (uint8_t *)publickeyhashrmd160_uncompress[0], (uint8_t *)publickeyhashrmd160_uncompress[1], (uint8_t *)publickeyhashrmd160_uncompress[2], (uint8_t *)publickeyhashrmd160_uncompress[3]);
                                }
                            }

                            // Check all the generated hashes for matches
                            for (k = 0; k < 4; k++)
                            {
                                if (FLAGSEARCH == SEARCH_COMPRESS || FLAGSEARCH == SEARCH_BOTH)
                                {
                                    if (FLAGENDOMORPHISM)
                                    {
                                        for (l = 0; l < 6; l++)
                                        {
                                            r = bloom_check(&bloom, publickeyhashrmd160_endomorphism[l][k], MAXLENGTHADDRESS);
                                            if (r)
                                            {
                                                r = searchbinary(addressTable, publickeyhashrmd160_endomorphism[l][k], N);
                                                if (r)
                                                {
                                                    keyfound.SetInt32(k);
                                                    keyfound.Mult(&stride);
                                                    keyfound.Add(&key_mpz);
                                                    publickey = secp->ComputePublicKey(&keyfound);
                                                    switch (l)
                                                    {
                                                    case 0: // Original point, prefix 02
                                                        if (publickey.y.IsOdd())
                                                        {
                                                            keyfound.Neg();
                                                            keyfound.Add(&secp->order);
                                                        }
                                                        break;
                                                    case 1: // Original point, prefix 03
                                                        if (publickey.y.IsEven())
                                                        {
                                                            keyfound.Neg();
                                                            keyfound.Add(&secp->order);
                                                        }
                                                        break;
                                                    case 2: // Beta point, prefix 02
                                                        keyfound.ModMulK1order(&lambda);
                                                        if (publickey.y.IsOdd())
                                                        {
                                                            keyfound.Neg();
                                                            keyfound.Add(&secp->order);
                                                        }
                                                        break;
                                                    case 3: // Beta point, prefix 03
                                                        keyfound.ModMulK1order(&lambda);
                                                        if (publickey.y.IsEven())
                                                        {
                                                            keyfound.Neg();
                                                            keyfound.Add(&secp->order);
                                                        }
                                                        break;
                                                    case 4: // Beta^2 point, prefix 02
                                                        keyfound.ModMulK1order(&lambda2);
                                                        if (publickey.y.IsOdd())
                                                        {
                                                            keyfound.Neg();
                                                            keyfound.Add(&secp->order);
                                                        }
                                                        break;
                                                    case 5: // Beta^2 point, prefix 03
                                                        keyfound.ModMulK1order(&lambda2);
                                                        if (publickey.y.IsEven())
                                                        {
                                                            keyfound.Neg();
                                                            keyfound.Add(&secp->order);
                                                        }
                                                        break;
                                                    }
                                                    writekey(true, &keyfound);
                                                }
                                            }
                                        }
                                    }
                                    else
                                    {
                                        for (l = 0; l < 2; l++)
                                        {
                                            r = bloom_check(&bloom, publickeyhashrmd160_endomorphism[l][k], MAXLENGTHADDRESS);
                                            if (r)
                                            {
                                                r = searchbinary(addressTable, publickeyhashrmd160_endomorphism[l][k], N);
                                                if (r)
                                                {
                                                    keyfound.SetInt32(k);
                                                    keyfound.Mult(&stride);
                                                    keyfound.Add(&key_mpz);

                                                    publickey = secp->ComputePublicKey(&keyfound);
                                                    secp->GetHash160(P2PKH, true, publickey, (uint8_t *)publickeyhashrmd160);
                                                    if (memcmp(publickeyhashrmd160_endomorphism[l][k], publickeyhashrmd160, 20) != 0)
                                                    {
                                                        keyfound.Neg();
                                                        keyfound.Add(&secp->order);
                                                    }
                                                    writekey(true, &keyfound);
                                                }
                                            }
                                        }
                                    }
                                }

                                if (FLAGSEARCH == SEARCH_UNCOMPRESS || FLAGSEARCH == SEARCH_BOTH)
                                {
                                    if (FLAGENDOMORPHISM)
                                    {
                                        for (l = 6; l < 12; l++)
                                        {
                                            r = bloom_check(&bloom, publickeyhashrmd160_endomorphism[l][k], MAXLENGTHADDRESS);
                                            if (r)
                                            {
                                                r = searchbinary(addressTable, publickeyhashrmd160_endomorphism[l][k], N);
                                                if (r)
                                                {
                                                    keyfound.SetInt32(k);
                                                    keyfound.Mult(&stride);
                                                    keyfound.Add(&key_mpz);
                                                    switch (l)
                                                    {
                                                    case 6:
                                                    case 7:
                                                        publickey = secp->ComputePublicKey(&keyfound);
                                                        secp->GetHash160(P2PKH, false, publickey, (uint8_t *)publickeyhashrmd160_uncompress[0]);
                                                        if (memcmp(publickeyhashrmd160_endomorphism[l][k], publickeyhashrmd160_uncompress[0], 20) != 0)
                                                        {
                                                            keyfound.Neg();
                                                            keyfound.Add(&secp->order);
                                                        }
                                                        break;
                                                    case 8:
                                                    case 9:
                                                        keyfound.ModMulK1order(&lambda);
                                                        publickey = secp->ComputePublicKey(&keyfound);
                                                        secp->GetHash160(P2PKH, false, publickey, (uint8_t *)publickeyhashrmd160_uncompress[0]);
                                                        if (memcmp(publickeyhashrmd160_endomorphism[l][k], publickeyhashrmd160_uncompress[0], 20) != 0)
                                                        {
                                                            keyfound.Neg();
                                                            keyfound.Add(&secp->order);
                                                        }
                                                        break;
                                                    case 10:
                                                    case 11:
                                                        keyfound.ModMulK1order(&lambda2);
                                                        publickey = secp->ComputePublicKey(&keyfound);
                                                        secp->GetHash160(P2PKH, false, publickey, (uint8_t *)publickeyhashrmd160_uncompress[0]);
                                                        if (memcmp(publickeyhashrmd160_endomorphism[l][k], publickeyhashrmd160_uncompress[0], 20) != 0)
                                                        {
                                                            keyfound.Neg();
                                                            keyfound.Add(&secp->order);
                                                        }
                                                        break;
                                                    }
                                                    writekey(false, &keyfound);
                                                }
                                            }
                                        }
                                    }
                                    else
                                    {
                                        r = bloom_check(&bloom, publickeyhashrmd160_uncompress[k], MAXLENGTHADDRESS);
                                        if (r)
                                        {
                                            r = searchbinary(addressTable, publickeyhashrmd160_uncompress[k], N);
                                            if (r)
                                            {
                                                keyfound.SetInt32(k);
                                                keyfound.Mult(&stride);
                                                keyfound.Add(&key_mpz);
                                                writekey(false, &keyfound);
                                            }
                                        }
                                    }
                                }
                            }

                            // Save compressed public keys using the new buffering system if FLAGPRINTPUBKEYS is set
                            if (FLAGPRINTPUBKEYS && thread_buffers != NULL)
                            {
                                for (k = 0; k < 4; k++)
                                {
                                    Int privateKey;
                                    privateKey.SetInt32(k);
                                    privateKey.Mult(&stride);
                                    privateKey.Add(&key_mpz);

                                    Point publicKey = secp->ComputePublicKey(&privateKey);

                                    // Create 33-byte binary public key
                                    unsigned char binPubKey[33];
                                    binPubKey[0] = publicKey.y.IsEven() ? 0x02 : 0x03;
                                    publicKey.x.Get32Bytes(binPubKey + 1);

                                    // Add to thread's buffer
                                    add_pubkey_to_buffer(binPubKey, thread_number);
                                }
                            }
                        }
                        else if (FLAGCRYPTO == CRYPTO_ETH)
                        {
                            if (FLAGENDOMORPHISM)
                            {
                                for (k = 0; k < 4; k++)
                                {
                                    endomorphism_negeted_point[k] = secp->Negation(pts[(j * 4) + k]);
                                    generate_binaddress_eth(pts[(4 * j) + k], (uint8_t *)publickeyhashrmd160_endomorphism[0][k]);
                                    generate_binaddress_eth(endomorphism_negeted_point[k], (uint8_t *)publickeyhashrmd160_endomorphism[1][k]);
                                    endomorphism_negeted_point[k] = secp->Negation(endomorphism_beta[(j * 4) + k]);
                                    generate_binaddress_eth(endomorphism_beta[(4 * j) + k], (uint8_t *)publickeyhashrmd160_endomorphism[2][k]);
                                    generate_binaddress_eth(endomorphism_negeted_point[k], (uint8_t *)publickeyhashrmd160_endomorphism[3][k]);
                                    endomorphism_negeted_point[k] = secp->Negation(endomorphism_beta2[(j * 4) + k]);
                                    generate_binaddress_eth(endomorphism_beta[(4 * j) + k], (uint8_t *)publickeyhashrmd160_endomorphism[4][k]);
                                    generate_binaddress_eth(endomorphism_negeted_point[k], (uint8_t *)publickeyhashrmd160_endomorphism[5][k]);
                                }
                            }
                            else
                            {
                                for (k = 0; k < 4; k++)
                                {
                                    generate_binaddress_eth(pts[(4 * j) + k], (uint8_t *)publickeyhashrmd160_uncompress[k]);
                                }
                            }

                            if (FLAGENDOMORPHISM)
                            {
                                for (k = 0; k < 4; k++)
                                {
                                    for (l = 0; l < 6; l++)
                                    {
                                        r = bloom_check(&bloom, publickeyhashrmd160_endomorphism[l][k], MAXLENGTHADDRESS);
                                        if (r)
                                        {
                                            r = searchbinary(addressTable, publickeyhashrmd160_endomorphism[l][k], N);
                                            if (r)
                                            {
                                                keyfound.SetInt32(k);
                                                keyfound.Mult(&stride);
                                                keyfound.Add(&key_mpz);
                                                switch (l)
                                                {
                                                case 0:
                                                case 1:
                                                    publickey = secp->ComputePublicKey(&keyfound);
                                                    generate_binaddress_eth(publickey, (uint8_t *)publickeyhashrmd160_uncompress[0]);
                                                    if (memcmp(publickeyhashrmd160_endomorphism[l][k], publickeyhashrmd160_uncompress[0], 20) != 0)
                                                    {
                                                        keyfound.Neg();
                                                        keyfound.Add(&secp->order);
                                                    }
                                                    break;
                                                case 2:
                                                case 3:
                                                    keyfound.ModMulK1order(&lambda);
                                                    publickey = secp->ComputePublicKey(&keyfound);
                                                    generate_binaddress_eth(publickey, (uint8_t *)publickeyhashrmd160_uncompress[0]);
                                                    if (memcmp(publickeyhashrmd160_endomorphism[l][k], publickeyhashrmd160_uncompress[0], 20) != 0)
                                                    {
                                                        keyfound.Neg();
                                                        keyfound.Add(&secp->order);
                                                    }
                                                    break;
                                                case 4:
                                                case 5:
                                                    keyfound.ModMulK1order(&lambda2);
                                                    publickey = secp->ComputePublicKey(&keyfound);
                                                    generate_binaddress_eth(publickey, (uint8_t *)publickeyhashrmd160_uncompress[0]);
                                                    if (memcmp(publickeyhashrmd160_endomorphism[l][k], publickeyhashrmd160_uncompress[0], 20) != 0)
                                                    {
                                                        keyfound.Neg();
                                                        keyfound.Add(&secp->order);
                                                    }
                                                    break;
                                                }
                                                writekeyeth(&keyfound);
                                            }
                                        }
                                    }
                                }
                            }
                            else
                            {
                                for (k = 0; k < 4; k++)
                                {
                                    r = bloom_check(&bloom, publickeyhashrmd160_uncompress[k], MAXLENGTHADDRESS);
                                    if (r)
                                    {
                                        r = searchbinary(addressTable, publickeyhashrmd160_uncompress[k], N);
                                        if (r)
                                        {
                                            keyfound.SetInt32(k);
                                            keyfound.Mult(&stride);
                                            keyfound.Add(&key_mpz);
                                            writekeyeth(&keyfound);
                                        }
                                    }
                                }
                            }

                            // Save public keys if FLAGPRINTPUBKEYS is set - using buffering system
                            if (FLAGPRINTPUBKEYS && thread_buffers != NULL)
                            {
                                for (k = 0; k < 4; k++)
                                {
                                    Int privateKey;
                                    privateKey.SetInt32(k);
                                    privateKey.Mult(&stride);
                                    privateKey.Add(&key_mpz);

                                    Point publicKey = secp->ComputePublicKey(&privateKey);

                                    // Create 33-byte binary public key
                                    unsigned char binPubKey[33];
                                    binPubKey[0] = publicKey.y.IsEven() ? 0x02 : 0x03;
                                    publicKey.x.Get32Bytes(binPubKey + 1);

                                    // Add to thread's buffer
                                    add_pubkey_to_buffer(binPubKey, thread_number);
                                }
                            }
                        }
                        break;
                    case MODE_XPOINT:
    for (k = 0; k < 4; k++)
    {
        if (FLAGENDOMORPHISM)
        {
            pts[(4 * j) + k].x.Get32Bytes((unsigned char *)rawvalue);
            r = bloom_check(&bloom, rawvalue, 32);
            if (r)
            {
                // For bloom-only mode (N == 0), skip binary search
                if (N == 0) {
                    // Bloom filter match in bloom-only mode
                    if (FLAGDEBUG) {
                        printf("\n[D] Bloom filter match (bloom-only mode) for X coordinate\n");
                    }
                    keyfound.SetInt32(k);
                    keyfound.Mult(&stride);
                    keyfound.Add(&key_mpz);
                    writekey(false, &keyfound);
                } else {
                    // Normal mode with addressTable
                    r = searchbinary(addressTable, rawvalue, N);
                    if (r)
                    {
                        keyfound.SetInt32(k);
                        keyfound.Mult(&stride);
                        keyfound.Add(&key_mpz);
                        writekey(false, &keyfound);
                    }
                }
            }
            
            endomorphism_beta[(j * 4) + k].x.Get32Bytes((unsigned char *)rawvalue);
            r = bloom_check(&bloom, rawvalue, 32);
            if (r)
            {
                // For bloom-only mode (N == 0), skip binary search
                if (N == 0) {
                    keyfound.SetInt32(k);
                    keyfound.Mult(&stride);
                    keyfound.Add(&key_mpz);
                    keyfound.ModMulK1order(&lambda);
                    writekey(false, &keyfound);
                } else {
                    r = searchbinary(addressTable, rawvalue, N);
                    if (r)
                    {
                        keyfound.SetInt32(k);
                        keyfound.Mult(&stride);
                        keyfound.Add(&key_mpz);
                        keyfound.ModMulK1order(&lambda);
                        writekey(false, &keyfound);
                    }
                }
            }

            endomorphism_beta2[(j * 4) + k].x.Get32Bytes((unsigned char *)rawvalue);
            r = bloom_check(&bloom, rawvalue, 32);
            if (r)
            {
                // For bloom-only mode (N == 0), skip binary search
                if (N == 0) {
                    keyfound.SetInt32(k);
                    keyfound.Mult(&stride);
                    keyfound.Add(&key_mpz);
                    keyfound.ModMulK1order(&lambda2);
                    writekey(false, &keyfound);
                } else {
                    r = searchbinary(addressTable, rawvalue, N);
                    if (r)
                    {
                        keyfound.SetInt32(k);
                        keyfound.Mult(&stride);
                        keyfound.Add(&key_mpz);
                        keyfound.ModMulK1order(&lambda2);
                        writekey(false, &keyfound);
                    }
                }
            }
        }
        else
        {
            pts[(4 * j) + k].x.Get32Bytes((unsigned char *)rawvalue);
            r = bloom_check(&bloom, rawvalue, 32);
            if (r)
            {
                // For bloom-only mode (N == 0), skip binary search
                if (N == 0) {
                    // Bloom filter match in bloom-only mode
                    if (FLAGDEBUG) {
                        printf("\n[D] Bloom filter match (bloom-only mode) for X coordinate\n");
                    }
                    keyfound.SetInt32(k);
                    keyfound.Mult(&stride);
                    keyfound.Add(&key_mpz);
                    writekey(false, &keyfound);
                } else {
                    // Normal mode with addressTable
                    r = searchbinary(addressTable, rawvalue, N);
                    if (r)
                    {
                        keyfound.SetInt32(k);
                        keyfound.Mult(&stride);
                        keyfound.Add(&key_mpz);
                        writekey(false, &keyfound);
                    }
                }
            }
        }
    }
    break;
                    }
                    count += 4;
                    temp_stride.SetInt32(4);
                    temp_stride.Mult(&stride);
                    key_mpz.Add(&temp_stride);
                }

                steps[thread_number]++;

                // Next start point (startP + GRP_SIZE*G)
                pp = startP;
                dy.ModSub(&_2Gn.y, &pp.y);

                _s.ModMulK1(&dy, &dx[i + 1]);
                _p.ModSquareK1(&_s);

                pp.x.ModNeg();
                pp.x.ModAdd(&_p);
                pp.x.ModSub(&_2Gn.x);

                // The Y value for the next start point always need to be calculated
                pp.y.ModSub(&_2Gn.x, &pp.x);
                pp.y.ModMulK1(&_s);
                pp.y.ModSub(&_2Gn.y);
                startP = pp;
            } while (count < N_SEQUENTIAL_MAX && continue_flag);
        }
    } while (continue_flag);
    
    ends[thread_number] = 1;
    delete grp;
    return NULL;
}

#if defined(_WIN64) && !defined(__CYGWIN__)
DWORD WINAPI thread_process_vanity(LPVOID vargp)
{
#else
void *thread_process_vanity(void *vargp)
{
#endif
    struct tothread *tt;
    Point pts[CPU_GRP_SIZE];
    Point endomorphism_beta[CPU_GRP_SIZE];
    Point endomorphism_beta2[CPU_GRP_SIZE];
    Point endomorphism_negeted_point[4];

    Int dx[CPU_GRP_SIZE / 2 + 1];

    IntGroup *grp = new IntGroup(CPU_GRP_SIZE / 2 + 1);
    Point startP;
    Int dy;
    Int dyn;
    Int _s;
    Int _p;
    Point pp; // point positive
    Point pn; // point negative
    int l, pp_offset, pn_offset, i, hLength = (CPU_GRP_SIZE / 2 - 1);
    uint64_t j, count;
    Point R, temporal, publickey;
    int thread_number, continue_flag = 1, k;
    char *hextemp = NULL;
    char publickeyhashrmd160[20];
    char publickeyhashrmd160_uncompress[4][20];

    char publickeyhashrmd160_endomorphism[12][4][20];

    Int key_mpz, temp_stride, keyfound;
    tt = (struct tothread *)vargp;
    thread_number = tt->nt;
    free(tt);
    grp->Set(dx);

    // if FLAGENDOMORPHISM  == 1 and only compress search is enabled then there is no need to calculate the Y value value

    bool calculate_y = FLAGSEARCH == SEARCH_UNCOMPRESS || FLAGSEARCH == SEARCH_BOTH;

    /*
    if(FLAGDEBUG && thread_number == 0)	{
        printf("[D] vanity_rmd_targets = %i          fillllll\n",vanity_rmd_targets);
        printf("[D] vanity_rmd_total = %i\n",vanity_rmd_total);
        for(i =0; i < vanity_rmd_targets;i++)	{
            printf("[D] vanity_rmd_limits[%li] = %i\n",i,vanity_rmd_limits[i]);

        }
        printf("[D] vanity_rmd_minimun_bytes_check_length = %i\n",vanity_rmd_minimun_bytes_check_length);
    }
    */

    do
    {
        if (FLAGRANDOM)
        {
            key_mpz.Rand(&n_range_start, &n_range_end);
        }
        else
        {
            if (n_range_start.IsLower(&n_range_end))
            {
#if defined(_WIN64) && !defined(__CYGWIN__)
                WaitForSingleObject(write_random, INFINITE);
                key_mpz.Set(&n_range_start);
                n_range_start.Add(N_SEQUENTIAL_MAX);
                ReleaseMutex(write_random);
#else
                pthread_mutex_lock(&write_random);
                key_mpz.Set(&n_range_start);
                n_range_start.Add(N_SEQUENTIAL_MAX);
                pthread_mutex_unlock(&write_random);
#endif
            }
            else
            {
                continue_flag = 0;
            }
        }
        if (continue_flag)
        {
            count = 0;
            if (FLAGMATRIX)
            {
                hextemp = key_mpz.GetBase16();
                printf("Base key: %s thread %i\n", hextemp, thread_number);
                fflush(stdout);
                free(hextemp);
            }
            else
            {
                if (FLAGQUIET == 0)
                {
                    hextemp = key_mpz.GetBase16();
                    printf("\rBase key: %s     \r", hextemp);
                    fflush(stdout);
                    free(hextemp);
                    THREADOUTPUT = 1;
                }
            }
            do
            {
                temp_stride.SetInt32(CPU_GRP_SIZE / 2);
                temp_stride.Mult(&stride);
                key_mpz.Add(&temp_stride);
                startP = secp->ComputePublicKey(&key_mpz);
                key_mpz.Sub(&temp_stride);

                for (i = 0; i < hLength; i++)
                {
                    dx[i].ModSub(&Gn[i].x, &startP.x);
                }

                dx[i].ModSub(&Gn[i].x, &startP.x);    // For the first point
                dx[i + 1].ModSub(&_2Gn.x, &startP.x); // For the next center point
                grp->ModInv();

                pts[CPU_GRP_SIZE / 2] = startP;

                for (i = 0; i < hLength; i++)
                {
                    pp = startP;
                    pn = startP;

                    // P = startP + i*G
                    dy.ModSub(&Gn[i].y, &pp.y);

                    _s.ModMulK1(&dy, &dx[i]); // s = (p2.y-p1.y)*inverse(p2.x-p1.x);
                    _p.ModSquareK1(&_s);      // _p = pow2(s)

                    pp.x.ModNeg();
                    pp.x.ModAdd(&_p);
                    pp.x.ModSub(&Gn[i].x); // rx = pow2(s) - p1.x - p2.x;

                    if (calculate_y)
                    {
                        pp.y.ModSub(&Gn[i].x, &pp.x);
                        pp.y.ModMulK1(&_s);
                        pp.y.ModSub(&Gn[i].y); // ry = - p2.y - s*(ret.x-p2.x);
                    }

                    // P = startP - i*G  , if (x,y) = i*G then (x,-y) = -i*G
                    dyn.Set(&Gn[i].y);
                    dyn.ModNeg();
                    dyn.ModSub(&pn.y);

                    _s.ModMulK1(&dyn, &dx[i]); // s = (p2.y-p1.y)*inverse(p2.x-p1.x);
                    _p.ModSquareK1(&_s);       // _p = pow2(s)
                    pn.x.ModNeg();
                    pn.x.ModAdd(&_p);
                    pn.x.ModSub(&Gn[i].x); // rx = pow2(s) - p1.x - p2.x;

                    if (calculate_y)
                    {
                        pn.y.ModSub(&Gn[i].x, &pn.x);
                        pn.y.ModMulK1(&_s);
                        pn.y.ModAdd(&Gn[i].y); // ry = - p2.y - s*(ret.x-p2.x);
                    }
                    pp_offset = CPU_GRP_SIZE / 2 + (i + 1);
                    pn_offset = CPU_GRP_SIZE / 2 - (i + 1);

                    pts[pp_offset] = pp;
                    pts[pn_offset] = pn;

                    if (FLAGENDOMORPHISM)
                    {
                        /*
                            Q = (x,y)
                            For any point Q
                            Q*lambda = (x*beta mod p ,y)
                            Q*lambda is a Scalar Multiplication
                            x*beta is just a Multiplication (Very fast)
                        */

                        if (calculate_y)
                        {
                            endomorphism_beta[pp_offset].y.Set(&pp.y);
                            endomorphism_beta[pn_offset].y.Set(&pn.y);
                            endomorphism_beta2[pp_offset].y.Set(&pp.y);
                            endomorphism_beta2[pn_offset].y.Set(&pn.y);
                        }
                        endomorphism_beta[pp_offset].x.ModMulK1(&pp.x, &beta);
                        endomorphism_beta[pn_offset].x.ModMulK1(&pn.x, &beta);
                        endomorphism_beta2[pp_offset].x.ModMulK1(&pp.x, &beta2);
                        endomorphism_beta2[pn_offset].x.ModMulK1(&pn.x, &beta2);
                    }
                }
                /*
                    Half point for endomorphism because pts[CPU_GRP_SIZE / 2] was not calcualte in the previous cycle
                */
                if (FLAGENDOMORPHISM)
                {
                    if (calculate_y)
                    {

                        endomorphism_beta[CPU_GRP_SIZE / 2].y.Set(&pts[CPU_GRP_SIZE / 2].y);
                        endomorphism_beta2[CPU_GRP_SIZE / 2].y.Set(&pts[CPU_GRP_SIZE / 2].y);
                    }
                    endomorphism_beta[CPU_GRP_SIZE / 2].x.ModMulK1(&pts[CPU_GRP_SIZE / 2].x, &beta);
                    endomorphism_beta2[CPU_GRP_SIZE / 2].x.ModMulK1(&pts[CPU_GRP_SIZE / 2].x, &beta2);
                }

                // First point (startP - (GRP_SZIE/2)*G)
                pn = startP;
                dyn.Set(&Gn[i].y);
                dyn.ModNeg();
                dyn.ModSub(&pn.y);

                _s.ModMulK1(&dyn, &dx[i]);
                _p.ModSquareK1(&_s);

                pn.x.ModNeg();
                pn.x.ModAdd(&_p);
                pn.x.ModSub(&Gn[i].x);

                if (calculate_y)
                {
                    pn.y.ModSub(&Gn[i].x, &pn.x);
                    pn.y.ModMulK1(&_s);
                    pn.y.ModAdd(&Gn[i].y);
                }
                pts[0] = pn;

                /*
                    First point for endomorphism because pts[0] was not calcualte previously
                */
                if (FLAGENDOMORPHISM)
                {
                    if (calculate_y)
                    {
                        endomorphism_beta[0].y.Set(&pn.y);
                        endomorphism_beta2[0].y.Set(&pn.y);
                    }
                    endomorphism_beta[0].x.ModMulK1(&pn.x, &beta);
                    endomorphism_beta2[0].x.ModMulK1(&pn.x, &beta2);
                }

                for (j = 0; j < CPU_GRP_SIZE / 4; j++)
                {
                    if (FLAGSEARCH == SEARCH_COMPRESS || FLAGSEARCH == SEARCH_BOTH)
                    {
                        if (FLAGENDOMORPHISM)
                        {
                            secp->GetHash160_fromX(P2PKH, 0x02, &pts[(j * 4)].x, &pts[(j * 4) + 1].x, &pts[(j * 4) + 2].x, &pts[(j * 4) + 3].x, (uint8_t *)publickeyhashrmd160_endomorphism[0][0], (uint8_t *)publickeyhashrmd160_endomorphism[0][1], (uint8_t *)publickeyhashrmd160_endomorphism[0][2], (uint8_t *)publickeyhashrmd160_endomorphism[0][3]);
                            secp->GetHash160_fromX(P2PKH, 0x03, &pts[(j * 4)].x, &pts[(j * 4) + 1].x, &pts[(j * 4) + 2].x, &pts[(j * 4) + 3].x, (uint8_t *)publickeyhashrmd160_endomorphism[1][0], (uint8_t *)publickeyhashrmd160_endomorphism[1][1], (uint8_t *)publickeyhashrmd160_endomorphism[1][2], (uint8_t *)publickeyhashrmd160_endomorphism[1][3]);

                            secp->GetHash160_fromX(P2PKH, 0x02, &endomorphism_beta[(j * 4)].x, &endomorphism_beta[(j * 4) + 1].x, &endomorphism_beta[(j * 4) + 2].x, &endomorphism_beta[(j * 4) + 3].x, (uint8_t *)publickeyhashrmd160_endomorphism[2][0], (uint8_t *)publickeyhashrmd160_endomorphism[2][1], (uint8_t *)publickeyhashrmd160_endomorphism[2][2], (uint8_t *)publickeyhashrmd160_endomorphism[2][3]);
                            secp->GetHash160_fromX(P2PKH, 0x03, &endomorphism_beta[(j * 4)].x, &endomorphism_beta[(j * 4) + 1].x, &endomorphism_beta[(j * 4) + 2].x, &endomorphism_beta[(j * 4) + 3].x, (uint8_t *)publickeyhashrmd160_endomorphism[3][0], (uint8_t *)publickeyhashrmd160_endomorphism[3][1], (uint8_t *)publickeyhashrmd160_endomorphism[3][2], (uint8_t *)publickeyhashrmd160_endomorphism[3][3]);

                            secp->GetHash160_fromX(P2PKH, 0x02, &endomorphism_beta2[(j * 4)].x, &endomorphism_beta2[(j * 4) + 1].x, &endomorphism_beta2[(j * 4) + 2].x, &endomorphism_beta2[(j * 4) + 3].x, (uint8_t *)publickeyhashrmd160_endomorphism[4][0], (uint8_t *)publickeyhashrmd160_endomorphism[4][1], (uint8_t *)publickeyhashrmd160_endomorphism[4][2], (uint8_t *)publickeyhashrmd160_endomorphism[4][3]);
                            secp->GetHash160_fromX(P2PKH, 0x03, &endomorphism_beta2[(j * 4)].x, &endomorphism_beta2[(j * 4) + 1].x, &endomorphism_beta2[(j * 4) + 2].x, &endomorphism_beta2[(j * 4) + 3].x, (uint8_t *)publickeyhashrmd160_endomorphism[5][0], (uint8_t *)publickeyhashrmd160_endomorphism[5][1], (uint8_t *)publickeyhashrmd160_endomorphism[5][2], (uint8_t *)publickeyhashrmd160_endomorphism[5][3]);
                        }
                        else
                        {
                            secp->GetHash160_fromX(P2PKH, 0x02, &pts[(j * 4)].x, &pts[(j * 4) + 1].x, &pts[(j * 4) + 2].x, &pts[(j * 4) + 3].x, (uint8_t *)publickeyhashrmd160_endomorphism[0][0], (uint8_t *)publickeyhashrmd160_endomorphism[0][1], (uint8_t *)publickeyhashrmd160_endomorphism[0][2], (uint8_t *)publickeyhashrmd160_endomorphism[0][3]);
                            secp->GetHash160_fromX(P2PKH, 0x03, &pts[(j * 4)].x, &pts[(j * 4) + 1].x, &pts[(j * 4) + 2].x, &pts[(j * 4) + 3].x, (uint8_t *)publickeyhashrmd160_endomorphism[1][0], (uint8_t *)publickeyhashrmd160_endomorphism[1][1], (uint8_t *)publickeyhashrmd160_endomorphism[1][2], (uint8_t *)publickeyhashrmd160_endomorphism[1][3]);
                        }
                    }
                    if (FLAGSEARCH == SEARCH_UNCOMPRESS || FLAGSEARCH == SEARCH_BOTH)
                    {
                        if (FLAGENDOMORPHISM)
                        {
                            for (l = 0; l < 4; l++)
                            {
                                endomorphism_negeted_point[l] = secp->Negation(pts[(j * 4) + l]);
                            }
                            secp->GetHash160(P2PKH, false, pts[(j * 4)], pts[(j * 4) + 1], pts[(j * 4) + 2], pts[(j * 4) + 3], (uint8_t *)publickeyhashrmd160_endomorphism[6][0], (uint8_t *)publickeyhashrmd160_endomorphism[6][1], (uint8_t *)publickeyhashrmd160_endomorphism[6][2], (uint8_t *)publickeyhashrmd160_endomorphism[6][3]);
                            secp->GetHash160(P2PKH, false, endomorphism_negeted_point[0], endomorphism_negeted_point[1], endomorphism_negeted_point[2], endomorphism_negeted_point[3], (uint8_t *)publickeyhashrmd160_endomorphism[7][0], (uint8_t *)publickeyhashrmd160_endomorphism[7][1], (uint8_t *)publickeyhashrmd160_endomorphism[7][2], (uint8_t *)publickeyhashrmd160_endomorphism[7][3]);
                            for (l = 0; l < 4; l++)
                            {
                                endomorphism_negeted_point[l] = secp->Negation(endomorphism_beta[(j * 4) + l]);
                            }
                            secp->GetHash160(P2PKH, false, endomorphism_beta[(j * 4)], endomorphism_beta[(j * 4) + 1], endomorphism_beta[(j * 4) + 2], endomorphism_beta[(j * 4) + 3], (uint8_t *)publickeyhashrmd160_endomorphism[8][0], (uint8_t *)publickeyhashrmd160_endomorphism[8][1], (uint8_t *)publickeyhashrmd160_endomorphism[8][2], (uint8_t *)publickeyhashrmd160_endomorphism[8][3]);
                            secp->GetHash160(P2PKH, false, endomorphism_negeted_point[0], endomorphism_negeted_point[1], endomorphism_negeted_point[2], endomorphism_negeted_point[3], (uint8_t *)publickeyhashrmd160_endomorphism[9][0], (uint8_t *)publickeyhashrmd160_endomorphism[9][1], (uint8_t *)publickeyhashrmd160_endomorphism[9][2], (uint8_t *)publickeyhashrmd160_endomorphism[9][3]);

                            for (l = 0; l < 4; l++)
                            {
                                endomorphism_negeted_point[l] = secp->Negation(endomorphism_beta2[(j * 4) + l]);
                            }
                            secp->GetHash160(P2PKH, false, endomorphism_beta2[(j * 4)], endomorphism_beta2[(j * 4) + 1], endomorphism_beta2[(j * 4) + 2], endomorphism_beta2[(j * 4) + 3], (uint8_t *)publickeyhashrmd160_endomorphism[10][0], (uint8_t *)publickeyhashrmd160_endomorphism[10][1], (uint8_t *)publickeyhashrmd160_endomorphism[10][2], (uint8_t *)publickeyhashrmd160_endomorphism[10][3]);
                            secp->GetHash160(P2PKH, false, endomorphism_negeted_point[0], endomorphism_negeted_point[1], endomorphism_negeted_point[2], endomorphism_negeted_point[3], (uint8_t *)publickeyhashrmd160_endomorphism[11][0], (uint8_t *)publickeyhashrmd160_endomorphism[11][1], (uint8_t *)publickeyhashrmd160_endomorphism[11][2], (uint8_t *)publickeyhashrmd160_endomorphism[11][3]);
                        }
                        else
                        {
                            secp->GetHash160(P2PKH, false, pts[(j * 4)], pts[(j * 4) + 1], pts[(j * 4) + 2], pts[(j * 4) + 3], (uint8_t *)publickeyhashrmd160_uncompress[0], (uint8_t *)publickeyhashrmd160_uncompress[1], (uint8_t *)publickeyhashrmd160_uncompress[2], (uint8_t *)publickeyhashrmd160_uncompress[3]);
                        }
                    }
                    for (k = 0; k < 4; k++)
                    {
                        if (FLAGSEARCH == SEARCH_COMPRESS || FLAGSEARCH == SEARCH_BOTH)
                        {
                            if (FLAGENDOMORPHISM)
                            {
                                for (l = 0; l < 6; l++)
                                {
                                    if (vanityrmdmatch((uint8_t *)publickeyhashrmd160_endomorphism[l][k]))
                                    {
                                        // Here the given publickeyhashrmd160 match againts one of the vanity targets
                                        // We need to check which of the cases is it.

                                        keyfound.SetInt32(k);
                                        keyfound.Mult(&stride);
                                        keyfound.Add(&key_mpz);
                                        publickey = secp->ComputePublicKey(&keyfound);

                                        switch (l)
                                        {
                                        case 0: // Original point, prefix 02
                                            if (publickey.y.IsOdd())
                                            { // if the current publickey is odd that means, we need to negate the keyfound to get the correct key
                                                keyfound.Neg();
                                                keyfound.Add(&secp->order);
                                            }
                                            // else we dont need to chage the current keyfound because it already have prefix 02
                                            break;
                                        case 1: // Original point, prefix 03
                                            if (publickey.y.IsEven())
                                            { // if the current publickey is even that means, we need to negate the keyfound to get the correct key
                                                keyfound.Neg();
                                                keyfound.Add(&secp->order);
                                            }
                                            // else we dont need to chage the current keyfound because it already have prefix 03
                                            break;
                                        case 2: // Beta point, prefix 02
                                            keyfound.ModMulK1order(&lambda);
                                            if (publickey.y.IsOdd())
                                            { // if the current publickey is odd that means, we need to negate the keyfound to get the correct key
                                                keyfound.Neg();
                                                keyfound.Add(&secp->order);
                                            }
                                            // else we dont need to chage the current keyfound because it already have prefix 02
                                            break;
                                        case 3: // Beta point, prefix 03
                                            keyfound.ModMulK1order(&lambda);
                                            if (publickey.y.IsEven())
                                            { // if the current publickey is even that means, we need to negate the keyfound to get the correct key
                                                keyfound.Neg();
                                                keyfound.Add(&secp->order);
                                            }
                                            // else we dont need to chage the current keyfound because it already have prefix 02
                                            break;
                                        case 4: // Beta^2 point, prefix 02
                                            keyfound.ModMulK1order(&lambda2);
                                            if (publickey.y.IsOdd())
                                            { // if the current publickey is odd that means, we need to negate the keyfound to get the correct key
                                                keyfound.Neg();
                                                keyfound.Add(&secp->order);
                                            }
                                            // else we dont need to chage the current keyfound because it already have prefix 02
                                            break;
                                        case 5: // Beta^2 point, prefix 03
                                            keyfound.ModMulK1order(&lambda2);
                                            if (publickey.y.IsEven())
                                            { // if the current publickey is even that means, we need to negate the keyfound to get the correct key
                                                keyfound.Neg();
                                                keyfound.Add(&secp->order);
                                            }
                                            // else we dont need to chage the current keyfound because it already have prefix 02
                                            break;
                                        }
                                        writevanitykey(true, &keyfound);
                                    }
                                }
                            }
                            else
                            {
                                for (l = 0; l < 2; l++)
                                {
                                    if (vanityrmdmatch((uint8_t *)publickeyhashrmd160_endomorphism[l][k]))
                                    {
                                        keyfound.SetInt32(k);
                                        keyfound.Mult(&stride);
                                        keyfound.Add(&key_mpz);

                                        publickey = secp->ComputePublicKey(&keyfound);
                                        secp->GetHash160(P2PKH, true, publickey, (uint8_t *)publickeyhashrmd160);
                                        if (memcmp(publickeyhashrmd160_endomorphism[l][k], publickeyhashrmd160, 20) != 0)
                                        {
                                            keyfound.Neg();
                                            keyfound.Add(&secp->order);
                                            // if(FLAGDEBUG) printf("[D] Key need to be negated\n");
                                        }
                                        writevanitykey(true, &keyfound);
                                    }
                                }
                            }
                        }
                        if (FLAGSEARCH == SEARCH_UNCOMPRESS || FLAGSEARCH == SEARCH_BOTH)
                        {
                            if (FLAGENDOMORPHISM)
                            {
                                for (l = 6; l < 12; l++)
                                {
                                    if (vanityrmdmatch((uint8_t *)publickeyhashrmd160_endomorphism[l][k]))
                                    {
                                        // Here the given publickeyhashrmd160 match againts one of the vanity targets
                                        // We need to check which of the cases is it.

                                        // rmd160toaddress_dst(publickeyhashrmd160_endomorphism[l][k],address);
                                        keyfound.SetInt32(k);
                                        keyfound.Mult(&stride);
                                        keyfound.Add(&key_mpz);

                                        switch (l)
                                        {
                                        case 6:
                                        case 7:
                                            publickey = secp->ComputePublicKey(&keyfound);
                                            secp->GetHash160(P2PKH, false, publickey, (uint8_t *)publickeyhashrmd160_uncompress[0]);
                                            if (memcmp(publickeyhashrmd160_endomorphism[l][k], publickeyhashrmd160_uncompress[0], 20) != 0)
                                            {
                                                keyfound.Neg();
                                                keyfound.Add(&secp->order);
                                            }
                                            break;
                                        case 8:
                                        case 9:
                                            keyfound.ModMulK1order(&lambda);
                                            publickey = secp->ComputePublicKey(&keyfound);
                                            secp->GetHash160(P2PKH, false, publickey, (uint8_t *)publickeyhashrmd160_uncompress[0]);
                                            if (memcmp(publickeyhashrmd160_endomorphism[l][k], publickeyhashrmd160_uncompress[0], 20) != 0)
                                            {
                                                keyfound.Neg();
                                                keyfound.Add(&secp->order);
                                            }
                                            break;
                                        case 10:
                                        case 11:
                                            keyfound.ModMulK1order(&lambda2);
                                            publickey = secp->ComputePublicKey(&keyfound);
                                            secp->GetHash160(P2PKH, false, publickey, (uint8_t *)publickeyhashrmd160_uncompress[0]);
                                            if (memcmp(publickeyhashrmd160_endomorphism[l][k], publickeyhashrmd160_uncompress[0], 20) != 0)
                                            {
                                                keyfound.Neg();
                                                keyfound.Add(&secp->order);
                                            }
                                            break;
                                        }
                                        writevanitykey(false, &keyfound);
                                    }
                                }
                            }
                            else
                            {
                                if (vanityrmdmatch((uint8_t *)publickeyhashrmd160_uncompress[k]))
                                {
                                    keyfound.SetInt32(k);
                                    keyfound.Mult(&stride);
                                    keyfound.Add(&key_mpz);
                                    writevanitykey(false, &keyfound);
                                }
                            }
                        }
                    }

                    count += 4;
                    temp_stride.SetInt32(4);
                    temp_stride.Mult(&stride);
                    key_mpz.Add(&temp_stride);
                }
                steps[thread_number]++;

                // Next start point (startP + GRP_SIZE*G)
                pp = startP;
                dy.ModSub(&_2Gn.y, &pp.y);

                _s.ModMulK1(&dy, &dx[i + 1]);
                _p.ModSquareK1(&_s);

                pp.x.ModNeg();
                pp.x.ModAdd(&_p);
                pp.x.ModSub(&_2Gn.x);

                // The Y value for the next start point always need to be calculated
                pp.y.ModSub(&_2Gn.x, &pp.x);
                pp.y.ModMulK1(&_s);
                pp.y.ModSub(&_2Gn.y);
                startP = pp;
            } while (count < N_SEQUENTIAL_MAX && continue_flag);
        }
    } while (continue_flag);
    ends[thread_number] = 1;
    return NULL;
}

void _swap(struct address_value *a, struct address_value *b)
{
    struct address_value t;
    t = *a;
    *a = *b;
    *b = t;
}

void _sort(struct address_value *arr, int64_t n)
{
    uint32_t depthLimit = ((uint32_t)ceil(log(n))) * 2;
    _introsort(arr, depthLimit, n);
}

void _introsort(struct address_value *arr, uint32_t depthLimit, int64_t n)
{
    int64_t p;
    if (n > 1)
    {
        if (n <= 16)
        {
            _insertionsort(arr, n);
        }
        else
        {
            if (depthLimit == 0)
            {
                _myheapsort(arr, n);
            }
            else
            {
                p = _partition(arr, n);
                if (p > 0)
                    _introsort(arr, depthLimit - 1, p);
                if (p < n)
                    _introsort(&arr[p + 1], depthLimit - 1, n - (p + 1));
            }
        }
    }
}

void _insertionsort(struct address_value *arr, int64_t n)
{
    int64_t j;
    int64_t i;
    struct address_value key;
    for (i = 1; i < n; i++)
    {
        key = arr[i];
        j = i - 1;
        while (j >= 0 && memcmp(arr[j].value, key.value, 20) > 0)
        {
            arr[j + 1] = arr[j];
            j--;
        }
        arr[j + 1] = key;
    }
}

int64_t _partition(struct address_value *arr, int64_t n)
{
    struct address_value pivot;
    int64_t r, left, right;
    r = n / 2;
    pivot = arr[r];
    left = 0;
    right = n - 1;
    do
    {
        while (left < right && memcmp(arr[left].value, pivot.value, 20) <= 0)
        {
            left++;
        }
        while (right >= left && memcmp(arr[right].value, pivot.value, 20) > 0)
        {
            right--;
        }
        if (left < right)
        {
            if (left == r || right == r)
            {
                if (left == r)
                {
                    r = right;
                }
                if (right == r)
                {
                    r = left;
                }
            }
            _swap(&arr[right], &arr[left]);
        }
    } while (left < right);
    if (right != r)
    {
        _swap(&arr[right], &arr[r]);
    }
    return right;
}

void _heapify(struct address_value *arr, int64_t n, int64_t i)
{
    int64_t largest = i;
    int64_t l = 2 * i + 1;
    int64_t r = 2 * i + 2;
    if (l < n && memcmp(arr[l].value, arr[largest].value, 20) > 0)
        largest = l;
    if (r < n && memcmp(arr[r].value, arr[largest].value, 20) > 0)
        largest = r;
    if (largest != i)
    {
        _swap(&arr[i], &arr[largest]);
        _heapify(arr, n, largest);
    }
}

void _myheapsort(struct address_value *arr, int64_t n)
{
    int64_t i;
    for (i = (n / 2) - 1; i >= 0; i--)
    {
        _heapify(arr, n, i);
    }
    for (i = n - 1; i > 0; i--)
    {
        _swap(&arr[0], &arr[i]);
        _heapify(arr, i, 0);
    }
}

/*	OK	*/
void bsgs_swap(struct bsgs_xvalue *a, struct bsgs_xvalue *b)
{
    struct bsgs_xvalue t;
    t = *a;
    *a = *b;
    *b = t;
}

/*	OK	*/
void bsgs_sort(struct bsgs_xvalue *arr, int64_t n)
{
    uint32_t depthLimit = ((uint32_t)ceil(log(n))) * 2;
    bsgs_introsort(arr, depthLimit, n);
}

/*	OK	*/
void bsgs_introsort(struct bsgs_xvalue *arr, uint32_t depthLimit, int64_t n)
{
    int64_t p;
    if (n > 1)
    {
        if (n <= 16)
        {
            bsgs_insertionsort(arr, n);
        }
        else
        {
            if (depthLimit == 0)
            {
                bsgs_myheapsort(arr, n);
            }
            else
            {
                p = bsgs_partition(arr, n);
                if (p > 0)
                    bsgs_introsort(arr, depthLimit - 1, p);
                if (p < n)
                    bsgs_introsort(&arr[p + 1], depthLimit - 1, n - (p + 1));
            }
        }
    }
}

/*	OK	*/
void bsgs_insertionsort(struct bsgs_xvalue *arr, int64_t n)
{
    int64_t j;
    int64_t i;
    struct bsgs_xvalue key;
    for (i = 1; i < n; i++)
    {
        key = arr[i];
        j = i - 1;
        while (j >= 0 && memcmp(arr[j].value, key.value, BSGS_XVALUE_RAM) > 0)
        {
            arr[j + 1] = arr[j];
            j--;
        }
        arr[j + 1] = key;
    }
}

int64_t bsgs_partition(struct bsgs_xvalue *arr, int64_t n)
{
    struct bsgs_xvalue pivot;
    int64_t r, left, right;
    r = n / 2;
    pivot = arr[r];
    left = 0;
    right = n - 1;
    do
    {
        while (left < right && memcmp(arr[left].value, pivot.value, BSGS_XVALUE_RAM) <= 0)
        {
            left++;
        }
        while (right >= left && memcmp(arr[right].value, pivot.value, BSGS_XVALUE_RAM) > 0)
        {
            right--;
        }
        if (left < right)
        {
            if (left == r || right == r)
            {
                if (left == r)
                {
                    r = right;
                }
                if (right == r)
                {
                    r = left;
                }
            }
            bsgs_swap(&arr[right], &arr[left]);
        }
    } while (left < right);
    if (right != r)
    {
        bsgs_swap(&arr[right], &arr[r]);
    }
    return right;
}

void bsgs_heapify(struct bsgs_xvalue *arr, int64_t n, int64_t i)
{
    int64_t largest = i;
    int64_t l = 2 * i + 1;
    int64_t r = 2 * i + 2;
    if (l < n && memcmp(arr[l].value, arr[largest].value, BSGS_XVALUE_RAM) > 0)
        largest = l;
    if (r < n && memcmp(arr[r].value, arr[largest].value, BSGS_XVALUE_RAM) > 0)
        largest = r;
    if (largest != i)
    {
        bsgs_swap(&arr[i], &arr[largest]);
        bsgs_heapify(arr, n, largest);
    }
}

void bsgs_myheapsort(struct bsgs_xvalue *arr, int64_t n)
{
    int64_t i;
    for (i = (n / 2) - 1; i >= 0; i--)
    {
        bsgs_heapify(arr, n, i);
    }
    for (i = n - 1; i > 0; i--)
    {
        bsgs_swap(&arr[0], &arr[i]);
        bsgs_heapify(arr, i, 0);
    }
}

int bsgs_searchbinary(struct bsgs_xvalue *buffer, char *data, int64_t array_length, uint64_t *r_value)
{
    int64_t min, max, half, current;
    int r = 0, rcmp;
    min = 0;
    current = 0;
    max = array_length;
    half = array_length;
    while (!r && half >= 1)
    {
        half = (max - min) / 2;
        rcmp = memcmp(data + 16, buffer[current + half].value, BSGS_XVALUE_RAM);
        if (rcmp == 0)
        {
            *r_value = buffer[current + half].index;
            r = 1;
        }
        else
        {
            if (rcmp < 0)
            {
                max = (max - half);
            }
            else
            {
                min = (min + half);
            }
            current = min;
        }
    }
    return r;
}

#if defined(_WIN64) && !defined(__CYGWIN__)
DWORD WINAPI thread_process_bsgs(LPVOID vargp)
{
#else
void *thread_process_bsgs(void *vargp)
{
#endif
    // File-related variables
    FILE *filekey;
    struct tothread *tt;

    // Character variables
    char xpoint_raw[32], *aux_c, *hextemp;

    // Integer variables
    Int base_key, keyfound;
    IntGroup *grp = new IntGroup(CPU_GRP_SIZE / 2 + 1);
    Int dx[CPU_GRP_SIZE / 2 + 1];
    Int dy, dyn, _s, _p, km, intaux;

    // Point variables
    Point base_point, point_aux, point_found;
    Point startP;
    Point pp, pn;
    Point pts[CPU_GRP_SIZE];

    // Unsigned integer variables
    uint32_t k, l, r, salir, thread_number, cycles;

    // Other variables
    int hLength = (CPU_GRP_SIZE / 2 - 1);
    grp->Set(dx);

    tt = (struct tothread *)vargp;
    thread_number = tt->nt;
    free(tt);

    cycles = bsgs_aux / 1024;
    if (bsgs_aux % 1024 != 0)
    {
        cycles++;
    }

    intaux.Set(&BSGS_M_double);
    intaux.Mult(CPU_GRP_SIZE / 2);
    intaux.Add(&BSGS_M);

    do
    {
        /*
            We do this in an atomic pthread_mutex operation to not affect others threads
            so BSGS_CURRENT is never the same between threads
        */
#if defined(_WIN64) && !defined(__CYGWIN__)
        WaitForSingleObject(bsgs_thread, INFINITE);
#else
        pthread_mutex_lock(&bsgs_thread);
#endif

        base_key.Set(&BSGS_CURRENT);      /* we need to set our base_key to the current BSGS_CURRENT value*/
        BSGS_CURRENT.Add(&BSGS_N_double); /*Then add 2*BSGS_N to BSGS_CURRENT*/
                                          /*
                                          BSGS_CURRENT.Add(&BSGS_N);		//Then add BSGS_N to BSGS_CURRENT
                                          BSGS_CURRENT.Add(&BSGS_N);		//Then add BSGS_N to BSGS_CURRENT
                                          */

#if defined(_WIN64) && !defined(__CYGWIN__)
        ReleaseMutex(bsgs_thread);
#else
        pthread_mutex_unlock(&bsgs_thread);
#endif

        if (base_key.IsGreaterOrEqual(&n_range_end))
            break;

        if (FLAGMATRIX)
        {
            aux_c = base_key.GetBase16();
            printf("[+] Thread 0x%s \n", aux_c);
            fflush(stdout);
            free(aux_c);
        }
        else
        {
            if (FLAGQUIET == 0)
            {
                aux_c = base_key.GetBase16();
                printf("\r[+] Thread 0x%s   \r", aux_c);
                fflush(stdout);
                free(aux_c);
                THREADOUTPUT = 1;
            }
        }
        base_point = secp->ComputePublicKey(&base_key);
        km.Set(&base_key);
        km.Neg();
        km.Add(&secp->order);
        km.Sub(&intaux);
        point_aux = secp->ComputePublicKey(&km);
        for (k = 0; k < bsgs_point_number; k++)
        {
            if (bsgs_found[k] == 0)
            {
                startP = secp->AddDirect(OriginalPointsBSGS[k], point_aux);
                uint32_t j = 0;
                while (j < cycles && bsgs_found[k] == 0)
                {
                    int i;
                    // Unroll the loop for speed
                    dx[0].ModSub(&GSn[0].x, &startP.x);
                    dx[1].ModSub(&GSn[1].x, &startP.x);
                    dx[2].ModSub(&GSn[2].x, &startP.x);
                    dx[3].ModSub(&GSn[3].x, &startP.x);
                    dx[4].ModSub(&GSn[4].x, &startP.x);
                    dx[5].ModSub(&GSn[5].x, &startP.x);
                    dx[6].ModSub(&GSn[6].x, &startP.x);
                    dx[7].ModSub(&GSn[7].x, &startP.x);
                    // Handle any remaining points
                    for (i = 8; i < hLength; i++)
                    {
                        dx[i].ModSub(&GSn[i].x, &startP.x);
                    }
                    dx[i].ModSub(&GSn[i].x, &startP.x);    // For the first point
                    dx[i + 1].ModSub(&_2GSn.x, &startP.x); // For the next center point
                    // Grouped ModInv
                    grp->ModInv();
                    /*
                    We use the fact that P + i*G and P - i*G has the same deltax, so the same inverse
                    We compute key in the positive and negative way from the center of the group
                    */
                    // center point
                    pts[CPU_GRP_SIZE / 2] = startP;
                    for (i = 0; i < hLength; i++)
                    {
                        pp = startP;
                        pn = startP;

                        // P = startP + i*G
                        dy.ModSub(&GSn[i].y, &pp.y);

                        _s.ModMulK1(&dy, &dx[i]); // s = (p2.y-p1.y)*inverse(p2.x-p1.x);
                        _p.ModSquareK1(&_s);      // _p = pow2(s)

                        pp.x.ModNeg();
                        pp.x.ModAdd(&_p);
                        pp.x.ModSub(&GSn[i].x); // rx = pow2(s) - p1.x - p2.x;
#if 0
  pp.y.ModSub(&GSn[i].x,&pp.x);
  pp.y.ModMulK1(&_s);
  pp.y.ModSub(&GSn[i].y);           // ry = - p2.y - s*(ret.x-p2.x);
#endif
                        // P = startP - i*G  , if (x,y) = i*G then (x,-y) = -i*G
                        dyn.Set(&GSn[i].y);
                        dyn.ModNeg();
                        dyn.ModSub(&pn.y);

                        _s.ModMulK1(&dyn, &dx[i]); // s = (p2.y-p1.y)*inverse(p2.x-p1.x);
                        _p.ModSquareK1(&_s);       // _p = pow2(s)

                        pn.x.ModNeg();
                        pn.x.ModAdd(&_p);
                        pn.x.ModSub(&GSn[i].x); // rx = pow2(s) - p1.x - p2.x;

#if 0
  pn.y.ModSub(&GSn[i].x,&pn.x);
  pn.y.ModMulK1(&_s);
  pn.y.ModAdd(&GSn[i].y);          // ry = - p2.y - s*(ret.x-p2.x);
#endif

                        pts[CPU_GRP_SIZE / 2 + (i + 1)] = pp;
                        pts[CPU_GRP_SIZE / 2 - (i + 1)] = pn;
                    }
                    // First point (startP - (GRP_SZIE/2)*G)
                    pn = startP;
                    dyn.Set(&GSn[i].y);
                    dyn.ModNeg();
                    dyn.ModSub(&pn.y);

                    _s.ModMulK1(&dyn, &dx[i]);
                    _p.ModSquareK1(&_s);

                    pn.x.ModNeg();
                    pn.x.ModAdd(&_p);
                    pn.x.ModSub(&GSn[i].x);

#if 0
pn.y.ModSub(&GSn[i].x,&pn.x);
pn.y.ModMulK1(&_s);
pn.y.ModAdd(&GSn[i].y);
#endif
                    pts[0] = pn;
                    for (int i = 0; i < CPU_GRP_SIZE && bsgs_found[k] == 0; i++)
                    {
                        pts[i].x.Get32Bytes((unsigned char *)xpoint_raw);
                        r = bloom_check(&bloom_bP[((unsigned char)xpoint_raw[0])], xpoint_raw, 32);
                        if (r)
                        {
                            r = bsgs_secondcheck(&base_key, ((j * 1024) + i), k, &keyfound);
                            if (r)
                            {
                                hextemp = keyfound.GetBase16();
                                printf("[+] Thread Key found privkey %s   \n", hextemp);
                                point_found = secp->ComputePublicKey(&keyfound);
                                aux_c = secp->GetPublicKeyHex(OriginalPointsBSGScompressed[k], point_found);
                                printf("[+] Publickey %s\n", aux_c);
#if defined(_WIN64) && !defined(__CYGWIN__)
                                WaitForSingleObject(write_keys, INFINITE);
#else
                                pthread_mutex_lock(&write_keys);
#endif

                                filekey = fopen("KEYFOUNDKEYFOUND.txt", "a");
                                if (filekey != NULL)
                                {
                                    fprintf(filekey, "Key found privkey %s\nPublickey %s\n", hextemp, aux_c);
                                    fclose(filekey);
                                }
                                free(hextemp);
                                free(aux_c);
#if defined(_WIN64) && !defined(__CYGWIN__)
                                ReleaseMutex(write_keys);
#else
                                pthread_mutex_unlock(&write_keys);
#endif
                                bsgs_found[k] = 1;
                                salir = 1;
                                for (l = 0; l < bsgs_point_number && salir; l++)
                                {
                                    salir &= bsgs_found[l];
                                }
                                if (salir)
                                {
                                    printf("All points were found\n");
                                    exit(EXIT_FAILURE);
                                }
                            } // End if second check
                        } // End if first check
                    } // For for pts variable
                    // Next start point (startP += (bsSize*GRP_SIZE).G)
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
                } // end while
            } // End if
        }
        steps[thread_number] += 2;
    } while (1);
    ends[thread_number] = 1;
    return NULL;
}

#if defined(_WIN64) && !defined(__CYGWIN__)
DWORD WINAPI thread_process_bsgs_random(LPVOID vargp)
{
#else
void *thread_process_bsgs_random(void *vargp)
{
#endif

    FILE *filekey;
    struct tothread *tt;
    char xpoint_raw[32], *aux_c, *hextemp;
    Int base_key, keyfound, n_range_random;
    Point base_point, point_aux, point_found;
    uint32_t l, k, r, salir, thread_number, cycles;

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

    tt = (struct tothread *)vargp;
    thread_number = tt->nt;
    free(tt);

    cycles = bsgs_aux / 1024;
    if (bsgs_aux % 1024 != 0)
    {
        cycles++;
    }

    intaux.Set(&BSGS_M_double);
    intaux.Mult(CPU_GRP_SIZE / 2);
    intaux.Add(&BSGS_M);

    do
    {

        /*          | Start Range	| End Range     |
            None	| 1             | EC.N          |
            -b	bit | Min bit value | Max bit value |
            -r	A:B | A             | B             |
        */
#if defined(_WIN64) && !defined(__CYGWIN__)
        WaitForSingleObject(bsgs_thread, INFINITE);
#else
        pthread_mutex_lock(&bsgs_thread);
#endif

        base_key.Rand(&n_range_start, &n_range_end);
#if defined(_WIN64) && !defined(__CYGWIN__)
        ReleaseMutex(bsgs_thread);
#else
        pthread_mutex_unlock(&bsgs_thread);
#endif

        if (FLAGMATRIX)
        {
            aux_c = base_key.GetBase16();
            printf("[+] Thread 0x%s  \n", aux_c);
            fflush(stdout);
            free(aux_c);
        }
        else
        {
            if (FLAGQUIET == 0)
            {
                aux_c = base_key.GetBase16();
                printf("\r[+] Thread 0x%s  \r", aux_c);
                fflush(stdout);
                free(aux_c);
                THREADOUTPUT = 1;
            }
        }
        base_point = secp->ComputePublicKey(&base_key);

        km.Set(&base_key);
        km.Neg();

        km.Add(&secp->order);
        km.Sub(&intaux);
        point_aux = secp->ComputePublicKey(&km);

        /* We need to test individually every point in BSGS_Q */
        for (k = 0; k < bsgs_point_number; k++)
        {
            if (bsgs_found[k] == 0)
            {
                startP = secp->AddDirect(OriginalPointsBSGS[k], point_aux);
                uint32_t j = 0;
                while (j < cycles && bsgs_found[k] == 0)
                {

                    int i;
                    // Unroll the loop for speed
                    dx[0].ModSub(&GSn[0].x, &startP.x);
                    dx[1].ModSub(&GSn[1].x, &startP.x);
                    dx[2].ModSub(&GSn[2].x, &startP.x);
                    dx[3].ModSub(&GSn[3].x, &startP.x);
                    dx[4].ModSub(&GSn[4].x, &startP.x);
                    dx[5].ModSub(&GSn[5].x, &startP.x);
                    dx[6].ModSub(&GSn[6].x, &startP.x);
                    dx[7].ModSub(&GSn[7].x, &startP.x);
                    // Handle any remaining points
                    for (i = 8; i < hLength; i++)
                    {
                        dx[i].ModSub(&GSn[i].x, &startP.x);
                    }

                    dx[i].ModSub(&GSn[i].x, &startP.x);    // For the first point
                    dx[i + 1].ModSub(&_2GSn.x, &startP.x); // For the next center point

                    // Grouped ModInv
                    grp->ModInv();

                    /*
                    We use the fact that P + i*G and P - i*G has the same deltax, so the same inverse
                    We compute key in the positive and negative way from the center of the group
                    */

                    // center point
                    pts[CPU_GRP_SIZE / 2] = startP;

                    for (i = 0; i < hLength; i++)
                    {

                        pp = startP;
                        pn = startP;

                        // P = startP + i*G
                        dy.ModSub(&GSn[i].y, &pp.y);

                        _s.ModMulK1(&dy, &dx[i]); // s = (p2.y-p1.y)*inverse(p2.x-p1.x);
                        _p.ModSquareK1(&_s);      // _p = pow2(s)

                        pp.x.ModNeg();
                        pp.x.ModAdd(&_p);
                        pp.x.ModSub(&GSn[i].x); // rx = pow2(s) - p1.x - p2.x;

#if 0
  pp.y.ModSub(&GSn[i].x,&pp.x);
  pp.y.ModMulK1(&_s);
  pp.y.ModSub(&GSn[i].y);           // ry = - p2.y - s*(ret.x-p2.x);
#endif

                        // P = startP - i*G  , if (x,y) = i*G then (x,-y) = -i*G
                        dyn.Set(&GSn[i].y);
                        dyn.ModNeg();
                        dyn.ModSub(&pn.y);

                        _s.ModMulK1(&dyn, &dx[i]); // s = (p2.y-p1.y)*inverse(p2.x-p1.x);
                        _p.ModSquareK1(&_s);       // _p = pow2(s)

                        pn.x.ModNeg();
                        pn.x.ModAdd(&_p);
                        pn.x.ModSub(&GSn[i].x); // rx = pow2(s) - p1.x - p2.x;

#if 0
  pn.y.ModSub(&GSn[i].x,&pn.x);
  pn.y.ModMulK1(&_s);
  pn.y.ModAdd(&GSn[i].y);          // ry = - p2.y - s*(ret.x-p2.x);
#endif

                        pts[CPU_GRP_SIZE / 2 + (i + 1)] = pp;
                        pts[CPU_GRP_SIZE / 2 - (i + 1)] = pn;
                    }

                    // First point (startP - (GRP_SZIE/2)*G)
                    pn = startP;
                    dyn.Set(&GSn[i].y);
                    dyn.ModNeg();
                    dyn.ModSub(&pn.y);

                    _s.ModMulK1(&dyn, &dx[i]);
                    _p.ModSquareK1(&_s);

                    pn.x.ModNeg();
                    pn.x.ModAdd(&_p);
                    pn.x.ModSub(&GSn[i].x);

#if 0
pn.y.ModSub(&GSn[i].x,&pn.x);
pn.y.ModMulK1(&_s);
pn.y.ModAdd(&GSn[i].y);
#endif

                    pts[0] = pn;

                    for (int i = 0; i < CPU_GRP_SIZE && bsgs_found[k] == 0; i++)
                    {
                        pts[i].x.Get32Bytes((unsigned char *)xpoint_raw);
                        r = bloom_check(&bloom_bP[((unsigned char)xpoint_raw[0])], xpoint_raw, 32);
                        if (r)
                        {
                            r = bsgs_secondcheck(&base_key, ((j * 1024) + i), k, &keyfound);
                            if (r)
                            {
                                hextemp = keyfound.GetBase16();
                                printf("[+] Thread Key found privkey %s    \n", hextemp);
                                point_found = secp->ComputePublicKey(&keyfound);
                                aux_c = secp->GetPublicKeyHex(OriginalPointsBSGScompressed[k], point_found);
                                printf("[+] Publickey %s\n", aux_c);
#if defined(_WIN64) && !defined(__CYGWIN__)
                                WaitForSingleObject(write_keys, INFINITE);
#else
                                pthread_mutex_lock(&write_keys);
#endif

                                filekey = fopen("KEYFOUNDKEYFOUND.txt", "a");
                                if (filekey != NULL)
                                {
                                    fprintf(filekey, "Key found privkey %s\nPublickey %s\n", hextemp, aux_c);
                                    fclose(filekey);
                                }
                                free(hextemp);
                                free(aux_c);
#if defined(_WIN64) && !defined(__CYGWIN__)
                                ReleaseMutex(write_keys);
#else
                                pthread_mutex_unlock(&write_keys);
#endif

                                bsgs_found[k] = 1;
                                salir = 1;
                                for (l = 0; l < bsgs_point_number && salir; l++)
                                {
                                    salir &= bsgs_found[l];
                                }
                                if (salir)
                                {
                                    printf("All points were found\n");
                                    exit(EXIT_FAILURE);
                                }
                            } // End if second check
                        } // End if first check

                    } // For for pts variable

                    // Next start point (startP += (bsSize*GRP_SIZE).G)

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

                } // End While
            } // End if
        } // End for with k bsgs_point_number

        steps[thread_number] += 2;
    } while (1);
    ends[thread_number] = 1;
    return NULL;
}

/*
    The bsgs_secondcheck function is made to perform a second BSGS search in a Range of less size.
    This funtion is made with the especific purpouse to USE a smaller bPtable in RAM.
*/
int bsgs_secondcheck(Int *start_range, uint32_t a, uint32_t k_index, Int *privatekey)
{
    int i = 0, found = 0, r = 0;
    Int base_key;
    Point base_point, point_aux;
    Point BSGS_Q, BSGS_S, BSGS_Q_AMP;
    char xpoint_raw[32];

    base_key.Set(&BSGS_M_double);
    base_key.Mult((uint64_t)a);
    base_key.Add(start_range);

    base_point = secp->ComputePublicKey(&base_key);
    point_aux = secp->Negation(base_point);

    /*
        BSGS_S = Q - base_key
                 Q is the target Key
        base_key is the Start range + a*BSGS_M
    */
    BSGS_S = secp->AddDirect(OriginalPointsBSGS[k_index], point_aux);
    BSGS_Q.Set(BSGS_S);
    do
    {
        BSGS_Q_AMP = secp->AddDirect(BSGS_Q, BSGS_AMP2[i]);
        BSGS_S.Set(BSGS_Q_AMP);
        BSGS_S.x.Get32Bytes((unsigned char *)xpoint_raw);
        r = bloom_check(&bloom_bPx2nd[(uint8_t)xpoint_raw[0]], xpoint_raw, 32);
        if (r)
        {
            found = bsgs_thirdcheck(&base_key, i, k_index, privatekey);
        }
        i++;
    } while (i < 32 && !found);
    return found;
}

int bsgs_thirdcheck(Int *start_range, uint32_t a, uint32_t k_index, Int *privatekey)
{
    uint64_t j = 0;
    int i = 0, found = 0, r = 0;
    Int base_key, calculatedkey;
    Point base_point, point_aux;
    Point BSGS_Q, BSGS_S, BSGS_Q_AMP;
    char xpoint_raw[32];

    base_key.SetInt32(a);
    base_key.Mult(&BSGS_M2_double);
    base_key.Add(start_range);

    base_point = secp->ComputePublicKey(&base_key);
    point_aux = secp->Negation(base_point);

    BSGS_S = secp->AddDirect(OriginalPointsBSGS[k_index], point_aux);
    BSGS_Q.Set(BSGS_S);

    do
    {
        BSGS_Q_AMP = secp->AddDirect(BSGS_Q, BSGS_AMP3[i]);
        BSGS_S.Set(BSGS_Q_AMP);
        BSGS_S.x.Get32Bytes((unsigned char *)xpoint_raw);
        r = bloom_check(&bloom_bPx3rd[(uint8_t)xpoint_raw[0]], xpoint_raw, 32);
        if (r)
        {
            r = bsgs_searchbinary(bPtable, xpoint_raw, bsgs_m3, &j);
            if (r)
            {
                calcualteindex(i, &calculatedkey);
                privatekey->Set(&calculatedkey);
                privatekey->Add((uint64_t)(j + 1));
                privatekey->Add(&base_key);
                point_aux = secp->ComputePublicKey(privatekey);
                if (point_aux.x.IsEqual(&OriginalPointsBSGS[k_index].x))
                {
                    found = 1;
                }
                else
                {
                    calcualteindex(i, &calculatedkey);
                    privatekey->Set(&calculatedkey);
                    privatekey->Sub((uint64_t)(j + 1));
                    privatekey->Add(&base_key);
                    point_aux = secp->ComputePublicKey(privatekey);
                    if (point_aux.x.IsEqual(&OriginalPointsBSGS[k_index].x))
                    {
                        found = 1;
                    }
                }
            }
        }
        else
        {
            /*
                For some reason the AddDirect don't return 000000... value when the publickeys are the negated values from each other
                Why JLP?
                This is is an special case
            */
            if (BSGS_Q.x.IsEqual(&BSGS_AMP3[i].x))
            {
                calcualteindex(i, &calculatedkey);
                privatekey->Set(&calculatedkey);
                privatekey->Add(&base_key);
                found = 1;
            }
        }
        i++;
    } while (i < 32 && !found);
    return found;
}

void sleep_ms(int milliseconds)
{ // cross-platform sleep function
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

void init_generator()
{
    Point G = secp->ComputePublicKey(&stride);
    Point g;
    g.Set(G);
    Gn.reserve(CPU_GRP_SIZE / 2);
    Gn[0] = g;
    g = secp->DoubleDirect(g);
    Gn[1] = g;
    for (int i = 2; i < CPU_GRP_SIZE / 2; i++)
    {
        g = secp->AddDirect(g, G);
        Gn[i] = g;
    }
    _2Gn = secp->DoubleDirect(Gn[CPU_GRP_SIZE / 2 - 1]);
}

#if defined(_WIN64) && !defined(__CYGWIN__)
DWORD WINAPI thread_bPload(LPVOID vargp)
{
#else
void *thread_bPload(void *vargp)
{
#endif

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
    tt = (struct bPload *)vargp;
    Int km((uint64_t)(tt->from + 1));
    threadid = tt->threadid;
    // if(FLAGDEBUG) printf("[D] thread %i from %" PRIu64 " to %" PRIu64 "\n",threadid,tt->from,tt->to);

    i_counter = tt->from;

    nbStep = (tt->to - tt->from) / CPU_GRP_SIZE;

    if (((tt->to - tt->from) % CPU_GRP_SIZE) != 0)
    {
        nbStep++;
    }
    // if(FLAGDEBUG) printf("[D] thread %i nbStep %" PRIu64 "\n",threadid,nbStep);
    to = tt->to;

    km.Add((uint64_t)(CPU_GRP_SIZE / 2));
    startP = secp->ComputePublicKey(&km);
    grp->Set(dx);
    for (uint64_t s = 0; s < nbStep; s++)
    {
        for (i = 0; i < hLength; i++)
        {
            dx[i].ModSub(&Gn[i].x, &startP.x);
        }
        dx[i].ModSub(&Gn[i].x, &startP.x);    // For the first point
        dx[i + 1].ModSub(&_2Gn.x, &startP.x); // For the next center point
        // Grouped ModInv
        grp->ModInv();

        // We use the fact that P + i*G and P - i*G has the same deltax, so the same inverse
        // We compute key in the positive and negative way from the center of the group
        // center point

        pts[CPU_GRP_SIZE / 2] = startP; // Center point

        for (i = 0; i < hLength; i++)
        {
            pp = startP;
            pn = startP;

            // P = startP + i*G
            dy.ModSub(&Gn[i].y, &pp.y);

            _s.ModMulK1(&dy, &dx[i]); // s = (p2.y-p1.y)*inverse(p2.x-p1.x);
            _p.ModSquareK1(&_s);      // _p = pow2(s)

            pp.x.ModNeg();
            pp.x.ModAdd(&_p);
            pp.x.ModSub(&Gn[i].x); // rx = pow2(s) - p1.x - p2.x;

#if 0
			pp.y.ModSub(&Gn[i].x,&pp.x);
			pp.y.ModMulK1(&_s);
			pp.y.ModSub(&Gn[i].y);           // ry = - p2.y - s*(ret.x-p2.x);
#endif

            // P = startP - i*G  , if (x,y) = i*G then (x,-y) = -i*G
            dyn.Set(&Gn[i].y);
            dyn.ModNeg();
            dyn.ModSub(&pn.y);

            _s.ModMulK1(&dyn, &dx[i]); // s = (p2.y-p1.y)*inverse(p2.x-p1.x);
            _p.ModSquareK1(&_s);       // _p = pow2(s)

            pn.x.ModNeg();
            pn.x.ModAdd(&_p);
            pn.x.ModSub(&Gn[i].x); // rx = pow2(s) - p1.x - p2.x;

#if 0
			pn.y.ModSub(&Gn[i].x,&pn.x);
			pn.y.ModMulK1(&_s);
			pn.y.ModAdd(&Gn[i].y);          // ry = - p2.y - s*(ret.x-p2.x);
#endif

            pts[CPU_GRP_SIZE / 2 + (i + 1)] = pp;
            pts[CPU_GRP_SIZE / 2 - (i + 1)] = pn;
        }

        // First point (startP - (GRP_SZIE/2)*G)
        pn = startP;
        dyn.Set(&Gn[i].y);
        dyn.ModNeg();
        dyn.ModSub(&pn.y);

        _s.ModMulK1(&dyn, &dx[i]);
        _p.ModSquareK1(&_s);

        pn.x.ModNeg();
        pn.x.ModAdd(&_p);
        pn.x.ModSub(&Gn[i].x);

#if 0
		pn.y.ModSub(&Gn[i].x,&pn.x);
		pn.y.ModMulK1(&_s);
		pn.y.ModAdd(&Gn[i].y);
#endif

        pts[0] = pn;
        for (j = 0; j < CPU_GRP_SIZE; j++)
        {
            pts[j].x.Get32Bytes((unsigned char *)rawvalue);
            bloom_bP_index = (uint8_t)rawvalue[0];
            /*
            if(FLAGDEBUG){
                tohex_dst(rawvalue,32,hexraw);
                printf("%i : %s : %i\n",i_counter,hexraw,bloom_bP_index);
            }
            */
            if (i_counter < bsgs_m3)
            {
                if (!FLAGREADEDFILE3)
                {
                    memcpy(bPtable[i_counter].value, rawvalue + 16, BSGS_XVALUE_RAM);
                    bPtable[i_counter].index = i_counter;
                }
                if (!FLAGREADEDFILE4)
                {
#if defined(_WIN64) && !defined(__CYGWIN__)
                    WaitForSingleObject(bloom_bPx3rd_mutex[bloom_bP_index], INFINITE);
                    bloom_add(&bloom_bPx3rd[bloom_bP_index], rawvalue, BSGS_BUFFERXPOINTLENGTH);
                    ReleaseMutex(bloom_bPx3rd_mutex[bloom_bP_index]);
#else
                    pthread_mutex_lock(&bloom_bPx3rd_mutex[bloom_bP_index]);
                    bloom_add(&bloom_bPx3rd[bloom_bP_index], rawvalue, BSGS_BUFFERXPOINTLENGTH);
                    pthread_mutex_unlock(&bloom_bPx3rd_mutex[bloom_bP_index]);
#endif
                }
            }
            if (i_counter < bsgs_m2 && !FLAGREADEDFILE2)
            {
#if defined(_WIN64) && !defined(__CYGWIN__)
                WaitForSingleObject(bloom_bPx2nd_mutex[bloom_bP_index], INFINITE);
                bloom_add(&bloom_bPx2nd[bloom_bP_index], rawvalue, BSGS_BUFFERXPOINTLENGTH);
                ReleaseMutex(bloom_bPx2nd_mutex[bloom_bP_index]);
#else
                pthread_mutex_lock(&bloom_bPx2nd_mutex[bloom_bP_index]);
                bloom_add(&bloom_bPx2nd[bloom_bP_index], rawvalue, BSGS_BUFFERXPOINTLENGTH);
                pthread_mutex_unlock(&bloom_bPx2nd_mutex[bloom_bP_index]);
#endif
            }
            if (i_counter < to && !FLAGREADEDFILE1)
            {
#if defined(_WIN64) && !defined(__CYGWIN__)
                WaitForSingleObject(bloom_bP_mutex[bloom_bP_index], INFINITE);
                bloom_add(&bloom_bP[bloom_bP_index], rawvalue, BSGS_BUFFERXPOINTLENGTH);
                ReleaseMutex(bloom_bP_mutex[bloom_bP_index);
#else
                pthread_mutex_lock(&bloom_bP_mutex[bloom_bP_index]);
                bloom_add(&bloom_bP[bloom_bP_index], rawvalue, BSGS_BUFFERXPOINTLENGTH);
                pthread_mutex_unlock(&bloom_bP_mutex[bloom_bP_index]);
#endif
            }
            i_counter++;
        }
        // Next start point (startP + GRP_SIZE*G)
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
#if defined(_WIN64) && !defined(__CYGWIN__)
    WaitForSingleObject(bPload_mutex[threadid], INFINITE);
    tt->finished = 1;
    ReleaseMutex(bPload_mutex[threadid]);
#else
    pthread_mutex_lock(&bPload_mutex[threadid]);
    tt->finished = 1;
    pthread_mutex_unlock(&bPload_mutex[threadid]);
    pthread_exit(NULL);
#endif
    return NULL;
}

#if defined(_WIN64) && !defined(__CYGWIN__)
DWORD WINAPI thread_bPload_2blooms(LPVOID vargp)
{
#else
void *thread_bPload_2blooms(void *vargp)
{
#endif
    char rawvalue[32];
    struct bPload *tt;
    uint64_t i_counter, j, nbStep; //,to;
    IntGroup *grp = new IntGroup(CPU_GRP_SIZE / 2 + 1);
    Point startP;
    Int dx[CPU_GRP_SIZE / 2 + 1];
    Point pts[CPU_GRP_SIZE];
    Int dy, dyn, _s, _p;
    Point pp, pn;
    int i, bloom_bP_index, hLength = (CPU_GRP_SIZE / 2 - 1), threadid;
    tt = (struct bPload *)vargp;
    Int km((uint64_t)(tt->from + 1));
    threadid = tt->threadid;

    i_counter = tt->from;

    nbStep = (tt->to - (tt->from)) / CPU_GRP_SIZE;

    if (((tt->to - (tt->from)) % CPU_GRP_SIZE) != 0)
    {
        nbStep++;
    }
    // if(FLAGDEBUG) printf("[D] thread %i nbStep %" PRIu64 "\n",threadid,nbStep);
    // to = tt->to;

    km.Add((uint64_t)(CPU_GRP_SIZE / 2));
    startP = secp->ComputePublicKey(&km);
    grp->Set(dx);
    for (uint64_t s = 0; s < nbStep; s++)
    {
        for (i = 0; i < hLength; i++)
        {
            dx[i].ModSub(&Gn[i].x, &startP.x);
        }
        dx[i].ModSub(&Gn[i].x, &startP.x);    // For the first point
        dx[i + 1].ModSub(&_2Gn.x, &startP.x); // For the next center point
        // Grouped ModInv
        grp->ModInv();

        // We use the fact that P + i*G and P - i*G has the same deltax, so the same inverse
        // We compute key in the positive and negative way from the center of the group
        // center point

        pts[CPU_GRP_SIZE / 2] = startP; // Center point

        for (i = 0; i < hLength; i++)
        {
            pp = startP;
            pn = startP;

            // P = startP + i*G
            dy.ModSub(&Gn[i].y, &pp.y);

            _s.ModMulK1(&dy, &dx[i]); // s = (p2.y-p1.y)*inverse(p2.x-p1.x);
            _p.ModSquareK1(&_s);      // _p = pow2(s)

            pp.x.ModNeg();
            pp.x.ModAdd(&_p);
            pp.x.ModSub(&Gn[i].x); // rx = pow2(s) - p1.x - p2.x;

#if 0
			pp.y.ModSub(&Gn[i].x,&pp.x);
			pp.y.ModMulK1(&_s);
			pp.y.ModSub(&Gn[i].y);           // ry = - p2.y - s*(ret.x-p2.x);
#endif

            // P = startP - i*G  , if (x,y) = i*G then (x,-y) = -i*G
            dyn.Set(&Gn[i].y);
            dyn.ModNeg();
            dyn.ModSub(&pn.y);

            _s.ModMulK1(&dyn, &dx[i]); // s = (p2.y-p1.y)*inverse(p2.x-p1.x);
            _p.ModSquareK1(&_s);       // _p = pow2(s)

            pn.x.ModNeg();
            pn.x.ModAdd(&_p);
            pn.x.ModSub(&Gn[i].x); // rx = pow2(s) - p1.x - p2.x;

#if 0
			pn.y.ModSub(&Gn[i].x,&pn.x);
			pn.y.ModMulK1(&_s);
			pn.y.ModAdd(&Gn[i].y);          // ry = - p2.y - s*(ret.x-p2.x);
#endif

            pts[CPU_GRP_SIZE / 2 + (i + 1)] = pp;
            pts[CPU_GRP_SIZE / 2 - (i + 1)] = pn;
        }

        // First point (startP - (GRP_SZIE/2)*G)
        pn = startP;
        dyn.Set(&Gn[i].y);
        dyn.ModNeg();
        dyn.ModSub(&pn.y);

        _s.ModMulK1(&dyn, &dx[i]);
        _p.ModSquareK1(&_s);

        pn.x.ModNeg();
        pn.x.ModAdd(&_p);
        pn.x.ModSub(&Gn[i].x);

#if 0
		pn.y.ModSub(&Gn[i].x,&pn.x);
		pn.y.ModMulK1(&_s);
		pn.y.ModAdd(&Gn[i].y);
#endif

        pts[0] = pn;
        for (j = 0; j < CPU_GRP_SIZE; j++)
        {
            pts[j].x.Get32Bytes((unsigned char *)rawvalue);
            bloom_bP_index = (uint8_t)rawvalue[0];
            if (i_counter < bsgs_m3)
            {
                if (!FLAGREADEDFILE3)
                {
                    memcpy(bPtable[i_counter].value, rawvalue + 16, BSGS_XVALUE_RAM);
                    bPtable[i_counter].index = i_counter;
                }
                if (!FLAGREADEDFILE4)
                {
#if defined(_WIN64) && !defined(__CYGWIN__)
                    WaitForSingleObject(bloom_bPx3rd_mutex[bloom_bP_index], INFINITE);
                    bloom_add(&bloom_bPx3rd[bloom_bP_index], rawvalue, BSGS_BUFFERXPOINTLENGTH);
                    ReleaseMutex(bloom_bPx3rd_mutex[bloom_bP_index]);
#else
                    pthread_mutex_lock(&bloom_bPx3rd_mutex[bloom_bP_index]);
                    bloom_add(&bloom_bPx3rd[bloom_bP_index], rawvalue, BSGS_BUFFERXPOINTLENGTH);
                    pthread_mutex_unlock(&bloom_bPx3rd_mutex[bloom_bP_index]);
#endif
                }
            }
            if (i_counter < bsgs_m2 && !FLAGREADEDFILE2)
            {
#if defined(_WIN64) && !defined(__CYGWIN__)
                WaitForSingleObject(bloom_bPx2nd_mutex[bloom_bP_index], INFINITE);
                bloom_add(&bloom_bPx2nd[bloom_bP_index], rawvalue, BSGS_BUFFERXPOINTLENGTH);
                ReleaseMutex(bloom_bPx2nd_mutex[bloom_bP_index]);
#else
                pthread_mutex_lock(&bloom_bPx2nd_mutex[bloom_bP_index]);
                bloom_add(&bloom_bPx2nd[bloom_bP_index], rawvalue, BSGS_BUFFERXPOINTLENGTH);
                pthread_mutex_unlock(&bloom_bPx2nd_mutex[bloom_bP_index]);
#endif
            }
            i_counter++;
        }
        // Next start point (startP + GRP_SIZE*G)
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
#if defined(_WIN64) && !defined(__CYGWIN__)
    WaitForSingleObject(bPload_mutex[threadid], INFINITE);
    tt->finished = 1;
    ReleaseMutex(bPload_mutex[threadid]);
#else
    pthread_mutex_lock(&bPload_mutex[threadid]);
    tt->finished = 1;
    pthread_mutex_unlock(&bPload_mutex[threadid]);
    pthread_exit(NULL);
#endif
    return NULL;
}

#if defined(_WIN64) && !defined(__CYGWIN__)
DWORD WINAPI thread_subtract_bloom_load(LPVOID vargp)
{
#else
void *thread_subtract_bloom_load(void *vargp)
{
#endif
    struct subtractBPload *tt = (struct subtractBPload *)vargp;
    int threadid = tt->threadid;
    

    
    // Simple sequential generation for subtract bloom
    Int currentSubtract;
    Point subtractPubKey, negatedSubtractPubKey, resultPoint;
    unsigned char xcoord[32];
    
    // Process each key in the assigned range
    for (uint64_t i = tt->from; i < tt->to; i++) {
        // Calculate subtract value: i * spacing
        currentSubtract.SetInt64(i);
        currentSubtract.Mult(&subtract_bloom_spacing);
        
        // Special handling for subtract value 0
        if (currentSubtract.IsZero()) {
            // Origin - 0 = Origin
            resultPoint = subtract_bloom_origin;
        } else {
            // Compute the public key for this subtract value
            subtractPubKey = secp->ComputePublicKey(&currentSubtract);
            
            // Negate for subtraction
            negatedSubtractPubKey = secp->Negation(subtractPubKey);
            
            // Calculate result: origin - (i * spacing)
            resultPoint = secp->AddDirect(subtract_bloom_origin, negatedSubtractPubKey);
        }
    
        
        // Get X coordinate
        resultPoint.x.Get32Bytes(xcoord);
    
        
        // Use first byte as mutex index
        uint8_t mutex_index = xcoord[0];
        
#if defined(_WIN64) && !defined(__CYGWIN__)
        WaitForSingleObject(subtract_bloom_mutex[mutex_index], INFINITE);
        bloom_add(&bloom, xcoord, 32);  // Always use 32 bytes for xpoint mode
        ReleaseMutex(subtract_bloom_mutex[mutex_index]);
#else
        pthread_mutex_lock(&subtract_bloom_mutex[mutex_index]);
        bloom_add(&bloom, xcoord, 32);  // Always use 32 bytes for xpoint mode
        pthread_mutex_unlock(&subtract_bloom_mutex[mutex_index]);
#endif
    }
    
#if defined(_WIN64) && !defined(__CYGWIN__)
    WaitForSingleObject(bPload_mutex[threadid], INFINITE);
    tt->finished = 1;
    ReleaseMutex(bPload_mutex[threadid]);
#else
    pthread_mutex_lock(&bPload_mutex[threadid]);
    tt->finished = 1;
    pthread_mutex_unlock(&bPload_mutex[threadid]);
#endif
    
    return NULL;
}

/* This function perform the KECCAK Opetation*/
void KECCAK_256(uint8_t *source, size_t size, uint8_t *dst)
{
    SHA3_256_CTX ctx;
    SHA3_256_Init(&ctx);
    SHA3_256_Update(&ctx, source, size);
    KECCAK_256_Final(dst, &ctx);
}

/* This function takes in two parameters:

publickey: a reference to a Point object representing a public key.
dst_address: a pointer to an unsigned char array where the generated binary address will be stored.
The function is designed to generate a binary address for Ethereum using the given public key.
It first extracts the x and y coordinates of the public key as 32-byte arrays, and concatenates them
to form a 64-byte array called bin_publickey. Then, it applies the KECCAK-256 hashing algorithm to
bin_publickey to generate the binary address, which is stored in dst_address. */

void generate_binaddress_eth(Point &publickey, unsigned char *dst_address)
{
    unsigned char bin_publickey[64];
    publickey.x.Get32Bytes(bin_publickey);
    publickey.y.Get32Bytes(bin_publickey + 32);
    KECCAK_256(bin_publickey, 64, bin_publickey);
    memcpy(dst_address, bin_publickey + 12, 20);
}

#if defined(_WIN64) && !defined(__CYGWIN__)
DWORD WINAPI thread_process_bsgs_levy(LPVOID vargp)
{
#else
void *thread_process_bsgs_levy(void *vargp)
{
#endif
    FILE *filekey;
    struct tothread *tt;
    char xpoint_raw[32], *aux_c, *hextemp;
    Int base_key, keyfound;
    Point base_point, point_aux, point_found;
    uint32_t k, l, r, salir, thread_number, cycles;

    // For Lévy flight calculations
    double u1, u2, gaussian, sigma;
    Int levy_step, temp_key;

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

    tt = (struct tothread *)vargp;
    thread_number = tt->nt;
    free(tt);

    cycles = bsgs_aux / 1024;
    if (bsgs_aux % 1024 != 0)
    {
        cycles++;
    }

    intaux.Set(&BSGS_M_double);
    intaux.Mult(CPU_GRP_SIZE / 2);
    intaux.Add(&BSGS_M);

    // Calculate sigma for Lévy flight
    sigma = pow(tgamma(1.0 + LEVY_ALPHA) * sin(M_PI * LEVY_ALPHA / 2.0) /
                    (tgamma((1.0 + LEVY_ALPHA) / 2.0) * LEVY_ALPHA * pow(2.0, (LEVY_ALPHA - 1.0) / 2.0)),
                1.0 / LEVY_ALPHA);

    do
    {
        // Generate Lévy flight step
        u1 = ((double)rand() / RAND_MAX);
        u2 = ((double)rand() / RAND_MAX);

        if (u1 < 1e-10)
            u1 = 1e-10;
        gaussian = sqrt(-2.0 * log(u1)) * cos(2.0 * M_PI * u2);
        double step_size = gaussian * sigma / pow(fabs(u1), 1.0 / LEVY_ALPHA);

        levy_step.SetInt64((int64_t)(step_size * 1e15));
        levy_step.Mod(&n_range_diff);

        if (rand() % 2)
        {
            levy_step.Neg();
        }

#if defined(_WIN64) && !defined(__CYGWIN__)
        WaitForSingleObject(bsgs_thread, INFINITE);
#else
        pthread_mutex_lock(&bsgs_thread);
#endif

        temp_key.Set(&BSGS_CURRENT);
        temp_key.Add(&levy_step);

        if (temp_key.IsGreater(&n_range_end))
        {
            temp_key.Sub(&n_range_diff);
        }
        else if (temp_key.IsLower(&n_range_start))
        {
            temp_key.Add(&n_range_diff);
        }

        base_key.Set(&temp_key);
        BSGS_CURRENT.Set(&temp_key);

#if defined(_WIN64) && !defined(__CYGWIN__)
        ReleaseMutex(bsgs_thread);
#else
        pthread_mutex_unlock(&bsgs_thread);
#endif

        if (FLAGMATRIX)
        {
            aux_c = base_key.GetBase16();
            printf("[+] Thread 0x%s \n", aux_c);
            fflush(stdout);
            free(aux_c);
        }
        else
        {
            if (FLAGQUIET == 0)
            {
                aux_c = base_key.GetBase16();
                printf("\r[+] Thread 0x%s   \r", aux_c); // The \r here returns to the line's beginning
                fflush(stdout);
                free(aux_c);
                THREADOUTPUT = 1;
            }
        }

        base_point = secp->ComputePublicKey(&base_key);
        km.Set(&base_key);
        km.Neg();
        km.Add(&secp->order);
        km.Sub(&intaux);
        point_aux = secp->ComputePublicKey(&km);

        for (k = 0; k < bsgs_point_number; k++)
        {
            if (bsgs_found[k] == 0)
            {
                startP = secp->AddDirect(OriginalPointsBSGS[k], point_aux);
                uint32_t j = 0;

                while (j < cycles && bsgs_found[k] == 0)
                {
                    int i;

                    for (i = 0; i < hLength; i++)
                    {
                        dx[i].ModSub(&GSn[i].x, &startP.x);
                    }

                    dx[i].ModSub(&GSn[i].x, &startP.x);
                    dx[i + 1].ModSub(&_2GSn.x, &startP.x);

                    grp->ModInv();

                    pts[CPU_GRP_SIZE / 2] = startP;

                    for (i = 0; i < hLength; i++)
                    {
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

                    for (int i = 0; i < CPU_GRP_SIZE && bsgs_found[k] == 0; i++)
                    {
                        pts[i].x.Get32Bytes((unsigned char *)xpoint_raw);
                        r = bloom_check(&bloom_bP[((unsigned char)xpoint_raw[0])], xpoint_raw, 32);
                        if (r)
                        {
                            r = bsgs_secondcheck(&base_key, ((j * 1024) + i), k, &keyfound);
                            if (r)
                            {
                                hextemp = keyfound.GetBase16();
                                printf("\n[+] Thread Key found privkey %s\n", hextemp);
                                point_found = secp->ComputePublicKey(&keyfound);
                                aux_c = secp->GetPublicKeyHex(OriginalPointsBSGScompressed[k], point_found);
                                printf("[+] Publickey %s\n", aux_c);

#if defined(_WIN64) && !defined(__CYGWIN__)
                                WaitForSingleObject(write_keys, INFINITE);
#else
                                pthread_mutex_lock(&write_keys);
#endif

                                filekey = fopen("KEYFOUNDKEYFOUND.txt", "a+");
                                if (filekey != NULL)
                                {
                                    fprintf(filekey, "Key found privkey %s\nPublickey %s\n", hextemp, aux_c);
                                    fclose(filekey);
                                }
                                free(hextemp);
                                free(aux_c);

#if defined(_WIN64) && !defined(__CYGWIN__)
                                ReleaseMutex(write_keys);
#else
                                pthread_mutex_unlock(&write_keys);
#endif

                                bsgs_found[k] = 1;
                                salir = 1;
                                for (l = 0; l < bsgs_point_number && salir; l++)
                                {
                                    salir &= bsgs_found[l];
                                }
                                if (salir)
                                {
                                    printf("All points were found\n");
                                    exit(EXIT_FAILURE);
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
        }
        steps[thread_number] += 2;
    } while (1);

    ends[thread_number] = 1;
    delete grp;
    return NULL;
}

#if defined(_WIN64) && !defined(__CYGWIN__)
DWORD WINAPI thread_process_bsgs_dance(LPVOID vargp)
{
#else
void *thread_process_bsgs_dance(void *vargp)
{
#endif

    Point pts[CPU_GRP_SIZE];
    Int dx[CPU_GRP_SIZE / 2 + 1];
    Point pp, pn, startP, base_point, point_aux, point_found;
    FILE *filekey;
    struct tothread *tt;
    char xpoint_raw[32], *aux_c, *hextemp;
    Int base_key, keyfound, dy, dyn, _s, _p, km, intaux;
    IntGroup *grp = new IntGroup(CPU_GRP_SIZE / 2 + 1);
    uint32_t k, l, r, salir, thread_number, entrar, cycles;
    int hLength = (CPU_GRP_SIZE / 2 - 1);

    grp->Set(dx);

    tt = (struct tothread *)vargp;
    thread_number = tt->nt;
    free(tt);

    cycles = bsgs_aux / 1024;
    if (bsgs_aux % 1024 != 0)
    {
        cycles++;
    }

    intaux.Set(&BSGS_M_double);
    intaux.Mult(CPU_GRP_SIZE / 2);
    intaux.Add(&BSGS_M);

    entrar = 1;

    /*
        while base_key is less than n_range_end then:
    */
    do
    {
        r = rand() % 3;
#if defined(_WIN64) && !defined(__CYGWIN__)
        WaitForSingleObject(bsgs_thread, INFINITE);
#else
        pthread_mutex_lock(&bsgs_thread);
#endif
        switch (r)
        {
        case 0: // TOP
            if (n_range_end.IsGreater(&BSGS_CURRENT))
            {
                /*
                    n_range_end.Sub(&BSGS_N);
                    n_range_end.Sub(&BSGS_N);
                */
                n_range_end.Sub(&BSGS_N_double);
                if (n_range_end.IsLower(&BSGS_CURRENT))
                {
                    base_key.Set(&BSGS_CURRENT);
                }
                else
                {
                    base_key.Set(&n_range_end);
                }
            }
            else
            {
                entrar = 0;
            }
            break;
        case 1: // BOTTOM
            if (BSGS_CURRENT.IsLower(&n_range_end))
            {
                base_key.Set(&BSGS_CURRENT);
                // BSGS_N_double
                BSGS_CURRENT.Add(&BSGS_N_double);
                /*
                BSGS_CURRENT.Add(&BSGS_N);
                BSGS_CURRENT.Add(&BSGS_N);
                */
            }
            else
            {
                entrar = 0;
            }
            break;
        case 2: // random - middle
            base_key.Rand(&BSGS_CURRENT, &n_range_end);
            break;
        }
#if defined(_WIN64) && !defined(__CYGWIN__)
        ReleaseMutex(bsgs_thread);
#else
        pthread_mutex_unlock(&bsgs_thread);
#endif

        if (entrar == 0)
            break;

        if (FLAGMATRIX)
        {
            aux_c = base_key.GetBase16();
            printf("[+] Thread 0x%s \n", aux_c);
            fflush(stdout);
            free(aux_c);
        }
        else
        {
            if (FLAGQUIET == 0)
            {
                aux_c = base_key.GetBase16();
                printf("\r[+] Thread 0x%s   \r", aux_c);
                fflush(stdout);
                free(aux_c);
                THREADOUTPUT = 1;
            }
        }

        base_point = secp->ComputePublicKey(&base_key);

        km.Set(&base_key);
        km.Neg();

        km.Add(&secp->order);
        km.Sub(&intaux);
        point_aux = secp->ComputePublicKey(&km);

        for (k = 0; k < bsgs_point_number; k++)
        {
            if (bsgs_found[k] == 0)
            {
                startP = secp->AddDirect(OriginalPointsBSGS[k], point_aux);
                uint32_t j = 0;
                while (j < cycles && bsgs_found[k] == 0)
                {

                    int i;

                    for (i = 0; i < hLength; i++)
                    {
                        dx[i].ModSub(&GSn[i].x, &startP.x);
                    }
                    dx[i].ModSub(&GSn[i].x, &startP.x);    // For the first point
                    dx[i + 1].ModSub(&_2GSn.x, &startP.x); // For the next center point

                    // Grouped ModInv
                    grp->ModInv();

                    /*
                    We use the fact that P + i*G and P - i*G has the same deltax, so the same inverse
                    We compute key in the positive and negative way from the center of the group
                    */

                    // center point
                    pts[CPU_GRP_SIZE / 2] = startP;

                    for (i = 0; i < hLength; i++)
                    {

                        pp = startP;
                        pn = startP;

                        // P = startP + i*G
                        dy.ModSub(&GSn[i].y, &pp.y);

                        _s.ModMulK1(&dy, &dx[i]); // s = (p2.y-p1.y)*inverse(p2.x-p1.x);
                        _p.ModSquareK1(&_s);      // _p = pow2(s)

                        pp.x.ModNeg();
                        pp.x.ModAdd(&_p);
                        pp.x.ModSub(&GSn[i].x); // rx = pow2(s) - p1.x - p2.x;

#if 0
  pp.y.ModSub(&GSn[i].x,&pp.x);
  pp.y.ModMulK1(&_s);
  pp.y.ModSub(&GSn[i].y);           // ry = - p2.y - s*(ret.x-p2.x);
#endif

                        // P = startP - i*G  , if (x,y) = i*G then (x,-y) = -i*G
                        dyn.Set(&GSn[i].y);
                        dyn.ModNeg();
                        dyn.ModSub(&pn.y);

                        _s.ModMulK1(&dyn, &dx[i]); // s = (p2.y-p1.y)*inverse(p2.x-p1.x);
                        _p.ModSquareK1(&_s);       // _p = pow2(s)

                        pn.x.ModNeg();
                        pn.x.ModAdd(&_p);
                        pn.x.ModSub(&GSn[i].x); // rx = pow2(s) - p1.x - p2.x;

#if 0
  pn.y.ModSub(&GSn[i].x,&pn.x);
  pn.y.ModMulK1(&_s);
  pn.y.ModAdd(&GSn[i].y);          // ry = - p2.y - s*(ret.x-p2.x);
#endif

                        pts[CPU_GRP_SIZE / 2 + (i + 1)] = pp;
                        pts[CPU_GRP_SIZE / 2 - (i + 1)] = pn;
                    }

                    // First point (startP - (GRP_SZIE/2)*G)
                    pn = startP;
                    dyn.Set(&GSn[i].y);
                    dyn.ModNeg();
                    dyn.ModSub(&pn.y);

                    _s.ModMulK1(&dyn, &dx[i]);
                    _p.ModSquareK1(&_s);

                    pn.x.ModNeg();
                    pn.x.ModAdd(&_p);
                    pn.x.ModSub(&GSn[i].x);

#if 0
pn.y.ModSub(&GSn[i].x,&pn.x);
pn.y.ModMulK1(&_s);
pn.y.ModAdd(&GSn[i].y);
#endif

                    pts[0] = pn;

                    for (int i = 0; i < CPU_GRP_SIZE && bsgs_found[k] == 0; i++)
                    {
                        pts[i].x.Get32Bytes((unsigned char *)xpoint_raw);
                        r = bloom_check(&bloom_bP[((unsigned char)xpoint_raw[0])], xpoint_raw, 32);
                        if (r)
                        {
                            r = bsgs_secondcheck(&base_key, ((j * 1024) + i), k, &keyfound);
                            if (r)
                            {
                                hextemp = keyfound.GetBase16();
                                printf("[+] Thread Key found privkey %s   \n", hextemp);
                                point_found = secp->ComputePublicKey(&keyfound);
                                aux_c = secp->GetPublicKeyHex(OriginalPointsBSGScompressed[k], point_found);
                                printf("[+] Publickey %s\n", aux_c);
#if defined(_WIN64) && !defined(__CYGWIN__)
                                WaitForSingleObject(write_keys, INFINITE);
#else
                                pthread_mutex_lock(&write_keys);
#endif

                                filekey = fopen("KEYFOUNDKEYFOUND.txt", "a");
                                if (filekey != NULL)
                                {
                                    fprintf(filekey, "Key found privkey %s\nPublickey %s\n", hextemp, aux_c);
                                    fclose(filekey);
                                }
                                free(hextemp);
                                free(aux_c);
#if defined(_WIN64) && !defined(__CYGWIN__)
                                ReleaseMutex(write_keys);
#else
                                pthread_mutex_unlock(&write_keys);
#endif

                                bsgs_found[k] = 1;
                                salir = 1;
                                for (l = 0; l < bsgs_point_number && salir; l++)
                                {
                                    salir &= bsgs_found[l];
                                }
                                if (salir)
                                {
                                    printf("All points were found\n");
                                    exit(EXIT_FAILURE);
                                }
                            } // End if second check
                        } // End if first check

                    } // For for pts variable

                    // Next start point (startP += (bsSize*GRP_SIZE).G)

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
                } // while all the aMP points
            } // End if
        }
        steps[thread_number] += 2;
    } while (1);
    ends[thread_number] = 1;
    return NULL;
}

#if defined(_WIN64) && !defined(__CYGWIN__)
DWORD WINAPI thread_process_bsgs_backward(LPVOID vargp)
{
#else
void *thread_process_bsgs_backward(void *vargp)
{
#endif
    FILE *filekey;
    struct tothread *tt;
    char xpoint_raw[32], *aux_c, *hextemp;
    Int base_key, keyfound;
    Point base_point, point_aux, point_found;
    uint32_t k, l, r, salir, thread_number, entrar, cycles;

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

    tt = (struct tothread *)vargp;
    thread_number = tt->nt;
    free(tt);

    cycles = bsgs_aux / 1024;
    if (bsgs_aux % 1024 != 0)
    {
        cycles++;
    }

    intaux.Set(&BSGS_M_double);
    intaux.Mult(CPU_GRP_SIZE / 2);
    intaux.Add(&BSGS_M);

    entrar = 1;
    /*
        while base_key is less than n_range_end then:
    */
    do
    {

#if defined(_WIN64) && !defined(__CYGWIN__)
        WaitForSingleObject(bsgs_thread, INFINITE);
#else
        pthread_mutex_lock(&bsgs_thread);
#endif
        if (n_range_end.IsGreater(&n_range_start))
        {
            n_range_end.Sub(&BSGS_N_double);
            if (n_range_end.IsLower(&n_range_start))
            {
                base_key.Set(&n_range_start);
            }
            else
            {
                base_key.Set(&n_range_end);
            }
        }
        else
        {
            entrar = 0;
        }
#if defined(_WIN64) && !defined(__CYGWIN__)
        ReleaseMutex(bsgs_thread);
#else
        pthread_mutex_unlock(&bsgs_thread);
#endif
        if (entrar == 0)
            break;

        // In the Lévy flight thread, modify the output section:
        if (FLAGMATRIX)
        {
            aux_c = base_key.GetBase16();
            printf("[+] Thread 0x%s \n", aux_c);
            fflush(stdout);
            free(aux_c);
        }
        else
        {
            if (FLAGQUIET == 0)
            {
                aux_c = base_key.GetBase16();
                printf("\r[+] Thread 0x%s   \r", aux_c);
                fflush(stdout);
                free(aux_c);
                THREADOUTPUT = 1;
            }
        }

        base_point = secp->ComputePublicKey(&base_key);

        km.Set(&base_key);
        km.Neg();

        km.Add(&secp->order);
        km.Sub(&intaux);
        point_aux = secp->ComputePublicKey(&km);

        for (k = 0; k < bsgs_point_number; k++)
        {
            if (bsgs_found[k] == 0)
            {
                startP = secp->AddDirect(OriginalPointsBSGS[k], point_aux);
                uint32_t j = 0;
                while (j < cycles && bsgs_found[k] == 0)
                {
                    int i;
                    for (i = 0; i < hLength; i++)
                    {
                        dx[i].ModSub(&GSn[i].x, &startP.x);
                    }
                    dx[i].ModSub(&GSn[i].x, &startP.x);    // For the first point
                    dx[i + 1].ModSub(&_2GSn.x, &startP.x); // For the next center point

                    // Grouped ModInv
                    grp->ModInv();

                    /*
                    We use the fact that P + i*G and P - i*G has the same deltax, so the same inverse
                    We compute key in the positive and negative way from the center of the group
                    */

                    // center point
                    pts[CPU_GRP_SIZE / 2] = startP;

                    for (i = 0; i < hLength; i++)
                    {

                        pp = startP;
                        pn = startP;

                        // P = startP + i*G
                        dy.ModSub(&GSn[i].y, &pp.y);

                        _s.ModMulK1(&dy, &dx[i]); // s = (p2.y-p1.y)*inverse(p2.x-p1.x);
                        _p.ModSquareK1(&_s);      // _p = pow2(s)

                        pp.x.ModNeg();
                        pp.x.ModAdd(&_p);
                        pp.x.ModSub(&GSn[i].x); // rx = pow2(s) - p1.x - p2.x;

#if 0
  pp.y.ModSub(&GSn[i].x,&pp.x);
  pp.y.ModMulK1(&_s);
  pp.y.ModSub(&GSn[i].y);           // ry = - p2.y - s*(ret.x-p2.x);
#endif

                        // P = startP - i*G  , if (x,y) = i*G then (x,-y) = -i*G
                        dyn.Set(&GSn[i].y);
                        dyn.ModNeg();
                        dyn.ModSub(&pn.y);

                        _s.ModMulK1(&dyn, &dx[i]); // s = (p2.y-p1.y)*inverse(p2.x-p1.x);
                        _p.ModSquareK1(&_s);       // _p = pow2(s)

                        pn.x.ModNeg();
                        pn.x.ModAdd(&_p);
                        pn.x.ModSub(&GSn[i].x); // rx = pow2(s) - p1.x - p2.x;

#if 0
  pn.y.ModSub(&GSn[i].x,&pn.x);
  pn.y.ModMulK1(&_s);
  pn.y.ModAdd(&GSn[i].y);          // ry = - p2.y - s*(ret.x-p2.x);
#endif

                        pts[CPU_GRP_SIZE / 2 + (i + 1)] = pp;
                        pts[CPU_GRP_SIZE / 2 - (i + 1)] = pn;
                    }

                    // First point (startP - (GRP_SZIE/2)*G)
                    pn = startP;
                    dyn.Set(&GSn[i].y);
                    dyn.ModNeg();
                    dyn.ModSub(&pn.y);

                    _s.ModMulK1(&dyn, &dx[i]);
                    _p.ModSquareK1(&_s);

                    pn.x.ModNeg();
                    pn.x.ModAdd(&_p);
                    pn.x.ModSub(&GSn[i].x);

#if 0
pn.y.ModSub(&GSn[i].x,&pn.x);
pn.y.ModMulK1(&_s);
pn.y.ModAdd(&GSn[i].y);
#endif

                    pts[0] = pn;

                    for (int i = 0; i < CPU_GRP_SIZE && bsgs_found[k] == 0; i++)
                    {
                        pts[i].x.Get32Bytes((unsigned char *)xpoint_raw);
                        r = bloom_check(&bloom_bP[((unsigned char)xpoint_raw[0])], xpoint_raw, 32);
                        if (r)
                        {
                            r = bsgs_secondcheck(&base_key, ((j * 1024) + i), k, &keyfound);
                            if (r)
                            {
                                hextemp = keyfound.GetBase16();
                                printf("[+] Thread Key found privkey %s   \n", hextemp);
                                point_found = secp->ComputePublicKey(&keyfound);
                                aux_c = secp->GetPublicKeyHex(OriginalPointsBSGScompressed[k], point_found);
                                printf("[+] Publickey %s\n", aux_c);
#if defined(_WIN64) && !defined(__CYGWIN__)
                                WaitForSingleObject(write_keys, INFINITE);
#else
                                pthread_mutex_lock(&write_keys);
#endif

                                filekey = fopen("KEYFOUNDKEYFOUND.txt", "a");
                                if (filekey != NULL)
                                {
                                    fprintf(filekey, "Key found privkey %s\nPublickey %s\n", hextemp, aux_c);
                                    fclose(filekey);
                                }
                                free(hextemp);
                                free(aux_c);
#if defined(_WIN64) && !defined(__CYGWIN__)
                                ReleaseMutex(write_keys);
#else
                                pthread_mutex_unlock(&write_keys);
#endif

                                bsgs_found[k] = 1;
                                salir = 1;
                                for (l = 0; l < bsgs_point_number && salir; l++)
                                {
                                    salir &= bsgs_found[l];
                                }
                                if (salir)
                                {
                                    printf("All points were found\n");
                                    exit(EXIT_FAILURE);
                                }
                            } // End if second check
                        } // End if first check

                    } // For for pts variable

                    // Next start point (startP += (bsSize*GRP_SIZE).G)

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
                } // while all the aMP points
            } // End if
        }
        steps[thread_number] += 2;
    } while (1);
    ends[thread_number] = 1;
    return NULL;
}

#if defined(_WIN64) && !defined(__CYGWIN__)
DWORD WINAPI thread_process_bsgs_both(LPVOID vargp)
{
#else
void *thread_process_bsgs_both(void *vargp)
{
#endif
    FILE *filekey;
    struct tothread *tt;
    char xpoint_raw[32], *aux_c, *hextemp;
    Int base_key, keyfound;
    Point base_point, point_aux, point_found;
    uint32_t k, l, r, salir, thread_number, entrar, cycles;

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

    tt = (struct tothread *)vargp;
    thread_number = tt->nt;
    free(tt);

    cycles = bsgs_aux / 1024;
    if (bsgs_aux % 1024 != 0)
    {
        cycles++;
    }
    intaux.Set(&BSGS_M_double);
    intaux.Mult(CPU_GRP_SIZE / 2);
    intaux.Add(&BSGS_M);

    entrar = 1;

    /*
        while BSGS_CURRENT is less than n_range_end
    */
    do
    {

        r = rand() % 2;
#if defined(_WIN64) && !defined(__CYGWIN__)
        WaitForSingleObject(bsgs_thread, INFINITE);
#else
        pthread_mutex_lock(&bsgs_thread);
#endif
        switch (r)
        {
        case 0: // TOP
            if (n_range_end.IsGreater(&BSGS_CURRENT))
            {
                n_range_end.Sub(&BSGS_N_double);
                /*
                n_range_end.Sub(&BSGS_N);
                n_range_end.Sub(&BSGS_N);
                */
                if (n_range_end.IsLower(&BSGS_CURRENT))
                {
                    base_key.Set(&BSGS_CURRENT);
                }
                else
                {
                    base_key.Set(&n_range_end);
                }
            }
            else
            {
                entrar = 0;
            }
            break;
        case 1: // BOTTOM
            if (BSGS_CURRENT.IsLower(&n_range_end))
            {
                base_key.Set(&BSGS_CURRENT);
                // BSGS_N_double
                BSGS_CURRENT.Add(&BSGS_N_double);
                /*
                BSGS_CURRENT.Add(&BSGS_N);
                BSGS_CURRENT.Add(&BSGS_N);
                */
            }
            else
            {
                entrar = 0;
            }
            break;
        }
#if defined(_WIN64) && !defined(__CYGWIN__)
        ReleaseMutex(bsgs_thread);
#else
        pthread_mutex_unlock(&bsgs_thread);
#endif

        if (entrar == 0)
            break;

        if (FLAGMATRIX)
        {
            aux_c = base_key.GetBase16();
            printf("[+] Thread 0x%s \n", aux_c);
            fflush(stdout);
            free(aux_c);
        }
        else
        {
            if (FLAGQUIET == 0)
            {
                aux_c = base_key.GetBase16();
                printf("\r[+] Thread 0x%s   \r", aux_c);
                fflush(stdout);
                free(aux_c);
                THREADOUTPUT = 1;
            }
        }

        base_point = secp->ComputePublicKey(&base_key);

        km.Set(&base_key);
        km.Neg();

        km.Add(&secp->order);
        km.Sub(&intaux);
        point_aux = secp->ComputePublicKey(&km);

        for (k = 0; k < bsgs_point_number; k++)
        {
            if (bsgs_found[k] == 0)
            {
                startP = secp->AddDirect(OriginalPointsBSGS[k], point_aux);
                uint32_t j = 0;
                while (j < cycles && bsgs_found[k] == 0)
                {
                    int i;
                    for (i = 0; i < hLength; i++)
                    {
                        dx[i].ModSub(&GSn[i].x, &startP.x);
                    }
                    dx[i].ModSub(&GSn[i].x, &startP.x);    // For the first point
                    dx[i + 1].ModSub(&_2GSn.x, &startP.x); // For the next center point

                    // Grouped ModInv
                    grp->ModInv();

                    /*
                    We use the fact that P + i*G and P - i*G has the same deltax, so the same inverse
                    We compute key in the positive and negative way from the center of the group
                    */

                    // center point
                    pts[CPU_GRP_SIZE / 2] = startP;

                    for (i = 0; i < hLength; i++)
                    {

                        pp = startP;
                        pn = startP;

                        // P = startP + i*G
                        dy.ModSub(&GSn[i].y, &pp.y);

                        _s.ModMulK1(&dy, &dx[i]); // s = (p2.y-p1.y)*inverse(p2.x-p1.x);
                        _p.ModSquareK1(&_s);      // _p = pow2(s)

                        pp.x.ModNeg();
                        pp.x.ModAdd(&_p);
                        pp.x.ModSub(&GSn[i].x); // rx = pow2(s) - p1.x - p2.x;

#if 0
	  pp.y.ModSub(&GSn[i].x,&pp.x);
	  pp.y.ModMulK1(&_s);
	  pp.y.ModSub(&GSn[i].y);           // ry = - p2.y - s*(ret.x-p2.x);
#endif

                        // P = startP - i*G  , if (x,y) = i*G then (x,-y) = -i*G
                        dyn.Set(&GSn[i].y);
                        dyn.ModNeg();
                        dyn.ModSub(&pn.y);

                        _s.ModMulK1(&dyn, &dx[i]); // s = (p2.y-p1.y)*inverse(p2.x-p1.x);
                        _p.ModSquareK1(&_s);       // _p = pow2(s)

                        pn.x.ModNeg();
                        pn.x.ModAdd(&_p);
                        pn.x.ModSub(&GSn[i].x); // rx = pow2(s) - p1.x - p2.x;

#if 0
	  pn.y.ModSub(&GSn[i].x,&pn.x);
	  pn.y.ModMulK1(&_s);
	  pn.y.ModAdd(&GSn[i].y);          // ry = - p2.y - s*(ret.x-p2.x);
#endif

                        pts[CPU_GRP_SIZE / 2 + (i + 1)] = pp;
                        pts[CPU_GRP_SIZE / 2 - (i + 1)] = pn;
                    }

                    // First point (startP - (GRP_SZIE/2)*G)
                    pn = startP;
                    dyn.Set(&GSn[i].y);
                    dyn.ModNeg();
                    dyn.ModSub(&pn.y);

                    _s.ModMulK1(&dyn, &dx[i]);
                    _p.ModSquareK1(&_s);

                    pn.x.ModNeg();
                    pn.x.ModAdd(&_p);
                    pn.x.ModSub(&GSn[i].x);

#if 0
	pn.y.ModSub(&GSn[i].x,&pn.x);
	pn.y.ModMulK1(&_s);
	pn.y.ModAdd(&GSn[i].y);
#endif

                    pts[0] = pn;

                    for (int i = 0; i < CPU_GRP_SIZE && bsgs_found[k] == 0; i++)
                    {
                        pts[i].x.Get32Bytes((unsigned char *)xpoint_raw);
                        r = bloom_check(&bloom_bP[((unsigned char)xpoint_raw[0])], xpoint_raw, 32);
                        if (r)
                        {
                            r = bsgs_secondcheck(&base_key, ((j * 1024) + i), k, &keyfound);
                            if (r)
                            {
                                hextemp = keyfound.GetBase16();
                                printf("[+] Thread Key found privkey %s   \n", hextemp);
                                point_found = secp->ComputePublicKey(&keyfound);
                                aux_c = secp->GetPublicKeyHex(OriginalPointsBSGScompressed[k], point_found);
                                printf("[+] Publickey %s\n", aux_c);
#if defined(_WIN64) && !defined(__CYGWIN__)
                                WaitForSingleObject(write_keys, INFINITE);
#else
                                pthread_mutex_lock(&write_keys);
#endif

                                filekey = fopen("KEYFOUNDKEYFOUND.txt", "a");
                                if (filekey != NULL)
                                {
                                    fprintf(filekey, "Key found privkey %s\nPublickey %s\n", hextemp, aux_c);
                                    fclose(filekey);
                                }
                                free(hextemp);
                                free(aux_c);
#if defined(_WIN64) && !defined(__CYGWIN__)
                                ReleaseMutex(write_keys);
#else
                                pthread_mutex_unlock(&write_keys);
#endif

                                bsgs_found[k] = 1;
                                salir = 1;
                                for (l = 0; l < bsgs_point_number && salir; l++)
                                {
                                    salir &= bsgs_found[l];
                                }
                                if (salir)
                                {
                                    printf("All points were found\n");
                                    exit(EXIT_FAILURE);
                                }
                            } // End if second check
                        } // End if first check

                    } // For for pts variable

                    // Next start point (startP += (bsSize*GRP_SIZE).G)

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
                } // while all the aMP points
            } // End if
        }
        steps[thread_number] += 2;
    } while (1);
    ends[thread_number] = 1;
    return NULL;
}

/* This function takes in three parameters:

buffer: a pointer to a char array where the minikey will be stored.
rawbuffer: a pointer to a char array that contains the raw data.
length: an integer representing the length of the raw data.
The function is designed to convert the raw data using a lookup table (Ccoinbuffer) and store the result in the buffer.
*/
void set_minikey(char *buffer, char *rawbuffer, int length)
{
    for (int i = 0; i < length; i++)
    {
        buffer[i] = Ccoinbuffer[(uint8_t)rawbuffer[i]];
    }
}

/* This function takes in three parameters:

buffer: a pointer to a char array where the minikey will be stored.
rawbuffer: a pointer to a char array that contains the raw data.
index: an integer representing the index of the raw data array to be incremented.
The function is designed to increment the value at the specified index in the raw data array,
and update the corresponding value in the buffer using a lookup table (Ccoinbuffer).
If the value at the specified index exceeds 57, it is reset to 0x00 and the function recursively
calls itself to increment the value at the previous index, unless the index is already 0, in which
case the function returns false. The function returns true otherwise.
*/

bool increment_minikey_index(char *buffer, char *rawbuffer, int index)
{
    if (rawbuffer[index] < 57)
    {
        rawbuffer[index]++;
        buffer[index] = Ccoinbuffer[(uint8_t)rawbuffer[index]];
    }
    else
    {
        rawbuffer[index] = 0x00;
        buffer[index] = Ccoinbuffer[0];
        if (index > 0)
        {
            return increment_minikey_index(buffer, rawbuffer, index - 1);
        }
        else
        {
            return false;
        }
    }
    return true;
}

/* This function takes in a single parameter:

rawbuffer: a pointer to a char array that contains the raw data.
The function is designed to increment the values in the raw data array
using a lookup table (minikeyN), while also handling carry-over to the
previous element in the array if necessary. The maximum number of iterations
is limited by minikey_n_limit.


*/
void increment_minikey_N(char *rawbuffer)
{
    int i = 20, j = 0;
    while (i > 0 && j < minikey_n_limit)
    {
        rawbuffer[i] = rawbuffer[i] + minikeyN[i];
        if (rawbuffer[i] > 57)
        { // Handling carry-over if value exceeds 57
            rawbuffer[i] = rawbuffer[i] % 58;
            rawbuffer[i - 1]++;
        }
        i--;
        j++;
    }
}

#define BUFFMINIKEY(buff, src)                                                                                  \
    (buff)[0] = (uint32_t)src[0] << 24 | (uint32_t)src[1] << 16 | (uint32_t)src[2] << 8 | (uint32_t)src[3];     \
    (buff)[1] = (uint32_t)src[4] << 24 | (uint32_t)src[5] << 16 | (uint32_t)src[6] << 8 | (uint32_t)src[7];     \
    (buff)[2] = (uint32_t)src[8] << 24 | (uint32_t)src[9] << 16 | (uint32_t)src[10] << 8 | (uint32_t)src[11];   \
    (buff)[3] = (uint32_t)src[12] << 24 | (uint32_t)src[13] << 16 | (uint32_t)src[14] << 8 | (uint32_t)src[15]; \
    (buff)[4] = (uint32_t)src[16] << 24 | (uint32_t)src[17] << 16 | (uint32_t)src[18] << 8 | (uint32_t)src[19]; \
    (buff)[5] = (uint32_t)src[20] << 24 | (uint32_t)src[21] << 16 | 0x8000;                                     \
    (buff)[6] = 0;                                                                                              \
    (buff)[7] = 0;                                                                                              \
    (buff)[8] = 0;                                                                                              \
    (buff)[9] = 0;                                                                                              \
    (buff)[10] = 0;                                                                                             \
    (buff)[11] = 0;                                                                                             \
    (buff)[12] = 0;                                                                                             \
    (buff)[13] = 0;                                                                                             \
    (buff)[14] = 0;                                                                                             \
    (buff)[15] = 0xB0; // 176 bits => 22 BYTES

void sha256sse_22(uint8_t *src0, uint8_t *src1, uint8_t *src2, uint8_t *src3, uint8_t *dst0, uint8_t *dst1, uint8_t *dst2, uint8_t *dst3)
{
    uint32_t b0[16];
    uint32_t b1[16];
    uint32_t b2[16];
    uint32_t b3[16];
    BUFFMINIKEY(b0, src0);
    BUFFMINIKEY(b1, src1);
    BUFFMINIKEY(b2, src2);
    BUFFMINIKEY(b3, src3);
    sha256sse_1B(b0, b1, b2, b3, dst0, dst1, dst2, dst3);
}

#define BUFFMINIKEYCHECK(buff, src)                                                                             \
    (buff)[0] = (uint32_t)src[0] << 24 | (uint32_t)src[1] << 16 | (uint32_t)src[2] << 8 | (uint32_t)src[3];     \
    (buff)[1] = (uint32_t)src[4] << 24 | (uint32_t)src[5] << 16 | (uint32_t)src[6] << 8 | (uint32_t)src[7];     \
    (buff)[2] = (uint32_t)src[8] << 24 | (uint32_t)src[9] << 16 | (uint32_t)src[10] << 8 | (uint32_t)src[11];   \
    (buff)[3] = (uint32_t)src[12] << 24 | (uint32_t)src[13] << 16 | (uint32_t)src[14] << 8 | (uint32_t)src[15]; \
    (buff)[4] = (uint32_t)src[16] << 24 | (uint32_t)src[17] << 16 | (uint32_t)src[18] << 8 | (uint32_t)src[19]; \
    (buff)[5] = (uint32_t)src[20] << 24 | (uint32_t)src[21] << 16 | (uint32_t)src[22] << 8 | 0x80;              \
    (buff)[6] = 0;                                                                                              \
    (buff)[7] = 0;                                                                                              \
    (buff)[8] = 0;                                                                                              \
    (buff)[9] = 0;                                                                                              \
    (buff)[10] = 0;                                                                                             \
    (buff)[11] = 0;                                                                                             \
    (buff)[12] = 0;                                                                                             \
    (buff)[13] = 0;                                                                                             \
    (buff)[14] = 0;                                                                                             \
    (buff)[15] = 0xB8; // 184 bits => 23 BYTES

void sha256sse_23(uint8_t *src0, uint8_t *src1, uint8_t *src2, uint8_t *src3, uint8_t *dst0, uint8_t *dst1, uint8_t *dst2, uint8_t *dst3)
{
    uint32_t b0[16];
    uint32_t b1[16];
    uint32_t b2[16];
    uint32_t b3[16];
    BUFFMINIKEYCHECK(b0, src0);
    BUFFMINIKEYCHECK(b1, src1);
    BUFFMINIKEYCHECK(b2, src2);
    BUFFMINIKEYCHECK(b3, src3);
    sha256sse_1B(b0, b1, b2, b3, dst0, dst1, dst2, dst3);
}

void menu()
{
    printf("\nUsage:\n");
    printf("-h          show this help\n");
    printf("-B Mode     BSGS now have some modes <sequential, backward, both, random, dance>\n");
    printf("-b bits     For some puzzles you only need some numbers of bits in the test keys.\n");
    printf("-c crypto   Search for specific crypto. <btc, eth> valid only w/ -m address\n");
    printf("-C mini     Set the minikey Base only 22 character minikeys, ex: SRPqx8QiwnW4WNWnTVa2W5\n");
    printf("-8 alpha    Set the bas58 alphabet for minikeys\n");
    printf("-e          Enable endomorphism search (Only for address, rmd160 and vanity)\n");
    printf("-f file     Specify file name with addresses or xpoints or uncompressed public keys\n");
    printf("-I stride   Stride for xpoint, rmd160 and address, this option don't work with bsgs\n");
    printf("-k value    Use this only with bsgs mode, k value is factor for M, more speed but more RAM use wisely\n");
    printf("-l look     What type of address/hash160 are you looking for <compress, uncompress, both> Only for rmd160 and address\n");
    printf("-m mode     mode of search for cryptos. (bsgs, xpoint, rmd160, address, vanity) default: address\n");
    printf("-M          Matrix screen, feel like a h4x0r, but performance will dropped\n");
    printf("-n number   Check for N sequential numbers before the random chosen, this only works with -R option\n");
    printf("            Use -n to set the N for the BSGS process. Bigger N more RAM needed\n");
    printf("-q          Quiet the thread output\n");
    printf("-r SR:EN    StarRange:EndRange, the end range can be omitted for search from start range to N-1 ECC value\n");
    printf("-R          Random, this is the default behavior\n");
    printf("-s ns       Number of seconds for the stats output, 0 to omit output.\n");
    printf("-S          S is for SAVING in files BSGS data (Bloom filters and bPtable)\n");
    printf("-6          to skip sha256 Checksum on data files");
    printf("-t tn       Threads number, must be a positive integer\n");
    printf("-v value    Search for vanity Address, only with -m vanity\n");
    printf("-z value    Bloom size multiplier, only address,rmd160,vanity, xpoint, value >= 1\n");
    printf("-o          optimized prime mode, uses prime number as step count\n");
    printf("-O value    Starting prime number for optimized prime mode (used with -o)\n");
    printf("-P pubkey   takes publickeys from cmd line seperated by ,\n");
    printf("\nExample:\n\n");
    printf("./keyhunt -m rmd160 -f tests/unsolvedpuzzles.rmd -b 66 -l compress -R -q -t 8\n\n");
    printf("This line runs the program with 8 threads from the range 20000000000000000 to 40000000000000000 without stats output\n\n");
    printf("Developed by AlbertoBSD\tTips BTC: 1Coffee1jV4gB5gaXfHgSHDz9xx9QSECVW\n");
    printf("Thanks to Iceland always helping and sharing his ideas.\nTips to Iceland: bc1q39meky2mn5qjq704zz0nnkl0v7kj4uz6r529at\n\n");
    exit(EXIT_FAILURE);
}

bool vanityrmdmatch(unsigned char *rmdhash)
{
    bool r = false;
    int i, j, cmpA, cmpB, result;
    result = bloom_check(vanity_bloom, rmdhash, vanity_rmd_minimun_bytes_check_length);
    switch (result)
    {
    case -1:
        fprintf(stderr, "[E] Bloom is not initialized\n");
        exit(EXIT_FAILURE);
        break;
    case 1:
        for (i = 0; i < vanity_rmd_targets && !r; i++)
        {
            for (j = 0; j < vanity_rmd_limits[i] && !r; j++)
            {
                cmpA = memcmp(vanity_rmd_limit_values_A[i][j], rmdhash, 20);
                cmpB = memcmp(vanity_rmd_limit_values_B[i][j], rmdhash, 20);
                if (cmpA <= 0 && cmpB >= 0)
                {
                    // if(FLAGDEBUG ) printf("\n\n[D] cmpA = %i, cmpB = %i \n\n",cmpA,cmpB);
                    r = true;
                }
            }
        }
        break;
    default:
        r = false;
        break;
    }
    return r;
}

// Utility function to convert binary pubkeys back to readable format
void convert_bin_to_txt(const char *bin_file, const char *txt_file)
{
    FILE *bin = fopen(bin_file, "rb");
    FILE *txt = fopen(txt_file, "w");

    if (!bin || !txt)
    {
        printf("Error opening files for conversion\n");
        return;
    }

    unsigned char pubkey[33];
    char hex_pubkey[67];

    while (fread(pubkey, 1, 33, bin) == 33)
    {
        // Convert first byte to hex
        sprintf(hex_pubkey, "%02x", pubkey[0]);

        // Convert remaining 32 bytes to hex
        for (int i = 1; i < 33; i++)
        {
            sprintf(hex_pubkey + (i * 2), "%02x", pubkey[i]);
        }

        fprintf(txt, "%s\n", hex_pubkey);
    }

    fclose(bin);
    fclose(txt);
}

void writevanitykey(bool compressed, Int *key)
{
    Point publickey;
    FILE *keys;
    char *hextemp, *hexrmd, public_key_hex[131], address[50], rmdhash[20];
    hextemp = key->GetBase16();
    publickey = secp->ComputePublicKey(key);
    secp->GetPublicKeyHex(compressed, publickey, public_key_hex);

    secp->GetHash160(P2PKH, compressed, publickey, (uint8_t *)rmdhash);
    hexrmd = tohex(rmdhash, 20);
    rmd160toaddress_dst(rmdhash, address);

#if defined(_WIN64) && !defined(__CYGWIN__)
    WaitForSingleObject(write_keys, INFINITE);
#else
    pthread_mutex_lock(&write_keys);
#endif
    keys = fopen("VANITYKEYFOUND.txt", "a+");
    if (keys != NULL)
    {
        fprintf(keys, "Vanity Private Key: %s\npubkey: %s\nAddress %s\nrmd160 %s\n", hextemp, public_key_hex, address, hexrmd);
        fclose(keys);
    }
    printf("\nVanity Private Key: %s\npubkey: %s\nAddress %s\nrmd160 %s\n", hextemp, public_key_hex, address, hexrmd);

#if defined(_WIN64) && !defined(__CYGWIN__)
    ReleaseMutex(write_keys);
#else
    pthread_mutex_unlock(&write_keys);
#endif
    free(hextemp);
    free(hexrmd);
}

int addvanity(char *target)
{
    unsigned char raw_value_A[50], raw_value_B[50];
    char target_copy[50];
    int stringsize, targetsize, j, r = 0;
    size_t raw_value_length;
    int values_A_size = 0, values_B_size = 0, minimun_bytes;
    raw_value_length = 50;
    targetsize = strlen(target);
    stringsize = targetsize;
    memset(raw_value_A, 0, 50);
    memset(target_copy, 0, 50);
    if (targetsize >= 30)
    {
        return 0;
    }
    memcpy(target_copy, target, targetsize);
    j = 0;
    vanity_address_targets = (char **)realloc(vanity_address_targets, (vanity_rmd_targets + 1) * sizeof(char *));
    vanity_address_targets[vanity_rmd_targets] = NULL;
    checkpointer((void *)vanity_address_targets, __FILE__, "realloc", "vanity_address_targets", __LINE__ - 1);
    vanity_rmd_limits = (int *)realloc(vanity_rmd_limits, (vanity_rmd_targets + 1) * sizeof(int));
    vanity_rmd_limits[vanity_rmd_targets] = 0;
    checkpointer((void *)vanity_rmd_limits, __FILE__, "realloc", "vanity_rmd_limits", __LINE__ - 1);
    vanity_rmd_limit_values_A = (uint8_t ***)realloc(vanity_rmd_limit_values_A, (vanity_rmd_targets + 1) * sizeof(unsigned char *));
    checkpointer((void *)vanity_rmd_limit_values_A, __FILE__, "realloc", "vanity_rmd_limit_values_A", __LINE__ - 1);
    vanity_rmd_limit_values_A[vanity_rmd_targets] = NULL;
    vanity_rmd_limit_values_B = (uint8_t ***)realloc(vanity_rmd_limit_values_B, (vanity_rmd_targets + 1) * sizeof(unsigned char *));
    checkpointer((void *)vanity_rmd_limit_values_B, __FILE__, "realloc", "vanity_rmd_limit_values_B", __LINE__ - 1);
    vanity_rmd_limit_values_B[vanity_rmd_targets] = NULL;
    do
    {
        raw_value_length = 50;
        b58tobin(raw_value_A, &raw_value_length, target_copy, stringsize);
        if (raw_value_length < 25)
        {
            target_copy[stringsize] = '1';
            stringsize++;
        }
        if (raw_value_length == 25)
        {
            b58tobin(raw_value_A, &raw_value_length, target_copy, stringsize);

            vanity_rmd_limit_values_A[vanity_rmd_targets] = (uint8_t **)realloc(vanity_rmd_limit_values_A[vanity_rmd_targets], (j + 1) * sizeof(unsigned char *));
            checkpointer((void *)vanity_rmd_limit_values_A[vanity_rmd_targets], __FILE__, "realloc", "vanity_rmd_limit_values_A", __LINE__ - 1);
            vanity_rmd_limit_values_A[vanity_rmd_targets][j] = (uint8_t *)calloc(20, 1);
            checkpointer((void *)vanity_rmd_limit_values_A[vanity_rmd_targets][j], __FILE__, "realloc", "vanity_rmd_limit_values_A", __LINE__ - 1);

            memcpy(vanity_rmd_limit_values_A[vanity_rmd_targets][j], raw_value_A + 1, 20);

            j++;
            values_A_size = j;
            target_copy[stringsize] = '1';
            stringsize++;
        }
    } while (raw_value_length <= 25);

    stringsize = targetsize;
    memset(raw_value_B, 0, 50);
    memset(target_copy, 0, 50);
    memcpy(target_copy, target, targetsize);

    j = 0;
    do
    {
        raw_value_length = 50;
        b58tobin(raw_value_B, &raw_value_length, target_copy, stringsize);
        if (raw_value_length < 25)
        {
            target_copy[stringsize] = 'z';
            stringsize++;
        }
        if (raw_value_length == 25)
        {

            b58tobin(raw_value_B, &raw_value_length, target_copy, stringsize);
            vanity_rmd_limit_values_B[vanity_rmd_targets] = (uint8_t **)realloc(vanity_rmd_limit_values_B[vanity_rmd_targets], (j + 1) * sizeof(unsigned char *));
            checkpointer((void *)vanity_rmd_limit_values_B[vanity_rmd_targets], __FILE__, "realloc", "vanity_rmd_limit_values_B", __LINE__ - 1);
            checkpointer((void *)vanity_rmd_limit_values_B[vanity_rmd_targets], __FILE__, "realloc", "vanity_rmd_limit_values_B", __LINE__ - 1);
            vanity_rmd_limit_values_B[vanity_rmd_targets][j] = (uint8_t *)calloc(20, 1);
            checkpointer((void *)vanity_rmd_limit_values_B[vanity_rmd_targets][j], __FILE__, "calloc", "vanity_rmd_limit_values_B", __LINE__ - 1);
            memcpy(vanity_rmd_limit_values_B[vanity_rmd_targets][j], raw_value_B + 1, 20);

            j++;
            values_B_size = j;

            target_copy[stringsize] = 'z';
            stringsize++;
        }
    } while (raw_value_length <= 25);

    if (values_A_size >= 1 && values_B_size >= 1)
    {
        if (values_A_size != values_B_size)
        {
            if (values_A_size > values_B_size)
                r = values_B_size;
            else
                r = values_A_size;
        }
        else
        {
            r = values_A_size;
        }
        for (j = 0; j < r; j++)
        {
            minimun_bytes = minimum_same_bytes(vanity_rmd_limit_values_A[vanity_rmd_targets][j], vanity_rmd_limit_values_B[vanity_rmd_targets][j], 20);
            if (minimun_bytes < vanity_rmd_minimun_bytes_check_length)
            {
                vanity_rmd_minimun_bytes_check_length = minimun_bytes;
            }
        }
        vanity_address_targets[vanity_rmd_targets] = (char *)calloc(targetsize + 1, sizeof(char));
        checkpointer((void *)vanity_address_targets[vanity_rmd_targets], __FILE__, "calloc", "vanity_address_targets", __LINE__ - 1);
        memcpy(vanity_address_targets[vanity_rmd_targets], target, targetsize + 1); // +1 to copy the null character
        vanity_rmd_limits[vanity_rmd_targets] = r;
        vanity_rmd_total += r;
        vanity_rmd_targets++;
    }
    else
    {
        for (j = 0; j < values_A_size; j++)
        {
            free(vanity_rmd_limit_values_A[vanity_rmd_targets][j]);
        }
        free(vanity_rmd_limit_values_A[vanity_rmd_targets]);
        vanity_rmd_limit_values_A[vanity_rmd_targets] = NULL;

        for (j = 0; j < values_B_size; j++)
        {
            free(vanity_rmd_limit_values_B[vanity_rmd_targets][j]);
        }
        free(vanity_rmd_limit_values_B[vanity_rmd_targets]);
        vanity_rmd_limit_values_B[vanity_rmd_targets] = NULL;
        r = 0;
    }
    return r;
}

/*
A and B are binary o string data pointers
length the max lenght to check.

Caller must by sure that the pointer are valid and have at least length bytes readebles witout causing overflow
*/
int minimum_same_bytes(unsigned char *A, unsigned char *B, int length)
{
    int minBytes = 0; // Assume initially that all bytes are the same
    if (A == NULL || B == NULL)
    { // In case of some NULL pointer
        return 0;
    }
    for (int i = 0; i < length; i++)
    {
        if (A[i] != B[i])
        {
            break; // Exit the loop since we found a mismatch
        }
        minBytes++; // Update the minimum number of bytes where data is the same
    }

    return minBytes;
}

void checkpointer(void *ptr, const char *file, const char *function, const char *name, int line)
{
    if (ptr == NULL)
    {
        fprintf(stderr, "[E] error in file %s, %s pointer %s on line %i\n", file, function, name, line);
        exit(EXIT_FAILURE);
    }
}

void write_pubkey_binary(unsigned char *pubkey_bytes)
{
    if (pubkeyfile_bin != NULL)
    {
        fwrite(pubkey_bytes, 1, 33, pubkeyfile_bin);
        pubkeys_generated++;

        if (pubkeys_generated >= max_pubkeys_to_generate)
        {
            printf("\n[+] Generated %llu public keys. Stopping as requested.\n", pubkeys_generated);
            fclose(pubkeyfile_bin);
            exit(EXIT_SUCCESS);
        }
    }
}

void writekey(bool compressed, Int *key)
{
    Point publickey;
    FILE *keys;
    char *hextemp, *hexrmd, public_key_hex[132], address[50], rmdhash[20];
    memset(address, 0, 50);
    memset(public_key_hex, 0, 132);
    hextemp = key->GetBase16();
    publickey = secp->ComputePublicKey(key);
    secp->GetPublicKeyHex(compressed, publickey, public_key_hex);
    secp->GetHash160(P2PKH, compressed, publickey, (uint8_t *)rmdhash);
    hexrmd = tohex(rmdhash, 20);
    rmd160toaddress_dst(rmdhash, address);

#if defined(_WIN64) && !defined(__CYGWIN__)
    WaitForSingleObject(write_keys, INFINITE);
#else
    pthread_mutex_lock(&write_keys);
#endif
    keys = fopen("KEYFOUNDKEYFOUND.txt", "a+");
    if (keys != NULL)
    {
        fprintf(keys, "Private Key: %s\npubkey: %s\nAddress %s\nrmd160 %s\n", hextemp, public_key_hex, address, hexrmd);
        fclose(keys);
    }
    printf("\nHit! Private Key: %s\npubkey: %s\nAddress %s\nrmd160 %s\n", hextemp, public_key_hex, address, hexrmd);

#if defined(_WIN64) && !defined(__CYGWIN__)
    ReleaseMutex(write_keys);
#else
    pthread_mutex_unlock(&write_keys);
#endif
    free(hextemp);
    free(hexrmd);
}

void writekeyeth(Int *key)
{
    Point publickey;
    FILE *keys;
    char *hextemp, address[43], hash[20];
    hextemp = key->GetBase16();
    publickey = secp->ComputePublicKey(key);
    generate_binaddress_eth(publickey, (unsigned char *)hash);
    address[0] = '0';
    address[1] = 'x';
    tohex_dst(hash, 20, address + 2);

#if defined(_WIN64) && !defined(__CYGWIN__)
    WaitForSingleObject(write_keys, INFINITE);
#else
    pthread_mutex_lock(&write_keys);
#endif
    keys = fopen("KEYFOUNDKEYFOUND.txt", "a+");
    if (keys != NULL)
    {
        fprintf(keys, "Private Key: %s\naddress: %s\n", hextemp, address);
        fclose(keys);
    }
    printf("\n Hit!!!! Private Key: %s\naddress: %s\n", hextemp, address);
#if defined(_WIN64) && !defined(__CYGWIN__)
    ReleaseMutex(write_keys);
#else
    pthread_mutex_unlock(&write_keys);
#endif
    free(hextemp);
}

bool isBase58(char c)
{
    // Define the base58 set
    const char base58Set[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    // Check if the character is in the base58 set
    return strchr(base58Set, c) != NULL;
}

bool isValidBase58String(char *str)
{
    int len = strlen(str);
    bool continuar = true;
    for (int i = 0; i < len && continuar; i++)
    {
        continuar = isBase58(str[i]);
    }
    return continuar;
}

bool processOneVanity()
{
    int i, k;
    if (vanity_rmd_targets == 0)
    {
        fprintf(stderr, "[E] There aren't any vanity targets\n");
        return false;
    }

    if (!initBloomFilter(vanity_bloom, vanity_rmd_total))
        return false;

    for (i = 0; i < vanity_rmd_targets; i++)
    {
        for (k = 0; k < vanity_rmd_limits[i]; k++)
        {
            bloom_add(vanity_bloom, vanity_rmd_limit_values_A[i][k], vanity_rmd_minimun_bytes_check_length);
        }
    }
    return true;
}

bool readFileVanity(char *fileName)
{
    FILE *fileDescriptor;
    int i, k, len;
    char aux[100], *hextemp;

    fileDescriptor = fopen(fileName, "r");
    if (fileDescriptor == NULL)
    {
        if (vanity_rmd_targets == 0)
        {
            fprintf(stderr, "[E] There aren't any vanity targets\n");
            return false;
        }
    }
    else
    {
        while (!feof(fileDescriptor))
        {
            hextemp = fgets(aux, 100, fileDescriptor);
            if (hextemp == aux)
            {
                trim(aux, " \t\n\r");
                len = strlen(aux);
                if (len > 0 && len < 36)
                {
                    if (isValidBase58String(aux))
                    {
                        addvanity(aux);
                    }
                    else
                    {
                        fprintf(stderr, "[E] the string \"%s\" is not valid Base58, omiting it\n", aux);
                    }
                }
            }
        }
        fclose(fileDescriptor);
    }

    N = vanity_rmd_total;
    if (!initBloomFilter(vanity_bloom, N))
        return false;

    for (i = 0; i < vanity_rmd_targets; i++)
    {
        for (k = 0; k < vanity_rmd_limits[i]; k++)
        {
            bloom_add(vanity_bloom, vanity_rmd_limit_values_A[i][k], vanity_rmd_minimun_bytes_check_length);
        }
    }
    return true;
}

bool readFileAddress(char *fileName)
{
    // Check if we're in subtract bloom mode
    if (FLAGSUBTRACTBLOOM) {
        return loadSubtractedKeysToBloom();
    }
    
    FILE *fileDescriptor;
    char fileBloomName[30];
    uint8_t checksum[32], hexPrefix[9];
    char dataChecksum[32], bloomChecksum[32];
    size_t bytesRead;
    uint64_t dataSize;
    /*
        if the FLAGSAVEREADFILE is Set to 1 we need to the checksum and check if we have that information already saved
    */
    if (FLAGSAVEREADFILE)
    { /* if the flag is set to REAd and SAVE the file firs we need to check it the file exist*/
        if (!sha256_file((const char *)fileName, checksum))
        {
            fprintf(stderr, "[E] sha256_file error line %i\n", __LINE__ - 1);
            return false;
        }
        tohex_dst((char *)checksum, 4, (char *)hexPrefix); // we save the prefix (last fourt bytes) hexadecimal value
        snprintf(fileBloomName, 30, "data_%s.dat", hexPrefix);
        fileDescriptor = fopen(fileBloomName, "rb");
        if (fileDescriptor != NULL)
        {
            printf("[+] Reading file %s\n", fileBloomName);

            // read bloom checksum (expected value to be checked)
            // read bloom filter structure
            // read bloom filter data
            // calculate checksum of the current readed data
            // Compare checksums
            // read data checksum (expected value to be checked)
            // read data size
            // read data
            // compare the expected datachecksum againts the current data checksum
            // compare the expected bloom checksum againts the current bloom checksum

            // read bloom checksum (expected value to be checked)
            bytesRead = fread(bloomChecksum, 1, 32, fileDescriptor);
            if (bytesRead != 32)
            {
                fprintf(stderr, "[E] Errore reading file, code line %i\n", __LINE__ - 2);
                fclose(fileDescriptor);
                return false;
            }

            // read bloom filter structure
            bytesRead = fread(&bloom, 1, sizeof(struct bloom), fileDescriptor);
            if (bytesRead != sizeof(struct bloom))
            {
                fprintf(stderr, "[E] Error reading file, code line %i\n", __LINE__ - 2);
                fclose(fileDescriptor);
                return false;
            }

            printf("[+] Bloom filter for %" PRIu64 " elements.\n", bloom.entries);

            bloom.bf = (uint8_t *)malloc(bloom.bytes);
            if (bloom.bf == NULL)
            {
                fprintf(stderr, "[E] Error allocating memory, code line %i\n", __LINE__ - 2);
                fclose(fileDescriptor);
                return false;
            }

            // read bloom filter data
            bytesRead = fread(bloom.bf, 1, bloom.bytes, fileDescriptor);
            if (bytesRead != bloom.bytes)
            {
                fprintf(stderr, "[E] Error reading file, code line %i\n", __LINE__ - 2);
                fclose(fileDescriptor);
                return false;
            }
            if (FLAGSKIPCHECKSUM == 0)
            {

                // calculate checksum of the current readed data
                sha256((uint8_t *)bloom.bf, bloom.bytes, (uint8_t *)checksum);

                // Compare checksums
                /*
                if(FLAGDEBUG)	{
                    hextemp = tohex((char*)checksum,32);
                    printf("[D] Current Bloom checksum %s\n",hextemp);
                    free(hextemp);
                }
                */
                if (memcmp(checksum, bloomChecksum, 32) != 0)
                {
                    fprintf(stderr, "[E] Error checksum mismatch, code line %i\n", __LINE__ - 2);
                    fclose(fileDescriptor);
                    return false;
                }
            }

            /*
            if(FLAGDEBUG) {
                hextemp = tohex((char*)bloom.bf,32);
                printf("[D] first 32 bytes of the bloom : %s\n",hextemp);
                bloom_print(&bloom);
                printf("[D] bloom.bf points to %p\n",bloom.bf);
            }
            */

            bytesRead = fread(dataChecksum, 1, 32, fileDescriptor);
            if (bytesRead != 32)
            {
                fprintf(stderr, "[E] Errore reading file, code line %i\n", __LINE__ - 2);
                fclose(fileDescriptor);
                return false;
            }

            bytesRead = fread(&dataSize, 1, sizeof(uint64_t), fileDescriptor);
            if (bytesRead != sizeof(uint64_t))
            {
                fprintf(stderr, "[E] Errore reading file, code line %i\n", __LINE__ - 2);
                fclose(fileDescriptor);
                return false;
            }
            N = dataSize / sizeof(struct address_value);

            printf("[+] Allocating memory for %" PRIu64 " elements: %.2f MB\n", N, (double)(((double)sizeof(struct address_value) * N) / (double)1048576));

            addressTable = (struct address_value *)malloc(dataSize);
            if (addressTable == NULL)
            {
                fprintf(stderr, "[E] Error allocating memory, code line %i\n", __LINE__ - 2);
                fclose(fileDescriptor);
                return false;
            }

            bytesRead = fread(addressTable, 1, dataSize, fileDescriptor);
            if (bytesRead != dataSize)
            {
                fprintf(stderr, "[E] Error reading file, code line %i\n", __LINE__ - 2);
                fclose(fileDescriptor);
                return false;
            }
            if (FLAGSKIPCHECKSUM == 0)
            {

                sha256((uint8_t *)addressTable, dataSize, (uint8_t *)checksum);
                if (memcmp(checksum, dataChecksum, 32) != 0)
                {
                    fprintf(stderr, "[E] Error checksum mismatch, code line %i\n", __LINE__ - 2);
                    fclose(fileDescriptor);
                    return false;
                }
            }
            // printf("[D] bloom.bf points to %p\n",bloom.bf);
            FLAGREADEDFILE1 = 1; /* We mark the file as readed*/
            fclose(fileDescriptor);
            MAXLENGTHADDRESS = sizeof(struct address_value);
        }
    }
    if (FLAGVANITY)
    {
        processOneVanity();
    }
    if (!FLAGREADEDFILE1)
    {
        /*
            if the data_ file doesn't exist we need read it first:
        */
        switch (FLAGMODE)
        {
        case MODE_ADDRESS:
            if (FLAGCRYPTO == CRYPTO_BTC)
            {
                return forceReadFileAddress(fileName);
            }
            if (FLAGCRYPTO == CRYPTO_ETH)
            {
                return forceReadFileAddressEth(fileName);
            }
            break;
        case MODE_MINIKEYS:
        case MODE_RMD160:
            return forceReadFileAddress(fileName);
            break;
        case MODE_XPOINT:
            return forceReadFileXPoint(fileName);
            break;
        default:
            return false;
            break;
        }
    }
    return true;
}

bool forceReadFileAddress(char *fileName)
{
    /* Here we read the original file as usual */
    FILE *fileDescriptor;
    bool validAddress;
    uint64_t numberItems, i;
    size_t r, raw_value_length;
    uint8_t rawvalue[50];
    char aux[100], *hextemp;
    fileDescriptor = fopen(fileName, "r");
    if (fileDescriptor == NULL)
    {
        fprintf(stderr, "[E] Error opening the file %s, line %i\n", fileName, __LINE__ - 2);
        return false;
    }

    /*Count lines in the file*/
    numberItems = 0;
    while (!feof(fileDescriptor))
    {
        hextemp = fgets(aux, 100, fileDescriptor);
        trim(aux, " \t\n\r");
        if (hextemp == aux)
        {
            r = strlen(aux);
            if (r > 20)
            {
                numberItems++;
            }
        }
    }
    fseek(fileDescriptor, 0, SEEK_SET);
    MAXLENGTHADDRESS = 20; /*20 bytes beacuase we only need the data in binary*/

    printf("[+] Allocating memory for %" PRIu64 " elements: %.2f MB\n", numberItems, (double)(((double)sizeof(struct address_value) * numberItems) / (double)1048576));
    addressTable = (struct address_value *)malloc(sizeof(struct address_value) * numberItems);
    checkpointer((void *)addressTable, __FILE__, "malloc", "addressTable", __LINE__ - 1);

    if (!initBloomFilter(&bloom, numberItems))
        return false;

    i = 0;
    while (i < numberItems)
    {
        validAddress = false;
        memset(aux, 0, 100);
        memset(addressTable[i].value, 0, sizeof(struct address_value));
        hextemp = fgets(aux, 100, fileDescriptor);
        trim(aux, " \t\n\r");
        r = strlen(aux);
        if (r > 0 && r <= 40)
        {
            if (r < 40 && isValidBase58String(aux))
            { // Address
                raw_value_length = 25;
                b58tobin(rawvalue, &raw_value_length, aux, r);
                if (raw_value_length == 25)
                {
                    // hextemp = tohex((char*)rawvalue+1,20);
                    bloom_add(&bloom, rawvalue + 1, sizeof(struct address_value));
                    memcpy(addressTable[i].value, rawvalue + 1, sizeof(struct address_value));
                    i++;
                    validAddress = true;
                }
            }
            if (r == 40 && isValidHex(aux))
            { // RMD
                hexs2bin(aux, rawvalue);
                bloom_add(&bloom, rawvalue, sizeof(struct address_value));
                memcpy(addressTable[i].value, rawvalue, sizeof(struct address_value));
                i++;
                validAddress = true;
            }
        }
        if (!validAddress)
        {
            fprintf(stderr, "[I] Ommiting invalid line %s\n", aux);
            numberItems--;
        }
    }
    N = numberItems;
    return true;
}

bool forceReadFileAddressEth(char *fileName)
{
    /* Here we read the original file as usual */
    FILE *fileDescriptor;
    bool validAddress;
    uint64_t numberItems, i;
    size_t r;
    uint8_t rawvalue[50];
    char aux[100], *hextemp;
    fileDescriptor = fopen(fileName, "r");
    if (fileDescriptor == NULL)
    {
        fprintf(stderr, "[E] Error opening the file %s, line %i\n", fileName, __LINE__ - 2);
        return false;
    }
    /*Count lines in the file*/
    numberItems = 0;
    while (!feof(fileDescriptor))
    {
        hextemp = fgets(aux, 100, fileDescriptor);
        trim(aux, " \t\n\r");
        if (hextemp == aux)
        {
            r = strlen(aux);
            if (r >= 40)
            {
                numberItems++;
            }
        }
    }
    fseek(fileDescriptor, 0, SEEK_SET);

    MAXLENGTHADDRESS = 20; /*20 bytes beacuase we only need the data in binary*/
    N = numberItems;

    printf("[+] Allocating memory for %" PRIu64 " elements: %.2f MB\n", numberItems, (double)(((double)sizeof(struct address_value) * numberItems) / (double)1048576));
    addressTable = (struct address_value *)malloc(sizeof(struct address_value) * numberItems);
    checkpointer((void *)addressTable, __FILE__, "malloc", "addressTable", __LINE__ - 1);

    if (!initBloomFilter(&bloom, N))
        return false;

    i = 0;
    while (i < numberItems)
    {
        validAddress = false;
        memset(aux, 0, 100);
        memset(addressTable[i].value, 0, sizeof(struct address_value));
        hextemp = fgets(aux, 100, fileDescriptor);
        trim(aux, " \t\n\r");
        r = strlen(aux);
        if (r >= 40 && r <= 42)
        {
            switch (r)
            {
            case 40:
                if (isValidHex(aux))
                {
                    hexs2bin(aux, rawvalue);
                    bloom_add(&bloom, rawvalue, sizeof(struct address_value));
                    memcpy(addressTable[i].value, rawvalue, sizeof(struct address_value));
                    i++;
                    validAddress = true;
                }
                break;
            case 42:
                if (isValidHex(aux + 2))
                {
                    hexs2bin(aux + 2, rawvalue);
                    bloom_add(&bloom, rawvalue, sizeof(struct address_value));
                    memcpy(addressTable[i].value, rawvalue, sizeof(struct address_value));
                    i++;
                    validAddress = true;
                }
                break;
            }
        }
        if (!validAddress)
        {
            fprintf(stderr, "[I] Ommiting invalid line %s\n", aux);
            numberItems--;
        }
    }

    fclose(fileDescriptor);
    return true;
}

bool forceReadFileXPoint(char *fileName)
{
    FILE *fileDescriptor;
    uint64_t numberItems = 0, i = 0;
    size_t r, lenaux;
    uint8_t rawvalue[100];
    char aux[1000], *hextemp;
    Tokenizer tokenizer_xpoint;
    
    // Open file in binary mode to detect format
    fileDescriptor = fopen(fileName, "rb");
    if (fileDescriptor == NULL)
    {
        fprintf(stderr, "[E] Error opening the file %s, line %i\n", fileName, __LINE__ - 2);
        return false;
    }
    
    // Detect if file is binary or text
    bool is_binary = false;
    unsigned char detect_buf[4];
    size_t bytes_read = fread(detect_buf, 1, 4, fileDescriptor);
    
    if (bytes_read >= 1) {
        if (detect_buf[0] == 0x02 || detect_buf[0] == 0x03 || detect_buf[0] == 0x04) {
            is_binary = true;
        }
    }
    
    // Get file size
    fseek(fileDescriptor, 0, SEEK_END);
    long file_size = ftell(fileDescriptor);
    fseek(fileDescriptor, 0, SEEK_SET);
    
    // Count items based on file type
    if (is_binary) {
        int key_size = (detect_buf[0] == 0x04) ? 65 : 33;
        numberItems = file_size / key_size;
        
        printf("[+] Detected binary file format (%s keys)\n", 
               key_size == 33 ? "compressed" : "uncompressed");
    } else {
        // Text file - count valid lines
        fclose(fileDescriptor);
        fileDescriptor = fopen(fileName, "r");
        
        while (!feof(fileDescriptor))
        {
            if (fgets(aux, 1000, fileDescriptor) != NULL)
            {
                char *comment = strchr(aux, '#');
                if (comment) *comment = '\0';
                
                trim(aux, " \t\n\r");
                r = strlen(aux);
                if (r >= 64)
                {
                    numberItems++;
                }
            }
        }
        fseek(fileDescriptor, 0, SEEK_SET);
        printf("[+] Detected text file format\n");
    }
    
    if (numberItems == 0) {
        fprintf(stderr, "[E] No valid keys found in file\n");
        fclose(fileDescriptor);
        return false;
    }
    
    MAXLENGTHADDRESS = 20;
    N = numberItems;
    
    printf("[+] Total keys to process: %" PRIu64 "\n", numberItems);
    
    // For large datasets, only allocate minimal addressTable
    // We'll rely primarily on the bloom filter
    if (numberItems > 10000000) {  // More than 10M keys
        printf("[+] Large dataset detected. Using bloom-filter-only mode.\n");
        printf("[+] Note: There may be occasional false positives.\n");
        
        // Allocate just a dummy addressTable to keep the code structure intact
        addressTable = (struct address_value *)malloc(sizeof(struct address_value) * 1);
        N = 0;  // Set to 0 so binary search always fails, forcing bloom-only mode
    } else {
        // Original behavior for smaller files
        printf("[+] Allocating memory for %" PRIu64 " elements: %.2f MB\n", 
               numberItems, (double)(((double)sizeof(struct address_value) * numberItems) / (double)1048576));
        
        addressTable = (struct address_value *)malloc(sizeof(struct address_value) * numberItems);
        if (addressTable == NULL) {
            fprintf(stderr, "[E] Failed to allocate memory.\n");
            fclose(fileDescriptor);
            return false;
        }
    }
    
    checkpointer((void *)addressTable, __FILE__, "malloc", "addressTable", __LINE__ - 1);
    
    // Initialize bloom filter with the full dataset size
    printf("[+] Initializing bloom filter for %" PRIu64 " elements\n", numberItems);
    if (!initBloomFilter(&bloom, numberItems))
        return false;
    
    i = 0;
    
    if (is_binary) {
        // Binary file processing
        unsigned char entry[65];
        int key_size = (detect_buf[0] == 0x04) ? 65 : 33;
        
        // Reopen in binary mode
        fclose(fileDescriptor);
        fileDescriptor = fopen(fileName, "rb");
        
        uint64_t keys_processed = 0;
        while (fread(entry, key_size, 1, fileDescriptor) == 1)
        {
            // For bloom filter, we only need to add the X coordinate
            bloom_add(&bloom, entry + 1, MAXLENGTHADDRESS);
            
            // Only store in addressTable if using small dataset mode
            if (N > 0 && i < N) {
                memset((void *)&addressTable[i], 0, sizeof(struct address_value));
                memcpy(addressTable[i].value, entry + 1, 20);
                i++;
            }
            
            keys_processed++;
            
            // Progress indicator
            if (keys_processed % 1000000 == 0) {
                printf("\r[+] Processed %lu/%lu keys (%.1f%%)", 
                       keys_processed, numberItems, (float)keys_processed * 100 / numberItems);
                fflush(stdout);
            }
        }
        printf("\r[+] Processed %lu/%lu keys (100.0%%)\n", keys_processed, numberItems);
    } else {
        // Text file processing
        uint64_t keys_processed = 0;
        while (!feof(fileDescriptor))
        {
            memset(aux, 0, 1000);
            if (fgets(aux, 1000, fileDescriptor) != NULL)
            {
                char *comment = strchr(aux, '#');
                if (comment) *comment = '\0';
                
                trim(aux, " \t\n\r");
                
                if (strlen(aux) >= 64)
                {
                    const char* hex_start = aux;
                    
                    if (strlen(aux) >= 2 && aux[0] == '0' && aux[1] == 'x') {
                        hex_start = aux + 2;
                    }
                    
                    lenaux = strlen(hex_start);
                    
                    if (isValidHex((char*)hex_start))
                    {
                        bool valid = false;
                        switch (lenaux)
                        {
                        case 64: // X coordinate only
                            r = hexs2bin((char*)hex_start, (uint8_t *)rawvalue);
                            if (r) valid = true;
                            break;
                            
                        case 66: // Compressed public key
                            r = hexs2bin((char*)hex_start + 2, (uint8_t *)rawvalue);
                            if (r) valid = true;
                            break;
                            
                        case 130: // Uncompressed public key
                            r = hexs2bin((char*)hex_start + 2, (uint8_t *)rawvalue);
                            if (r) valid = true;
                            break;
                        }
                        
                        if (valid) {
                            bloom_add(&bloom, rawvalue, MAXLENGTHADDRESS);
                            
                            // Only store in addressTable if using small dataset mode
                            if (N > 0 && i < N) {
                                memset((void *)&addressTable[i], 0, sizeof(struct address_value));
                                memcpy(addressTable[i].value, rawvalue, 20);
                                i++;
                            }
                            
                            keys_processed++;
                        }
                    }
                }
            }
            
            if (keys_processed % 100000 == 0 && keys_processed > 0) {
                printf("\r[+] Processed %lu keys", keys_processed);
                fflush(stdout);
            }
        }
        if (keys_processed % 100000 != 0) {
            printf("\r[+] Processed %lu keys\n", keys_processed);
        }
    }
    
    fclose(fileDescriptor);
    
    printf("[+] Bloom filter initialized with %lu keys\n", numberItems);
    printf("[+] Bloom filter size: %.2f MB\n", (float)bloom.bytes / (1024.0 * 1024.0));
    
    return true;
}

/*
    I write this as a function because i have the same segment of code in 3 different functions
*/

uint64_t estimate_subtract_bloom_size(uint64_t items, double fp_rate) {
    return (uint64_t)((-1.0 * items * log(fp_rate)) / (log(2.0) * log(2.0))) / 8;
}

void display_subtract_bloom_info(uint64_t items, double fp_rate) {
    uint64_t bloom_size = estimate_subtract_bloom_size(items, fp_rate);
    double mb_size = bloom_size / (1024.0 * 1024.0);
    printf("[+] Subtract bloom filter (%.6f FP rate): %.2f MB\n", fp_rate, mb_size);
}

bool init_subtract_bloom_filter(const char *filename) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        fprintf(stderr, "[E] Can't open file %s\n", filename);
        return false;
    }
    
    // Determine if file is binary or text
    bool is_binary = false;
    unsigned char buf[4];
    size_t read = fread(buf, 1, 4, file);
    fseek(file, 0, SEEK_SET);
    
    if (read >= 1 && (buf[0] == 0x02 || buf[0] == 0x03 || buf[0] == 0x04)) {
        is_binary = true;
    }
    
    // Calculate file size and estimate entries
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    uint64_t total_entries;
    if (is_binary) {
        // Determine compressed or uncompressed by examining first byte
        if (buf[0] == 0x04) {
            total_entries = file_size / 65; // Uncompressed public key size
        } else {
            total_entries = file_size / 33; // Compressed public key size
        }
    } else {
        // Estimate based on average line length
        if (read >= 2 && buf[0] == '0' && buf[1] == '4') {
            total_entries = file_size / 130; // Hex uncompressed key
        } else {
            total_entries = file_size / 67; // Hex compressed key
        }
    }
    
    printf("[+] Loading subtract bloom filter from %s\n", filename);
    printf("[+] File type: %s\n", is_binary ? "Binary" : "Text");
    printf("[+] Estimated entries: %lu\n", total_entries);
    
    // Calculate bloom filter size with low false positive rate
    double fp_rate = 0.000000000001; // One in a million false positive rate
    
    // Initialize bloom filter - use a larger size factor for better performance
    if (bloom_init2(&bloom_subtract, total_entries * FLAGBLOOMMULTIPLIER, fp_rate) != 0) {
        fprintf(stderr, "[E] Failed to initialize subtract bloom filter\n");
        fclose(file);
        return false;
    }
    bloom_subtract_initialized = true;
    
    printf("[+] Subtract bloom filter size: %.2f MB\n", 
           (float)bloom_subtract.bytes / (1024.0 * 1024.0));
    
    // Use larger buffer for improved disk I/O
    const size_t BUFFER_SIZE = 1024 * 1024 * 16; // 16MB buffer
    unsigned char *buffer = (unsigned char *)malloc(BUFFER_SIZE);
    if (!buffer) {
        fprintf(stderr, "[E] Failed to allocate buffer memory\n");
        fclose(file);
        return false;
    }
    
    size_t entries_processed = 0;
    size_t last_reported = 0;
    clock_t start_time = clock();
    
    if (is_binary) {
        if (buf[0] == 0x04) {
            // Uncompressed binary format (65 bytes per entry)
            unsigned char entry[65];
            while (fread(entry, 65, 1, file) == 1) {
                // Add X coordinate to bloom filter (bytes 1-33)
                bloom_add(&bloom_subtract, entry + 1, 32);
                entries_processed++;
                
                // Show progress
                if (entries_processed % 100000 == 0 && entries_processed != last_reported) {
                    printf("\r[+] Processed %zu/%lu entries (%.1f%%)  ", 
                           entries_processed, total_entries, 
                           (float)entries_processed * 100 / total_entries);
                    fflush(stdout);
                    last_reported = entries_processed;
                }
            }
        } else {
            // Compressed binary format (33 bytes per entry)
            unsigned char entry[33];
            while (fread(entry, 33, 1, file) == 1) {
                // Add X coordinate to bloom filter (bytes 1-33)
                bloom_add(&bloom_subtract, entry + 1, 32);
                entries_processed++;
                
                // Show progress
                if (entries_processed % 100000 == 0 && entries_processed != last_reported) {
                    printf("\r[+] Processed %zu/%lu entries (%.1f%%)  ", 
                           entries_processed, total_entries, 
                           (float)entries_processed * 100 / total_entries);
                    fflush(stdout);
                    last_reported = entries_processed;
                }
            }
        }
    } else {
        // Text format (hex strings)
        char line[300];
        while (fgets(line, sizeof(line), file) != NULL) {
            // Remove newline
            size_t len = strlen(line);
            if (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r'))
                line[--len] = 0;
            
            // Skip empty lines
            if (len == 0)
                continue;
                
            // Handle different formats
            unsigned char bin_pubkey[65];
            
            if (len >= 66 && len <= 68) {
                // Compressed public key in hex format
                if ((line[0] == '0' && (line[1] == '2' || line[1] == '3')) || 
                    ((line[0] == '0' && line[1] == 'x') && (line[2] == '0' && (line[3] == '2' || line[3] == '3')))) {
                    
                    const char* hex_start = line;
                    if (line[0] == '0' && line[1] == 'x') {
                        hex_start += 2; // Skip '0x' prefix
                    }
                    
                    // Convert hex to binary - hexs2bin returns length of converted bytes or 0 on error
                    int converted_len = hexs2bin((char*)hex_start, bin_pubkey);
                    if (converted_len >= 33) {
                        // Add X coordinate to bloom filter (skip the prefix byte)
                        bloom_add(&bloom_subtract, bin_pubkey + 1, 32);
                        entries_processed++;
                    }
                }
            } 
            else if (len >= 130 && len <= 132) {
                // Uncompressed public key in hex format
                if ((line[0] == '0' && line[1] == '4') || 
                    ((line[0] == '0' && line[1] == 'x') && (line[2] == '0' && line[3] == '4'))) {
                    
                    const char* hex_start = line;
                    if (line[0] == '0' && line[1] == 'x') {
                        hex_start += 2; // Skip '0x' prefix
                    }
                    
                    // Convert hex to binary - hexs2bin returns length of converted bytes or 0 on error
                    int converted_len = hexs2bin((char*)hex_start, bin_pubkey);
                    if (converted_len >= 65) {
                        // Add X coordinate to bloom filter (skip the prefix byte)
                        bloom_add(&bloom_subtract, bin_pubkey + 1, 32);
                        entries_processed++;
                    }
                }
            }
            
            // Show progress
            if (entries_processed % 10000 == 0 && entries_processed != last_reported) {
                printf("\r[+] Processed %zu/%lu entries (%.1f%%)  ", 
                       entries_processed, total_entries, 
                       (float)entries_processed * 100 / total_entries);
                fflush(stdout);
                last_reported = entries_processed;
            }
        }
    }
    
    clock_t end_time = clock();
    double seconds = (double)(end_time - start_time) / CLOCKS_PER_SEC;
    
    printf("\r[+] Processed %zu public keys in %.2f seconds (%.2f keys/sec)\n", 
           entries_processed, seconds, entries_processed / seconds);
    printf("[+] Bloom filter memory usage: %.2f MB\n", 
           (float)bloom_subtract.bytes / (1024.0 * 1024.0));
    
    // Check if we actually loaded any entries
    if (entries_processed == 0) {
        fprintf(stderr, "[W] No valid public keys were found in the file!\n");
        fprintf(stderr, "[W] Please check the file format.\n");
        if (!is_binary) {
            fprintf(stderr, "[I] For text files, each line should contain a hex-encoded public key\n");
            fprintf(stderr, "[I] Format: '02|03|04' followed by X (and Y for uncompressed) coordinates\n");
        }
    }
    
    free(buffer);
    fclose(file);
    return true;
}

bool parse_target_subtract_keys() {
    if (targetSubtractKeyStrs.empty()) {
        fprintf(stderr, "[E] No target public keys specified for subtract mode\n");
        return false;
    }
    
    targetSubtractKeys.resize(targetSubtractKeyStrs.size());
    subtractKeyFound.resize(targetSubtractKeyStrs.size(), false);
    
    printf("[+] Processing %zu target public key(s)...\n", targetSubtractKeyStrs.size());
    
    for (size_t i = 0; i < targetSubtractKeyStrs.size(); i++) {
        std::string& keyStr = targetSubtractKeyStrs[i];
        bool isCompressed = false;
        
        // Trim any whitespace
        while (!keyStr.empty() && std::isspace(keyStr.front()))
            keyStr.erase(keyStr.begin());
        while (!keyStr.empty() && std::isspace(keyStr.back()))
            keyStr.pop_back();
            
        // Handle 0x prefix
        if (keyStr.size() >= 2 && keyStr[0] == '0' && keyStr[1] == 'x') {
            keyStr = keyStr.substr(2);
        }
        
        // Check the key format
        if (keyStr.empty()) {
            fprintf(stderr, "[E] Empty public key specified at position %zu\n", i+1);
            return false;
        }
        
        // Validate key length
        size_t len = keyStr.length();
        if (len != 66 && len != 130) {
            fprintf(stderr, "[E] Invalid public key length (%zu) for key #%zu: %s\n", 
                    len, i+1, keyStr.c_str());
            fprintf(stderr, "    Public key must be 66 chars (compressed) or 130 chars (uncompressed)\n");
            return false;
        }
        
        // Validate first byte indicates format
        if (len == 66) {
            if (keyStr[0] != '0' || (keyStr[1] != '2' && keyStr[1] != '3')) {
                fprintf(stderr, "[E] Invalid compressed public key format for key #%zu: %s\n", 
                        i+1, keyStr.c_str());
                fprintf(stderr, "    Compressed key must start with '02' or '03'\n");
                return false;
            }
            isCompressed = true;
        } else if (len == 130) {
            if (keyStr[0] != '0' || keyStr[1] != '4') {
                fprintf(stderr, "[E] Invalid uncompressed public key format for key #%zu: %s\n", 
                        i+1, keyStr.c_str());
                fprintf(stderr, "    Uncompressed key must start with '04'\n");
                return false;
            }
            isCompressed = false;
        }
        
        // Validate hex characters
        for (size_t j = 0; j < len; j++) {
            if (!std::isxdigit(keyStr[j])) {
                fprintf(stderr, "[E] Invalid hex character '%c' in public key #%zu\n", 
                        keyStr[j], i+1);
                return false;
            }
        }
        
        // Try to parse the public key
        if (!secp->ParsePublicKeyHex((char*)keyStr.c_str(), targetSubtractKeys[i], isCompressed)) {
            fprintf(stderr, "[E] Unable to parse target public key #%zu: %s\n", 
                    i+1, keyStr.c_str());
            return false;
        }
        
        // Verify the point is on the curve
        if (!secp->EC(targetSubtractKeys[i])) {
            fprintf(stderr, "[E] Public key #%zu is not a valid point on the curve\n", i+1);
            return false;
        }
        
        // For compressed keys, fix the Y coordinate if needed
        if (isCompressed) {
            // For compressed keys, ParsePublicKeyHex should handle this automatically
            // but we double-check here to be sure
            if ((keyStr[1] == '2' && targetSubtractKeys[i].y.IsOdd()) || 
                (keyStr[1] == '3' && !targetSubtractKeys[i].y.IsOdd())) {
                targetSubtractKeys[i].y.ModNeg();
            }
        }
        
        printf("[+] Target public key #%zu: %s\n", i+1, keyStr.c_str());
    }
    
    return true;
}


void write_subtract_key(Int &subtractValue, size_t keyIndex) {
    FILE *filekey;
    
    // Get the subtract value in hex
    char *subtractHex = subtractValue.GetBase16();
    
    // Calculate the public key that gets subtracted
    Point subtractPubKey = secp->ComputePublicKey(&subtractValue);
    
    // Calculate the negated public key for proper display
    Point negatedSubtractPubKey = secp->Negation(subtractPubKey);
    
    // Get the hex representations of both public keys
    char *subtractPubKeyHex = secp->GetPublicKeyHex(true, subtractPubKey);
    char *negatedPubKeyHex = secp->GetPublicKeyHex(true, negatedSubtractPubKey);
    
    // Calculate result of target - subtractValue (as points on the curve)
    Point resultPoint = secp->AddDirect(targetSubtractKeys[keyIndex], negatedSubtractPubKey);
    char *resultPointHex = secp->GetPublicKeyHex(true, resultPoint);
    
#if defined(_WIN64) && !defined(__CYGWIN__)
    WaitForSingleObject(write_keys, INFINITE);
#else
    pthread_mutex_lock(&write_keys);
#endif
    
    filekey = fopen("KEYFOUNDKEYFOUND.txt", "a");
    if (filekey != NULL) {
        fprintf(filekey, "Key found by subtraction:\n");
        fprintf(filekey, "Target key #%zu: %s\n", keyIndex+1, targetSubtractKeyStrs[keyIndex].c_str());
        fprintf(filekey, "Subtract value: %s\n", subtractHex);
        fprintf(filekey, "Subtract public key: %s\n", subtractPubKeyHex);
        fprintf(filekey, "Negated subtract key: %s\n", negatedPubKeyHex);
        fprintf(filekey, "Result (Target - Subtract): %s\n", resultPointHex);
        fprintf(filekey, "Private key calculation: (Database private key) = (Target private key) - %s\n", subtractHex);
        
        if (FLAGOPTIMIZEDPRIME) {
            fprintf(filekey, "Prime step: %llu, Steps taken: %llu\n", current_prime, steps_taken);
        }
        
        fprintf(filekey, "\n");
        fclose(filekey);
    }
    
    printf("\nHIT! Key found by subtraction:\n");
    printf("Target key #%zu: %s\n", keyIndex+1, targetSubtractKeyStrs[keyIndex].c_str());
    printf("Subtract value: %s\n", subtractHex);
    printf("Subtract public key: %s\n", subtractPubKeyHex);
    printf("Negated subtract key: %s\n", negatedPubKeyHex);
    printf("Result (Target - Subtract): %s\n", resultPointHex);
    printf("Private key calculation: (Database private key) = (Target private key) - %s\n", subtractHex);
    
    if (FLAGOPTIMIZEDPRIME) {
        printf("Prime step: %llu, Steps taken: %llu\n", current_prime, steps_taken);
    }
    
#if defined(_WIN64) && !defined(__CYGWIN__)
    ReleaseMutex(write_keys);
#else
    pthread_mutex_unlock(&write_keys);
#endif
    
    free(subtractHex);
    free(subtractPubKeyHex);
    free(negatedPubKeyHex);
    free(resultPointHex);
}

bool is_prime(uint64_t n) {
    if (n <= 1) return false;
    if (n <= 3) return true;
    if (n % 2 == 0 || n % 3 == 0) return false;
    
    for (uint64_t i = 5; i * i <= n; i += 6) {
        if (n % i == 0 || n % (i + 2) == 0)
            return false;
    }
    return true;
}



void calculate_prime_stride(Int &range_diff, Int &current_prime_int, Int &stride) {
    // We want to find a stride value such that:
    // stride * prime_number = range_size (approximately)
    Int range_size;
    range_size.Set(&range_diff);
    
    Int prime_copy;
    prime_copy.Set(&current_prime_int);
    
    // Divide the range by the prime number to get our stride
    stride.Set(&range_size);
    stride.Div(&prime_copy);
    
    // Ensure we don't get stride = 0
    if (stride.IsZero()) {
        stride.SetInt32(1);
    }
    
    // Debug output if needed
    if (FLAGDEBUG) {
        char *range_str = range_size.GetBase10();
        char *prime_str = prime_copy.GetBase10();
        char *stride_str = stride.GetBase10();
        
        printf("[D] Range size: %s, Prime: %s, Calculated stride: %s\n",
               range_str, prime_str, stride_str);
        
        free(range_str);
        free(prime_str);
        free(stride_str);
    }
}

// Fix the prime number generation
uint64_t next_prime(uint64_t n) {
    if (n <= 1) return 2;
    
    uint64_t prime = n;
    bool found = false;
    
    // Simple implementation for finding the next prime
    while (!found) {
        prime++;
        
        // Check if prime
        bool is_prime = true;
        if (prime <= 1) is_prime = false;
        else if (prime <= 3) is_prime = true;
        else if (prime % 2 == 0 || prime % 3 == 0) is_prime = false;
        else {
            for (uint64_t i = 5; i * i <= prime; i += 6) {
                if (prime % i == 0 || prime % (i + 2) == 0) {
                    is_prime = false;
                    break;
                }
            }
        }
        
        if (is_prime) found = true;
    }
    
    return prime;
}


bool initBloomFilter(struct bloom *bloom_arg, uint64_t items_bloom)
{
    bool r = true;
    printf("[+] Bloom filter for %" PRIu64 " elements.\n", items_bloom);
    if (items_bloom <= 10000)
    {
        if (bloom_init2(bloom_arg, 10000, 0.001) == 1)
        {
            fprintf(stderr, "[E] error bloom_init for 10000 elements.\n");
            r = false;
        }
    }
    else
    {
        if (bloom_init2(bloom_arg, FLAGBLOOMMULTIPLIER * items_bloom, 0.001) == 1)
        {
            fprintf(stderr, "[E] error bloom_init for %" PRIu64 " elements.\n", items_bloom);
            r = false;
        }
    }
    printf("[+] Loading data to the bloomfilter total: %.2f MB\n", (double)(((double)bloom_arg->bytes) / (double)1048576));
    return r;
}

void writeFileIfNeeded(const char *fileName)
{
    // printf("[D] FLAGSAVEREADFILE %i, FLAGREADEDFILE1 %i\n",FLAGSAVEREADFILE,FLAGREADEDFILE1);
    if (FLAGSAVEREADFILE && !FLAGREADEDFILE1)
    {
        FILE *fileDescriptor;
        char fileBloomName[30];
        uint8_t checksum[32], hexPrefix[9];
        char dataChecksum[32], bloomChecksum[32];
        size_t bytesWrite;
        uint64_t dataSize;
        if (!sha256_file((const char *)fileName, checksum))
        {
            fprintf(stderr, "[E] sha256_file error line %i\n", __LINE__ - 1);
            exit(EXIT_FAILURE);
        }
        tohex_dst((char *)checksum, 4, (char *)hexPrefix); // we save the prefix (last fourt bytes) hexadecimal value
        snprintf(fileBloomName, 30, "data_%s.dat", hexPrefix);
        fileDescriptor = fopen(fileBloomName, "wb");
        dataSize = N * (sizeof(struct address_value));
        printf("[D] size data %li\n", dataSize);
        if (fileDescriptor != NULL)
        {
            printf("[+] Writing file %s ", fileBloomName);

            // calculate bloom checksum
            // write bloom checksum (expected value to be checked)
            // write bloom filter structure
            // write bloom filter data

            // calculate dataChecksum
            // write data checksum (expected value to be checked)
            // write data size
            // write data

            sha256((uint8_t *)bloom.bf, bloom.bytes, (uint8_t *)bloomChecksum);
            printf(".");
            bytesWrite = fwrite(bloomChecksum, 1, 32, fileDescriptor);
            if (bytesWrite != 32)
            {
                fprintf(stderr, "[E] Errore writing file, code line %i\n", __LINE__ - 2);
                exit(EXIT_FAILURE);
            }
            printf(".");

            bytesWrite = fwrite(&bloom, 1, sizeof(struct bloom), fileDescriptor);
            if (bytesWrite != sizeof(struct bloom))
            {
                fprintf(stderr, "[E] Error writing file, code line %i\n", __LINE__ - 2);
                exit(EXIT_FAILURE);
            }
            printf(".");

            bytesWrite = fwrite(bloom.bf, 1, bloom.bytes, fileDescriptor);
            if (bytesWrite != bloom.bytes)
            {
                fprintf(stderr, "[E] Error writing file, code line %i\n", __LINE__ - 2);
                fclose(fileDescriptor);
                exit(EXIT_FAILURE);
            }
            printf(".");

            /*
            if(FLAGDEBUG)	{
                hextemp = tohex((char*)bloom.bf,32);
                printf("\n[D] first 32 bytes bloom : %s\n",hextemp);
                bloom_print(&bloom);
                free(hextemp);
            }
            */

            sha256((uint8_t *)addressTable, dataSize, (uint8_t *)dataChecksum);
            printf(".");

            bytesWrite = fwrite(dataChecksum, 1, 32, fileDescriptor);
            if (bytesWrite != 32)
            {
                fprintf(stderr, "[E] Errore writing file, code line %i\n", __LINE__ - 2);
                exit(EXIT_FAILURE);
            }
            printf(".");

            bytesWrite = fwrite(&dataSize, 1, sizeof(uint64_t), fileDescriptor);
            if (bytesWrite != sizeof(uint64_t))
            {
                fprintf(stderr, "[E] Errore writing file, code line %i\n", __LINE__ - 2);
                exit(EXIT_FAILURE);
            }
            printf(".");

            bytesWrite = fwrite(addressTable, 1, dataSize, fileDescriptor);
            if (bytesWrite != dataSize)
            {
                fprintf(stderr, "[E] Error writing file, code line %i\n", __LINE__ - 2);
                exit(EXIT_FAILURE);
            }
            printf(".");

            FLAGREADEDFILE1 = 1;
            fclose(fileDescriptor);
            printf("\n");
        }
    }
}

void calcualteindex(int i, Int *key)
{
    if (i == 0)
    {
        key->Set(&BSGS_M3);
    }
    else
    {
        key->SetInt32(i);
        key->Mult(&BSGS_M3_double);
        key->Add(&BSGS_M3);
    }
}
