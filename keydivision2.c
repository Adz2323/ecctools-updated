#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <gmp.h>
#include <string.h>
#include <unistd.h>
#include <math.h>
#include <time.h>
#include <pthread.h>
#include "util.h"
#include "bloom/bloom.h"
#include "gmpecc.h"
#include "base58/libbase58.h"
#include "rmd160/rmd160.h"
#include "sha256/sha256.h"
#include "xxhash/xxhash.h"

struct Elliptic_Curve EC;
struct Point G;
struct Point DoublingG[256];

const char *version = "0.2.0";
const char *EC_constant_N = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
const char *EC_constant_P = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f";
const char *EC_constant_Gx = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const char *EC_constant_Gy = "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";

const char *formats[3] = {"publickey", "rmd160", "address"};
const char *looks[2] = {"compress", "uncompress"};

// Function prototypes
void set_publickey(char *param, struct Point *publickey);
void generate_strpublickey(struct Point *publickey, bool compress, char *dst);
void Scalar_Multiplication_custom(struct Point P, struct Point *R, mpz_t m);
void save_path_to_file(const char *path, const char *found_pk, bool is_match);
bool Point_is_zero(struct Point *P);
void *find_division_path_thread(void *arg);
void cleanup_bloom_filters(void);
int init_multi_bloom_from_file(const char *filename);
bool triple_bloom_check(const char *pubkey);

// Enhanced bloom filter setup
struct bloom bloom_filter1;
struct bloom bloom_filter2;
struct bloom bloom_filter3;
bool bloom_initialized1 = false;
bool bloom_initialized2 = false;
bool bloom_initialized3 = false;
bool save_unsuccessful_paths = false;

#define MAX_ENTRIES1 100000000
#define MAX_ENTRIES2 80000000
#define MAX_ENTRIES3 60000000
#define FP_RATE1 0.001
#define FP_RATE2 0.0001
#define FP_RATE3 0.00001

// Thread-safe globals
pthread_mutex_t print_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t file_mutex = PTHREAD_MUTEX_INITIALIZER;
unsigned long long total_attempts = 0;
pthread_mutex_t attempts_mutex = PTHREAD_MUTEX_INITIALIZER;

// Thread argument structure
struct thread_args
{
    struct Point start_pubkey;
    int target_bit;
    int thread_id;
    char initial_pk[132];
};

char *str_output = NULL;
char *str_input = NULL;
char *str_publickey_ptr = NULL;

char str_publickey[132];
char str_rmd160[41];
char str_address[41];

struct Point A, B, C;
int FLAG_NUMBER = 0;
mpz_t inversemultiplier, number;

// Initialize all three bloom filters
int init_multi_bloom_from_file(const char *filename)
{
    FILE *file = fopen(filename, "r");
    if (!file)
    {
        printf("Error: Cannot open bloom filter file %s\n", filename);
        return 0;
    }

    if (bloom_init2(&bloom_filter1, MAX_ENTRIES1, FP_RATE1) != 0 ||
        bloom_init2(&bloom_filter2, MAX_ENTRIES2, FP_RATE2) != 0 ||
        bloom_init2(&bloom_filter3, MAX_ENTRIES3, FP_RATE3) != 0)
    {
        printf("Error: Failed to initialize bloom filters\n");
        fclose(file);
        return 0;
    }

    bloom_initialized1 = true;
    bloom_initialized2 = true;
    bloom_initialized3 = true;

    printf("Initialized bloom filters:\n");
    printf("Filter 1: %d entries, FP rate: %.6f%%\n", MAX_ENTRIES1, FP_RATE1 * 100);
    printf("Filter 2: %d entries, FP rate: %.6f%%\n", MAX_ENTRIES2, FP_RATE2 * 100);
    printf("Filter 3: %d entries, FP rate: %.6f%%\n", MAX_ENTRIES3, FP_RATE3 * 100);

    char pubkey[132];
    size_t count = 0;

    while (fgets(pubkey, sizeof(pubkey), file) && count < MAX_ENTRIES1)
    {
        pubkey[strcspn(pubkey, "\n")] = 0;

        bloom_add(&bloom_filter1, pubkey, strlen(pubkey));

        XXH64_hash_t hash = XXH64(pubkey, strlen(pubkey), 0x1234);
        bloom_add(&bloom_filter2, (char *)&hash, sizeof(hash));

        hash = XXH64(pubkey, strlen(pubkey), 0x5678);
        bloom_add(&bloom_filter3, (char *)&hash, sizeof(hash));

        count++;
        if (count % 1000000 == 0)
        {
            printf("Loaded %zu million entries into bloom filters\n", count / 1000000);
        }
    }

    printf("Finished loading %zu entries into all bloom filters\n", count);
    fclose(file);
    return 1;
}

bool triple_bloom_check(const char *pubkey)
{
    if (!bloom_initialized1 || !bloom_initialized2 || !bloom_initialized3)
    {
        return false;
    }

    if (!bloom_check(&bloom_filter1, pubkey, strlen(pubkey)))
    {
        return false;
    }

    XXH64_hash_t hash = XXH64(pubkey, strlen(pubkey), 0x1234);
    if (!bloom_check(&bloom_filter2, (char *)&hash, sizeof(hash)))
    {
        return false;
    }

    hash = XXH64(pubkey, strlen(pubkey), 0x5678);
    if (!bloom_check(&bloom_filter3, (char *)&hash, sizeof(hash)))
    {
        return false;
    }

    return true;
}

void cleanup_bloom_filters(void)
{
    if (bloom_initialized1)
    {
        bloom_free(&bloom_filter1);
    }
    if (bloom_initialized2)
    {
        bloom_free(&bloom_filter2);
    }
    if (bloom_initialized3)
    {
        bloom_free(&bloom_filter3);
    }
}

bool Point_is_zero(struct Point *P)
{
    return (mpz_cmp_ui(P->x, 0) == 0 && mpz_cmp_ui(P->y, 0) == 0);
}

void save_path_to_file(const char *path, const char *found_pk, bool is_match)
{
    if (!is_match && !save_unsuccessful_paths)
    {
        return;
    }

    pthread_mutex_lock(&file_mutex);
    time_t now;
    time(&now);

    FILE *file = fopen("found_paths.txt", "a");
    if (file)
    {
        fprintf(file, "=== Search at %s", ctime(&now));
        fprintf(file, "Public Key: %s\n", found_pk);
        fprintf(file, "Path: %s\n\n", path);
        fclose(file);
    }
    else
    {
        printf("Warning: Could not save path to file\n");
    }
    pthread_mutex_unlock(&file_mutex);
}

void print_status(const char *pubkey, int divisions, int target_bit, bool must_divide, unsigned long long thread_attempts)
{
    pthread_mutex_lock(&print_mutex);
    printf("\r\033[2K");
    printf("Total Attempts: %llu | Progress: %d/%d | Operation: %-8s | Key: %s",
           thread_attempts,
           divisions,
           target_bit,
           must_divide ? "MUST DIV" : (rand() % 2 == 1 ? "DIV" : "SUB"),
           pubkey);
    fflush(stdout);
    pthread_mutex_unlock(&print_mutex);
}

void *find_division_path_thread(void *arg)
{
    struct thread_args *args = (struct thread_args *)arg;
    struct Point current_point;
    mpz_init(current_point.x);
    mpz_init(current_point.y);
    unsigned long long thread_attempts = 0;

    while (1)
    {
        char current_pk[132];
        char path[10000] = "";
        int divisions = 0;
        bool must_divide = false;

        mpz_set(current_point.x, args->start_pubkey.x);
        mpz_set(current_point.y, args->start_pubkey.y);

        mpz_t two, one, inversemultiplier;
        mpz_init_set_str(two, "2", 10);
        mpz_init_set_str(one, "1", 10);
        mpz_init(inversemultiplier);

        unsigned int seed;
        char seed_str[65];
        thread_attempts++;

        pthread_mutex_lock(&attempts_mutex);
        total_attempts++;
        pthread_mutex_unlock(&attempts_mutex);

        gmp_snprintf(seed_str, 65, "%Zx%d%d", current_point.x, thread_attempts, args->thread_id);
        seed = time(NULL) ^ (thread_attempts * 1099511628211ULL) ^ args->thread_id;
        srand(seed);

        while (divisions < args->target_bit)
        {
            generate_strpublickey(&current_point, true, current_pk);

            // Only thread 0 prints status
            if (args->thread_id == 0)
            {
                print_status(current_pk, divisions, args->target_bit, must_divide, total_attempts);
            }

            if (bloom_initialized1 && triple_bloom_check(current_pk))
            {
                pthread_mutex_lock(&print_mutex);
                printf("\nPotential match found by thread %d!\n", args->thread_id);
                printf("Public Key: %s\n", current_pk);
                printf("Verification Path: %s\n", path);
                pthread_mutex_unlock(&print_mutex);

                pthread_mutex_lock(&file_mutex);
                FILE *file = fopen("found_matches.txt", "a");
                if (file)
                {
                    time_t now;
                    time(&now);
                    fprintf(file, "\n=== Match Found at %s", ctime(&now));
                    fprintf(file, "Initial Public Key: %s\n", args->initial_pk);
                    fprintf(file, "Found Public Key: %s\n", current_pk);
                    fprintf(file, "By Thread: %d\n", args->thread_id);
                    fprintf(file, "At Attempt: %llu\n", thread_attempts);
                    fprintf(file, "After %d divisions\n", divisions);
                    fprintf(file, "Complete Path: %s\n", path);
                    fprintf(file, "=====================================\n");
                    fclose(file);
                }
                pthread_mutex_unlock(&file_mutex);
            }

            if (must_divide || (rand() % 2 == 1))
            {
                struct Point temp_point;
                mpz_init(temp_point.x);
                mpz_init(temp_point.y);

                mpz_invert(inversemultiplier, two, EC.n);
                Scalar_Multiplication_custom(current_point, &temp_point, inversemultiplier);

                mpz_set(current_point.x, temp_point.x);
                mpz_set(current_point.y, temp_point.y);

                divisions++;
                strcat(path, "/2,");
                must_divide = false;

                mpz_clear(temp_point.x);
                mpz_clear(temp_point.y);
            }
            else
            {
                struct Point G_point, temp_point;
                mpz_init_set(G_point.x, G.x);
                mpz_init_set(G_point.y, G.y);
                mpz_init(temp_point.x);
                mpz_init(temp_point.y);

                Scalar_Multiplication(G, &temp_point, one);

                struct Point point_to_subtract;
                mpz_init_set(point_to_subtract.x, temp_point.x);
                mpz_init_set(point_to_subtract.y, temp_point.y);

                Point_Negation(&point_to_subtract, &temp_point);

                mpz_set(point_to_subtract.x, temp_point.x);
                mpz_set(point_to_subtract.y, temp_point.y);

                Point_Addition(&current_point, &point_to_subtract, &temp_point);

                mpz_set(current_point.x, temp_point.x);
                mpz_set(current_point.y, temp_point.y);

                strcat(path, "-1,");
                must_divide = true;

                mpz_clear(G_point.x);
                mpz_clear(G_point.y);
                mpz_clear(temp_point.x);
                mpz_clear(temp_point.y);
                mpz_clear(point_to_subtract.x);
                mpz_clear(point_to_subtract.y);
            }
        }

        mpz_clear(two);
        mpz_clear(one);
        mpz_clear(inversemultiplier);
    }

    mpz_clear(current_point.x);
    mpz_clear(current_point.y);
    return NULL;
}

void generate_strpublickey(struct Point *publickey, bool compress, char *dst)
{
    memset(dst, 0, 131);
    if (compress)
    {
        if (mpz_tstbit(publickey->y, 0) == 0)
        {
            gmp_snprintf(dst, 67, "02%0.64Zx", publickey->x);
        }
        else
        {
            gmp_snprintf(dst, 67, "03%0.64Zx", publickey->x);
        }
    }
    else
    {
        gmp_snprintf(dst, 131, "04%0.64Zx%0.64Zx", publickey->x, publickey->y);
    }
}

void set_publickey(char *param, struct Point *publickey)
{
    char hexvalue[65];
    char *dest;
    int len;
    len = strlen(param);
    dest = (char *)calloc(len + 1, 1);
    if (dest == NULL)
    {
        fprintf(stderr, "[E] Error calloc\n");
        exit(0);
    }
    memset(hexvalue, 0, 65);
    memcpy(dest, param, len);
    trim(dest, " \t\n\r");
    len = strlen(dest);

    switch (len)
    {
    case 66:
        mpz_set_str(publickey->x, dest + 2, 16);
        break;
    case 130:
        memcpy(hexvalue, dest + 2, 64);
        mpz_set_str(publickey->x, hexvalue, 16);
        memcpy(hexvalue, dest + 66, 64);
        mpz_set_str(publickey->y, hexvalue, 16);
        if (mpz_cmp_ui(publickey->y, 0) == 0)
        {
            mpz_set_ui(publickey->x, 0);
        }
        else if (mpz_cmp_ui(publickey->x, 0) == 0)
        {
            mpz_set_ui(publickey->y, 0);
        }
        break;
    }

    if (mpz_cmp_ui(publickey->x, 0) == 0)
    {
        mpz_set_ui(publickey->y, 0);
    }
    else if (mpz_cmp_ui(publickey->y, 0) == 0)
    {
        mpz_t mpz_aux, mpz_aux2, Ysquared;
        mpz_init(mpz_aux);
        mpz_init(mpz_aux2);
        mpz_init(Ysquared);

        mpz_pow_ui(mpz_aux, publickey->x, 3);
        mpz_add_ui(mpz_aux2, mpz_aux, 7);
        mpz_mod(Ysquared, mpz_aux2, EC.p);

        mpz_add_ui(mpz_aux, EC.p, 1);
        mpz_fdiv_q_ui(mpz_aux2, mpz_aux, 4);
        mpz_powm(publickey->y, Ysquared, mpz_aux2, EC.p);

        mpz_sub(mpz_aux, EC.p, publickey->y);

        switch (dest[1])
        {
        case '2':
            if (mpz_tstbit(publickey->y, 0) == 1)
            {
                mpz_set(publickey->y, mpz_aux);
            }
            break;
        case '3':
            if (mpz_tstbit(publickey->y, 0) == 0)
            {
                mpz_set(publickey->y, mpz_aux);
            }
            break;
        default:
            fprintf(stderr, "[E] Invalid public key format: %s\n", dest);
            exit(0);
            break;
        }

        mpz_clear(mpz_aux);
        mpz_clear(mpz_aux2);
        mpz_clear(Ysquared);
    }
    free(dest);
}

void Scalar_Multiplication_custom(struct Point P, struct Point *R, mpz_t m)
{
    struct Point Q, T;
    long no_of_bits, loop;
    mpz_init(Q.x);
    mpz_init(Q.y);
    mpz_init(T.x);
    mpz_init(T.y);

    no_of_bits = mpz_sizeinbase(m, 2);
    mpz_set_ui(R->x, 0);
    mpz_set_ui(R->y, 0);

    if (mpz_cmp_ui(m, 0) != 0)
    {
        mpz_set(Q.x, P.x);
        mpz_set(Q.y, P.y);

        if (mpz_tstbit(m, 0) == 1)
        {
            mpz_set(R->x, P.x);
            mpz_set(R->y, P.y);
        }

        for (loop = 1; loop < no_of_bits; loop++)
        {
            Point_Doubling(&Q, &T);
            mpz_set(Q.x, T.x);
            mpz_set(Q.y, T.y);
            mpz_set(T.x, R->x);
            mpz_set(T.y, R->y);

            if (mpz_tstbit(m, loop))
            {
                Point_Addition(&T, &Q, R);
            }
        }
    }

    mpz_clear(Q.x);
    mpz_clear(Q.y);
    mpz_clear(T.x);
    mpz_clear(T.y);
}

int main(int argc, char **argv)
{
    // Initialize EC parameters
    mpz_init_set_str(EC.p, EC_constant_P, 16);
    mpz_init_set_str(EC.n, EC_constant_N, 16);
    mpz_init_set_str(G.x, EC_constant_Gx, 16);
    mpz_init_set_str(G.y, EC_constant_Gy, 16);
    init_doublingG(&G);

    mpz_init_set_ui(A.x, 0);
    mpz_init_set_ui(A.y, 0);
    mpz_init_set_ui(B.x, 0);
    mpz_init_set_ui(B.y, 0);
    mpz_init_set_ui(C.x, 0);
    mpz_init_set_ui(C.y, 0);

    mpz_init(number);
    mpz_init(inversemultiplier);

    int opt;
    char *bloom_file = NULL;
    int target_bit = 0;
    int num_threads = 1; // Default to 1 thread

    while ((opt = getopt(argc, argv, "f:b:st:")) != -1)
    {
        switch (opt)
        {
        case 'f':
            bloom_file = optarg;
            break;
        case 'b':
            target_bit = atoi(optarg);
            break;
        case 's':
            save_unsuccessful_paths = true;
            break;
        case 't':
            num_threads = atoi(optarg);
            if (num_threads < 1)
                num_threads = 1;
            break;
        default:
            printf("Usage: %s [-f bloom_file] [-b target_bit] [-t threads] [-s] <pubkey1> [operation] [pubkey2/number]\n", argv[0]);
            printf("Operations:\n");
            printf("  Normal mode: <pubkey1> [+|-|x|/] <pubkey2/number>\n");
            printf("  Division path mode: -b <target_bit> <pubkey1>\n");
            printf("  Optional: -f <bloom_filter_file> to check against known public keys\n");
            printf("  Optional: -t <threads> number of threads to use (default: 1)\n");
            printf("  Optional: -s to save unsuccessful paths\n");
            exit(1);
        }
    }

    argc -= optind;
    argv += optind;

    if (bloom_file)
    {
        if (!init_multi_bloom_from_file(bloom_file))
        {
            printf("Failed to initialize bloom filters\n");
            exit(1);
        }
    }

    if (argc < 1)
    {
        printf("Error: No public key provided\n");
        exit(1);
    }

    switch (strlen(argv[0]))
    {
    case 66:
    case 130:
        set_publickey(argv[0], &A);
        break;
    default:
        printf("Error: Invalid public key length\n");
        exit(1);
    }

    if (target_bit > 0)
    {
        if (target_bit > 256)
        {
            printf("Warning: Target bit %d is very high, this might take a while\n", target_bit);
        }

        // Create thread arguments and thread array
        pthread_t *threads = malloc(num_threads * sizeof(pthread_t));
        struct thread_args *args = malloc(num_threads * sizeof(struct thread_args));
        char initial_pk[132];
        generate_strpublickey(&A, true, initial_pk);

        printf("Starting search with %d threads\n", num_threads);
        printf("Initial public key: %s\n", initial_pk);

        // Initialize and start threads
        for (int i = 0; i < num_threads; i++)
        {
            args[i].start_pubkey = A; // Copy the initial public key
            args[i].target_bit = target_bit;
            args[i].thread_id = i;
            strcpy(args[i].initial_pk, initial_pk);

            if (pthread_create(&threads[i], NULL, find_division_path_thread, &args[i]) != 0)
            {
                printf("Failed to create thread %d\n", i);
                exit(1);
            }
        }

        // Wait for threads (though they run indefinitely in current implementation)
        for (int i = 0; i < num_threads; i++)
        {
            pthread_join(threads[i], NULL);
        }

        free(threads);
        free(args);
        cleanup_bloom_filters();

        mpz_clear(EC.p);
        mpz_clear(EC.n);
        mpz_clear(G.x);
        mpz_clear(G.y);
        mpz_clear(A.x);
        mpz_clear(A.y);
        mpz_clear(B.x);
        mpz_clear(B.y);
        mpz_clear(C.x);
        mpz_clear(C.y);
        mpz_clear(number);
        mpz_clear(inversemultiplier);

        return 0;
    }

    // Normal operation mode (non-threaded)
    if (argc != 3)
    {
        printf("Error: Incorrect number of arguments for normal operation\n");
        exit(1);
    }

    char operation = argv[1][0];
    if (operation != '+' && operation != '-' && operation != 'x' && operation != '/')
    {
        printf("Error: Invalid operation '%c'\n", operation);
        exit(1);
    }

    switch (strlen(argv[2]))
    {
    case 66:
        if (argv[2][0] == '0' && argv[2][1] == 'x')
        {
            mpz_set_str(number, argv[2], 0);
            FLAG_NUMBER = 1;
        }
        else
        {
            set_publickey(argv[2], &B);
            FLAG_NUMBER = 0;
        }
        break;
    case 130:
        set_publickey(argv[2], &B);
        FLAG_NUMBER = 0;
        break;
    default:
        mpz_set_str(number, argv[2], 0);
        FLAG_NUMBER = 1;
        break;
    }

    mpz_mod(number, number, EC.n);
    switch (operation)
    {
    case '+':
        if (FLAG_NUMBER)
        {
            Scalar_Multiplication(G, &B, number);
        }
        Point_Addition(&A, &B, &C);
        break;

    case '-':
        if (FLAG_NUMBER)
        {
            Scalar_Multiplication(G, &B, number);
        }
        Point_Negation(&B, &C);
        mpz_set(B.x, C.x);
        mpz_set(B.y, C.y);
        Point_Addition(&A, &B, &C);
        break;

    case '/':
        if (!FLAG_NUMBER)
        {
            printf("Error: Division requires a scalar number\n");
            exit(1);
        }
        mpz_invert(inversemultiplier, number, EC.n);
        Scalar_Multiplication_custom(A, &C, inversemultiplier);
        break;

    case 'x':
        if (!FLAG_NUMBER)
        {
            printf("Error: Multiplication requires a scalar number\n");
            exit(1);
        }
        Scalar_Multiplication_custom(A, &C, number);
        break;
    }

    generate_strpublickey(&C, true, str_publickey);
    printf("Result: %s\n\n", str_publickey);

    cleanup_bloom_filters();

    mpz_clear(EC.p);
    mpz_clear(EC.n);
    mpz_clear(G.x);
    mpz_clear(G.y);
    mpz_clear(A.x);
    mpz_clear(A.y);
    mpz_clear(B.x);
    mpz_clear(B.y);
    mpz_clear(C.x);
    mpz_clear(C.y);
    mpz_clear(number);
    mpz_clear(inversemultiplier);

    return 0;
}
