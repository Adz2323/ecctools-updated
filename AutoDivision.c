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
#include "Random.h"

// Version
const char *VERSION = "1.0.0";

// Optimization constants
#define OPTIMAL_MIN_STEPS 158
#define OPTIMAL_MAX_STEPS 230
#define TARGET_MIN_DIVISIONS 134
#define TARGET_MAX_DIVISIONS 134
#define MIN_SUBTRACTIONS 40
#define MAX_SUBTRACTIONS 97
#define PATHS_PER_SUBTRACTION_LEVEL 1000
#define MAX_TIME_AT_LEVEL 300    // 5 minutes in seconds
#define PATH_CHECK_INTERVAL 1000 // Check every 1000 attempts

// Thread management
#define MAX_THREADS 256
#define THREAD_SLEEP_MICROSECONDS 100

// Bloom filter configuration
#define MAX_ENTRIES1 1000000000
#define MAX_ENTRIES2 800000000
#define MAX_ENTRIES3 600000000
#define FP_RATE1 0.0001
#define FP_RATE2 0.00001
#define FP_RATE3 0.000001

bool debug_mode = false;

// Performance tracking
struct PerformanceMetrics
{
    double avg_path_length;
    double avg_divisions;
    double avg_subtractions;
    double success_rate;
    uint64_t total_attempts;
    uint64_t successful_attempts;
    time_t start_time;
    time_t last_success_time; // New field
    pthread_mutex_t metrics_mutex;
};

// Division control structure
struct DivisionControl
{
    int consecutive_failures;
    int success_count;
    int current_subtractions;
    int completed_paths_at_current_level;
    bool last_was_subtraction;
    pthread_mutex_t mutex;
};

// Thread argument structure
struct thread_args
{
    struct Point *start_pubkeys;
    int num_pubkeys;
    int target_bit;
    int thread_id;
    char **initial_pks;
    struct DivisionControl *div_ctrl;
    struct PerformanceMetrics *metrics;
};

// Global variables
struct Elliptic_Curve EC;
struct Point G;
struct Point DoublingG[256];

const char *EC_constant_N = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
const char *EC_constant_P = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f";
const char *EC_constant_Gx = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const char *EC_constant_Gy = "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";

// Bloom filter globals
struct bloom bloom_filter1;
struct bloom bloom_filter2;
struct bloom bloom_filter3;
bool bloom_initialized1 = false;
bool bloom_initialized2 = false;
bool bloom_initialized3 = false;
bool save_unsuccessful_paths = false;

// Thread-safe globals
pthread_mutex_t print_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t file_mutex = PTHREAD_MUTEX_INITIALIZER;
unsigned long long total_attempts = 0;
pthread_mutex_t attempts_mutex = PTHREAD_MUTEX_INITIALIZER;

// Function declarations
void initialize_performance_metrics(struct PerformanceMetrics *metrics);
void update_performance_metrics(struct PerformanceMetrics *metrics, bool success,
                                int path_length, int divisions, int subtractions);
void initialize_division_control(struct DivisionControl *ctrl);
bool should_divide(struct DivisionControl *ctrl, int current_divisions,
                   int current_subtractions, int remaining_steps,
                   int remaining_divisions_needed);
void update_division_control(struct DivisionControl *ctrl, bool path_successful);
void *find_division_path_thread(void *arg);
int init_multi_bloom_from_file(const char *filename);
void cleanup_bloom_filters(void);
bool triple_bloom_check(const char *pubkey);
void generate_strpublickey(struct Point *publickey, bool compress, char *dst);
void set_publickey(char *param, struct Point *publickey);
void save_path_to_file(const char *path, const char *found_pk, bool is_match);
bool Point_is_zero(struct Point *P);
void Scalar_Multiplication_custom(struct Point P, struct Point *R, mpz_t m);
void save_debug_info(const char *path, const char *pubkey, int divisions, int subtractions,
                     char **intermediate_pubkeys, int step_count);

void save_debug_info(const char *path, const char *pubkey, int divisions, int subtractions,
                     char **intermediate_pubkeys, int step_count)
{
    FILE *debug_file = fopen("debug_paths.txt", "a");
    if (debug_file)
    {
        double div_percentage = (divisions * 100.0) / (divisions + subtractions);
        double sub_percentage = (subtractions * 100.0) / (divisions + subtractions);

        fprintf(debug_file, "=== Path Analysis ===\n");
        fprintf(debug_file, "Path: %s\n", path);
        fprintf(debug_file, "Final Public Key: %s\n", pubkey);
        fprintf(debug_file, "Total Steps: %d\n", divisions + subtractions);
        fprintf(debug_file, "Divisions: %d (%.1f%%)\n", divisions, div_percentage);
        fprintf(debug_file, "Subtractions: %d (%.1f%%)\n", subtractions, sub_percentage);

        // Print intermediate public keys
        fprintf(debug_file, "\nIntermediate Keys:\n");
        for (int i = 0; i < step_count; i++)
        {
            fprintf(debug_file, "Step %d: %s\n", i + 1, intermediate_pubkeys[i]);
        }
        fprintf(debug_file, "\n");
        fclose(debug_file);
    }
}

// Performance tracking functions
void initialize_performance_metrics(struct PerformanceMetrics *metrics)
{
    metrics->avg_path_length = 0.0;
    metrics->avg_divisions = 0.0;
    metrics->avg_subtractions = 0.0;
    metrics->success_rate = 0.0;
    metrics->total_attempts = 0;
    metrics->successful_attempts = 0;
    metrics->start_time = time(NULL);
    metrics->last_success_time = time(NULL);
    pthread_mutex_init(&metrics->metrics_mutex, NULL);
}

void update_performance_metrics(struct PerformanceMetrics *metrics, bool success,
                                int path_length, int divisions, int subtractions)
{
    pthread_mutex_lock(&metrics->metrics_mutex);

    metrics->total_attempts++;
    if (success)
    {
        metrics->successful_attempts++;
    }

    // Update rolling averages
    double weight = 1.0 / metrics->total_attempts;
    metrics->avg_path_length = (metrics->avg_path_length * (metrics->total_attempts - 1) + path_length) * weight;
    metrics->avg_divisions = (metrics->avg_divisions * (metrics->total_attempts - 1) + divisions) * weight;
    metrics->avg_subtractions = (metrics->avg_subtractions * (metrics->total_attempts - 1) + subtractions) * weight;
    metrics->success_rate = (double)metrics->successful_attempts / metrics->total_attempts * 100.0;

    pthread_mutex_unlock(&metrics->metrics_mutex);
}

// Path validation
bool is_valid_path(int divisions, int subtractions, int total_steps,
                   struct DivisionControl *ctrl)
{
    return (divisions >= TARGET_MIN_DIVISIONS &&
            divisions <= TARGET_MAX_DIVISIONS &&
            subtractions == ctrl->current_subtractions &&
            total_steps >= OPTIMAL_MIN_STEPS &&
            total_steps <= OPTIMAL_MAX_STEPS);
}

void initialize_division_control(struct DivisionControl *ctrl)
{
    ctrl->consecutive_failures = 0;
    ctrl->success_count = 0;
    ctrl->current_subtractions = MIN_SUBTRACTIONS;
    ctrl->completed_paths_at_current_level = 0;
    ctrl->last_was_subtraction = false;
    pthread_mutex_init(&ctrl->mutex, NULL);
}

bool should_divide(struct DivisionControl *ctrl, int current_divisions,
                   int current_subtractions, int remaining_steps,
                   int remaining_divisions_needed)
{
    pthread_mutex_lock(&ctrl->mutex);

    // Calculate maximum allowed path length
    int max_path_length = TARGET_MAX_DIVISIONS + ctrl->current_subtractions;

    // Calculate remaining operations needed
    int needed_divisions = TARGET_MIN_DIVISIONS - current_divisions;
    int needed_subtractions = ctrl->current_subtractions - current_subtractions;
    int remaining_operations = max_path_length - (current_divisions + current_subtractions);

    // If we're at max path length or have all needed operations, no more allowed
    if (current_divisions + current_subtractions >= max_path_length)
    {
        pthread_mutex_unlock(&ctrl->mutex);
        return false;
    }

    // Must divide after a subtraction
    if (ctrl->last_was_subtraction)
    {
        ctrl->last_was_subtraction = false;
        pthread_mutex_unlock(&ctrl->mutex);
        return true;
    }

    // If this is the last possible operation, it must be a division
    if (remaining_operations == 1)
    {
        pthread_mutex_unlock(&ctrl->mutex);
        return true;
    }

    // Calculate probability based on remaining requirements
    double probability = 0.5; // Start with 50/50

    // If we're behind on subtractions relative to path length, favor subtractions
    double current_progress = (double)(current_divisions + current_subtractions) / max_path_length;
    double subtraction_progress = (double)current_subtractions / ctrl->current_subtractions;

    if (subtraction_progress < current_progress && needed_subtractions > 0)
    {
        probability = 0.3; // 30% chance of division to catch up on subtractions
    }

    // If we need most remaining slots for divisions, favor divisions
    if (needed_divisions > (remaining_operations * 0.7))
    {
        probability = 0.7; // 70% chance of division
    }

    // Make random choice
    bool should_do_division = rnd() < probability;

    // Verify we can actually do a subtraction if that's what was chosen
    if (!should_do_division && needed_subtractions > 0 && remaining_operations >= 2)
    {
        ctrl->last_was_subtraction = true;
    }
    else
    {
        should_do_division = true;
    }

    pthread_mutex_unlock(&ctrl->mutex);
    return should_do_division;
}

void update_division_control(struct DivisionControl *ctrl, bool path_successful)
{
    pthread_mutex_lock(&ctrl->mutex);

    if (path_successful) {
        ctrl->consecutive_failures = 0;
        ctrl->success_count++;
        ctrl->completed_paths_at_current_level++;

        if (ctrl->completed_paths_at_current_level >= PATHS_PER_SUBTRACTION_LEVEL) {
            if (ctrl->current_subtractions == MAX_SUBTRACTIONS) {
                pthread_mutex_lock(&print_mutex);
                printf("\rResetting from %d back to %d subtractions        ", 
                       ctrl->current_subtractions, MIN_SUBTRACTIONS);
                fflush(stdout);
                pthread_mutex_unlock(&print_mutex);

                ctrl->current_subtractions = MIN_SUBTRACTIONS;
                ctrl->completed_paths_at_current_level = 0;
            }
            else {
                ctrl->current_subtractions++;
                pthread_mutex_lock(&print_mutex);
                printf("\rAdvancing to subtraction level: %d        ", 
                       ctrl->current_subtractions);
                fflush(stdout);
                pthread_mutex_unlock(&print_mutex);
                ctrl->completed_paths_at_current_level = 0;
            }
        }
    }
    else {
        ctrl->consecutive_failures++;
        
        // Optional: Add failure handling logic here if needed
        if (ctrl->consecutive_failures > 1000000) { // Example threshold
            ctrl->consecutive_failures = 0;
        }
    }

    pthread_mutex_unlock(&ctrl->mutex);
}

// Thread worker function
void *find_division_path_thread(void *arg)
{
    struct thread_args *args = (struct thread_args *)arg;
    struct Point *current_points = malloc(args->num_pubkeys * sizeof(struct Point));
    unsigned long long thread_attempts = 0;

    // Initialize current points
    for (int i = 0; i < args->num_pubkeys; i++)
    {
        mpz_init(current_points[i].x);
        mpz_init(current_points[i].y);
    }

    // Initialize GMP variables
    mpz_t two, one;
    mpz_init_set_str(two, "2", 10);
    mpz_init_set_str(one, "1", 10);
    mpz_t inversemultiplier;
    mpz_init(inversemultiplier);

    // Debug mode variables
    char **intermediate_pubkeys = NULL;
    int step_count = 0;
    if (debug_mode)
    {
        intermediate_pubkeys = malloc(OPTIMAL_MAX_STEPS * sizeof(char *));
        for (int i = 0; i < OPTIMAL_MAX_STEPS; i++)
        {
            intermediate_pubkeys[i] = malloc(132);
        }
    }

    while (1)
    {
        // Reset step count for new attempt
        step_count = 0;

        // Allocate memory for current public keys
        char **current_pks = malloc(args->num_pubkeys * sizeof(char *));
        for (int i = 0; i < args->num_pubkeys; i++)
        {
            current_pks[i] = malloc(132);
        }

        // Initialize path variables
        char path[10000] = "";
        int divisions = 0;
        int subtractions = 0;
        int total_steps = 0;
        bool must_divide = false;

        // Initialize current points
        for (int i = 0; i < args->num_pubkeys; i++)
        {
            mpz_set(current_points[i].x, args->start_pubkeys[i].x);
            mpz_set(current_points[i].y, args->start_pubkeys[i].y);
        }

        // Update attempt counters
        pthread_mutex_lock(&attempts_mutex);
        total_attempts++;
        thread_attempts++;
        pthread_mutex_unlock(&attempts_mutex);

        // Check if we need to reset based on time
        pthread_mutex_lock(&args->div_ctrl->mutex);
        time_t current_time = time(NULL);
        if (args->div_ctrl->current_subtractions == MAX_SUBTRACTIONS &&
            current_time - args->metrics->last_success_time > MAX_TIME_AT_LEVEL)
        {

            pthread_mutex_lock(&print_mutex);
            printf("\nResetting due to timeout at max level (no success in %d seconds)\n",
                   MAX_TIME_AT_LEVEL);
            pthread_mutex_unlock(&print_mutex);

            args->div_ctrl->current_subtractions = MIN_SUBTRACTIONS;
            args->div_ctrl->completed_paths_at_current_level = 0;
            args->metrics->last_success_time = current_time;
        }
        pthread_mutex_unlock(&args->div_ctrl->mutex);

        // Main path finding loop
        while (divisions < TARGET_MAX_DIVISIONS && total_steps < OPTIMAL_MAX_STEPS)
        {
            // Generate current public keys
            for (int i = 0; i < args->num_pubkeys; i++)
            {
                generate_strpublickey(&current_points[i], true, current_pks[i]);

                // Save intermediate keys in debug mode
                if (debug_mode && step_count < OPTIMAL_MAX_STEPS)
                {
                    strncpy(intermediate_pubkeys[step_count], current_pks[i], 131);
                    intermediate_pubkeys[step_count][131] = '\0';
                }
            }

            // Print status for thread 0
            if (args->thread_id == 0)
            {
                pthread_mutex_lock(&print_mutex);
                printf("\r\033[K"); // Clear line
                printf("Attempts: %llu | DIV: %.1f%% SUB: %.1f%% | Steps: %d/%d | "
                       "Divisions: %d/%d | Subs: %d/%d | Level Progress: %d/%d | Key: %.20s",
                       total_attempts,
                       divisions > 0 ? (divisions * 100.0) / (divisions + subtractions) : 0,
                       subtractions > 0 ? (subtractions * 100.0) / (divisions + subtractions) : 0,
                       total_steps,
                       TARGET_MAX_DIVISIONS + args->div_ctrl->current_subtractions,
                       divisions,
                       TARGET_MAX_DIVISIONS,
                       subtractions,
                       args->div_ctrl->current_subtractions,
                       args->div_ctrl->completed_paths_at_current_level,
                       PATHS_PER_SUBTRACTION_LEVEL,
                       current_pks[0]);
                fflush(stdout);
                pthread_mutex_unlock(&print_mutex);
            }

            // Check keys against bloom filter
            for (int i = 0; i < args->num_pubkeys; i++)
            {
                if (bloom_initialized1 && triple_bloom_check(current_pks[i]))
                {
                    pthread_mutex_lock(&print_mutex);
                    printf("\nMatch found! Thread %d, Key %d\n", args->thread_id, i);
                    printf("Original: %s\n", args->initial_pks[i]);
                    printf("Found: %s\n", current_pks[i]);
                    printf("Path: %s\n", path);
                    pthread_mutex_unlock(&print_mutex);

                    save_path_to_file(path, current_pks[i], true);
                }
            }

            int remaining_steps = OPTIMAL_MAX_STEPS - total_steps;
            int remaining_divisions = TARGET_MIN_DIVISIONS - divisions;

            if (should_divide(args->div_ctrl, divisions, subtractions,
                              remaining_steps, remaining_divisions))
            {
                // Perform division
                for (int i = 0; i < args->num_pubkeys; i++)
                {
                    struct Point temp_point;
                    mpz_init(temp_point.x);
                    mpz_init(temp_point.y);

                    mpz_invert(inversemultiplier, two, EC.n);
                    Scalar_Multiplication_custom(current_points[i], &temp_point, inversemultiplier);

                    mpz_set(current_points[i].x, temp_point.x);
                    mpz_set(current_points[i].y, temp_point.y);

                    mpz_clear(temp_point.x);
                    mpz_clear(temp_point.y);
                }
                divisions++;
                total_steps++;
                strcat(path, "/2,");
                must_divide = false;
            }
            else
            {
                // Perform subtraction
                for (int i = 0; i < args->num_pubkeys; i++)
                {
                    struct Point temp_point, point_to_subtract;
                    mpz_init(temp_point.x);
                    mpz_init(temp_point.y);
                    mpz_init(point_to_subtract.x);
                    mpz_init(point_to_subtract.y);

                    Scalar_Multiplication(G, &point_to_subtract, one);
                    Point_Negation(&point_to_subtract, &temp_point);
                    Point_Addition(&current_points[i], &temp_point, &point_to_subtract);

                    mpz_set(current_points[i].x, point_to_subtract.x);
                    mpz_set(current_points[i].y, point_to_subtract.y);

                    mpz_clear(temp_point.x);
                    mpz_clear(temp_point.y);
                    mpz_clear(point_to_subtract.x);
                    mpz_clear(point_to_subtract.y);
                }
                subtractions++;
                total_steps++;
                strcat(path, "-1,");
                must_divide = true;
            }

            // Increment step count after each operation
            if (debug_mode)
            {
                step_count++;
            }

            // Check if all points are zero
            bool all_zero = true;
            for (int i = 0; i < args->num_pubkeys; i++)
            {
                if (!Point_is_zero(&current_points[i]))
                {
                    all_zero = false;
                    break;
                }
            }
            if (all_zero)
                break;
        }

        // Update division control based on path success
        bool path_successful = is_valid_path(divisions, subtractions, total_steps, args->div_ctrl);
        if (path_successful)
        {
            if (debug_mode)
            {
                save_debug_info(path, current_pks[0], divisions, subtractions,
                                intermediate_pubkeys, step_count);
            }
            args->metrics->last_success_time = time(NULL);
        }

        update_division_control(args->div_ctrl, path_successful);
        update_performance_metrics(args->metrics, path_successful, total_steps, divisions, subtractions);

        // Check if we should validate paths at max level
        if (args->div_ctrl->current_subtractions == MAX_SUBTRACTIONS &&
            thread_attempts % PATH_CHECK_INTERVAL == 0)
        {

            pthread_mutex_lock(&args->div_ctrl->mutex);
            time_t current_time = time(NULL);
            if (current_time - args->metrics->last_success_time > MAX_TIME_AT_LEVEL)
            {
                args->div_ctrl->current_subtractions = MIN_SUBTRACTIONS;
                args->div_ctrl->completed_paths_at_current_level = 0;
                args->metrics->last_success_time = current_time;

                pthread_mutex_lock(&print_mutex);
                printf("\nResetting from max level due to inactivity\n");
                pthread_mutex_unlock(&print_mutex);
            }
            pthread_mutex_unlock(&args->div_ctrl->mutex);
        }

        // Save successful paths
        if (path_successful || save_unsuccessful_paths)
        {
            for (int i = 0; i < args->num_pubkeys; i++)
            {
                save_path_to_file(path, current_pks[i], path_successful);
            }
        }

        // Cleanup current iteration
        for (int i = 0; i < args->num_pubkeys; i++)
        {
            free(current_pks[i]);
        }
        free(current_pks);
    }

    // Final cleanup
    mpz_clear(two);
    mpz_clear(one);
    mpz_clear(inversemultiplier);

    // Cleanup debug resources
    if (debug_mode)
    {
        for (int i = 0; i < OPTIMAL_MAX_STEPS; i++)
        {
            free(intermediate_pubkeys[i]);
        }
        free(intermediate_pubkeys);
    }

    for (int i = 0; i < args->num_pubkeys; i++)
    {
        mpz_clear(current_points[i].x);
        mpz_clear(current_points[i].y);
    }
    free(current_points);

    return NULL;
}

// Bloom filter operations
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

// Public key operations
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
        }

        mpz_clear(mpz_aux);
        mpz_clear(mpz_aux2);
        mpz_clear(Ysquared);
    }
    free(dest);
}

void save_path_to_file(const char *path, const char *found_pk, bool is_match)
{
    pthread_mutex_lock(&file_mutex);
    time_t now;
    time(&now);

    FILE *file = fopen("found_paths.txt", "a");
    if (file)
    {
        fprintf(file, "=== Search Result %s", ctime(&now));
        fprintf(file, "Public Key: %s\n", found_pk);
        fprintf(file, "Path: %s\n", path);
        fprintf(file, "Match Type: %s\n\n", is_match ? "CONFIRMED" : "POTENTIAL");
        fclose(file);
    }
    else
    {
        printf("Warning: Could not save path to file\n");
    }
    pthread_mutex_unlock(&file_mutex);
}

bool Point_is_zero(struct Point *P)
{
    return (mpz_cmp_ui(P->x, 0) == 0 && mpz_cmp_ui(P->y, 0) == 0);
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

// Main function
int main(int argc, char **argv)
{
    // Initialize Random
    rseed(time(NULL));

    // Initialize elliptic curve constants
    mpz_init_set_str(EC.p, EC_constant_P, 16);
    mpz_init_set_str(EC.n, EC_constant_N, 16);
    mpz_init_set_str(G.x, EC_constant_Gx, 16);
    mpz_init_set_str(G.y, EC_constant_Gy, 16);
    init_doublingG(&G);

    // Initialize points for single operations
    struct Point A, B, C;
    mpz_init_set_ui(A.x, 0);
    mpz_init_set_ui(A.y, 0);
    mpz_init_set_ui(B.x, 0);
    mpz_init_set_ui(B.y, 0);
    mpz_init_set_ui(C.x, 0);
    mpz_init_set_ui(C.y, 0);

    mpz_t number, inversemultiplier;
    mpz_init(number);
    mpz_init(inversemultiplier);
    bool FLAG_NUMBER = false;
    char str_publickey[132];

    // Initialize performance metrics
    struct PerformanceMetrics metrics;
    initialize_performance_metrics(&metrics);

    int opt;
    char *bloom_file = NULL;
    int target_bit = 0;
    int num_threads = 1;

    while ((opt = getopt(argc, argv, "f:b:st:d")) != -1)
    {
        switch (opt)
        {
        case 'd':
            debug_mode = true;
            break;
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
            if (num_threads > MAX_THREADS)
                num_threads = MAX_THREADS;
            break;
        default:
            printf("Usage: %s [-f bloom_file] [-b target_bit] [-t threads] [-s] <pubkey1> [operation] [pubkey2/number]\n", argv[0]);
            printf("Operations:\n");
            printf("  Normal mode: <pubkey1> [+|-|x|/] <pubkey2/number>\n");
            printf("  Division path mode: -b <target_bit> <pubkey1> [pubkey2...]\n");
            printf("  Optional: -f <bloom_filter_file> to check against known public keys\n");
            exit(1);
        }
    }

    argc -= optind;
    argv += optind;

    if (bloom_file && !init_multi_bloom_from_file(bloom_file))
    {
        printf("Failed to initialize bloom filters\n");
        exit(1);
    }

    if (argc < 1)
    {
        printf("Error: No public key provided\n");
        exit(1);
    }

    // Normal operation mode (non-threaded)
    if (target_bit == 0)
    {
        if (argc != 3)
        {
            printf("Error: Incorrect number of arguments for normal operation\n");
            exit(1);
        }

        // Set first public key
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

        char operation = argv[1][0];
        if (operation != '+' && operation != '-' && operation != 'x' && operation != '/')
        {
            printf("Error: Invalid operation '%c'\n", operation);
            exit(1);
        }

        // Parse second argument
        switch (strlen(argv[2]))
        {
        case 66:
            if (argv[2][0] == '0' && argv[2][1] == 'x')
            {
                mpz_set_str(number, argv[2], 0);
                FLAG_NUMBER = true;
            }
            else
            {
                set_publickey(argv[2], &B);
                FLAG_NUMBER = false;
            }
            break;
        case 130:
            set_publickey(argv[2], &B);
            FLAG_NUMBER = false;
            break;
        default:
            mpz_set_str(number, argv[2], 0);
            FLAG_NUMBER = true;
            break;
        }

        mpz_mod(number, number, EC.n);

        // Perform operation
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

        case 'x':
            if (!FLAG_NUMBER)
            {
                printf("Error: Multiplication requires a scalar number\n");
                exit(1);
            }
            Scalar_Multiplication_custom(A, &C, number);
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
        }

        generate_strpublickey(&C, true, str_publickey);
        printf("Result: %s\n\n", str_publickey);
    }
    // Threading mode
    else
    {
        int num_pubkeys = argc;
        struct Point *pubkeys = malloc(num_pubkeys * sizeof(struct Point));
        char **initial_pks = malloc(num_pubkeys * sizeof(char *));

        for (int i = 0; i < num_pubkeys; i++)
        {
            mpz_init(pubkeys[i].x);
            mpz_init(pubkeys[i].y);
            initial_pks[i] = malloc(132);
            set_publickey(argv[i], &pubkeys[i]);
            generate_strpublickey(&pubkeys[i], true, initial_pks[i]);
        }

        pthread_t *threads = malloc(num_threads * sizeof(pthread_t));
        struct thread_args *args = malloc(num_threads * sizeof(struct thread_args));
        struct DivisionControl *div_ctrl = malloc(sizeof(struct DivisionControl));
        initialize_division_control(div_ctrl);

        printf("Starting search with %d threads for %d public keys\n", num_threads, num_pubkeys);
        for (int i = 0; i < num_pubkeys; i++)
        {
            printf("Initial public key %d: %s\n", i + 1, initial_pks[i]);
        }

        for (int i = 0; i < num_threads; i++)
        {
            args[i].start_pubkeys = pubkeys;
            args[i].num_pubkeys = num_pubkeys;
            args[i].target_bit = target_bit;
            args[i].thread_id = i;
            args[i].initial_pks = initial_pks;
            args[i].div_ctrl = div_ctrl;
            args[i].metrics = &metrics;

            if (pthread_create(&threads[i], NULL, find_division_path_thread, &args[i]) != 0)
            {
                printf("Failed to create thread %d\n", i);
                exit(1);
            }
        }

        for (int i = 0; i < num_threads; i++)
        {
            pthread_join(threads[i], NULL);
        }

        // Cleanup threading resources
        for (int i = 0; i < num_pubkeys; i++)
        {
            mpz_clear(pubkeys[i].x);
            mpz_clear(pubkeys[i].y);
            free(initial_pks[i]);
        }
        free(pubkeys);
        free(initial_pks);
        free(threads);
        free(args);
        pthread_mutex_destroy(&div_ctrl->mutex);
        free(div_ctrl);
    }

    // Final cleanup
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
    pthread_mutex_destroy(&metrics.metrics_mutex);

    return 0;
}
