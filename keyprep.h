#ifndef KEYPREP_H
#define KEYPREP_H

#include <gmp.h>
#include <stdint.h>
#include <stdbool.h>
#include "gmpecc.h"

// Structure to hold a prepared public key and its subtraction path
struct PreparedKey
{
    struct Point point;     // The resulting public key point
    char *pubkey_hex;       // Hex string representation
    char *path;             // String representation of the subtraction path
    uint64_t *subtractions; // Array of subtraction values used
    int subtraction_count;  // Number of subtractions performed
    bool valid;             // Whether the preparation was successful
};

// Structure to hold multiple prepared keys
struct PreparedKeys
{
    struct PreparedKey *keys;
    int count;
};

// Get a random decimal from a specific group
const char *get_random_decimal(const char **group, int group_size);

// Main function to prepare keys through subtraction
struct PreparedKeys prepare_keys(const char **input_pubkeys, int num_keys, int start_group, int end_group, int subtractions_per_group);

// Function to reverse the pathway and calculate original private key
uint64_t reverse_preparation_path(uint64_t final_privkey, const struct PreparedKey *prep_key);

// Cleanup function
void cleanup_prepared_keys(struct PreparedKeys *keys);

#endif // KEYPREP_H
