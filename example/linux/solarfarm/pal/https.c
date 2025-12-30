#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <curl/curl.h>

struct MemoryStruct {
    char *memory;
    size_t size;
};

static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;
    
    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if(!ptr) {
        printf("Memory Insufficient\n");
        return 0;
    }
    
    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;
    
    return realsize;
}

// GET
void perform_get_request(const char *url) {
    printf("Send GET Request To: %s\n", url);
    
    CURL *curl;
    CURLcode res;
    struct MemoryStruct chunk;
    
    chunk.memory = malloc(1); 
    chunk.size = 0;
    
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    
    if(curl) {
        // Set URL
        curl_easy_setopt(curl, CURLOPT_URL, url);
        
        // Set SSL/TLS
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);    
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);    
        curl_easy_setopt(curl, CURLOPT_CAINFO, "/etc/ssl/certs/ca-certificates.crt");
        
        // Set Callback Function
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
        
        // Set Timeout
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
        
        // Set User-Agent
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "RaspberryPi-API-Client/1.0");
        
        res = curl_easy_perform(curl);
        
        // Check Error
        if(res != CURLE_OK) {
            fprintf(stderr, "Failed: %s\n", curl_easy_strerror(res));
        } else {
            long http_code = 0;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
            printf("HTTP Coed: %ld\n", http_code);
            printf("R-Body:\n%s\n", chunk.memory);
        }
        
        // Cleanup
        curl_easy_cleanup(curl);
        free(chunk.memory);
    }
    
    curl_global_cleanup();
}

// POST 
void perform_post_request(const char *url, const char *post_data) {
    printf("Send POST request to : %s\n", url);
    printf("POST Data: %s\n", post_data);
    
    CURL *curl;
    CURLcode res;
    struct MemoryStruct chunk;
    
    chunk.memory = malloc(1);
    chunk.size = 0;
    
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    
    if(curl) {
    
        curl_easy_setopt(curl, CURLOPT_URL, url);
        
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
        
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
        curl_easy_setopt(curl, CURLOPT_CAINFO, "/etc/ssl/certs/ca-certificates.crt");
        
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
        
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
        
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        headers = curl_slist_append(headers, "Accept: application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        
        res = curl_easy_perform(curl);
        
        if(res != CURLE_OK) {
            fprintf(stderr, "Failed to request: %s\n", curl_easy_strerror(res));
        } else {
            long http_code = 0;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
            printf("HTTP Status Code: %ld\n", http_code);
            printf("Response Body:\n%s\n", chunk.memory);
        }
        
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        free(chunk.memory);
    }
    
    curl_global_cleanup();
}

void perform_put_request(const char *url, const char *put_data) {
    printf("Send PUT Request to : %s\n", url);
    
    CURL *curl;
    CURLcode res;
    struct MemoryStruct chunk;
    
    chunk.memory = malloc(1);
    chunk.size = 0;
    
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url);
        
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
        
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, put_data);
        
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
        
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        
        res = curl_easy_perform(curl);
        
        if(res != CURLE_OK) {
            fprintf(stderr, "Failed to PUT Request: %s\n", curl_easy_strerror(res));
        } else {
            long http_code = 0;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
            printf("HTTP Status Code: %ld\n", http_code);
            printf("Response Body:\n%s\n", chunk.memory);
        }
        
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        free(chunk.memory);
    }
    
    curl_global_cleanup();
}

// DELETE
void perform_delete_request(const char *url) {
    printf("Send DELETE Request to: %s\n", url);
    
    CURL *curl;
    CURLcode res;
    struct MemoryStruct chunk;
    
    chunk.memory = malloc(1);
    chunk.size = 0;
    
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url);
        
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");
        
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
        
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
        
        res = curl_easy_perform(curl);
        
        if(res != CURLE_OK) {
            fprintf(stderr, "Failed to DELETE Request: %s\n", curl_easy_strerror(res));
        } else {
            long http_code = 0;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
            printf("HTTP Status Code: %ld\n", http_code);
            printf("Response Body:\n%s\n", chunk.memory);
        }
        
        curl_easy_cleanup(curl);
        free(chunk.memory);
    }
    
    curl_global_cleanup();
}

void perform_get_with_headers(const char *url, const char *api_key) {
    printf("Send a GET request with an authentication header.\n");
    
    CURL *curl;
    CURLcode res;
    struct MemoryStruct chunk;
    
    chunk.memory = malloc(1);
    chunk.size = 0;
    
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url);
        
        struct curl_slist *headers = NULL;
        
        char auth_header[256];
        snprintf(auth_header, sizeof(auth_header), "Authorization: Bearer %s", api_key);
        headers = curl_slist_append(headers, auth_header);
        
        headers = curl_slist_append(headers, "Accept: application/json");
        
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
        
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
        
        res = curl_easy_perform(curl);
        
        if(res != CURLE_OK) {
            fprintf(stderr, "Failed to Request: %s\n", curl_easy_strerror(res));
        } else {
            long http_code = 0;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
            printf("HTTP Status Code: %ld\n", http_code);
            printf("Response Body:\n%s\n", chunk.memory);
        }
        
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        free(chunk.memory);
    }
    
    curl_global_cleanup();
}

#if 0
// Testing
int main(void) {
    
    const char *test_get_url = "https://jsonplaceholder.typicode.com/posts/1";
    const char *test_post_url = "https://jsonplaceholder.typicode.com/posts";
    
    const char *post_json = "{\"title\":\"foo\",\"body\":\"bar\",\"userId\":1}";
    const char *put_json = "{\"title\":\"updated title\",\"body\":\"updated body\",\"userId\":1}";
    
    printf("1. Test GET Request:\n");
    perform_get_request(test_get_url);
    
    printf("\n2. Testing POST Request:\n");
    perform_post_request(test_post_url, post_json);
    
    printf("\n3. Testing PUT Request:\n");
    perform_put_request("https://jsonplaceholder.typicode.com/posts/1", put_json);
    
    printf("\n4. Testing DELETE Request:\n");
    perform_delete_request("https://jsonplaceholder.typicode.com/posts/1");
    
    printf("\n5. Testing a GET request with an authentication header:\n");
    // perform_get_with_headers("https://api.example.com/data", "your_api_key_here");
    
    return 0;
}
#endif

