// plugins/http/extra.c - HTTP extra features

#include "../../src/clobes.h"

// Multipart form upload
int http_multipart_upload(const char *url, const char *file_path, 
                          const char *field_name) {
    CURL *curl = curl_easy_init();
    if (!curl) return 1;
    
    struct curl_httppost *formpost = NULL;
    struct curl_httppost *lastptr = NULL;
    
    // Add file field
    curl_formadd(&formpost, &lastptr,
                 CURLFORM_COPYNAME, field_name,
                 CURLFORM_FILE, file_path,
                 CURLFORM_END);
    
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost);
    
    CURLcode res = curl_easy_perform(curl);
    
    curl_formfree(formpost);
    curl_easy_cleanup(curl);
    
    return (res == CURLE_OK) ? 0 : 1;
}

// HTTP/2 test
int http2_test(const char *url) {
    CURL *curl = curl_easy_init();
    if (!curl) return 1;
    
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    
    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    
    return (res == CURLE_OK) ? 0 : 1;
}
