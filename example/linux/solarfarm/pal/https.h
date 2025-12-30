#ifndef __IOTEX_PAL_UTILS_HTTPS__
#define __IOTEX_PAL_UTILS_HTTPS__

#include <curl/curl.h>

void perform_get_request(const char *url);
void perform_post_request(const char *url, const char *post_data);
void perform_put_request(const char *url, const char *put_data);
void perform_delete_request(const char *url);
void perform_get_with_headers(const char *url, const char *api_key);


#endif