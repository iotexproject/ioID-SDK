#ifndef __IOTEX_PAL_PAL_H__
#define __IOTEX_PAL_PAL_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "include/jose/jose.h"
#include "include/dids/dids.h"
#include "include/utils/baseX/base64.h"
#include "include/utils/convert/convert.h"

#define deviceSignKeyID  1

int32_t iotex_pal_init(void);
int32_t iotex_pal_send_packet(const char *post_data);
int32_t iotex_pal_build_and_send_packet(uint64_t value);
char *  iotex_pal_build_packet(uint64_t value);

#endif
