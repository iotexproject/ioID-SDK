#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "https.h"
#include "pal.h"
#include "pro_config.h"

int main (void) {

    char * message_body = NULL; 
    
    iotex_pal_init();

    int value = 5;

    while (true)
    {    
        sleep(5);

        if (value >= 10)
            value = 5;

        message_body = iotex_pal_build_packet(value++);
        if (NULL == message_body)
            continue;

        iotex_pal_send_packet(message_body);
        
        if (message_body) {
            free (message_body);
            message_body = NULL;
        }        
    }

// iotex_jwk_destroy(mySignJWK);        

exit:          

    return 0;
}