#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "pal.h"
#include "https.h"
#include "pro_config.h"

#include "include/jose/jose.h"
#include "include/dids/dids.h"
#include "include/utils/baseX/base64.h"
#include "include/utils/convert/convert.h"

#define IOTEX_SOLAR_FARM_DEMO_ERR_SUCCESS                 0
#define IOTEX_SOLAR_FARM_DEMO_ERR_BAD_INPUT_PARA         -1
#define IOTEX_SOLAR_FARM_DEMO_ERR_DATA_FORMAT            -2
#define IOTEX_SOLAR_FARM_DEMO_ERR_INSUFFICIENT_MEMORY    -3
#define IOTEX_SOLAR_FARM_DEMO_ERR_BAD_STATUS             -4
#define IOTEX_SOLAR_FARM_DEMO_ERR_ENCRYPT_FAIL           -5
#define IOTEX_SOLAR_FARM_DEMO_ERR_TIMEOUT                -6
#define IOTEX_SOLAR_FARM_DEMO_ERR_INTERNAL               -7
#define IOTEX_SOLAR_FARM_DEMO_ERR_DIDDOC_FROM_SERVER     -8
#define IOTEX_SOLAR_FARM_DEMO_ERR_REQUEST_TOKEN          -9
#define IOTEX_SOLAR_FARM_DEMO_ERR_CONFIG_UPLOAD          -10
#define IOTEX_SOLAR_FARM_DEMO_ERR_SIGNATURE_FAIL         -11
#define IOTEX_SOLAR_FARM_DEMO_ERR_VERIFY_FAIL            -12
#define IOTEX_SOLAR_FARM_DEMO_ERR_REQUEST_PUBKEY_FAIL    -13
#define IOTEX_SOLAR_FARM_DEMO_ERR_IMPORT_PUBKEY_FAIL     -14
#define IOTEX_SOLAR_FARM_DEMO_ERR_QUERY_FAIL             -15

// static char *mySignDID = NULL;
static JWK *mySignJWK  = NULL;

static void integer_to_bytes_le(uint8_t *output, uint64_t value, size_t size) {
    for (size_t i = 0; i < size; i++) {
        output[i] = (uint8_t)(value >> (i * 8));
    }
}

int32_t iotex_pal_init(void) {

    uint32_t mySignKeyID = deviceSignKeyID;
    
    psa_status_t status = psa_crypto_init();
    if (PSA_SUCCESS != status)
        return IOTEX_SOLAR_FARM_DEMO_ERR_BAD_STATUS;

    JWK *mySignJWK = iotex_jwk_generate(JWKTYPE_EC, JWK_SUPPORT_KEY_ALG_K256,
                            IOTEX_JWK_LIFETIME_PERSISTENT,
                            PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_EXPORT,
                            PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                            &mySignKeyID);    
    if (NULL == mySignJWK) {
        printf("Failed to Generate a our own Sign JWK\n");
        return IOTEX_SOLAR_FARM_DEMO_ERR_BAD_STATUS;
    }
 
#if 0
    mySignDID = iotex_did_generate("io", mySignJWK);
    if (mySignDID)
        printf("Device DID : \t\t\t%s\n", mySignDID);
    else
        return IOTEX_SOLAR_FARM_DEMO_ERR_BAD_STATUS;
#endif

    return IOTEX_SOLAR_FARM_DEMO_ERR_SUCCESS;
}

uint64_t iotex_pal_utils_get_utc_timestamp_ms() {

    return (uint64_t)time(NULL);
}

psa_status_t iotex_pal_crypt_random_generate(uint8_t *out, size_t out_size)
{
    if (NULL == out || 0 == out_size)
        return PSA_ERROR_INVALID_ARGUMENT;

    return psa_generate_random(out, out_size);
}


size_t iotex_pal_crypt_hash(uint32_t type, uint8_t *input, uint32_t input_length, uint8_t *hash_out, uint32_t hash_out_length)
{
    (void)type;
    
    size_t hash_length  = 0;
    psa_status_t status =  PSA_SUCCESS;

    if (NULL == input || NULL == hash_out)
        return PSA_ERROR_INVALID_ARGUMENT;

    if (0 == input_length)
        return PSA_ERROR_INVALID_ARGUMENT;

    if (hash_out_length < 32)
        return PSA_ERROR_INVALID_ARGUMENT;
   
    psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;    
    psa_hash_setup(&operation, PSA_ALG_SHA_256);
    psa_hash_update(&operation, input, input_length);
    status = psa_hash_finish(&operation, hash_out, hash_out_length, &hash_length); 
   
    if (PSA_SUCCESS != status)  
        hash_length = 0;

    return hash_length;
}

psa_status_t iotex_pal_crypt_ecdsa_sign(uint8_t *input, size_t input_length, uint8_t *sign, size_t *sign_length, bool isHash)
{
    psa_status_t status;

    if (NULL == input || NULL == sign || NULL == sign_length)
        return IOTEX_SOLAR_FARM_DEMO_ERR_BAD_INPUT_PARA;

    if (0 == input_length)
        return IOTEX_SOLAR_FARM_DEMO_ERR_BAD_INPUT_PARA;

    if (isHash && (input_length != 32))
        return IOTEX_SOLAR_FARM_DEMO_ERR_BAD_INPUT_PARA;

    if (isHash)
        status = psa_sign_hash(1, PSA_ALG_ECDSA(PSA_ALG_SHA_256), input, input_length, sign, 64, sign_length);         
    else
        status = psa_sign_message(1, PSA_ALG_ECDSA(PSA_ALG_SHA_256), input, input_length, sign, 64, sign_length);

#ifdef CONFIG_PSA_SECP256K1_LOWER_S_ENABLE       
    iotex_utils_secp256k1_eth_lower_s_calc(sign + 32, sign + 32);
#endif                

#if IOTEX_SOLAR_FARM_DEMO_FEATURE_ECDSA_VERIFY_ENABLE
    status = psa_verify_message(_sign_keyid, PSA_ALG_ECDSA(PSA_ALG_SHA_256), input, input_length, sign, 64);
    printf("iotex_pal_crypt_ecdsa_sign verify ret %d\n", status);     
#endif

    return status;
}

int32_t iotex_pal_send_packet(const char *post_data)
{
    if (NULL == post_data)
        return IOTEX_SOLAR_FARM_DEMO_ERR_BAD_INPUT_PARA;

    perform_post_request(IOTEX_SOLAR_FARM_DEMO_HTTP_HOST, post_data);

    return IOTEX_SOLAR_FARM_DEMO_ERR_SUCCESS;
}

char * iotex_pal_build_packet(uint64_t value)
{
    int ret = IOTEX_SOLAR_FARM_DEMO_ERR_SUCCESS;
    char * sprout_message_serialize = NULL;

    uint8_t hash_temp[32]  = {0}, publicKey[64]   = {0};
    uint8_t hash_input[48] = {0}, signature[64] = {0};
    size_t  hash_size = 0, signature_length = 0, publicKey_length = 0;

    char temp_str[64 * 2 + 2 + 1] = {0};
    temp_str[0] = '0';
    temp_str[1] = 'x';

    uint64_t now = iotex_pal_utils_get_utc_timestamp_ms();  

#if IOTEX_SOLAR_FARM_DEMO_TEST
    now = 1766905635;
#endif

    uint32_t random = 0;
    iotex_pal_crypt_random_generate((uint8_t *)&random, sizeof(random));

    cJSON * payload_json = cJSON_CreateObject();
    if (NULL == payload_json)
        return NULL;

    cJSON_AddNumberToObject(payload_json, "timestamp", now);   
    cJSON_AddNumberToObject(payload_json, "value", value);

#if 0
    cJSON_AddStringToObject(payload_json, "address", address);
#else
    psa_export_public_key(1, publicKey, sizeof(publicKey), &publicKey_length);
    if (publicKey_length != 64)
        goto exit;

    iotex_utils_convert_hex_to_str(publicKey , publicKey_length, temp_str + 2);

    cJSON_AddStringToObject(payload_json, "publicKey", temp_str);
#endif

    cJSON * upload_json = cJSON_CreateObject();
    if (NULL == upload_json) {
        ret = IOTEX_SOLAR_FARM_DEMO_ERR_INSUFFICIENT_MEMORY;
        
        cJSON_Delete(payload_json);
        
        goto exit;
    }  
    
#if IOTEX_SOLAR_FARM_DEMO_TEST
    random = 0x12345678;
#endif

    cJSON_AddNumberToObject(upload_json, "nonce", random);
    cJSON_AddStringToObject(upload_json, "projectID", IOTEX_SOLAR_FARM_DEMO_PROJECT_ID);
    cJSON_AddItemToObject(upload_json, "payload", payload_json);  
        
    char * payload_serialize = cJSON_PrintUnformatted(upload_json);
    if (NULL == payload_serialize) {
        ret = IOTEX_SOLAR_FARM_DEMO_ERR_INSUFFICIENT_MEMORY;   
        goto exit_1;
    }

    printf("Data[json] :\n%s\n", payload_serialize);

    hash_size = iotex_pal_crypt_hash(0, payload_serialize, strlen(payload_serialize), hash_input, sizeof(hash_input));
    if (32 != hash_size)
        goto exit_2; 

#if IOTEX_SOLAR_FARM_DEMO_TEST
    printf("hash [step.1]:\n");
    for (int i = 0; i < hash_size; i++) {
        printf("%02x", hash_input[i]);
    }
    printf("\n");
#endif

#if 0
    hash_input[hash_size]     = (uint8_t)(now & 0x000000FF);
    hash_input[hash_size + 1] = (uint8_t)((now & 0x0000FF00) >> 8);
    hash_input[hash_size + 2] = (uint8_t)((now & 0x00FF0000) >> 16);
    hash_input[hash_size + 3] = (uint8_t)((now & 0xFF000000) >> 24);
#endif

    integer_to_bytes_le((uint8_t *)hash_input + hash_size, now, 8);
    integer_to_bytes_le((uint8_t *)hash_input + hash_size + 8, value, 8);

#if IOTEX_SOLAR_FARM_DEMO_TEST
    printf("hash [step.2]:\n");
    for (int i = 0; i < sizeof(hash_input); i++) {
        printf("%02x", hash_input[i]);
    }
    printf("\n");
#endif

    hash_size = iotex_pal_crypt_hash(0, hash_input, sizeof(hash_input), hash_temp, sizeof(hash_temp));
    if (32 != hash_size)
        goto exit_1;

#if IOTEX_SOLAR_FARM_DEMO_TEST
    printf("hash [step.3]:\n");
    for (int i = 0; i < sizeof(hash_temp); i++) {
        printf("%02x", hash_temp[i]);
    }
    printf("\n");
#endif

    psa_status_t status = iotex_pal_crypt_ecdsa_sign(hash_temp, sizeof(hash_temp), signature, &signature_length, true);
    if (PSA_SUCCESS != status) {
        printf("Failed to Signature - %d", status);
        ret = IOTEX_SOLAR_FARM_DEMO_ERR_SIGNATURE_FAIL;
        goto exit_1;
    }    

#if IOTEX_SOLAR_FARM_DEMO_TEST
    printf("Signature R :\n");
    for (int i = 0; i < 32; i++) {
        printf("%02x", signature[i]);
    }
    printf("\n");

    printf("Signature S :\n");
    for (int i = 32; i < 64; i++) {
        printf("%02x", signature[i]);
    }
    printf("\n");
#endif
        
    iotex_utils_convert_hex_to_str(signature , signature_length, temp_str + 2);

    cJSON_AddStringToObject(upload_json, "signature", temp_str);

    sprout_message_serialize = cJSON_PrintUnformatted(upload_json);
    if (NULL == sprout_message_serialize) {
        ret = IOTEX_SOLAR_FARM_DEMO_ERR_INSUFFICIENT_MEMORY;   
        goto exit_2;
    }

    printf("Final Data : \n%s\n", sprout_message_serialize);
        
exit_2:
    if (payload_serialize) {
        free(payload_serialize);
        payload_serialize = NULL;
    }
exit_1:
    if (upload_json)
        cJSON_Delete(upload_json);
exit:
    return sprout_message_serialize;
}

