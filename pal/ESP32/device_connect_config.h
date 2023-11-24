#ifndef __IOTEX_DEVICECONNECT_SDK_CONFIG__
#define __IOTEX_DEVICECONNECT_SDK_CONFIG__

#define IOTEX_DEVICE_CONNECT_DATA_UPDATA_USE_STANDARD_LAYER
#define IOTEX_DEVICE_CONNECT_DATA_UPDATA_USE_STANDARD_LAYER_TEST      

#ifdef IOTEX_DEVICE_CONNECT_DATA_UPDATA_USE_STANDARD_LAYER
#define STANDARD_LAYER_EVENT_LOOP       sensor_data_event_handle
#define STANDARD_LAYER_EVENT_BASE       SENSOR_DATA_EVENT_BASE
#define STANDARD_LAYER_EVENT_ID         -1
#endif

#define IOTEX_DEVICE_SN_LEN     32
#define IOTEX_DEVICE_SN_USE_STATIC      
#ifdef IOTEX_DEVICE_SN_USE_STATIC
#define IOTEX_DEVICE_SN         "1234567890"
#endif

#endif



