#include "device.h"
#include "cpeutil.h"

int CpeGetTimeEnable(void *arg, char ** value)
{
    return CpeGetValue(arg, value, "ntpclient.global.enable");
}

int CpeSetTimeEnable(void * arg, const char * value, callback_reg_func_t func)
{
    return 0;
}

int CpeGetTimeNTPServer1(void *arg, char ** value)
{
    return CpeGetValue(arg, value, "ntpclient.ntpserver1.hostname");
}



int CpeSetTimeNTPServer1(void * arg, const char * value, callback_reg_func_t func)
{
    return CpeSetValue(arg, value, "ntpclient.ntpserver1.hostname");
}

int CpeGetTimeCurrentLocalTime(void *arg, char ** value)
{
    SoapDateTime dt;
    char buffer[128] = {0};

    dt = GetLocalSoapDateTime();
    sprintf(buffer,"%4d-%02d-%02dT%02d:%02d:%02d",
            dt.year,
            dt.month,
            dt.day,
            dt.hour,
            dt.min,
            dt.sec);
    *value = OTXMLStrdup(buffer);
    return FAULT_CPE_0;
}

