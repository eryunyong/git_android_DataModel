#include <stdio.h>  
#include <stdlib.h> 
#include <unistd.h>  
#include <sys/socket.h>  
#include <arpa/inet.h>  
#include <string.h>  
#include <sys/ioctl.h>  
#include <net/if.h>  

#include "device.h"
#include "cpeutil.h"
#include "log.h"

int CpeGetManagementServerConnectionRequestURL(void *arg, char ** value)
{
    char buffer[TR069_PARAMVALUE_SIZE] = {0};
    char *pVal = NULL;
    char ip[16] = {0};

    if (CpeGetValue(NULL, &pVal, "cpeagent.cpe.debugtest") == FAULT_CPE_0 && OTXMLStrcasecmp(pVal, "1") == 0)
    {
        if (pVal)
        {
            OTXMLFree(pVal);
            pVal = NULL;
        }
        
        if (CpeGetValue(NULL, &pVal, "cpeagent.cpe.debugip") == FAULT_CPE_0)
        {
             strncpy(ip, pVal, sizeof(ip));
             OTXMLFree(pVal);
             pVal = NULL;
        }
        
        device_error("============Andy debug: CpeGetManagementServerConnectionRequestURL debugip= %s.\n", ip);

        if (CpeGetValue(NULL, &pVal, "cpeagent.tr069.cpeport") == FAULT_CPE_0)
        {
            int cpeport = atoi(pVal);
            
            OTXMLFree(pVal);        
            pVal = NULL;
                    
            snprintf(buffer, TR069_PARAMVALUE_SIZE, "http://%s:%d", ip, cpeport);
            *value = (char *)OTXMLMalloc(strlen(buffer) + 1);
        
            if (*value == NULL)
            {
                device_error("OTXMLMalloc %d failed.\n", strlen(buffer) + 1);
                return FAULT_CPE_9002;
            }
            strcpy(*value, buffer);
            *((*value) + strlen(buffer)) = '\0';
        }
        else
        {
            return FAULT_CPE_9002;
        }
        device_error("============Andy debug: CpeGetManagementServerConnectionRequestURL *value = %s.\n", *value);

        return FAULT_CPE_0;
    }        

    if (CpeGetValue(NULL, &pVal, "cpeagent.tr069.cpeport") == FAULT_CPE_0)
    {
        int cpeport = atoi(pVal);
        
        OTXMLFree(pVal);        
        pVal = NULL;
        
        if (CpeGetValue(NULL, &pVal, "cpeagent.tr069.cpe_ipaddr") == FAULT_CPE_0)
        {       
             strncpy(ip, pVal, sizeof(ip));
             OTXMLFree(pVal);
             pVal = NULL;
        }

        snprintf(buffer, TR069_PARAMVALUE_SIZE, "http://%s:%d", ip, cpeport);
        *value = (char *)OTXMLMalloc(strlen(buffer) + 1);

        if (*value == NULL)
        {
            device_error("OTXMLMalloc %d failed.\n", strlen(buffer) + 1);
            return FAULT_CPE_9002;
        }
        strcpy(*value, buffer);
        *((*value) + strlen(buffer)) = '\0';
    }
    else
    {
        return FAULT_CPE_9002;
    }

    return 0;
}

int CpeGetManagementServerConnectionRequestUsername(void *arg, char ** value)
{
     return CpeGetValue(arg, value, "cpeagent.tr069.cpeauth_user");
}

int CpeSetManagementServerConnectionRequestUsername(void * arg, const char * value, callback_reg_func_t func)
{
    return CpeSetValue(arg, value, "cpeagent.tr069.cpeauth_user");
}

/*
When read, this parameter returns an empty string,
regardless of the actual value
*/
int CpeGetManagementServerConnectionRequestPassword(void *arg, char ** value)
{
     return CpeGetValue(arg, value, "cpeagent.tr069.cpeauth_pass");
}

int CpeSetManagementServerConnectionRequestPassword(void * arg, const char * value, callback_reg_func_t func)
{
    return CpeSetValue(arg, value, "cpeagent.tr069.cpeauth_pass");
}


int CpeGetManagementServerUsername(void *arg, char ** value)
{
     return CpeGetValue(arg, value, "cpeagent.tr069.acsauth_user");
}

int CpeSetManagementServerUsername(void * arg, const char * value, callback_reg_func_t func)
{
     return CpeSetValue(arg, value, "cpeagent.tr069.acsauth_user");
}

/*
FIXME
When read, this parameter returns an empty string,
regardless of the actual value.
*/
int CpeGetManagementServerPassword(void *arg, char ** value)
{
     return CpeGetValue(arg, value, "cpeagent.tr069.acsauth_pass");
    // *value = OTXMLStrdup("cpe");
    // return 0;
}



int CpeSetManagementServerPassword(void * arg, const char * value, callback_reg_func_t func)
{
    return CpeSetValue(arg, value, "cpeagent.tr069.acsauth_pass");
}


int CpeGetManagementServerParameterKey(void *arg, char ** value)
{
    *value = OTXMLStrdup("parameterkey");
    return 0;
}

int CpeSetManagementServerParameterKey(void * arg, const char * value, callback_reg_func_t func)
{
    return 0;
}

int CpeGetManagementServerUrl(void *arg, char ** value)
{
    return CpeGetValue(arg, value, "cpeagent.tr069.acsurl");
}

int CpeSetManagementServerUrl(void * arg, const char * value, callback_reg_func_t func)
{
    return 0;
}

int CpeGetManagementServerPeriodicInformEnable(void *arg, char ** value)
{
    return CpeGetValue(arg, value, "cpeagent.managementserver.PeriodicInformEnable");
}



int CpeSetManagementServerPeriodicInformEnable(void * arg, const char * value, callback_reg_func_t func)
{
    int ret = 0;
    
    if(is_boolean(value) == FALSE)
    {
        return FAULT_CPE_9007;
    }
    if (is_boolean_true(value) == TRUE)
        ret = CpeSetValue(arg, "1", "cpeagent.managementserver.PeriodicInformEnable");
    else
        ret= CpeSetValue(arg, "0", "cpeagent.managementserver.PeriodicInformEnable");

    return ret;
}

int CpeGetManagementServerPeriodicInformInterval(void *arg, char ** value)
{
    return CpeGetValue(arg, value, "cpeagent.managementserver.PeriodicInformInterval");
}

int CpeSetManagementServerPeriodicInformInterval(void * arg, const char * value, callback_reg_func_t func)
{
    return 0;
}


int CpeGetManagementServerPeriodicInformTime(void *arg, char ** value)
{
    char    buffer[TR069_PARAMVALUE_SIZE] = {0};
    char    *pTmp = NULL;

    if (CpeGetValue(arg, &pTmp, "cpeagent.managementserver.PeriodicInformTime") == FAULT_CPE_0)
    {
        if (isDigitStr(pTmp) == TRUE && time_t2datetime(atol(pTmp), buffer) ==0)
        {
            *value = OTXMLStrdup(buffer);
            OTXMLFree(pTmp);
            return FAULT_CPE_0;
        }
    }

    if (pTmp)
        OTXMLFree(pTmp);

    strcpy(buffer, UNKNOWN_TIME);
    *value = (char *)OTXMLMalloc(strlen(buffer) + 1);
    if (*value == NULL)
    {
        device_error("OTXMLMalloc %d failed.\n", strlen(buffer) + 1);
        return FAULT_CPE_9002;
    }
    strcpy(*value, buffer);
    *((*value) + strlen(buffer)) = '\0';
    return FAULT_CPE_0;
}

int CpeSetManagementServerPeriodicInformTime(void * arg, const char * value, callback_reg_func_t func)
{
    return 0;
}



