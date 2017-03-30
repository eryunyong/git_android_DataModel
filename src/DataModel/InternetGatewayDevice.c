#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include "cpeutil.h"
#include "device.h"
#include "uci.h"
#include "log.h"

int CpeGetDeviceSummary(void *arg, char ** value)
{
    *value = OTXMLStrdup("InternetGatewayDevice:1.0[](Baseline:1, EthernetLAN:7, WiFiLAN:4, EthernetWAN:1, Time:1, IPPing:1)");
    return FAULT_CPE_0;
}

int CpeGetLANDeviceNumberOfEntries(void *arg, char ** value)
{
    *value = OTXMLStrdup("1");
    return FAULT_CPE_0;
}

int CpeGetWANDeviceNumberOfEntries(void *arg, char ** value)
{
    *value = OTXMLStrdup("1");
    return FAULT_CPE_0;
}

int CpeGetObjTest_TestEnabled(void *arg, char ** value)
{
    return CpeGetValue(arg, value, "objtest.parameter.enable");
}


int CpeSetObjTest_TestEnabled(void * arg, const char * value, callback_reg_func_t func)
{
    int ret;

    if(is_boolean(value) == FALSE)
    {
        return FAULT_CPE_9007;
    }

    if (is_boolean_true(value) == TRUE)
    {
        ret = CpeSetValue(arg, "1", "objtest.parameter.enable");
    }
    else
    {
        ret = CpeSetValue(arg, "0", "objtest.parameter.enable");
    }

    return ret;
}

#define OBJ_MAXNUM 8

static int g_testobj_count = OBJ_MAXNUM;


// test Obj methods
int TRF_Refresh_ObjTest(void *arg, trf_param_t *param, callback_reg_func_t func)
{
    int             ret = FAULT_CPE_0;
    trf_param_t     *param_tmp = NULL;
    trf_param_t     *param_tmp2 = NULL;
    int             i = 0;
    char            buf[10] = {0};
    
    if(!param)
    {
        return FAULT_CPE_9002;
    }
    
    //É¾³ý×Ó½Úµã
    if(param->child)
    {
        for(param_tmp=param->child->nextSibling; param_tmp;)
        {
            param_tmp2 = param_tmp->nextSibling;
            delete_param(param_tmp);
            param_tmp = param_tmp2;
        }
        param->child->nextSibling = NULL;
    }
    
    for(i=0; i<g_testobj_count; i++)
    {
        sprintf(buf, "%d", i+1);   
        param_tmp = (trf_param_t*)calloc_check(sizeof(trf_param_t), 1);
        copy_param(param_tmp, param->child, buf);
    }

    refresh_obj(param, func, 0);    
    return ret;
}



int TRF_Add_ObjTest(trf_param_t *param, void *arg, int *pinstance_num, callback_reg_func_t func)
{
    if(g_testobj_count < OBJ_MAXNUM)
    {
        g_testobj_count++;
        *pinstance_num = g_testobj_count;
        TRF_Refresh_ObjTest(arg, param, func);
        return FAULT_CPE_0;
    }
    else
    {
        return FAULT_CPE_9005;
    }
}


int TRF_Del_ObjTest(trf_param_t *param, void *arg, int instance_num, callback_reg_func_t func)
{
    if(g_testobj_count > 0)
    {
        g_testobj_count--;
        TRF_Refresh_ObjTest(arg, param, func);
        return FAULT_CPE_0;
    }
    else
    {
        return FAULT_CPE_9005;
    }
}



