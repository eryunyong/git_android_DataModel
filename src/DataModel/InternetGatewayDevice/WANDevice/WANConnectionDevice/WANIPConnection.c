#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#include "log.h"
#include "cpeutil.h"
#include "device.h"
#include "low_level_func.h"

int TRF_Refresh_WANIPorPPPConnection(void *arg, trf_param_t *param, callback_reg_func_t func, LogFunc log_func)
{
    int                 i;
    trf_param_t     *param_tmp = NULL;
    trf_param_t     *param_tmp2 = NULL;
    char               buf[6] = {0};
    int                 num;
    int                 conn_num;
    int                 count = 0;
    char               *value = NULL;
    int                 mode;
    int                 id_wan;
    char               *pmode = NULL;
    int                 flag = 0;
    char               path[UCI_PATH_LEN] = {0};
    char               pNum[6] = {0};
    char               pNum1[6] = {0};
    
    if(!param)
    {
    	return FAULT_CPE_0;
    }
    
    if(GetNumAfterString(arg, pNum, "WANDevice.") == FALSE)
    {
        device_error("invalid arg=%s\n", arg);
        return FAULT_CPE_9005;
    }
    num = atoi(pNum);
    
    if(GetNumAfterString(arg, pNum1, "WANConnectionDevice.") == FALSE)
    {
        device_error("invalid arg=%s\n", arg);
        return FAULT_CPE_9005;
    }
    conn_num = atoi(pNum1);
    
    if(strstr(arg, "WANPPPConnection"))
    {
        flag = 1;
    }
    
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

    mode = get_wan_mode(&pmode);
    if(num == 1)
    {
        if(mode == WANMODE_SINGLE || mode == WANMODE_DOUBLE)
        {
            if (CpeGetValue(NULL, &value, "waniftype.global.wantype") == FAULT_CPE_0)
            {
                if(OTXMLStrcasecmp(value, "ETH") == 0)
                {
                    snprintf(path, UCI_PATH_LEN, "wanif.wan5.proto");
                }
                else
                {
                    snprintf(path, UCI_PATH_LEN, "wanif.wan.proto");
                }
                free_check(value);
                if(CpeGetValue(NULL, &value, path) == FAULT_CPE_0)
                {
                    if(flag == 0 && (strcasecmp(value, "static") == 0 || strcasecmp(value, "dhcp") == 0))
                        count = 1;
                    else if(flag == 1 && (strcasecmp(value, "pppoe") == 0))
                        count = 1;
                    else
                        count = 0;
                    free_check(value);
                }
            }
        }
        else if(mode == WANMODE_SUBWAN)
        {
            if (GetWANConnectionNum(conn_num, NULL, &id_wan, NULL) == FALSE)
            {   
        		return FAULT_CPE_9002;
            }
            
            snprintf(path, UCI_PATH_LEN, "swanif.swan%d.proto", id_wan);
            if(CpeGetValue(NULL, &value, path) == FAULT_CPE_0)
            {
                if(flag == 0 && (strcasecmp(value, "static") == 0 || strcasecmp(value, "dhcp") == 0))
                    count = 1;
                else if(flag == 1 && (strcasecmp(value, "pppoe") == 0))
                    count = 1;
                else
                    count = 0;
                free_check(value);
            }
        }
        else
            count = 0;
    }
    else if(num == 2)
    {
        if(strcasecmp(pmode, "doublewan") == 0)
        {
            if(CpeGetValue(NULL, &value, "wanif.wan2.proto") == FAULT_CPE_0)
            {
                if(flag == 0 && (strcasecmp(value, "static") == 0 || strcasecmp(value, "dhcp") == 0))
                    count = 1;
                else if(flag == 1 && (strcasecmp(value, "pppoe") == 0))
                    count = 1;
                else
                    count = 0;
                free_check(value);
            }
        }
        else
            count = 0;
    }   
    else
    {
         // TODO... 
    }
    free_check(pmode);
    
    for(i=1; i<=count; i++)
    {
        sprintf(buf, "%d", i);
        param_tmp = (trf_param_t*)calloc_check(sizeof(trf_param_t), 1);
        copy_param(param_tmp, param->child, buf);
    }
    refresh_obj(param, func, 0);

    return FAULT_CPE_0;
}

int TRF_Add_WANIPorPPPConnection(trf_param_t *param, void *arg, int *pinstance_num, callback_reg_func_t func, LogFunc log_func)
{
    char            pNum[6] = {0};
    char            pNum1[6] = {0};
    int             num;
    int             conn_num;
    int             id_wan;
    char            *value = NULL;
    char            *pmode = NULL;
    int             mode;
    int             flag = 0;
    char            str_sql[UCI_PATH_LEN] = {0};
    
    if(GetNumAfterString(arg, pNum, "WANDevice.") == FALSE)
    {
        device_error("invalid arg=%s\n", arg);
        return FAULT_CPE_9005;
    }
    num = atoi(pNum);
    
    if(GetNumAfterString(arg, pNum1, "WANConnectionDevice.") == FALSE)
    {
        device_error( "invalid arg=%s\n", arg);
        return FAULT_CPE_9005;
    }
    conn_num = atoi(pNum1);
    
    if(strstr(arg, "WANPPPConnection"))
    {
        flag = 1;
    }

    mode = get_wan_mode(&pmode);
    if(num == 1)
    {
        if(mode == WANMODE_SINGLE || mode == WANMODE_DOUBLE)  //单双WAN
        {
            strcpy(str_sql, "wanif.wan.proto");
            CpeGetValue(arg, &value, str_sql);
            memset(str_sql, 0, UCI_PATH_LEN);
            
            if(!value)
            {
                return FAULT_CPE_9002;
            }
            
            if(strcasecmp(value, "static") == 0)
            {
                if(flag == 0)
                {
                   device_info("flag=%d\n", flag);
                   return FAULT_CPE_9002;
                }
                else
                {
                   CpeSetValue(arg, "pppoe", "wanif.wan.proto");
                }
            }
            else if(strcasecmp(value, "dhcp") == 0)
            {
                if(flag == 0)
                {
                   device_info("flag=%d\n", flag);
                   return FAULT_CPE_9002;
                }
                else
                {
                   CpeSetValue(arg, "pppoe", "wanif.wan.proto");
                }
            }
            else
            {
                if(flag == 1)
                {
                   device_info("flag=%d\n", flag);
                   return FAULT_CPE_9002;
                }
                else
                {
                   CpeSetValue(arg, "static", "wanif.wan.proto");
                }
            }

            free_check(value);
        }
        else
        {
            if (GetWANConnectionNum(conn_num, NULL, &id_wan, NULL) == FALSE)
            {   
        		return FAULT_CPE_9002;
            }
            
            sprintf(str_sql, "swanif.swan%d.proto", id_wan);
            CpeGetValue(arg, &value, str_sql);
            
            if(!value)
            {
                return FAULT_CPE_9002;
            }
            memset(str_sql, 0, UCI_PATH_LEN);
            
            if(strcasecmp(value, "pppoe") == 0)
            {
                if(flag == 1) 
                {
                  device_info("flag=%d\n", flag);
                }
                else
                {
                   sprintf(str_sql, "swanif.swan%d.proto", id_wan);
                   CpeSetValue(arg, "static", str_sql);
                }
            }
            else
            {
                if(flag == 0)
                {
                   device_info("flag=%d\n", flag);
                }
                else
                {
                   sprintf(str_sql, "swanif.swan%d.proto", id_wan);
                   CpeSetValue(arg, "pppoe", str_sql);
                }
            }

            free_check(value);
        }
    }
    else
    {
         // TODO....
    }

    TRF_Refresh_WANIPorPPPConnection(arg, param, func, log_func);
    *pinstance_num = 1;
    handle_namechange(func);
    return FAULT_CPE_0;
}

int TRF_Del_WANIPorPPPConnection(trf_param_t *param, void *arg, int instance_num, callback_reg_func_t func, LogFunc log_func)
{
    char            pNum[6] = {0};
    char            pNum1[6] = {0};
    char          re_cmd[512]   = {0};
    char          cmd[2048]     = {0};
    int             num;
    int             conn_num;
    int             id_wan;
    char            *value = NULL;
    char            *pmode = NULL;
    int             mode;
    int             flag = 0;
    char            str_sql[UCI_PATH_LEN] = {0};
    
    if(GetNumAfterString(arg, pNum, "WANDevice.") == FALSE)
    {
        device_error("invalid arg=%s\n", arg);
        return FAULT_CPE_9005;
    }
    num = atoi(pNum);
    
    if(GetNumAfterString(arg, pNum1, "WANConnectionDevice.") == FALSE)
    {
        device_error("invalid arg=%s\n", arg);
        return FAULT_CPE_9005;
    }
    conn_num = atoi(pNum1);
    
    if(strstr(arg, "WANPPPConnection"))
    {
        flag = 1;
    }
    
    mode = get_wan_mode(&pmode);
    if(num == 1)
    {
        if(mode == WANMODE_SINGLE || mode == WANMODE_DOUBLE)  //单双WAN
        {
            strcpy(str_sql, "wanif.wan.proto");
            CpeGetValue(arg, &value, str_sql);
            memset(str_sql, 0, UCI_PATH_LEN);
            
            if(!value)
            {
                return FAULT_CPE_9002;
            }
            
            if(strcasecmp(value, "static") == 0)
            {
                if(flag == 1)
                {
                   device_info( "flag=%d\n", flag);
                   return FAULT_CPE_9002;
                }
                else
                {
                   CpeSetValue(arg, "pppoe", "wanif.wan.proto");
                }
            }
            else if(strcasecmp(value, "dhcp") == 0)
            {
                if(flag == 1)
                {
                   device_info("flag=%d\n", flag);
                   return FAULT_CPE_9002;
                }
                else
                {
                   CpeSetValue(arg, "pppoe", "wanif.wan.proto");
                }
            }
            else
            {
                if(flag == 0)
                {
                   device_info("flag=%d\n", flag);
                   return FAULT_CPE_9002;
                }
                else
                {
                   CpeSetValue(arg, "static", "wanif.wan.proto");
                }
            }

            free_check(value);
        }
        else
        {
            if (GetWANConnectionNum(conn_num, NULL, &id_wan, NULL) == FALSE)
            {   
        		return FAULT_CPE_9002;
            }
            
            sprintf(str_sql, "swanif.swan%d.proto", id_wan);
            CpeGetValue(arg, &value, str_sql);
            
            if(!value)
            {
                return FAULT_CPE_9002;
            }
            memset(str_sql, 0, UCI_PATH_LEN);
            
            if(strcasecmp(value, "pppoe") ==0)
            {
                if(flag == 0)
                {
                   device_info( "flag=%d\n", flag);
                   return FAULT_CPE_9002;
                }
                else
                {
                   sprintf(str_sql, "swanif.swan%d.proto", id_wan);
                   CpeSetValue(arg, "static", str_sql);
                }
            }
            else
            {
                if(flag == 1)
                {
                   device_info("flag=%d\n", flag);
                   return FAULT_CPE_9002;
                }
                else
                {
                   sprintf(str_sql, "swanif.swan%d.proto", id_wan);
                   CpeSetValue(arg, "pppoe", str_sql);
                }
            }

            free_check(value);
        }

        snprintf(cmd, sizeof(cmd), "uci set swanif.swan%d.enable='0';"
                                   "uci commit;", id_wan);
        device_info( "cmd is %s\n", cmd);
        mysystem(cmd);

        memset(re_cmd, 0, sizeof(re_cmd));
        sprintf(re_cmd, "/sbin/swanif.sh restart swan%d &", id_wan);
        mysystem(re_cmd);        
    }
    else 
    {
         // TODO....
    }
    
    TRF_Refresh_WANIPorPPPConnection(arg, param, func, log_func);
    handle_namechange(func);
    return FAULT_CPE_0;
}


int CpeGetWANIPConnectionEnable(void *arg, char ** value)
{
    int     ret;
    char    path[UCI_PATH_LEN] = {0};
    char    package[128] = {0};
    char    section[128] = {0};
    // int     flag = 0;   // 0 IP 1 PPPOE
    
    if (CpeGetWanPrefix(arg, package, section) != FAULT_CPE_0)
    {
        return FAULT_CPE_9005;
    }

    sprintf(path, "%s.%s.enable", package, section);

    ret = CpeGetValue(arg, value, path);    
    return ret;
}

int CpeSetWANIPConnectionEnable(void * arg, const char * value, callback_reg_func_t func, LogFunc log_func)
{
    int     ret;
    char    path[UCI_PATH_LEN] = {0};
    char    package[128] = {0};
    char    section[128] = {0};
    
    if (CpeGetWanPrefix(arg, package, section) != FAULT_CPE_0)
    {
        return FAULT_CPE_9005;
    }
    

    //子接口模式
    if(SWANEnable() == TRUE)
    {
        sprintf(path, "%s.%s.enable", package, section);
        if (is_boolean_true(value) == TRUE)
            CpeSetValue(NULL, "1", path);
        else
            CpeSetValue(NULL, "0", path);
    }
    else
    {
        // TODO...
    }

    // Apply WAN Interface
    return ret;
}

int CpeGetWANIPConnection_ExternalIPAddress(void *arg, char ** value, LogFunc log_func)
{
    device_error("TODO.............support yourself WAN interface ip addr\n");
    char    *pVal = NULL;

    if (CpeGetValue(NULL, &pVal, "cpeagent.cpe.debugtest") == FAULT_CPE_0 && OTXMLStrcasecmp(pVal, "1") == 0)
    {
        if (pVal)
        {
            OTXMLFree(pVal);
            pVal = NULL;
        }
        
        if (CpeGetValue(NULL, &pVal, "cpeagent.cpe.debugip") == FAULT_CPE_0)
        {
            *value = OTXMLStrdup(pVal);
            if (pVal)
            {
                OTXMLFree(pVal);
                pVal = NULL;
            }
        }
        
        return FAULT_CPE_0;
    }        

    return CpeGetValue(arg, value, "swanif.swan1.ipaddr");
}


int CpeSetWANIPConnection_ExternalIPAddress(void * arg, const char * value, callback_reg_func_t func, LogFunc log_func)
{
     device_error("TODO.............support yourself WAN interface ip addr\n");
     return CpeSetValue(arg, value, "swanif.swan1.ipaddr");
}


