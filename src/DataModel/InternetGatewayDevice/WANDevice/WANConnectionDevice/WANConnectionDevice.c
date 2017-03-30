#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#include "log.h"
#include "cpeutil.h"
#include "device.h"
#include "low_level_func.h"

void get_bindtype(char *pbindtype, const char *pval, char **keys)
{
    char  *pbind_tr069 = NULL;
    char  *pbind_voip = NULL;
    char  *pbind_internet = NULL;
    char  *pbind_other = NULL;
    char  *pbind_iptv = NULL;

    if(strcasestr(pval, keys[0]))
    {
        pbind_tr069 = "Management";
    }
    if((strcasestr(pval, keys[1])) || (strcasestr(pval, "voice")))
    {
        pbind_voip = "Voice";
    }
    if(strcasestr(pval, keys[2]))
    {
        pbind_internet = "Internet";
    }
    if(strcasestr(pval, keys[3]))
    {
        pbind_other = "Other";
    }
    if(strcasestr(pval, keys[4]))
    {
        pbind_iptv = "IPTV";
    }

    if(pbind_other)
    {
        strcpy(pbindtype, pbind_other);
    }
    else if(pbind_iptv)
    {
        strcpy(pbindtype, pbind_iptv);
    }
    else
    {
        if(pbind_tr069)
        {
            strcat(pbindtype, pbind_tr069);
        }
    
        if(pbind_voip)
        {
            if(strlen(pbindtype) > 0)
            {
                strcat(pbindtype, "_");
            }
            strcat(pbindtype, pbind_voip);
        }
    
        if(pbind_internet)
        {
            if(strlen(pbindtype) > 0)
            {
                strcat(pbindtype, "_");
            }
            strcat(pbindtype, pbind_internet);
        }
    }
}

void set_subwan_name(int index, const char *pbindvalue)
{
    char *val = NULL;
    char path[MAX_UCI_STR_LEN] = {0};
    int  vid = 0;
    char *ptype = NULL;
    char  pbindtype[MAX_UCI_STR_LEN] = {0};
    char  pdisplayname[MAX_UCI_STR_LEN] = {0};

    sprintf(path, "swanif.swan%d.vid", index);
    CpeGetValue(NULL, &val, path);
    if(!val)
    {
        return;
    }
    vid = atoi(val);
    free_check(val);
    val = NULL;

    sprintf(path, "swanif.swan%d.type", index);
    CpeGetValue(NULL, &val, path);
    if(!val)
    {
        return;
    }
    if (OTXMLStrcasecmp(val, "bridge") == 0)
    {
        ptype = "B";
    }
    else
    {
        ptype = "R";
    }
    free_check(val);
    val = NULL;
    
    if(pbindvalue)
    {
        char *pkeys[] = {"TR069", "VOIP", "INTERNET", "Other", "IPTV"};
        get_bindtype(pbindtype, pbindvalue, pkeys);
    }
    else
    {
        sprintf(path, "swanif.swan%d.displayname", index);
        CpeGetValue(NULL, &val, path);
        if(val)
        {
            char *pkeys[] = {"Management", "Voice", "Internet", "Other", "IPTV"};
            get_bindtype(pbindtype, val, pkeys);
            free_check(val);
            val = NULL;
        }
    }

    sprintf(pdisplayname, "%d_%s_%s_%d", index, pbindtype, ptype, vid);
    sprintf(path, "swanif.swan%d.displayname", index);
    CpeSetValue(NULL, pdisplayname, path);
}


int TRF_Refresh_WANConnection(void *arg, trf_param_t *param, callback_reg_func_t func)
{
    char            *pmode      = NULL;
    char            buf[6]      = {0};
    char            pNum[6]     = {0};
    int             num         = 0;
    int             count       = 0;
    int             i           = 0;
    int             mode        = 0;
    trf_param_t     *param_tmp  = NULL;
    trf_param_t     *param_tmp2 = NULL;
    static          pthread_mutex_t     g_mutex_wan = PTHREAD_MUTEX_INITIALIZER;    

    if(!param)
    {
        return FAULT_CPE_0;
    }

    if(GetNumAfterString(arg, pNum, "WANDevice.") == FALSE)
    {
        device_error(DEVICE_MODULE, "invalid arg=%s\n", arg);
        return FAULT_CPE_9005;
    }
    num = atoi(pNum);

    pthread_mutex_lock(&g_mutex_wan);
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
    pthread_mutex_unlock(&g_mutex_wan);

    mode = get_wan_mode(&pmode);

    if (mode == 0)
    {
        return FAULT_CPE_9002;
    }

    if (num == 1)
    {
        if (mode == WANMODE_SINGLE || mode == WANMODE_DOUBLE)
        {
            count = 1;
        }

        else if (mode == WANMODE_SUBWAN)
        {
            if (GetWANConnectionNum(0, &count, NULL, NULL) == FALSE)
            {
                return FAULT_CPE_9002;
            }
        }

        else
        {
            count = 0;
        }
    }

    else if(num == 2)
    {
        if(strcasecmp(pmode, "doublewan") == 0)
        {
            count = 1;
        }

        else
        {
            count = 0;
        }
    }
   
    else
    {
         // TODO... 
    }

    free_check(pmode);

    pthread_mutex_lock(&g_mutex_wan);
    for(i = 1; i <= count; i++)
    {
        sprintf(buf, "%d", i);
        param_tmp = (trf_param_t*)calloc_check(sizeof(trf_param_t), 1);
        copy_param(param_tmp, param->child, buf);
    }

    refresh_obj(param, func, 0);
    pthread_mutex_unlock(&g_mutex_wan);
    return FAULT_CPE_0;
}

int TRF_Add_WANConnection(trf_param_t *param, void *arg, int *pinstance_num, callback_reg_func_t func, LogFunc log_func)
{
    char  buf[6]         = {0};
    char  cmd[2048]      = {0};
    int   i              = 0;
    trf_param_t  *param_tmp = NULL; 
    
    if(SWANEnable() == FALSE)
    {
        device_error("Not SWAN mode cannot add WANConnection\n");
        return FAULT_CPE_9005;
    }
    
    if (CpeFindEnableFreeEntry("swanif", "swan", &i, SWAN_COUNT) == FALSE)
    {
        device_error("Find a free entry error!\n");
        return FAULT_CPE_9002;
    }

    // 初始化配置值
    snprintf(cmd, sizeof(cmd), "uci set swanif.swan%d=interface; "
        "uci set swanif.swan%d.enable='1'; "
        "uci set swanif.swan%d.vid='%d'; "
        "uci set swanif.swan%d.type='gateway'; "
        "uci set swanif.swan%d.bindingtype='other'; "
        "uci set swanif.swan%d.proto='dhcp'; "
        "uci set swanif.swan%d.ipaddr=''; "
        "uci set swanif.swan%d.netmask=''; "
        "uci set swanif.swan%d.gateway=''; "
        "uci set swanif.swan%d.mtu='1488'; "
        "uci set swanif.swan%d.keepalive='60'; "
        "uci set swanif.swan%d.demand=''; "
        "uci set swanif.swan%d.defaultroute=''; "
        "uci set swanif.swan%d.ppp_redial=''; "
        "uci set swanif.swan%d.username=''; "
        "uci set swanif.swan%d.password=''; "
        "uci set swanif.swan%d.configmode='2'; "
        "uci set swanif.swan%d.opt60_enable='0'; "
        "uci set swanif.swan%d.opt60_type='34'; "
        "uci set swanif.swan%d.opt60_val_mode='2'; "
        "uci set swanif.swan%d.opt60_val=''; "
        "uci set swanif.swan%d.opt125_enable='0'; "
        "uci set swanif.swan%d.opt125_code='0'; "
        "uci set swanif.swan%d.opt125_data=''; "
        "uci set swanif.swan%d.vpri='0'; "
        "uci set swanif.swan%d.showenable='1'; "
        "uci set swanif.swan%d.displayname='Other'; "
        "uci set swanif.swan%d.version='v4'; "
        "uci commit", i, i, i, 0, i, i, i, i, i, i, i, i, i, i, i, i, i, i, i, i, i, i, i, i, i, i, i, i, i);
    
    device_info("cmd is %s\n", cmd);
    mysystem(cmd);
    
    *pinstance_num = i;

    sprintf(buf, "%d", i);
    param_tmp = (trf_param_t*)calloc_check(sizeof(trf_param_t), 1);
    copy_param(param_tmp, param->child, buf);
    
    TRF_Refresh_WANConnection(arg, param, func);
    handle_namechange(func);
    set_subwan_name(i, NULL);
    //TODO ....
    // apply interface，多数情况下在WANConnectionDevice.{i}.WANIPConnection.{i}.Enable重启，而且要在工单下发完成后执行
    return FAULT_CPE_0;
}

int TRF_Del_WANConnection(trf_param_t *param, void *arg, int instance_num, callback_reg_func_t func, LogFunc log_func)
{
    char          cmd[2048]     = {0};
    int           i             = 0;
    trf_param_t   *param_tmp    = NULL;
    trf_param_t   *param_parent = NULL;
    
	if(!param || !param->parent)
    {
        return FAULT_CPE_9002;
    }
    
    if(SWANEnable() == FALSE)
    {
        device_error("Not SWAN mode cannot add WANConnection\n");
        return FAULT_CPE_9005;
    }
    
	if (GetWANConnectionNum(instance_num, NULL, &i, NULL) == FALSE)
    {   
		return FAULT_CPE_9002;
    }

    snprintf(cmd, sizeof(cmd), "uci del swanif.swan%d;"
                               "uci commit;", i);
     device_info("cmd is %s\n", cmd);
    mysystem(cmd);
    
    param_parent = param->parent;
    
    for(param_tmp=param_parent->child; param_tmp; param_tmp=param_tmp->nextSibling)
    {
        if(param_tmp->nextSibling == param)
        {
            param_tmp->nextSibling = param->nextSibling;
            break;
        }
    }
    
    delete_param(param);
    TRF_Refresh_WANConnection(arg, param_parent, func);

    /* 
      重启删除的对应WAN 子interface，而不用重启所有WAN interfaces
    memset(re_cmd, 0, sizeof(re_cmd));
    sprintf(re_cmd, "/sbin/swanif.sh restart swan%d &", i);
    mysystem(re_cmd);
    */
    handle_namechange(func);
    return FAULT_CPE_0;
}

int CpeGetWANIPConnectionNumberOfEntries(void * arg, char ** value)
{
    return 0;
}

int CpeGetWANPPPConnectionNumberOfEntries(void * arg, char ** value)
{
    return 0;
}



