#include <sys/timeb.h>
#include <time.h>
#include <dirent.h>
#include <pthread.h>

#include "log.h"
#include "cpeutil.h"
#include "device.h"

int WAN_COUNT = WAN_DEF_COUNT;

int CpeRefreshWANDevice(void *arg, trf_param_t *param, callback_reg_func_t func)
{
    int             i;
    trf_param_t     *param_tmp = NULL;
    trf_param_t     *param_tmp2 = NULL;
    char            buf[6] = {0};
    char    *pmode = NULL;
    static int      g_wandev_init = 0;

    if(g_wandev_init == 1)
    {
        return FAULT_CPE_0;
    }

    else if(get_wan_mode(&pmode) == WANMODE_DOUBLE)
    {
        WAN_COUNT = 2;
    }
    else
    {
        WAN_COUNT = 1;
    }

    free_check(pmode);

    if(!param)
    {
        return FAULT_CPE_9002;
    }
    
    device_debug("TRF_Refresh_WANDevice begin\n");
    if(param->child)
    {
        for(param_tmp=param->child->nextSibling; param_tmp;)
        {
            param_tmp2 = param_tmp->nextSibling;
            delete_param(param_tmp);
            param_tmp = param_tmp2;
        }
        param->child->nextSibling = NULL;
        for (i=1; i<=WAN_COUNT; i++)
        {
            sprintf(buf, "%d", i);
            param_tmp = (trf_param_t*)calloc_check(sizeof(trf_param_t), 1);
            copy_param(param_tmp, param->child, buf);
        }
        refresh_obj(param, func, 0);
    }
    device_debug( "TRF_Refresh_WANDevice end\n");
    g_wandev_init = 1;   
    return FAULT_CPE_0;
}

int GetWANConnectionNumberOfEntries(void *arg, char ** value)
{
    return 0;
}
