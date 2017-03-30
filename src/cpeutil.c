#include <netdb.h>  
#include <sys/types.h>  
#include <netinet/in.h>  
#include <sys/socket.h>  
#include <sys/ioctl.h>  
#include <arpa/inet.h>  
#include <net/if_arp.h>  
#include <net/if.h>  
#include <arpa/inet.h>  
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <poll.h>
#include <errno.h>
#include <stdarg.h>
#include <sys/timeb.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <curl/curl.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h> 
#include <sys/types.h>
#include <sys/wait.h>

#include "device.h"
#include "cpeutil.h"
#include "log.h"

char  g_BOOL_false[][10]={"false", "0"};
char  g_BOOL_true[][10]={"true", "1"};

BOOL isDigitStr(const char *str)
{
    char *p = (char *)str;

    if (p == NULL)
        return FALSE;

    while (*p)
    {
        //if (!isdigit(*p++)) return FALSE;
        //fixed problem for GetNumAfterString "LANDEVICE.1.XXX"
        if (isdigit(*p) || (*p == '.'))
            ;
        else
            return FALSE;
        p++;
    }

    return TRUE;
}

unsigned int OTXMLStrlen(const char * string)
{
    if (!string)
    {
        return 0;
    }
    return strlen(string);
}

char * OTXMLStrdup(const char * str)
{
    if (str)
        return strdup(str);
    else
        return NULL;
}

BOOL is_boolean(const char *str)
{
	int i;
	if(str==NULL)
	{
		return FALSE;
	}
	for(i=0; i<sizeof(g_BOOL_true)/10; i++)
	{
		if(strcasecmp(str, g_BOOL_true[i])==0)
			return TRUE;
		else
			continue;
	}
	for(i=0; i<sizeof(g_BOOL_false)/10; i++)
	{
		if(strcasecmp(str, g_BOOL_false[i])==0)
			return TRUE;
		else
			continue;
	}
	return FALSE;
}

int CpeDelRecord(void * arg, char *path)
{
    char    pFile[TR069_PARAMVALUE_SIZE] = {0};
    char    *buf = NULL;

    if (!path)
    {
        device_error("path is null.\n");
        return FAULT_CPE_9002;
    }

    buf = strchr(path, '.');
    if (buf)
    {
        strncpy(pFile, path, buf-path);
        if (cpe_uci_del(path) != 0)
        {
            device_error("cpe_uci_del error. path=%s\n", path);
            return FAULT_CPE_9002;
        }

        if (cpe_uci_commit(pFile) != 0)
        {
            device_error("cpe_uci_commit error. path=%s\n", path);
            return FAULT_CPE_9002;
        }

        return FAULT_CPE_0;
    }

    device_error("delete %s error.\n", path);
    return FAULT_CPE_9002;
}

int CpeGetValue(void * arg, char ** value, char *path)
{
    char buffer[TR069_PARAMVALUE_SIZE*10] = {0};

    *value = NULL;
    
    if (path==NULL)
    {
        return FAULT_CPE_9007;
    }
    
    if (0 != cpe_uci_get(path, buffer, 256))
    {
        return FAULT_CPE_9002;
    }

    if (OTXMLStrlen(buffer) > 0)
    {

        *value = (char *)OTXMLMalloc(strlen(buffer) + 1);
        if (*value == NULL)
        {
            return FAULT_CPE_9002;
        }
        strcpy(*value, buffer);
        *((*value) + strlen(buffer)) = '\0';
    }
    else
    {
        *value = OTXMLStrdup("");
    }

    return FAULT_CPE_0;
}

int cpe_uci_get(char * tag, char * buffer, int length)
{
    char arg[256];
    int ret;
    struct uci_context *ctx;

    if (!tag || (strlen(tag) > 128))
    {
        buffer[0] = 0;
        length = 0;
        return -1;
    }
    ctx = uci_alloc_context();
    if (!ctx)
    {
        fprintf(stderr, "Out of memory\n");
        uci_free_context(ctx);
        return -1;
    }

    if (tag[0] == '/')
    {
        snprintf(arg, 256, "%s",  tag);  
         ret =  uci_do_section_cmd(ctx, CMD_GET, arg, buffer, length);
    }
    else
    {
        snprintf(arg, 256, "%s/%s", UCI_USER_ROOT, tag); 
        ret =  uci_do_section_cmd(ctx, CMD_GET, arg, buffer, length);
        if (ret != 0)
        {
            uci_free_content(ctx);
            snprintf(arg, 256, "%s/%s", UCI_ROOT_DEFAULT, tag);         
            ret =  uci_do_section_cmd(ctx, CMD_GET, arg, buffer, length);
        }
    }

    uci_free_context(ctx);

    return ret;
}

int cpe_uci_set(char * tag, const char * value)
{
    char arg[256];
    char arg2[256*20];
    int ret;
    struct uci_context *ctx;

    if (!tag || (strlen(tag) > 128))
    {
        return -1;
    }

    ctx = uci_alloc_context();
    if (!ctx)
    {
        fprintf(stderr, "Out of memory\n");
        uci_free_context(ctx);
        return -1;
    }

    if(strlen(value) > 200)
    {
        snprintf(arg2, 256*20, "%s/%s=%s", UCI_USER_ROOT, tag, value);
        ret =  uci_do_section_cmd(ctx, CMD_SET, arg2, NULL, 0);
    }
    else
    {
        snprintf(arg, 256, "%s/%s=%s", UCI_USER_ROOT, tag, value);
        ret =  uci_do_section_cmd(ctx, CMD_SET, arg, NULL, 0);
    }

    uci_free_context(ctx);
    return ret;
}

int cpe_uci_del(char * tag)
{
    char arg[256];
    int ret;
    struct uci_context *ctx;

    if (!tag || (strlen(tag) > 128))
    {
        return -1;
    }

    ctx = uci_alloc_context();
    if (!ctx)
    {
        fprintf(stderr, "Out of memory\n");
        uci_free_context(ctx);
        return -1;
    }

    snprintf(arg, 256, "%s/%s", UCI_USER_ROOT, tag);
    ret =  uci_do_section_cmd(ctx, CMD_DEL, arg, NULL, 0);

    uci_free_context(ctx);
    return ret;
}

int cpe_uci_commit(char * tag)
{

    int ret;
    struct uci_context *ctx;

    if (!tag || (strlen(tag) > 128))
    {
        return -1;
    }

    ctx = uci_alloc_context();
    if (!ctx)
    {
        fprintf(stderr, "Out of memory\n");
        uci_free_context(ctx);
        return -1;
    }

    ret =  package_cmd(ctx, CMD_COMMIT, tag);
    uci_free_context(ctx);
    return ret;
}

int package_cmd(struct uci_context *ctx, int cmd, char *package)
{
    struct uci_package *p = NULL;
    int ret;

    if (cmd == CMD_CHANGES)
        ctx->flags |= UCI_FLAG_SAVED_HISTORY;
    ret = uci_load(ctx, package, &p);
    if (cmd == CMD_CHANGES)
        ctx->flags &= ~UCI_FLAG_SAVED_HISTORY;

    if (ret != UCI_OK)
    {
        //cli_perror();
        return 1;
    }
    if (!p)
        return 0;
    switch (cmd)
    {
    case CMD_CHANGES:
        // uci_show_changes(p);
        break;
    case CMD_COMMIT:
        //if (flags & CLI_FLAG_NOCOMMIT)
        //	return 0;
        if (uci_commit(ctx, &p, false) != UCI_OK)
        {
            //cli_perror();
        }
        break;
    case CMD_EXPORT:
        uci_export(ctx, stdout, p, true);
        break;
    case CMD_SHOW:
        //uci_show_package(p);
        break;
    }

    uci_unload(ctx, p);
    return 0;
}

int checkSection(struct uci_list *list, const char *section)
{
    struct uci_element *e;
    uci_foreach_element(list, e)
    {
        if (!strcmp(e->name, section))
            return 0;
    }
    return -1;
}

int checkPackage(const char *package)
{
    if (-1 == access(package, R_OK | W_OK))
    {
        FILE *fp = fopen(package, "w+");
        if (NULL == fp)
            return -1;
        fclose(fp);
    }
    return 0;
}

int uci_do_section_cmd(struct uci_context *ctx, int cmd, char * tag, char * buffer, int length)
{
    struct uci_package *p = NULL;
    struct uci_element *e = NULL;
    char *package = NULL;
    char *section = NULL;
    char *option = NULL;
    char *value = NULL;
    char **ptr = NULL;
    int ret = UCI_OK;

    switch (cmd)
    {
    case CMD_SET:
    case CMD_RENAME:
        ptr = &value;
        break;
    default:
        break;
    }
    
    if (uci_parse_tuple(ctx, tag, &package, &section, &option, ptr) != UCI_OK)
    {
        device_error("uci_parse_tuple error.\n");
        return 1;
    }
    
    if (section && !section[0])
    {
        device_error("section = %s\n", section);
        return 1;
    }
    
    if ((cmd == CMD_SET) && (-1 == checkPackage(package)))
    {
        device_error("set checkPackage %s error\n", package);
        return -1;
    }
            
    if (uci_load(ctx, package, &p) != UCI_OK || !p)
    {
        uci_perror(ctx, "cpeclient");
        //device_error("uci_load error, %s\n", package);
        return 1;
    }
    
    if (cmd == CMD_SET)
    {
        if (-1 == checkSection(&p->sections, section))
        {
            FILE *fp;
            char buffer[256];
            char *packname;

            uci_free_content(ctx);

            if (NULL == (fp = fopen(package, "a")))
            {
                device_error("fopen error, %s\n", package);
                return -1;
            }

            packname = strrchr(package, '/');
            snprintf(buffer, 256, "config %s %s\n", (packname) ? (packname + 1) : p->path, section);
            fwrite(buffer, strlen(buffer), 1, fp);
            fclose(fp);

            if (uci_load(ctx, package, &p) != UCI_OK)
            {
                uci_perror(ctx, "cpeclient");
                device_error("uci_load error, %s\n", package);
                return 1;
            }
        }
    }

    if (!p)
    {
        //device_error("package is NULL, %s\n", package);
        return 1;
    }
        
    switch (cmd)
    {
    case CMD_GET:
        if (uci_lookup(ctx, &e, p, section, option) != UCI_OK)
        {
            //device_error("uci_lookup error, %s\n", package);
            return 1;
        }
        
        switch (e->type)
        {
        case UCI_TYPE_SECTION:
            value = uci_to_section(e)->type;
            break;
        case UCI_TYPE_OPTION:
            value = uci_to_option(e)->value;
            break;
        default:
        {
            device_error("%s, type is error\n", package);
            /* should not happen */
            return 1;
        }

        }
        /* throw the value to stdout */
        if(strlen(value) > length)
        {
            strncpy(buffer, value, strlen(value));
        }
        else
        {
            strncpy(buffer, value, length);
        }

        break;
    case CMD_RENAME:
        ret = uci_rename(ctx, p, section, option, value);
        break;
    case CMD_REVERT:
        ret = uci_revert(ctx, &p, section, option);
        break;
    case CMD_SET:
        ret = uci_set(ctx, p, section, option, value, NULL);
        break;
    case CMD_DEL:
        ret = uci_delete(ctx, p, section, option);
        break;
    }

    /* no save necessary for get */
    if ((cmd == CMD_GET) || (cmd == CMD_REVERT))
        return 0;

    /* save changes, but don't commit them yet */
    if (ret == UCI_OK)
    {
        ret = uci_save(ctx, p);
    }

    if (ret != UCI_OK)
    {
        uci_perror(ctx, "cpeclient");
        if(ret != 6)
        {
            device_error("%s, return error, ret=%d\n", package, ret);
        }
        else
        {
            return ret;
        }
        return 1;
    }

    return 0;
}

int CpeSetValue(void * arg, const char * value, char *path)
{
    char    pFile[TR069_PARAMVALUE_SIZE] = {0};
    char    *buf = NULL;
    char    *pSecPos = NULL;
    char    *pType = NULL;
    char    pSecPath[UCI_PATH_LEN] = {0};
    int     ret;
    
    if (path==NULL)
    {
        device_error("CpeSetValue params is null.\n");
        return FAULT_CPE_9007;
    }

    buf = strchr(path, '.');
    pSecPos = strrchr(path, '.');
    if (buf)
    {
        strncpy(pFile, path, buf-path);
        if(pSecPos)
        {
            strncpy(pSecPath, path, pSecPos-path);
            if(CpeGetValue(NULL, &pType, pSecPath) == FAULT_CPE_0)
            {
                if(cpe_uci_set(pSecPath, pType) == 0 )
                {
                    cpe_uci_commit(pFile);
                }
            }
            
            if(pType != NULL)
            {
                OTXMLFree(pType);
                pType = NULL;
            }
        }
        if(value != NULL)
            ret = cpe_uci_set(path, value);
        else
            ret = cpe_uci_set(path, "");    //if the value is null pointer, it will set value to (null)
        if(ret == 6) 
        {
            return FAULT_CPE_0;
        }
        if (ret != 0)
        {
            device_error("cpe_uci_set error, path=%s\n", path);
            return FAULT_CPE_9002;
        }

        if (cpe_uci_commit(pFile) != 0)
        {
            device_error("cpe_uci_commit error, pFile=%s\n", pFile);
            return FAULT_CPE_9002;
        }
        return FAULT_CPE_0;
    }

    device_error("set value to %s error.\n", path);
    return FAULT_CPE_9002;
}

//复制param
int copy_param(trf_param_t *param_to, const trf_param_t *param_from, const char *name)
{
    trf_param_t     *param_tmp = NULL;
    trf_param_t     *param_tmp2 = NULL;
    trf_param_t     *param_cur = NULL;
    
    if(!param_to || !param_from)
    {
        return FALSE;
    }

    if(name)
    {
        memcpy(param_to, param_from, sizeof(trf_param_t));
        memset(param_to->name, 0, PARAM_NAME_LEN+1);
        strcpy(param_to->name, name);
        param_to->child = NULL;
        param_to->nextSibling = NULL;
        for(param_tmp=(trf_param_t*)param_from; param_tmp;)
        {
            if(!param_tmp->nextSibling)
            {
                param_tmp->nextSibling = param_to;
                break;
            }
            param_tmp = param_tmp->nextSibling;
        }
    }

    for(param_tmp=param_from->child; param_tmp; param_tmp=param_tmp->nextSibling)
    {
        param_tmp2 = calloc_check(sizeof(trf_param_t), 1);
        if(!param_tmp2)
        {
            continue;
        }
        memcpy(param_tmp2, param_tmp, sizeof(trf_param_t));
        param_tmp2->parent = param_to;
        param_tmp2->child = NULL;
        param_tmp2->nextSibling = NULL;
        if(!param_cur)
        {
            param_to->child = param_tmp2;
        }
        else
        {
            param_cur->nextSibling = param_tmp2;
        }
        param_cur = param_tmp2;

        copy_param(param_tmp2, param_tmp, NULL);
    }

    return TRUE;
}

int delete_param(trf_param_t *param)
{
    trf_param_t     *param_tmp = NULL;
    trf_param_t     *param_tmp2 = NULL;

    if(!param)
    {
        return FALSE;
    }
    
    for(param_tmp=param->child; param_tmp;)
    {
        param_tmp2 = param_tmp->nextSibling;
        delete_param(param_tmp);
        param_tmp = param_tmp2;
    }

    free_check(param);
    return TRUE;
}

//取得参数的全路径
int get_full_param_name(trf_param_t *param, char *fullname)
{
    trf_param_t *param_tmp;
    char        name_tmp[PARAM_FULL_NAME_LEN+1] = {0};
    
    if(!param || !fullname)
    {
        device_error(DEVICE_MODULE, "param or fullname is NULL\n");
        return FALSE;
    }

    for(param_tmp=param; param_tmp != NULL; param_tmp=param_tmp->parent)
    {
        memset(name_tmp, 0, PARAM_FULL_NAME_LEN+1);
        strcpy(name_tmp, fullname);
        if(strlen(name_tmp) == 0)
        {
            snprintf(fullname, PARAM_FULL_NAME_LEN+1, "%s", param_tmp->name);
        }
        else
        {
            snprintf(fullname, PARAM_FULL_NAME_LEN+1, "%s.%s", param_tmp->name, name_tmp);
        }
    }

    return TRUE;
}

int refresh_obj(trf_param_t *param, callback_reg_func_t func, int flag)
{
    char            fullname[PARAM_FULL_NAME_LEN+1] = {0};
    trf_param_t     *node = NULL;
    
    if(!param)
    {
        device_error("param is NULL\n");
        return FALSE;
    }
    
    if(param->refresh_func && flag == 1)
    {
        //取得参数全路径
        get_full_param_name(param, fullname);

        //调用refresh函数
        if(param->refresh_func)
        {
            param->refresh_func(fullname, param, func);
        }
    }
    
    for (node = param->child; node; node = node->nextSibling)
    {
        if(strcmp(param->name, "0") != 0)
        {
            refresh_obj(node, func, 1);
        }
    }

    return TRUE;
}

BOOL is_boolean_true(const char *str)
{
	int i;
	if(str==NULL)
	{
		return FALSE;
	}
	for(i=0; i<sizeof(g_BOOL_true)/10; i++)
	{
		if(strcasecmp(str, g_BOOL_true[i])==0)
			return TRUE;
		else
			continue;
	}
	return FALSE;
}

int datetime2time_t(const char *in_pDatetime, time_t *out_pTime)
{
    struct tm tm_time;
    time_t rettime=0;

    if (in_pDatetime == NULL || *in_pDatetime=='\0' || !OTXMLStrcasecmp(in_pDatetime,"0000-00-00T00:00:00"))
    {
        return -1;
    }

    if (sscanf(in_pDatetime,"%04d-%02d-%02dT%02d:%02d:%02d"
               ,&tm_time.tm_year,&tm_time.tm_mon,&tm_time.tm_mday
               ,&tm_time.tm_hour,&tm_time.tm_min,&tm_time.tm_sec) < 6)
    {
        return -1;
    }

    if (tm_time.tm_year<1900 || tm_time.tm_mon<1)
    {
        return -1;
    }

    tm_time.tm_year-=1900;
    tm_time.tm_mon-=1;

    rettime = mktime(&tm_time);
    if (rettime == -1)
    {
        return -1;
    }

    *out_pTime = rettime;
    return 0;
}

int time_t2datetime(const time_t in_time, char *out_pdatetime)
{
    struct tm *p = NULL;

    if (!out_pdatetime)
    {
        return -1;
    }

    //转化成本地时间，gmtime转化成UTC时间
    p = localtime(&in_time);
    if (p == NULL)
    {
        strcpy(out_pdatetime, UNKNOWN_TIME);
        return -1;
    }

    sprintf(out_pdatetime, "%04d-%02d-%02dT%02d:%02d:%02d",
            p->tm_year+1900, p->tm_mon+1, p->tm_mday,
            p->tm_hour, p->tm_min, p->tm_sec);

    return 0;
}

SoapDateTime GetLocalSoapDateTime()
{
    struct tm now;
    time_t tn;
    SoapDateTime soapnow;
    time(&tn);
    now = *localtime(&tn);
    soapnow.year = now.tm_year + 1900;
    soapnow.month = now.tm_mon + 1;
    soapnow.day = now.tm_mday;
    soapnow.hour = now.tm_hour;
    soapnow.min = now.tm_min;
    soapnow.sec = now.tm_sec;


    return soapnow;
}

int mysystem(const char *cmd)
{
    int stat;
    pid_t pid;
    struct sigaction sa, savintr, savequit;
    sigset_t saveblock;
    if (cmd == NULL)
        return(1);
    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigemptyset(&savintr.sa_mask);
    sigemptyset(&savequit.sa_mask);
    sigaction(SIGINT, &sa, &savintr);
    sigaction(SIGQUIT, &sa, &savequit);
    sigaddset(&sa.sa_mask, SIGCHLD);
    sigprocmask(SIG_BLOCK, &sa.sa_mask, &saveblock);
    if ((pid = fork()) == 0) 
    {
        sigaction(SIGINT, &savintr, (struct sigaction *)0);
        sigaction(SIGQUIT, &savequit, (struct sigaction *)0);
        sigprocmask(SIG_SETMASK, &saveblock, (sigset_t *)0);
        /*
        if(g_listensock != -1)
        {
            close(g_listensock);
        }
        */
        close_fd();
        execl("/bin/sh", "sh", "-c", cmd, (char *)0);
        _exit(127);
    }
    if (pid == -1) 
    {
        stat = -1; /* errno comes from fork() */
    } 
    else 
    {
        while (waitpid(pid, &stat, 0) == -1) 
        {
            if (errno != EINTR)
            {
                stat = -1;
                break;
            }
        }
    }
    sigaction(SIGINT, &savintr, (struct sigaction *)0);
    sigaction(SIGQUIT, &savequit, (struct sigaction *)0);
    sigprocmask(SIG_SETMASK, &saveblock, (sigset_t *)0);
    return(stat);
}

int close_fd(void)
{
    struct rlimit lim;
    unsigned int i;
    
    if (getrlimit(RLIMIT_NOFILE, &lim) < 0)
        return -1;
    if (lim.rlim_cur == RLIM_INFINITY)
        lim.rlim_cur = 1024;
    for (i = 3; i < lim.rlim_cur; i ++)
    {
        if (close(i) < 0 && errno != EBADF)
            return -1;
    }
    
    return 0;
}

BOOL CpeFindEnableFreeEntry(const char *package, const char * sectionNamePrefix, int * pI, int maxNumOfEntries)
{
    char *value    = NULL;
    char path[128] = {0};
    int i          = 0;
    
    for (i = 1; i <= maxNumOfEntries; i++) 
    {
        if (sectionNamePrefix)
        {
            sprintf(path, "%s.%s%d.enable", package, sectionNamePrefix, i);
        }
        
        else
        {
            sprintf(path, "%s.%d.enable", package, i);
        }
        
        if(CpeGetValue(NULL, &value, path) == FAULT_CPE_0)
        {
            if(strcmp(value, "1") == 0)
            {
                OTXMLFree(value);
                continue;
            }
            
            else
            {
                OTXMLFree(value);
                break;
            }
        }
        
        else
        {
            break;
        }
    }

    if (i > maxNumOfEntries)
    {
        device_error("Number of i exceed %d!\n", maxNumOfEntries);
        return FALSE;
    }

    *pI = i;
    return TRUE;
}

BOOL GetNumAfterString(void * arg,  char *pNum, char *pStr)
{
    char    *buf1 = NULL;
    char    buf2[10] = {0};
    int     i;

    if (!arg || !pNum || !pStr)
    {
        return FALSE;
    }

    buf1 = strcasestr((const char*)arg, (const char*)pStr);
    if (!buf1)
    {
        return FALSE;
    }

    //strlen("LANDevice.") = 10;
    buf1 = buf1 + strlen(pStr);
    for (i=0; i<strlen(buf1) && i<10; i++)
    {
        if ( *(buf1+i) != '.' )
        {
            //buf2[i] = *buf1;    //Bug: 10389
            buf2[i] = *(buf1+i);
        }
        //buf1++;
        else
        {
            break;
        }
    }

    strcpy(pNum, buf2);
    return isDigitStr(pNum);
}


/*
**return int: 1==single WAN, 2==double WAN, 3==Wan 3G(evdo), 4==subwan
**output param: pmode==wanmode.wanmode.type
**you must free pmode after using
*/
int get_wan_mode(char **pmode)
{
    char  *pVal = NULL;
    char  path[UCI_PATH_LEN] = {0};
    int    ret = WANMODE_NULL;
    
    sprintf(path, "%s", "wanmode.wanmode.type");
    
    if (CpeGetValue(NULL, &pVal, path) == FAULT_CPE_0)
    {
        if ( OTXMLStrcmp(pVal, "singlewan") == 0 
            ||OTXMLStrcmp(pVal, "singleadsl") == 0 )
        {
            ret = WANMODE_SINGLE;
        }
        else if (OTXMLStrcmp(pVal, "singleevdo") == 0)
        {
            ret = WANMODE_3G;
        }
        else if (OTXMLStrcmp(pVal, "doublewan") == 0 
            ||OTXMLStrcmp(pVal, "doublewanevdo") == 0 )
        {
            ret = WANMODE_DOUBLE;
        }
        else if (OTXMLStrcmp(pVal, "subwan") == 0
            ||OTXMLStrcmp(pVal, "subadsl") == 0 )
        {
            ret = WANMODE_SUBWAN;
        }
        *pmode = strdup_check(pVal);
    }

    if (pVal)
    {
        OTXMLFree(pVal);
    }
    return ret;
}

BOOL GetWANConnectionNum(unsigned int index, int *pCount, int *id, char *str_id)
{
    char *value    = NULL;
    char path[128] = {0};
    int  num       = 0;
    int  ret       = FALSE;
    int  i         = 0;
    
    for (i = 1; i <= 8; i++) 
    {
        sprintf(path, "swanif.swan%d.showenable", i);
        
        if(CpeGetValue(NULL, &value, path) == FAULT_CPE_0)
        {
            if(strcmp(value, "1") == 0)
            {
                num++;
                if (num == index)
                {
                    OTXMLFree(value);
                    break;
                }
            }
            OTXMLFree(value);
        }
        
        else
        {
            break;
        }
    }

    if (id)
	{
	    if (i > 8)
        {
            return FALSE;
        }
        else
        {
		    ret = TRUE;
		    *id = i;
        }
	}

    if (pCount)
    {
        ret = TRUE;
        *pCount = num;
    }
    
    return ret;
}

BOOL SWANEnable()
{
    char path[UCI_PATH_LEN] = {0};
    char * pVal = NULL;
    BOOL ret;
    
    ret = FALSE;
    sprintf(path, "%s", "wanmode.wanmode.type");
    
    if (CpeGetValue(NULL, &pVal, path) == FAULT_CPE_0)
    {
        if (OTXMLStrcmp(pVal, "subwan") == 0
          ||OTXMLStrcmp(pVal, "subadsl") == 0)
        {
            ret = TRUE;        
        }
    }
    if (pVal)
        OTXMLFree(pVal);
    
    return ret;

}

int CpeGetWanPrefix(void * arg, char * package, char * section)
{
    char    pNum[6]            = {0};
    char    path[UCI_PATH_LEN] = {0};
    int     id;
    int     wandevicenum; 
    int     wancnndevicenum;
    char    *val = NULL;

    if (GetNumAfterString(arg, pNum, "WANDevice.") == FALSE)
    {
        device_error("GetNumAfterString fail, arg=%s\n", arg);
        return FAULT_CPE_9005;
    }
    wandevicenum = atoi(pNum);
    
    if (GetNumAfterString(arg, pNum, "WANConnectionDevice.") == FALSE)
    {
        device_error("GetNumAfterString fail, arg=%s\n", arg);
        return FAULT_CPE_9005;
    }
    wancnndevicenum = atoi(pNum);

    if(wandevicenum == 1)
    {
        if(SWANEnable() == FALSE)
        {
            strcpy(package, "wanif");

            //get wan type to set section
            if((CpeGetValue(NULL, &val, "waniftype.global.wantype") == FAULT_CPE_0) && val)
            {
                if(OTXMLStrcasecmp(val, "ETH") == 0)
                {
                    strcpy(section, "wan5");
                } 
                else
                {
                    //lan靠
                    strcpy(section, "wan");
                }
            }
            else
            {
                device_error("Get waniftype fail\n");
                strcpy(section, "wan");
            }

            if(val)
            {   
                OTXMLFree(val);
                val = NULL;
            }

        }
        else
        {
            if (GetWANConnectionNum(wancnndevicenum, NULL, &id, NULL) == FALSE)
            {
		        return FAULT_CPE_9002;
            }
            
            strcpy(package, "swanif");
            snprintf(path, UCI_PATH_LEN, "swan%d", id);
            strcpy(section, path);
        }
    }
    
    else
    {
        strcpy(package, "wanif");
        sprintf(section, "wan%d", wandevicenum);
    }

    return FAULT_CPE_0;
}


