/* 
***********************************************************
This file provide basic function for cwmp core. We can modify function content
freely or add  implement to complete.

***********************************************************
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <netinet/in.h>  
#include <assert.h>
#include <poll.h>
#include <syslog.h>
#include <sys/socket.h>
#include <sys/ioctl.h>  
#include <pthread.h>
#include <curl/curl.h>
#include <syslog.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>

#include "low_level_func.h"
#include "cpeutil.h"
#include "device.h"
#include "uci.h"
#include "log.h"

// for test
#define CWMP_SOCK "/opt/cwmp.sock"

/* 
   电信要求设备首次启动上报BIND自定义 事件 
   自定义上报的EVENT 事件类型,   和device.xml 里面eventlist定义的名称一致
*/

#define BIND_EVENT  "X CT-COM BIND"

callback_reg_func_t g_reg_func = NULL;
pthread_mutex_t *g_pmutex_param = NULL;
trf_param_t *g_root_param = NULL;

BOOL isIpStr(const char *str)
{
    unsigned long ip;

    if(!str)
    {
        return FALSE;
    }
    
    ip = inet_addr(str);
    if (INADDR_NONE == ip)
    {
        return FALSE;
    }
    else
    {
        return TRUE;
    }
}

void closeinout()
{
    int fd = open("/dev/null", O_RDWR);

    if (fd < 0)
    {
        return;
    }

    dup2(fd, 0);
    dup2(fd, 1);
    dup2(fd, 2);
    close(fd);
}

//用于需要平台一开始初始化
void dev_init(trf_param_t* param, callback_reg_func_t func, pthread_mutex_t *pmutex_param, LogFunc log_func)
{
    //init local log pointer
    cwmplog_func = log_func;

    // 初始化全局变量供其他函数使用
    g_reg_func = func;
    g_root_param = param;
    g_pmutex_param = pmutex_param;
        
    closeinout();

    //初始化CPE 与ACS 连接状态
    CpeSetValue(NULL, "0", "cpeagent.tr069.acs_status");

    //initialize cwmp states    
    CpeSetValue(NULL, "0", "cpeagent.tr069.bs_status");
    CpeSetValue(NULL, "0", "cpeagent.tr069.cwmp_status");
    CpeSetValue(NULL, "0", "cpeagent.tr069.inform_status");

    //device.xml 自定义X CT-COM BIND 事件 
    //inform_bind(func);
    return;
}

/* test for telecom  */
void inform_bind(callback_reg_func_t func)
{
    inform_add_t    *pinfo_add = NULL;   
    pinfo_add = (inform_add_t*)malloc_check(sizeof(inform_add_t));
    if(!pinfo_add)
    {
        return;
    }
    
    memset(pinfo_add, 0, sizeof(inform_add_t));    
    pinfo_add->events_list = (char **)malloc_check(sizeof(char *));
    if(pinfo_add->events_list)
    {          
        // 终端每次上电，自动上报X CT-COM BIND事件
        pinfo_add->events_list[0] = strdup_check(BIND_EVENT);
        pinfo_add->event_count = 1;
    }
    
    func(NULL, TASK_ADD_INFORM, 0, (void *)pinfo_add, NULL);
}

/*
FIX ME
1、终端预配置的ACS URL变化 . 终端上报0 BOOTSTRAP
2、终端预配置的ACS URL不变化，ACS业务完整，双向连接正常
       即使ACS的IP地址发生变化，终端也不能上报0boot事件
       例如：ITMS平台域名没变，业务平滑割接，终端不能上报0 BOOTSTRAP
3、终端预配置的ACS URL不变化，终端和ACS平台首次连接，
       需要重新注册平台（例如：ITMS URL没变，但平台已经更换了另外一个厂商的ACS或原ACS完全崩溃
       业务数据或双向连接密钥缺失或不完整，需要重新注册）
       在第一次连接平台的时候上报0 BOOTSTRAP
*/
int dev_bootstrap(int type, int *pret)
{
     if(!pret)
     {
         return FALSE;
     }
 
     if(type == 0)   //get
     {
         char  *val = NULL;
         *pret = 0;
         CpeGetValue(NULL, &val, "cpeagent.inform.bootstarp");
         if(val)
         {
             *pret = atoi(val);
             free_check(val);
         }
     }
     else            //set
     {
         char    buf[64] = {0};
         char    path[UCI_PATH_LEN] = {0};
         sprintf(buf, "%d", *pret);
         sprintf(path, "cpeagent.inform.bootstarp");
         CpeSetValue(NULL, buf, path);
     }
     
    return 0;   
}

//用于download
size_t getcontentlengthfunc(void *ptr, size_t size, size_t nmemb, void *stream)
{
    int r;
    long len = 0;
    r = sscanf(ptr, "Content-Length: %ld\n", &len);
    if (r) /* Microsoft: we don't read the specs */
      *((long *) stream) = len;

    return size * nmemb;
}

#define FILETYPE_DOWNLOAD_FIRM  "1 Firmware Upgrade Image"
#define FILETYPE_DOWNLOAD_WEB   "2 Web Content"
#define FILETYPE_DOWNLOAD_CONF  "3 Vendor Configuration File"
#define FILETYPE_DOWNLOAD_CA    "4 X_CT-COM CERTIFICATE CA"
#define FILETYPE_DOWNLOAD_LOCAL "5 X_CT-COM CERTIFICATE LOCAL"

#define FILE_DOWNLOAD_FIRM      "/var/downloadfirm"
#define FILE_DOWNLOAD_WEB       "/var/downloadweb"
#define FILE_DOWNLOAD_CONF      "/var/downloadconf"
#define FILE_DOWNLOAD_CA        "/var/downloadCA"
#define FILE_DOWNLOAD_LOCAL     "/var/downloadlocal"

#define ACS_CA_PATH         "/etc/acs.crt"
#define CPE_CA_PATH         "/etc/cpe.crt"

int dev_download(void *data1, void *data2)
{
    download_arg_t      *arg = NULL;
    char                *filename = NULL;
    int                 resume_flag = 0;
    struct stat         f_stat;
    curl_off_t          file_len = -1 ;
    FILE                *fp = NULL;
    struct timeval      tv;
    int                 ret = FAULT_CPE_0;
    CURLcode            code;
    CURL                *curl = NULL;
    long                filesize =0 ;
    unsigned int        r2u=0;     /* ready  to upgrade */
    char                cmd[256] = {0};
    
    device_info( "call download\n");
    mysystem("rm -fr /usr/data/tr_download");
    arg = (download_arg_t*)data1;
    if(!arg || !arg->filetype || !arg->url)
    {
        device_error( "data1 is NULL\n");
        return FAULT_CPE_9002;
    }

    //fixme 内存检查
    if(strcasecmp(arg->filetype, FILETYPE_DOWNLOAD_FIRM) == 0)
    {
        r2u = 1;
        filename = FILE_DOWNLOAD_FIRM;
    }
    else if(strcasecmp(arg->filetype, FILETYPE_DOWNLOAD_WEB) == 0)
    {
        r2u = 5;
        filename = FILE_DOWNLOAD_WEB;
    }
    else if(strcasecmp(arg->filetype, FILETYPE_DOWNLOAD_CONF) == 0)
    {
        r2u = 2;
        filename = FILE_DOWNLOAD_CONF;
    }
    else if(strcasecmp(arg->filetype, FILETYPE_DOWNLOAD_CA) == 0)
    {
        r2u = 3;
        filename = FILE_DOWNLOAD_CA;
    }
    else if(strcasecmp(arg->filetype, FILETYPE_DOWNLOAD_LOCAL) == 0)
    {
        r2u = 4;
        filename = FILE_DOWNLOAD_LOCAL;
    }
    else
    {
        device_info( "invlid file type, %s\n", arg->filetype);
        return FAULT_CPE_9003;
    }
    
    //是否需要断点续传
    if(stat(filename, &f_stat) == 0) 
    {
        file_len = f_stat.st_size;
        resume_flag = 1;
    }

    fp = fopen(filename, "ab+");
    if (fp == NULL)
    {
        device_error( "could not open %s\n", filename);
        return FAULT_CPE_9002;
    }

    if(arg->delaysec > 0)
    {
        tv.tv_sec = arg->delaysec;
        select(0, NULL, NULL, NULL, &tv);
    }

    //为下载做准备
    curl = curl_easy_init();
    if (!curl)
    {
        device_error( "curl_easy_init fail\n");
        ret = FAULT_CPE_9002;
        goto finish;
    }
    curl_easy_setopt(curl, CURLOPT_USERNAME, arg->username);
    curl_easy_setopt(curl, CURLOPT_PASSWORD, arg->password);
    curl_easy_setopt(curl, CURLOPT_URL,arg->url);
    if(arg->srcip && isIpStr(arg->srcip))
        curl_easy_setopt(curl, CURLOPT_INTERFACE, arg->srcip);
    // support download ca
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1);
    curl_easy_setopt(curl, CURLOPT_SSL_CIPHER_LIST, "RC4-SHA:DES-CBC-SHA");
    if ((stat(ACS_CA_PATH, &f_stat) != -1) && ((long)f_stat.st_size != 0))
        curl_easy_setopt(curl, CURLOPT_CAINFO, ACS_CA_PATH);
    else
    {
        /* Motive need https work without CA imported */
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);
    }
    curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_ANY);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
    
    //设置http 头部处理函数
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, getcontentlengthfunc);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &filesize);
    // 设置文件续传的位置给libcurl
    curl_easy_setopt(curl, CURLOPT_RESUME_FROM_LARGE, resume_flag?file_len:0); 
    
    //30秒内不能完成10k，返回失败
    curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, 10240);  //10k
    curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME, 30);      //30
    
    code = curl_easy_perform(curl);
    if(fp)
    {
        fclose(fp);
        fp = NULL;
    }
    device_info( "code=%d\n", code);
    if( code == CURLE_OK)
    {
        //下载成功，置成功位
        mysystem("touch /usr/data/tr_download");
    }
    else if( code == CURLE_UNSUPPORTED_PROTOCOL)
    {
        //104057 靠靠靠
        syslog(LOG_CRIT|LOG_USER, "LOG_TYPE=1;ERR_CODE=104057");
        ret = FAULT_CPE_9013;
        goto finish;
    
    }
    else if(code == CURLE_FTP_ACCESS_DENIED ||code == CURLE_FTP_COULDNT_STOR_FILE || code == CURLE_COULDNT_CONNECT)
    {
        //靠靠靠靠
        syslog(LOG_CRIT|LOG_USER, "LOG_TYPE=1;ERR_CODE=104061");
        ret = FAULT_CPE_9001;//request denied
        goto finish;
    }
    else
    {
        syslog(LOG_CRIT|LOG_USER, "LOG_TYPE=1;ERR_CODE=104057");
        ret = FAULT_CPE_9010;
        goto finish;
    }

    if(r2u == 1)    //升级
    {
        device_info( "firmware update\n");
        if(CpeUpdateFirmwareImpl(filename) == FALSE)
        {
            ret = FAULT_CPE_9002;
            goto finish;
        }
    }
    else if(r2u == 2) //update config file
    {
        device_info( "config file update\n");
        if(CpeUpdateConfigImpl(filename) == FALSE)
        {
            ret = FAULT_CPE_9002;
            goto finish;
        }
    }
    else if(r2u == 3) //update ca
    {
        snprintf(cmd, 256, "mv %s %s", filename, ACS_CA_PATH);
        mysystem(cmd);
    }
    else if(r2u == 4) //update local
    {
        snprintf(cmd, 256, "mv %s %s", filename, CPE_CA_PATH);
        mysystem(cmd);
    }

finish:
    if(fp)
    {
        fclose(fp);
        fp = NULL;
    }

    if(curl)
    {
        curl_easy_cleanup(curl);
    }
    return ret;
}

BOOL CpeUploadConfFileImpl(const char *pFileName)
{
    // TODO...
    return TRUE;
}
BOOL CpeUpdateFirmwareImpl(const char *pFileName)
{
    // TODO...
    return TRUE;
}
BOOL CpeUpdateConfigImpl(const char *pFileName)
{
    // TODO...
    return TRUE;
}

//用于upload
#define FILETYPE_UPLOAD_CONF2   "X CT-COM 3 Vendor Configuration File"
#define BIND_EVENT  "X CT-COM BIND"

#define FILETYPE_UPLOAD_CONF    "1 Vendor Configuration File"
#define FILETYPE_UPLOAD_LOG     "2 Vendor Log File"

#define UPLOAD_CONF_FILE        "/var/config.tgz"
#define UPLOAD_LOG_FILE         "/var/log/cwmplog.tar.gz"

int dev_upload(void *data1, void *data2)
{
    upload_arg_t    *arg = NULL;
    char            *filename = NULL;
    struct timeval  tv;
    CURLcode        code;
    CURL            *curl = NULL;
    struct stat     f_stat;
    FILE            *fp = NULL;
    int             ret = FAULT_CPE_0;
    struct curl_slist   *http_headers = NULL;

    device_info("call upload\n");

    arg = (upload_arg_t*)data1;
    if(!arg || !arg->filetype || !arg->url)
    {
        device_error( "data1 is NULL\n");
        return FAULT_CPE_9002;
    }

    if(strcasecmp(arg->filetype, FILETYPE_UPLOAD_CONF) == 0 ||
       strcasecmp(arg->filetype, FILETYPE_UPLOAD_CONF2) == 0)
    {
        if(CpeUploadConfFileImpl(UPLOAD_CONF_FILE) == FALSE)
        {
            device_error( "gen_config fail\n");
            return FAULT_CPE_9002;
        }
        filename = UPLOAD_CONF_FILE;
    }
    else if(strcasecmp(arg->filetype, FILETYPE_UPLOAD_LOG) == 0)
    {
        // TODO...
    }
    else
    {
        device_error( "invlid file type, %s\n", arg->filetype);
        return FAULT_CPE_9003;
    }

    //判断文件是否存在
    if(access(filename, F_OK) == -1)
    {
        device_error( "%s is not exist\n", filename);
        return FAULT_CPE_9002;
    }
    fp = fopen(filename, "rb");
    if (fp == NULL)
    {
        device_error( "count not open %s\n", filename);
        return FAULT_CPE_9002;
    }
    
    if(arg->delaysec > 0)
    {
        tv.tv_sec = arg->delaysec;
        select(0, NULL, NULL, NULL, &tv);
    }
       
    //用CURL 为上传做准备
    curl = curl_easy_init();
    if (!curl)
    {
        device_error("curl_easy_init fail\n");
        ret = FAULT_CPE_9002;
        goto finish;
    }
    stat(filename, &f_stat);

    struct curl_httppost *post=NULL;
    struct curl_httppost *last=NULL;

    /* Add simple file section */
    if( curl_formadd(&post, &last, CURLFORM_COPYNAME, "upload", CURLFORM_FILE, filename, CURLFORM_END) != 0)
    {
        device_error("======= curl_formadd error.=========\n");
        goto finish;
    }
    
    /* Fill in the submit field too, even if this is rarely needed */
    curl_formadd(&post, &last, CURLFORM_COPYNAME, "submit", CURLFORM_COPYCONTENTS, "OK", CURLFORM_END);

    curl_easy_setopt(curl, CURLOPT_HEADER, 0);
    if(arg->srcip && isIpStr(arg->srcip))
    {
        curl_easy_setopt(curl, CURLOPT_INTERFACE, arg->srcip);
    }
    curl_easy_setopt(curl, CURLOPT_URL, arg->url); /*Set URL*/
    curl_easy_setopt(curl, CURLOPT_HTTPPOST, post);

    int timeout = 5;
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 1);

    device_info("upload size=%ld\n", f_stat.st_size);
    code = curl_easy_perform(curl);
    device_info("code=%d\n", code);
    curl_slist_free_all(http_headers);
    if( code == CURLE_OK)
    {
        
    }
    else if( code == CURLE_UNSUPPORTED_PROTOCOL)
    {
        ret = FAULT_CPE_9013;
    
    }
    else if(code == CURLE_FTP_ACCESS_DENIED ||code == CURLE_FTP_COULDNT_STOR_FILE)
    {
        ret = FAULT_CPE_9001;//request denied
    }
    else
    {
        device_error("curl perform err, %d:%s\n", code, curl_easy_strerror(code));
        ret = FAULT_CPE_9011;
    }
    curl_easy_cleanup(curl);
finish:
    if(fp)
    {
        fclose(fp);
    }
    device_info("upload end\n");
    
    return ret;
}

int dev_reboot(void *data1, void *data2)
{
    return 0;
}

int dev_factoryreset(void *data1, void *data2)
{
    return 0;
}

// 增加Inform上报的动态参数值
char** dev_dyninform(int *pcount)
{
    // TODO...
    return NULL;
}

#define  IPV4_ADDRESS_LEN    16
static char acs_back_ip[IPV4_ADDRESS_LEN] = {0};

/*
     url 是对应InternetGatewayDevice.ManagementServer.URL
     src_ip 是用于RPC方法的download或者upload的本设备ip地址
     new_url 当解析域名对应的ip地址发生变化的时候，保存新的URL地址
*/
int dev_url_dns_resolve(const char *url, char *src_ip, char **new_url)
{
    int  ret = FALSE;
    BOOL isIP = FALSE;
    const char *ps = NULL, *pe = NULL;
    char domain[128] = {0};
    char *dns_param_name = NULL;

    if(url == NULL)
    {
        device_error("url_dns_resolve: param is NULL\n");
        return FALSE;
    }
    
    //get domain name
    ps = strstr(url, "//");
    if(ps != NULL)
        ps = ps + strlen("//");
    else
        ps = url;

    pe = strchr(ps, ':');
    if(pe == NULL)
        pe = strchr(ps, '/');
    if(pe == NULL)
        pe = url + strlen(url);

    strncpy(domain, ps, pe - ps);
    device_debug("ACS domain name=%s\n", domain);
    //need resolving or not
    isIP = isIpStr(domain);

    // 解析DNS
    if(isIP == FALSE)
    {
        // TODO...
    }
    else
    {
        strcpy(acs_back_ip, domain);
        device_info("Already IP address.\n");
        ret = FALSE;
    }
    
    // 把WAN IP  传递给协议栈，用于download或者upload的方法
    if(src_ip != NULL)
    {
         char    *srcIP = NULL;
         //get TR069 binding WAN IP for src IP
         dev_get_wanparam_name(&dns_param_name);
         if(dns_param_name)
         {
             if(strstr(dns_param_name, "WANIPConnection"))
             {
                 CpeGetWANIPConnection_ExternalIPAddress(dns_param_name, &srcIP, NULL);
             }
             else
             {
                 //CpeGetWANPPPConnection_ExternalIPAddress(dns_paramname, &srcIP, NULL);
             }
         
             if(srcIP)
             {
                 strncpy(src_ip, srcIP, IPV4_ADDRESS_LEN-1);
                 device_info("binding src IP=%s\n", srcIP);
             }
         }
    }

    return ret;
}

//取得是否要验证ACS的标志
int dev_get_auth()
{
    char    *val = NULL;
    int     ret = -1;
    CpeGetValue(NULL, &val, "cpeagent.tr069.auth");
    if(val)
    {
        ret = atoi(val);
        free_check(val);
    }
    return ret;   
}


//取得监听端口Port
int dev_get_listenport()
{    
    char    *val = NULL;
    int     ret = -1;
    CpeGetValue(NULL, &val, "cpeagent.tr069.cpeport");
    device_info("get devlistenport\n");
    if(val)
    {
        ret = atoi(val);
        free_check(val);
    }
    return ret;    
}

int dev_debug(LogFunc log_func)
{
    char    *buf = NULL;
    int     flag = 0;
    
    device_info("call dev_debug\n");
    CpeGetValue(NULL, &buf, "cpeagent.cpe.debugtest");
    if(!buf)
    {
        return TRUE;
    }
    
    flag = atoi(buf);
    device_info("debug flag=%s\n", buf);
    free_check(buf);
    if(flag == 1)
    {
        return TRUE;
    }
    
    return FALSE;
}


int dev_cwmp_enable()
{    
    char    *val = NULL;
    int     ret = -1;
    CpeGetValue(NULL, &val, "cpeagent.tr069.enable");
    if(val)
    {
        ret = atoi(val);
        free_check(val);
    }
    return ret;    
}

/*
0: 表示ACS连接未建立
1: 表示ACS连接已建立，但无业务流
2: 表示ACS连接有业务流
*/
int dev_set_acs_status(int status)
{
    switch(status)
    {
       case 0:
       {          
           //mysystem("echo 0 > /tmp/acs_status");
           CpeSetValue(NULL, "0", "cpeagent.tr069.acs_status");
           break;
       }
       case 1:
       {
           mysystem("echo 1 > /tmp/acs_status");
           CpeSetValue(NULL, "1", "cpeagent.tr069.acs_status");
           break;
       }
       case 2:
       {
           CpeSetValue(NULL, "2", "cpeagent.tr069.acs_status");
           mysystem("echo 2 > /tmp/acs_status");
           break;
       }
       case 3:
       {
           CpeSetValue(NULL, "0", "cpeagent.tr069.acs_status");
           //syslog(LOG_CRIT|LOG_USER, "LOG_TYPE=1;ERR_CODE=104062");
           device_error("acs connection exceptional  !!!\n");
           break;
       }
    }

return 0;
}

/* 
  set cwmp status
  function: func_set_cwmp_status(int type,  int value)
  type=0, 主动上报Inform状态(0:未上报, 1: 上报无回应，2: 上报成功3:上报失败)
  type=1, 接受ACS连接状态(0: 未收到请求, 1: 远程连接中断, 2: 远程连接过程成功)
  type=2, 业务配置下发状态(0: 未下发, 1: 下发中, 2: 下发成功, 3: 下发失败)
*/

int dev_set_cwmp_status(int type, int val)
{
    char buf[10] = {0};

    sprintf(buf, "%d", val);
    device_info("dev_set_cwmp_status type(%d) val(%d) \n", type, val);
    switch(type)
    {
        case 0:
            {
                CpeSetValue(NULL, buf, "cpeagent.tr069.inform_status");
                break;
            }
        case 1:
            {
                CpeSetValue(NULL, buf, "cpeagent.tr069.cwmp_status");
                break;
            }
        case 2:
            {
                CpeSetValue(NULL, buf, "cpeagent.tr069.bs_status");
                break;
            }
    }
    return 0;
}

BOOL CpeGetValidExternIP(int *pNum, char *pExternIP, char *pProto, char *pDesp)
{
    char    *pVal = NULL;
    char    * wanMode = NULL;
    BOOL    ret = FALSE;
    char    path[UCI_PATH_LEN] = {0};
    
    if (CpeGetValue(NULL, &wanMode, "wanmode.wanmode.type") == FAULT_CPE_0)
    {
        if (OTXMLStrcmp(wanMode, "singlewan") == 0)
        {
             // TODO...
        }
        else if (OTXMLStrcmp(wanMode, "singleevdo") == 0)
        {
             // TODO...
        }
        else if (OTXMLStrcmp(wanMode, "singleadsl") == 0)
        {
             // TODO...
        }
        else if (OTXMLStrcmp(wanMode, "doublewan") == 0)
        {
             //TODO...
        }
        else if(OTXMLStrcmp(wanMode, "subwan") == 0
              ||OTXMLStrcmp(wanMode, "subadsl") == 0)
        {
            // Test
            int i = 0;
            int nEnable = 0;
            
            for (i = 1; i <= SWAN_COUNT; i++)
            {                
                snprintf(path, UCI_PATH_LEN, "swanif.swan%d.enable", i);
                if (CpeGetValue(NULL, &pVal, path) == FAULT_CPE_0)
                {
                    if(OTXMLStrcmp(pVal, "1") == 0)
                    {
                        nEnable++;
                    }
                    OTXMLFree(pVal);
                    pVal = NULL;
                }
                snprintf(path, UCI_PATH_LEN, "swanif.swan%d.proto", i);
                if (CpeGetValue(NULL, &pVal, path) == FAULT_CPE_0)
                {
                     if (strstr(pVal, "ppp") != NULL)
                     {
                          sprintf(pDesp, "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.%d.WANPPPConnection.1.ExternalIPAddress", nEnable);
                      }
                      else
                      {
                          sprintf(pDesp, "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.%d.WANIPConnection.1.ExternalIPAddress", nEnable);
                      }
                      
                      ret = TRUE;
                      OTXMLFree(pVal);
                      pVal = NULL;
                 }
                }
        }
        
        OTXMLFree(wanMode);
        wanMode = NULL;
    }
    return ret;
}

/*
  WAN口地址的参数项，和ACS保存连接的地址
  利用该参数项来得到WAN口地址，用于WAN地址是否变化以及上报
  该函数用于测试，具体实现需要根据设备的实际情况分析
  path: InternetGatewayDevice.DeviceInfo.CpeWANAddress
*/
int dev_get_wanparam_name(char **pwan_path)
{
    char    pDesp[128] = {0};
    if(pwan_path == NULL)
    {
        return FALSE;
    } 
    
    if (CpeGetValidExternIP(NULL, NULL, NULL, pDesp) == TRUE)
    {
        *pwan_path = strdup_check(pDesp);
    }


    if(*pwan_path == NULL)
        return FALSE;
    else
        return TRUE;
}

/*上报自定义的Name Change事件 */
void handle_namechange(callback_reg_func_t func)
{
    inform_add_t    *pinfo_add = NULL;
    pinfo_add = (inform_add_t*)malloc_check(sizeof(inform_add_t));
    if(!pinfo_add)
    {
        return;
    }
    
    memset(pinfo_add, 0, sizeof(inform_add_t));
    pinfo_add->events_list = (char **)malloc_check(sizeof(char *));
    if(pinfo_add->events_list)
    {
        pinfo_add->events_list[0] = strdup_check("X CT-COM NAME CHANGE");
        if(pinfo_add->events_list[0])
        {
            pinfo_add->event_count = 1;
        }
        else
        {
            free_check(pinfo_add->events_list);
            pinfo_add->events_list = NULL;
        }
    }
    func(NULL, TASK_ADD_INFORM, 0, (void *)pinfo_add, NULL);
    
    return;
}


