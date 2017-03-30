#ifndef _DEVICE_H_
#define _DEVICE_H_

// 设备模块名称
#define DEVICE_MODULE               "EB-MIG"

#define DEFAULT_INFORM_INTERVAL     (24*60*60)
#define TR069_PARAMVALUE_SIZE	 512
#define LINE_MAX_LEN                128
#define NODENAME_LEN                128
#define MAX_LINEBUFFER_LEN          129
#define MAX_SQL_LEN                 1024
#define UCI_PATH_LEN                128

//任务注册
//诊断
#define TASK_DIAG                   1
//重启
#define TASK_REBOOT                 2
//恢复出厂设置
#define TASK_FACTORY                3
//download
#define TASK_DOWNLOAD               4
//upload
#define TASK_UPLOAD                 5
//change ACS URL
#define TASK_CHANGE_ACS_URL         6

#define TASK_ALG_RESTART            7
#define TASK_SNMP_RESTART           8
#define TASK_NTP_RESTART            9
#define TASK_VLAN_RESTART           10
#define TASK_PORT_RESTART           11
#define TASK_WLAN_RESTART           12
#define TASK_SAVE_OPENRESET         13
#define TASK_PORTAL_RESTART         14
#define TASK_SUBDEVICE              15
#define TASK_TELECOMRESET           16
#define TASK_WAN_RESTART            17
#define TASK_NAT_RESTART            18
#define TASK_DDNS_RESTART           19
#define TASK_VPN_RESTART            20
#define TASK_SYSLOG_RESTART         21
#define TASK_FIREWARE_RESTART       22
#define TASK_PORTFORWARD_RESTART    23
#define TASK_ADD_EVENT              24
#define TASK_ADD_INFORM             25

#define TASK_DHCP_RESTART           30
#define TASK_MWAN_RESTART           31
#define TASK_CMWAN_RESTART          32
#define VLANALLOT                   33
#define TASK_FTPSERVICE             34
#define TASK_VOIP_RESTART           35
#define TASK_TERMINAL_RESTART       36
#define TASK_YAMAHA_RESTART         40


#define TASK_OTHER                  99



//ERROR
#define FAULT_CPE_0                 0
#define FAULT_CPE_9000              9000
#define FAULT_CPE_9001              9001
#define FAULT_CPE_9002              9002
#define FAULT_CPE_9003              9003
#define FAULT_CPE_9004              9004
#define FAULT_CPE_9005              9005
#define FAULT_CPE_9006              9006
#define FAULT_CPE_9007              9007
#define FAULT_CPE_9008              9008
#define FAULT_CPE_9009              9009
#define FAULT_CPE_9010              9010
#define FAULT_CPE_9011              9011
#define FAULT_CPE_9012              9012
#define FAULT_CPE_9013              9013
#define FAULT_CPE_9014              9014
#define FAULT_CPE_9015              9015
#define FAULT_CPE_9016              9016
#define FAULT_CPE_9017              9017
#define FAULT_CPE_9018              9018
#define FAULT_CPE_9019              9019


#define STRING_TRUE                       "true"
#define STRING_FALSE                     "false"

#define BOOL_TRUE_STR                     "1"
#define BOOL_FALSE_STR                    "0"

#define TRUE	                             1	
#define FALSE	                      0

//log函数
typedef void (*LogFunc)(int type, const char *, const char *, const char *, int, const char *, ...);
extern LogFunc cwmplog_func;

//返回值，TRUE/FALSE，
//参数 1: data1
//参数 2: data2
typedef int (*callback_func_t)(void *, void *, LogFunc);
//int callback_reg(callback_func_t func, int type, unsigned int priority, void *data1, void *data2)
typedef int (*callback_reg_func_t)(callback_func_t, int, unsigned int, void *, void *);

//参数名的长度
#define PARAM_NAME_LEN                    128
//参数名全路径的长度        
#define PARAM_FULL_NAME_LEN               512


typedef struct trf_param                  trf_param_t;

//取得参数值函数 属于Param
typedef int (*TRFGetParamValueFunc)(void *, char **);
//设置参数值函数 属于Param
typedef int (*TRFSetParamValueFunc)(void *, const char *, callback_reg_func_t);
//AddObject 函数  属于Object
typedef int (*TRFAddObjectFunc)(trf_param_t*, void *, int *, callback_reg_func_t);
//DeleteObject函数 属于Object
typedef int (*TRFDelObjectFunc)(trf_param_t*, void *, int, callback_reg_func_t);
//刷新函数 属于Object
typedef int (*TRFRefreshFunc)(void *, trf_param_t*, callback_reg_func_t);

struct trf_param
{
    char                    name[PARAM_NAME_LEN+1];     //参数名
    int                     type;                       //参数类型 trf_datatype_e
    int                     writable;                   //是否可写。0:不可写，1:可写，如果object
                                                        //可以Add，则可写
    int                     max_instance;               //属于Object, 最大instance值，-1表示无限制
    int                     notification;               //属于Parameter,  0:off,1:passive,2:active
    unsigned char           noti_rw;                    //属于Parameter,  是否可以设置上报属性，0 不可以 1 可以
    unsigned long           acl;                        //属于Parameter, access list 
    TRFGetParamValueFunc    getparamval_func;           //属于Parameter, 取得参数值函数
    TRFSetParamValueFunc    setparamval_func;           //属于Parameter, 设置参数值函数
    TRFAddObjectFunc        addobject_func;             //属于Object, AddObject
    TRFDelObjectFunc        delobject_func;             //属于Object, DeleteObject
    TRFRefreshFunc          refresh_func;               //属于Object, 刷新
    struct trf_param        *parent;                    //父节点
    struct trf_param        *child;                     //子节点
    struct trf_param        *nextSibling;               //兄弟节点
};

typedef struct
{
    char            *cmdkey;
    char            *filetype;
    char            *url;
    char            *username;
    char            *password;
    char            *targetname;
    char            *sucurl;
    char            *failurl;
    unsigned long   delaysec;
    unsigned long   filesize;
    char            *srcip;
}download_arg_t;

typedef struct
{
    char            *cmdkey;
    char            *filetype;
    char            *url;
    char            *username;
    char            *password;
    unsigned long   delaysec;
    char            *srcip;
}upload_arg_t;


#endif

