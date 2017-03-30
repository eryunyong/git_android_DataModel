#ifndef _CPE_UTIL_H_
#define  _CPE_UTIL_H_

#include <time.h>
#include "device.h"
#include "uci.h"
#include "glob.h"

#ifndef BOOL
typedef unsigned char BOOL;
#endif

#define SWAN_COUNT                  8
#define WAN_DEF_COUNT               2

#define MAX_UCI_STR_LEN     256


#define strdup_check(str)           strdup((const char *)(str))
#define malloc_check(size)          malloc((size_t)(size))
#define calloc_check(nbelem,size)   calloc(nbelem, size)
#define realloc_check(ptr,size)     realloc(ptr, size)
#define free_check(ptr)             free((void*)(ptr))
#define OTXMLStrcasecmp             strcasecmp
#define OTXMLStrncmp                strncmp
#define OTXMLStrcmp                 strcmp
#define OTXMLFree	                free
#define OTXMLMalloc                 malloc

#define UNKNOWN_TIME                "0001-01-01T00:00:00Z"

// default, we support one wan device not double wan
// you can modify here to support what you want, just do it!
#define WANDEVICE_COUNT        1

// max support 8 wan connection interfaces
#define MULTIWAN_COUNT          8

typedef struct{
    char    **events_list;
    char    **params_list;
    int     event_count;
    int     params_count;
}inform_add_t;

typedef struct SoapDateTime
{
    unsigned int year;
    unsigned int month;
    unsigned int day;
    unsigned int hour;
    unsigned int min;
    unsigned int sec;
} SoapDateTime;

// uci command
enum
{
    /* section cmds */
    CMD_GET,
    CMD_SET,
    CMD_DEL,
    CMD_RENAME,
    CMD_REVERT,
    /* package cmds */
    CMD_SHOW,
    CMD_CHANGES,
    CMD_EXPORT,
    CMD_COMMIT,
    /* other cmds */
    CMD_ADD,
    CMD_IMPORT,
    CMD_HELP,
};

// wan type
// wan interface 有多种情况，支持单WAN, 双WAN(单WAN+3G), 3G, 多个子WAN 接口(最大支持8个)
typedef enum
{
    WANMODE_NULL = 0,
    WANMODE_SINGLE,
    WANMODE_DOUBLE,
    WANMODE_3G,
    WANMODE_SUBWAN
}WAN_MODE;


#define UCI_ROOT_DEFAULT            "/system/etc/config"
#define UCI_USER_ROOT               "/system/usr/config"

BOOL isDigitStr(const char *str);

unsigned int OTXMLStrlen(const char * string);
char * OTXMLStrdup(const char * str);
BOOL is_boolean(const char *str);

int CpeDelRecord(void * arg, char *path);
int CpeGetValue(void * arg, char ** value, char *path);
int CpeSetValue(void * arg, const char * value, char *path);
int checkSection(struct uci_list *list, const char *section);
int checkPackage(const char *package);
int cpe_uci_get(char * tag, char * buffer, int length);
int cpe_uci_set(char * tag, const char * value);
int cpe_uci_del(char * tag);
int cpe_uci_commit(char * tag);
int package_cmd(struct uci_context *ctx, int cmd, char *package);
int uci_do_section_cmd(struct uci_context *ctx, int cmd, char * tag, char * buffer, int length);

int copy_param(trf_param_t *param_to, const trf_param_t *param_from, const char *name);
int delete_param(trf_param_t *param);
int refresh_obj(trf_param_t *param, callback_reg_func_t func, int flag);
int get_full_param_name(trf_param_t *param, char *fullname);

BOOL is_boolean_true(const char *str);
int datetime2time_t(const char *in_pDatetime, time_t *out_pTime);
int time_t2datetime(const time_t in_time, char *out_pdatetime);
SoapDateTime GetLocalSoapDateTime();
int mysystem(const char *cmd);
int close_fd(void);
BOOL CpeFindEnableFreeEntry(const char *package, const char * sectionNamePrefix, int * pI, int maxNumOfEntries);
BOOL GetNumAfterString(void * arg,  char *pNum, char *pStr);
int get_wan_mode(char **pmode);
BOOL GetWANConnectionNum(unsigned int index, int *pCount, int *id, char *str_id);
BOOL SWANEnable();
int CpeGetWanPrefix(void * arg, char * package, char * section);

#endif


