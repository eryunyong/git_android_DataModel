#ifndef __LOG_H__
#define __LOG_H__
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <syslog.h>
#include <limits.h>
#include <pthread.h>

#define MAX_LOGBUF_LENGTH           0x1000  // max 4K
#define MODULE_NAME_LEN             64

/* 结构体保持和cwmp core定义的一致 */
typedef enum device_log_level
{
    DEVICE_LOG_EMERG = LOG_EMERG,   //The message says the system is unusable. 
    DEVICE_LOG_ALERT = LOG_ALERT,   //Action on the message must be taken immediately.     
    DEVICE_LOG_CRIT  = LOG_CRIT,    //The message states a critical condition.     
    DEVICE_LOG_ERROR = LOG_ERR,     //The message describes an error. 
    DEVICE_LOG_WARN  = LOG_WARNING, //The message is a warning. 
    DEVICE_LOG_NOTICE= LOG_NOTICE,  //The message describes a normal but important event. 
    DEVICE_LOG_INFO  = LOG_INFO,    //The message is purely informational. 
    DEVICE_LOG_DEBUG = LOG_DEBUG    //The message is only for debugging purposes. 
}device_log_level_t;

struct device_log_t
{
    FILE                *fd;
    device_log_level_t      level;
    int                 enable_log;
    int                 enable_syslog;
    char                module_name[MODULE_NAME_LEN];
    char                fullname[PATH_MAX];
    pthread_mutex_t     log_mutex;
};
typedef struct device_log_t device_log_t;

void deviceprint_log(device_log_level_t level, const char * file, const char * func, int line, const char *fmt, va_list ap);
void device_debug_log(const char * file, const char * func, int line, const char * fmt, ...);
void device_info_log(const char * file, const char * func, int line, const char * fmt, ...);
void device_warn_log(const char * file, const char * func, int line, const char * fmt, ...);
void device_error_log(const char * file, const char * func, int line, const char * fmt, ...);


#define __FUNC__ __func__
#define device_debug(x...)      device_debug_log(__FILE__,__FUNC__, __LINE__, ##x)
#define device_info(x...)	    device_info_log(__FILE__,__FUNC__, __LINE__, ##x)
#define device_warn(x...)        device_warn_log(__FILE__,__FUNC__, __LINE__, ##x)
#define device_error(x...)	   device_error_log(__FILE__,__FUNC__, __LINE__, ##x)

#endif



