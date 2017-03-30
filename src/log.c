#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <sys/time.h>
#include <sys/timeb.h>
#include <stdarg.h>
#include <pthread.h>
#include <errno.h>
#include <stdarg.h>

#include "device.h"
#include "log.h"

LogFunc cwmplog_func = NULL;

void deviceprint_log(device_log_level_t level, const char * file, const char * func, int line, const char *fmt, va_list ap)
{
    char    buf[MAX_LOGBUF_LENGTH+1] = {0};
        
    if(cwmplog_func)
    {
        vsnprintf(buf, MAX_LOGBUF_LENGTH, fmt, ap);
        cwmplog_func(level, DEVICE_MODULE, file, func, line, buf);
    }
    else
    {
        vfprintf(stdout, fmt, ap);
    }
}

void device_debug_log(const char * file, const char * func, int line, const char * fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    deviceprint_log(DEVICE_LOG_DEBUG, file, func, line, fmt, ap);
    va_end(ap);
}

void device_info_log(const char * file, const char * func, int line, const char * fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    deviceprint_log(DEVICE_LOG_INFO, file, func, line, fmt, ap);
    va_end(ap);
}

void device_warn_log(const char * file, const char * func, int line, const char * fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    deviceprint_log(DEVICE_LOG_WARN, file, func, line, fmt, ap);
    va_end(ap);
}

void device_error_log(const char * file, const char * func, int line, const char * fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    deviceprint_log(DEVICE_LOG_ERROR, file, func, line, fmt, ap);
    va_end(ap);
}



