#ifndef _DEV_FUNC_H_
#define _DEV_FUNC_H_

#include "cpeutil.h"
#include "device.h"

int dev_cwmp_enable();
int dev_url_dns_resolve(const char *url, char *src_ip, char **new_url);
char** dev_dyninform(int *pcount);
int dev_get_auth();
int dev_get_listenport();
BOOL CpeGetValidExternIP(int *pNum, char *pExternIP, char *pProto, char *pDesp);
int dev_get_wanparam_name(char **pwan_path);
int dev_bootstrap(int type, int *pret);
void dev_init(trf_param_t* param, callback_reg_func_t func, pthread_mutex_t *pmutex_param, LogFunc log_func);
void inform_bind(callback_reg_func_t func);

BOOL CpeUploadConfFileImpl(const char *pFileName);
BOOL CpeUpdateConfigImpl(const char *pFileName);
BOOL CpeUpdateFirmwareImpl(const char *pFileName);
int dev_reboot(void *data1, void *data2);
int dev_factoryreset(void *data1, void *data2);
int dev_telecomreset(void *data1, void *data2);
size_t getcontentlengthfunc(void *ptr, size_t size, size_t nmemb, void *stream);
int dev_download(void *data1, void *data2);
int dev_upload(void *data1, void *data2);

void closeinout();
BOOL isIpStr(const char *str);
trf_param_t *dev_get_param_by_name(trf_param_t *param, const char *name);
void handle_namechange(callback_reg_func_t func);

#endif



