#include <sys/timeb.h>
#include <time.h>
#include <dirent.h>
#include <pthread.h>

#include "log.h"
#include "cpeutil.h"
#include "device.h"


int CpeGetDeviceInfoSpecVersion(void *arg, char ** value)
{
    *value = OTXMLStrdup("DomainName");
    return 0;
}

int CpeGetDeviceInfoSoftwareVersion(void *arg, char ** value)
{
    return CpeGetValue(arg, value, "sysbaseinfo.cpe.softver");
}

int CpeGetDeviceInfoHardwareVersion(void *arg, char ** value)
{
    return CpeGetValue(arg, value, "sysbaseinfo.cpe.hardwarever");
}

int CpeGetDeviceInfoManufacturer(void *arg, char ** value)
{
    return CpeGetValue(arg, value, "sysbaseinfo.cpe.manufacture");
}

int CpeGetDeviceInfoSerialNumber(void *arg, char ** value)
{
    return CpeGetValue(arg, value, "sysbaseinfo.cpe.serialnumber");
}

int CpeGetDeviceInfoManufacturerOUI(void *arg, char ** value)
{
    return CpeGetValue(arg, value, "sysbaseinfo.cpe.oui");
}

int CpeGetDeviceInfoProvisioningCode(void *arg, char ** value)
{
    return CpeGetValue(arg, value, "sysbaseinfo.cpe.provisioningcode");
}

int CpeSetDeviceInfoProvisioningCode(void * arg, const char * value, callback_reg_func_t func)
{
    return FAULT_CPE_0;
}

int CpeGetDeviceInfoProductClass(void *arg, char ** value)
{
    return CpeGetValue(arg, value, "sysbaseinfo.cpe.productclass");
}

int CpeGetDeviceInfoDeviceType(void *arg, char ** value)
{
    return CpeGetValue(arg, value, "sysbaseinfo.cpe.devicetype");
    return 0;
}

int CpeGetDeviceInfoModelName(void *arg, char ** value)
{
    return CpeGetValue(arg, value, "sysbaseinfo.cpe.modelname");
}

