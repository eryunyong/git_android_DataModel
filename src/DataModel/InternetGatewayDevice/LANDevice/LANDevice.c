#include "device.h"
#include "cpeutil.h"

int CpeGetLANEthernetInterfaceNumberOfEntries(void *arg, char ** value)
{
    *value = OTXMLStrdup("1");
    return FAULT_CPE_0;
}

