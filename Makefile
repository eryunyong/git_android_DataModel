CROSS_COMPILE = arm-linux-androideabi-
AS              = $(CROSS_COMPILE)as
LD              = $(CROSS_COMPILE)ld
CC              = $(CROSS_COMPILE)gcc
CPP             = $(CC) -E
AR              = $(CROSS_COMPILE)ar
NM              = $(CROSS_COMPILE)nm

STRIP           = $(CROSS_COMPILE)strip
OBJCOPY         = $(CROSS_COMPILE)objcopy
OBJDUMP         = $(CROSS_COMPILE)objdump

export AS LD CC CPP AR NM
export STRIP OBJCOPY OBJDUMP

CFLAGS := -Wall -O2 -g
LDFLAGS :=

CFLAGS += -I $(shell pwd)/include
LDFLAGS += -ldl -luci -lcurl
export CFLAGS LDFLAGS

TOPDIR := $(shell pwd)
export TOPDIR

TARGET := device.so

obj-y += src/

all: 
	#############3. make device.so #####################
	make -C $(TOPDIR)/ -f $(TOPDIR)/Makefile.build
	$(CC) -o $(TARGET) -shared -fPIC built-in.o $(LDFLAGS)

.PHONY: clean
clean:
	rm -f $(shell find -name "*.o")
	rm -f $(shell find -name "*.d")
	rm -f $(TARGET)
	
.PHONY: distclean
distclean:
	##########1. clear device and uci make #################
	rm -f $(shell find -name "*.o")
	rm -f $(shell find -name "*.d")
	rm -f $(TARGET)
