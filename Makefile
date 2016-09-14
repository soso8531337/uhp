CC=mipsel-openwrt-linux-gcc
CFLAGS=-g -Wall 

USB_DIR=/home/zhangwei/exercise/linux_c/vstfun/aoa/usb
CFLAGS += -I$(USB_DIR)/include
LDFLAGS+= -L$(USB_DIR)/lib -lusb-1.0 -lpthread

obj:=$(patsubst %.c, %.o, $(wildcard *.c))

	
UsbHost:$(obj)
	$(CC) $(CFLAGS) -o UsbHost $(obj) $(LDFLAGS)
	#cp baidupcs ~/mount/1/pcs

%.o: %.c, %.h
	$(CC) $(CFLAGS) $^ -o $@
	
.PHONY:clean
clean:
	-rm  UsbHost  *.o 

