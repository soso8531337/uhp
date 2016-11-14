#ifndef _STORAGE_H
#define _STORAGE_H
#include <stdint.h>
#include "protocol.h"

typedef void (*stor_callback)(int , unsigned char);

enum{
	STOR_ADD,
	STOR_REM
};

enum{
	STOR_SD_0=0,
	STOR_USB_1=1,
	STOR_USB_2=2,
	STOR_USB_3=3,
	STOR_USB_4=4,
	STOR_USB_5=5,
	STOR_USB_6=6,
	STOR_USB_7=7,
	STOR_NUM=8
};


void storage_init(void);
int storage_init_netlink_sock(void);
int storage_action_handle(int sockfd, stor_callback callback);
int storage_find(int diskID, char *devname, int len);
unsigned char  storage_get_disklun(void);
int storage_get_diskinfo(int16_t doffset, struct scsi_inquiry_info *info);

#endif

