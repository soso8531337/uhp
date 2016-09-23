#ifndef _STORAGE_H
#define _STORAGE_H
#include <stdint.h>
#include "protocol.h"

typedef void (*stor_callback)(int , unsigned char);

enum{
	STOR_ADD,
	STOR_REM
};
void storage_init(void);
int storage_init_netlink_sock(void);
int storage_action_handle(int sockfd, stor_callback callback);
int storage_find(int diskID, char *devname, int len);
unsigned char  storage_get_disklun(void);
int storage_get_diskinfo(int16_t doffset, struct scsi_inquiry_info *info);

#endif

