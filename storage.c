#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <getopt.h>
#include <pwd.h>
#include <grp.h>
#include <pthread.h>
#include <dirent.h>
#include <sys/un.h>
#include <sys/select.h>
#include <linux/types.h>
#include <linux/netlink.h>
#include <sys/ioctl.h>
#include <scsi/sg.h>


#include "utils.h"
#include "device.h"
#include "log.h"
#include "storage.h"
#include "protocol.h"

#ifndef NETLINK_KOBJECT_UEVENT
#define NETLINK_KOBJECT_UEVENT	15
#endif
#define UEVENT_BUFFER_SIZE		2048
#define UEVENT_NUM_ENVP			32
#define STOR_SUBSYS				"block"
#define STOR_DEVTYPE			"disk"
#define STOR_STR_ADD			"add"
#define STOR_STR_REM			"remove"
#define STOR_STR_CHANGE		"change"
#define STOR_ID_MAX				8
//#define SYS_BLK_SD		"usb1/1-1/1-1.1"
#define SYS_BLK_SD 		"mtk-sd.0"
#define SYS_CLA_BLK 	"/sys/class/block"
#define SYS_BLK		"/sys/block"

#define STOR_IDOFFSET(a)	(1<<(a))
#if !defined(BLKGETSIZE64)
#define BLKGETSIZE64           _IOR(0x12,114,size_t)
#endif

#define STOR_DFT_PRO		"U-Storage"
#define STOR_DFT_VENDOR		"i4season"

struct udevd_uevent_msg {
	unsigned char id;
	char *action;
	char *devpath;
	char *subsystem;	
	char *devname;
	char *devtype;
	dev_t devt;
	unsigned long long seqnum;
	unsigned int timeout;
	char *envp[UEVENT_NUM_ENVP+1];
	char envbuf[];
};

static struct collection storage_list;
unsigned char disk_ID = 0;

static int disk_sdid_get(void)
{
	if(!(disk_ID & 
		STOR_IDOFFSET(MERGE_(STOR_SD, 0)))){		
		disk_ID |= STOR_IDOFFSET(MERGE_(STOR_SD, 0));
		return MERGE_(STOR_SD, 0);
	}
	return -1;
}

static int disk_usbid_get(void)
{
	if(!(disk_ID & 
		STOR_IDOFFSET(MERGE_(STOR_USB, 1)))){
		disk_ID |= STOR_IDOFFSET(MERGE_(STOR_USB, 1));
		return MERGE_(STOR_USB, 1);
	}else if(!(disk_ID & 
		STOR_IDOFFSET(MERGE_(STOR_USB, 2)))){		
		disk_ID |= STOR_IDOFFSET(MERGE_(STOR_USB, 2));
		return MERGE_(STOR_USB, 2);
	}else if(!(disk_ID & 
		STOR_IDOFFSET(MERGE_(STOR_USB, 3)))){		
		disk_ID |= STOR_IDOFFSET(MERGE_(STOR_USB, 3));
		return MERGE_(STOR_USB, 3);
	}else if(!(disk_ID & 
		STOR_IDOFFSET(MERGE_(STOR_USB, 4)))){		
		disk_ID |= STOR_IDOFFSET(MERGE_(STOR_USB, 4));
		return MERGE_(STOR_USB, 4);
	}else if(!(disk_ID & 
		STOR_IDOFFSET(MERGE_(STOR_USB, 5)))){		
		disk_ID |= STOR_IDOFFSET(MERGE_(STOR_USB, 5));
		return MERGE_(STOR_USB, 5);
	}else if(!(disk_ID & 
		STOR_IDOFFSET(MERGE_(STOR_USB, 6)))){		
		disk_ID |= STOR_IDOFFSET(MERGE_(STOR_USB, 6));
		return MERGE_(STOR_USB, 6);
	}else if(!(disk_ID & 
		STOR_IDOFFSET(MERGE_(STOR_USB, 7)))){		
		disk_ID |= STOR_IDOFFSET(MERGE_(STOR_USB, 7));
		return MERGE_(STOR_USB, 7);
	}

	return -1;
}

static int disk_chk_proc(char *dev)
{
	FILE *procpt = NULL;
	int ma, mi, sz;
	char line[128], ptname[64], devname[256] = {0};

	if ((procpt = fopen("/proc/partitions", "r")) == NULL) {
		usbproxy_log(LL_NOTICE, "Fail to fopen(proc/partitions)");
		return 0;		
	}
	while (fgets(line, sizeof(line), procpt) != NULL) {
		memset(ptname, 0, sizeof(ptname));
		if (sscanf(line, " %d %d %d %[^\n ]",
				&ma, &mi, &sz, ptname) != 4)
				continue;
		if(!strcmp(ptname, dev)){
			usbproxy_log(LL_DEBUG, "Partition File Found %s", dev);
			sprintf(devname, "/dev/%s", dev);
			if(access(devname, F_OK)){
				mknod(devname, S_IFBLK|0644, makedev(ma, mi));
			}	
			fclose(procpt);
			return 1;
		}
	}

	fclose(procpt);
	return 0;
}

static int disk_get_space(char *devname, int64_t *capacity)
{
	unsigned char sense_b[32] = {0};
	unsigned char rcap_buff[8] = {0};
	unsigned char cmd[] = {0x25, 0, 0, 0 , 0, 0};
	struct sg_io_hdr io_hdr;
	unsigned int lastblock, blocksize;
	int64_t disk_cap = 0;
	int dev_fd;

	if(!devname){
		return -1;
	}
	dev_fd= open(devname, O_RDWR | O_NONBLOCK);
	if (dev_fd < 0 && errno == EROFS)
		dev_fd = open(devname, O_RDONLY | O_NONBLOCK);
	if (dev_fd<0){
		usbproxy_log(LL_ERROR, "Open %s Failed:%s", devname, strerror(errno));
		return -1; 
	}

	memset(&io_hdr, 0, sizeof(struct sg_io_hdr));
	io_hdr.interface_id = 'S';
	io_hdr.cmd_len = sizeof(cmd);
	io_hdr.dxferp = rcap_buff;
	io_hdr.dxfer_len = 8;
	io_hdr.mx_sb_len = sizeof(sense_b);
	io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
	io_hdr.cmdp = cmd;
	io_hdr.sbp = sense_b;
	io_hdr.timeout = 20000;

	if(ioctl(dev_fd, SG_IO, &io_hdr)<0){
		usbproxy_log(LL_ERROR,  "IOCTRL error:%s[Used BLKGETSIZE64]!", strerror(errno));
		if (ioctl(dev_fd, BLKGETSIZE64, &disk_cap) != 0) {			
			usbproxy_log(LL_ERROR, "Get Disk Capatiy Failed");
			close(dev_fd);
			return -1;		
		}		
		*capacity = disk_cap;		
		usbproxy_log(LL_ERROR,  "Disk Capacity = %lld Bytes", disk_cap);
		close(dev_fd);
		return 0;
	}

	/* Address of last disk block */
	lastblock =  ((rcap_buff[0]<<24)|(rcap_buff[1]<<16)|
	(rcap_buff[2]<<8)|(rcap_buff[3]));

	/* Block size */
	blocksize =  ((rcap_buff[4]<<24)|(rcap_buff[5]<<16)|
	(rcap_buff[6]<<8)|(rcap_buff[7]));

	/* Calculate disk capacity */
	disk_cap  = (lastblock+1);
	disk_cap *= blocksize;
	usbproxy_log(LL_ERROR,  "Disk Capacity = %lld Bytes", disk_cap);

	*capacity = disk_cap;
	close(dev_fd);

	return 0;
}

static const char *search_key(const char *searchkey, const char *buf, size_t buflen)
{
	size_t bufpos = 0;
	size_t searchkeylen = strlen(searchkey);

	while (bufpos < buflen) {
		const char *key;
		int keylen;

		key = &buf[bufpos];
		keylen = strlen(key);
		if (keylen == 0)
			break;
		 if ((strncmp(searchkey, key, searchkeylen) == 0) && key[searchkeylen] == '=')
			return &key[searchkeylen + 1];
		bufpos += keylen + 1;
	}
	return NULL;
}

static struct udevd_uevent_msg *get_msg_from_envbuf(const char *buf, int buf_size)
{
	int bufpos;
	int i;
	struct udevd_uevent_msg *msg;
	int maj = 0;
	int min = 0;

	msg = malloc(sizeof(struct udevd_uevent_msg) + buf_size);
	if (msg == NULL)
		return NULL;
	memset(msg, 0x00, sizeof(struct udevd_uevent_msg) + buf_size);

	/* copy environment buffer and reconstruct envp */
	memcpy(msg->envbuf, buf, buf_size);
	bufpos = 0;
	for (i = 0; (bufpos < buf_size) && (i < UEVENT_NUM_ENVP-2); i++) {
		int keylen;
		char *key;

		key = &msg->envbuf[bufpos];
		keylen = strlen(key);
		msg->envp[i] = key;
		bufpos += keylen + 1;
		usbproxy_log(LL_SPEW, "add '%s' to msg.envp[%i]", msg->envp[i], i);

		/* remember some keys for further processing */
		if (strncmp(key, "ACTION=", 7) == 0)
			msg->action = &key[7];
		else if (strncmp(key, "DEVPATH=", 8) == 0)
			msg->devpath = &key[8];
		else if (strncmp(key, "SUBSYSTEM=", 10) == 0)
			msg->subsystem = &key[10];		
		else if (strncmp(key, "DEVNAME=", 8) == 0)
			msg->devname = &key[8];
		else if (strncmp(key, "DEVTYPE=", 8) == 0)
			msg->devtype = &key[8];		
		else if (strncmp(key, "SEQNUM=", 7) == 0)
			msg->seqnum = strtoull(&key[7], NULL, 10);
		else if (strncmp(key, "MAJOR=", 6) == 0)
			maj = strtoull(&key[6], NULL, 10);
		else if (strncmp(key, "MINOR=", 6) == 0)
			min = strtoull(&key[6], NULL, 10);
		else if (strncmp(key, "TIMEOUT=", 8) == 0)
			msg->timeout = strtoull(&key[8], NULL, 10);
	}
	msg->devt = makedev(maj, min);
	msg->envp[i++] = "UDEVD_EVENT=1";
	msg->envp[i] = NULL;

	if (msg->devpath == NULL || msg->action == NULL) {
		usbproxy_log(LL_WARNING, "DEVPATH or ACTION missing, ignore message");
		free(msg);
		return NULL;
	}
	return msg;
}

static int storlist_insert(struct udevd_uevent_msg *msg)
{
	if(!msg){
		return -1;
	}
	FOREACH(struct udevd_uevent_msg *dev, &storage_list) {
		if(!strcmp(dev->devname, msg->devname)){
			if(!strcmp(dev->devpath, msg->devpath)){
				usbproxy_log(LL_NOTICE, "Storage Device  %s Have In List", dev->devname);
				return 1;
			}
			/*We must remove it and then insert it again, update it, it may not happen*/
			collection_remove(&storage_list, dev);
			free(dev);
		}
	} ENDFOREACH
	/*Insert it to list*/
	collection_add(&storage_list, msg);	
	return 0;
}

static int  storlist_remove(struct udevd_uevent_msg *msg, unsigned char *id)
{
	if(!msg || !id){
		return -1;
	}
	FOREACH(struct udevd_uevent_msg *dev, &storage_list) {
		if(!strcmp(dev->devname, msg->devname)
				&&!strcmp(dev->devpath, msg->devpath)){
			usbproxy_log(LL_NOTICE, "Remove Device  %s", dev->devname);
			/*remove it*/
			*id = dev->id;
			collection_remove(&storage_list, dev);
			free(dev);
			return 0;
		}
	} ENDFOREACH
	
	usbproxy_log(LL_NOTICE, "Remove Device But Not Found %s", msg->devname);
	return 1;
}


void storage_init(void)
{
	struct dirent *dent;
	DIR *dir;
	struct stat statbuf;
	char sys_dir[1024] = {0};

	collection_init(&storage_list);
	/*Get Block Device*/

	if(stat(SYS_CLA_BLK, &statbuf) == 0){
		strcpy(sys_dir, SYS_CLA_BLK);
	}else{
		if(stat(SYS_BLK, &statbuf) == 0){
			strcpy(sys_dir, SYS_BLK);
		}else{
			usbproxy_log(LL_DEBUG, "SYS_CLASS can not find block");
			memset(sys_dir, 0, sizeof(sys_dir));
			return ;
		}
	}
		
	dir = opendir(sys_dir);
	if(dir == NULL){
		usbproxy_log(LL_DEBUG, "Opendir Failed");
		return ;
	}	
	while((dent = readdir(dir)) != NULL){
		char devpath[512], linkbuf[1024] = {0}, *pdev = NULL;
		char uevent[2048] = {0}, udev[512] = {0};
		int len, ueventlen = 0, diskid = 0;			
		struct udevd_uevent_msg *msg = NULL;
		
		if(strstr(dent->d_name, "sd") == NULL || strlen(dent->d_name) != 3){
			if(strstr(dent->d_name, "mmcblk") == NULL || 
				strlen(dent->d_name) != 7){
				continue;
			}
		}		
		if(disk_chk_proc(dent->d_name) == 0){
			usbproxy_log(LL_ERROR, "Partition Not Exist %s", dent->d_name);
			continue;
		}
		len = strlen(sys_dir) + strlen(dent->d_name) + 1;
		sprintf(devpath, "%s/%s", sys_dir, dent->d_name);
		devpath[len] = '\0';
		if(readlink(devpath, linkbuf, sizeof(linkbuf)-1) < 0){
			usbproxy_log(LL_ERROR, "ReadLink %s Error:%s", linkbuf, strerror(errno));
			continue;
		}
		pdev = strstr(linkbuf, "/devices");
		if(pdev == NULL){
			continue;
		}
		/*Add it to LIst*/
		ueventlen = 48;
		memcpy(uevent, "ACTION=add\0MAJOR=8\0SUBSYSTEM=block\0DEVTYPE=disk\0", 48);
		memset(udev, 0, sizeof(udev));
		sprintf(udev, "DEVPATH=%s", pdev);
		memcpy(uevent+ueventlen, udev, strlen(udev)+1);
		ueventlen += strlen(udev)+1;
		memset(udev, 0, sizeof(udev));
		sprintf(udev, "DEVNAME=%s", dent->d_name);
		memcpy(uevent+ueventlen, udev, strlen(udev)+1);
		ueventlen += strlen(udev)+1;
		msg = get_msg_from_envbuf(uevent, ueventlen);
		if(msg == NULL){
			usbproxy_log(LL_ERROR, "Udev Event Decode Error[%s]", uevent);
			continue;
		}
	#ifdef MULTI_USB_SUPPORT		
		if(msg->devpath && strstr(msg->devpath, SYS_BLK_SD)){
			/*SD Card*/
			diskid = disk_sdid_get();
		}else{
			diskid = disk_usbid_get();
		}
	#else
		diskid = disk_sdid_get();
	#endif
		if(diskid < 0){
			usbproxy_log(LL_FLOOD, "To Much Storage In List [%s]", msg->devtype);
			free(msg);
			continue;
		}
		/*Add it to list*/
		msg->id = diskid;
		storlist_insert(msg);
		
		usbproxy_log(LL_NOTICE, "INIT ADD Device  %d [%s/%s] To Storage List", 
				msg->id, msg->devname,  msg->devpath);				
	}

	closedir(dir);
}

int storage_init_netlink_sock(void)
{
	struct sockaddr_nl snl;
	int retval, sockfd = -1;

	memset(&snl, 0x00, sizeof(struct sockaddr_nl));
	snl.nl_family = AF_NETLINK;
	snl.nl_pid = getpid();
	snl.nl_groups = 1;

	sockfd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_KOBJECT_UEVENT);
	if (sockfd == -1) {
		usbproxy_log(LL_ERROR, "error getting socket: %s", strerror(errno));
		return -1;
	}
	retval = bind(sockfd, (struct sockaddr *) &snl,
		      sizeof(struct sockaddr_nl));
	if (retval < 0) {
		usbproxy_log(LL_ERROR, "bind failed: %s", strerror(errno));
		close(sockfd);
		return -1;
	}

	return sockfd;
}

int storage_action_handle(int sockfd, stor_callback callback)
{
	char buffer[UEVENT_BUFFER_SIZE*2] = {0};
	struct udevd_uevent_msg *msg;
	int bufpos; 
	int diskid = 0;
	ssize_t size;
	char *pos = NULL;

	size = recv(sockfd, &buffer, sizeof(buffer), 0);
	if (size <= 0) {
		usbproxy_log(LL_ERROR, "error receiving uevent message: %s", strerror(errno));
		return -1;
	}
	if ((size_t)size > sizeof(buffer)-1)
		size = sizeof(buffer)-1;
	buffer[size] = '\0';
	/* start of event payload */
	bufpos = strlen(buffer)+1;
	msg = get_msg_from_envbuf(&buffer[bufpos], size-bufpos);
	if (msg == NULL)
		return -1;

	/* validate message */
	pos = strchr(buffer, '@');
	if (pos == NULL) {
		usbproxy_log(LL_ERROR,  "Invalid uevent '%s'", buffer);
		free(msg);
		return -1;
	}
	pos[0] = '\0';
	if (msg->action == NULL) {
		usbproxy_log(LL_ERROR,  "no ACTION in payload found, skip event '%s'", buffer);
		free(msg);
		return -1;
	}

	if (strcmp(msg->action, buffer) != 0) {
		usbproxy_log(LL_ERROR, "ACTION in payload does not match uevent, skip event '%s'", buffer);
		free(msg);
		return -1;
	}
	if(!msg->subsystem || strcasecmp(msg->subsystem, STOR_SUBSYS)){
		usbproxy_log(LL_FLOOD, "Subsystem mismatch [%s]", msg->subsystem);
		free(msg);
		return 0;
	}else if(!msg->devtype || strcasecmp(msg->devtype, STOR_DEVTYPE)){
		usbproxy_log(LL_FLOOD, "DevType mismatch [%s]", msg->devtype);
		free(msg);
		return 0;
	}

	/*handle event*/
	if(!strcasecmp(msg->action, STOR_STR_ADD)){
		char devbuf[128] = {0};
		int fd = -1;
		/*Disk ID*/
	#ifdef MULTI_USB_SUPPORT		
		if(msg->devpath && strstr(msg->devpath, SYS_BLK_SD)){
			/*SD Card*/
			diskid = disk_sdid_get();
		}else{
			diskid = disk_usbid_get();
		}
	#else
		diskid = disk_sdid_get();
	#endif
		if(diskid < 0){
			usbproxy_log(LL_FLOOD, "To Much Storage In List [%s]", msg->devtype);
			free(msg);
			return 0;
		}
		sprintf(devbuf, "/dev/%s", msg->devname);
		if(access(devbuf, F_OK)){
			mknod(devbuf, S_IFBLK|0644, msg->devt);
		}
		/*Check dev can open*/
		if((fd = open(devbuf, O_RDONLY)) < 0){
			/*Remove ID*/
			disk_ID &= (~(STOR_IDOFFSET(diskid)));
			usbproxy_log(LL_ERROR, "Open [%s] Failed:%s[Disk ID Recover to %d]", 
				devbuf, strerror(errno), disk_ID);
			free(msg);
			return 0;
		}else{
			close(fd);
		}
		/*Add it to list*/
		msg->id = diskid;
		if(storlist_insert(msg) == 0 && callback){
			callback(STOR_ADD, diskid);
		}
		usbproxy_log(LL_NOTICE, "ADD Device %d [%s/%s] To Storage List", 
				msg->id, msg->devname,  msg->devpath);		
	}else if(!strcasecmp(msg->action, STOR_STR_REM)){
		unsigned char id =0;
		usbproxy_log(LL_NOTICE, "Remove Device [%s/%s] From Storage List", 
				 msg->devname,  msg->devpath);				
		if(storlist_remove(msg, &id) == 0){
			if(callback){
				callback(STOR_REM, id);
			}
			/*Remove ID*/
			disk_ID &= (~(STOR_IDOFFSET(id)));			
		}
		free(msg);
	}else if(!strcasecmp(msg->action, STOR_STR_CHANGE)){		
		char devbuf[128] = {0};		
		int fd = -1;		
		unsigned char id =0;
		
		usbproxy_log(LL_NOTICE, "Try To Handle Device %s [%s/%s] Event", 
				msg->action, msg->devname,  msg->devpath);
		sprintf(devbuf, "/dev/%s", msg->devname);
		if(access(devbuf, F_OK)){
			mknod(devbuf, S_IFBLK|0644, msg->devt);
		}
		/*Check dev can open*/
		if((fd = open(devbuf, O_RDONLY)) < 0){
			/*Remove ID*/
			usbproxy_log(LL_ERROR, "We Think it may be Remove action[%s]", msg->devname);
			if(storlist_remove(msg, &id) == 0){
				if(callback){
					callback(STOR_REM, id);
				}
				/*Remove ID*/
				disk_ID &= (~(STOR_IDOFFSET(id)));			
			}			
			free(msg);
		}else{
			close(fd);			
			usbproxy_log(LL_ERROR, "We Think it may be Add action[%s]", msg->devname);
	#ifdef MULTI_USB_SUPPORT		
			if(msg->devpath && strstr(msg->devpath, SYS_BLK_SD)){
				/*SD Card*/
				diskid = disk_sdid_get();
			}else{
				diskid = disk_usbid_get();
			}
	#else
			diskid = disk_sdid_get();
	#endif
			if(diskid < 0){
				usbproxy_log(LL_FLOOD, "To Much Storage In List [%s]", msg->devtype);
				free(msg);
				return 0;
			}
			/*Add it to list*/
			msg->id = diskid;
			if(storlist_insert(msg) == 0 && callback){
				callback(STOR_ADD, diskid);
			}
			usbproxy_log(LL_NOTICE, "ADD Device %d [%s/%s] To Storage List", 
					msg->id, msg->devname,	msg->devpath);		
		}		
	}else{
		usbproxy_log(LL_NOTICE, "Unhandle Device %s [%s/%s] Event",
				msg->action, msg->devname,	msg->devpath);
		free(msg);
	}

	return 1;
}

int storage_find(int diskID, char *devname, int len)
{
	char tdev[256] = {0};
	if(devname == NULL){
		return -1;
	}	
		
	FOREACH(struct udevd_uevent_msg *dev, &storage_list) {
		if(dev->id == diskID){
			snprintf(tdev, sizeof(tdev)-1, "/dev/%s", dev->devname);
			memcpy(devname, tdev, len);			
			usbproxy_log(LL_NOTICE, "Found Device  %d [%s]", dev->id, devname);
			return 1;
		}
	} ENDFOREACH

	return 0;
}

unsigned char  storage_get_disklun(void)
{
	return disk_ID;
}

int storage_get_diskinfo(int16_t doffset, struct scsi_inquiry_info *info)
{
	char devname[512] = {0};
	int res;

	if(!info){
		return -1;
	}
	if(storage_find(doffset, devname, sizeof(devname)-1) != 1){
		usbproxy_log(LL_ERROR, "No Found Devname: %d", doffset);
		return -1;
	}
	res = disk_get_space(devname, &(info->size));
	if(res < 0){
		return -1;
	}
	/*Init Other Info*/
	strcpy(info->product, STOR_DFT_PRO);
	strcpy(info->vendor, STOR_DFT_VENDOR);
	strcpy(info->serial, "1234567890abcdef");
	strcpy(info->version, "1.0");

	return 0;
}
