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

#include "utils.h"
#include "device.h"
#include "log.h"
#include "storage.h"

#define SYS_CLA_BLK 	"/sys/class/block"
#define SYS_BLK		"/sys/block"
#define SYS_BLK_SD		"usb1/1-1/1-1.1"

#define STR_MID			64
#define STR_ADDR			256

struct storage_info{
	int id;
	uint32_t location;
	char addr[STR_ADDR];
	char storage[STR_MID];
};


static struct collection storage_list;
char sys_dir[STR_MID];
enum{
	STOR_SD=0,
	STOR_USB=1
};

static int storage_chk_proc(char *dev)
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

static int storage_chk_exist(char *lnk)
{
	FOREACH(struct storage_info *dev, &storage_list) {
		if(!strcmp(lnk, dev->addr)){
			usbproxy_log(LL_NOTICE, "Device  %d Have In Storage List", dev->location);				
			return 1;
		}
	} ENDFOREACH

	return 0;
}

int storage_find(int diskID, char *devname, int len)
{
	char tdev[256] = {0};
	if(devname == NULL){
		return -1;
	}
	
	FOREACH(struct storage_info *dev, &storage_list) {
		if(dev->id == diskID){
			snprintf(tdev, sizeof(tdev)-1, "/dev/%s", dev->storage);
			memcpy(devname, tdev, len);			
			usbproxy_log(LL_NOTICE, "Found Device  %u [%s]", dev->location, devname);
			return 1;
		}
	} ENDFOREACH

	return 0;
}
/*return diskID*/
int storage_add(char *dirname, uint32_t location)
{
	struct dirent *dent;
	DIR *dir;
	struct storage_info *sdev = NULL;
	
	/*Check ID Have In List*/
	FOREACH(struct storage_info *dev, &storage_list) {
		if(dev->location == location){
			usbproxy_log(LL_NOTICE, "Device  %d Have In Storage List", dev->location);				
			return 0;
		}
	} ENDFOREACH
	
	dir = opendir(dirname);
	if(dir == NULL){
		usbproxy_log(LL_DEBUG, "Opendir Failed");
		return -1;
	}	
	while((dent = readdir(dir)) != NULL){
		char devpath[512], linkbuf[1024] = {0};
		int len;
		if(strstr(dent->d_name, "sd") == NULL || strlen(dent->d_name) != 3){
			if(strstr(dent->d_name, "mmcblk") == NULL || 
				strlen(dent->d_name) != 7){
				continue;
			}
		}		
		if(storage_chk_proc(dent->d_name) == 0){
			usbproxy_log(LL_ERROR, "Partition Not Exist %s", dent->d_name);
			continue;
		}
		len = strlen(dirname) + strlen(dent->d_name) + 1;
		sprintf(devpath, "%s/%s", dirname, dent->d_name);
		devpath[len] = '\0';
		if(readlink(devpath, linkbuf, sizeof(linkbuf)-1) < 0){
			usbproxy_log(LL_ERROR, "ReadLink %s Error:%s", linkbuf, strerror(errno));
			continue;
		}
		/*Check the list have exist*/
		if(storage_chk_exist(linkbuf)){
			continue;
		}	
		/*Add it to LIst*/
		sdev = calloc(1, sizeof(struct storage_info));
		if(sdev == NULL){
			usbproxy_log(LL_ERROR, "Calloc Memory Faield:%s", strerror(errno));
			continue;
		}
		memcpy(sdev->addr, linkbuf, STR_ADDR-1);
		strcpy(sdev->storage, dent->d_name);
		sdev->location = location;
		if(strstr(linkbuf, SYS_BLK_SD) 
			|| strstr(dent->d_name, "mmcblk")){
			sdev->id = STOR_SD;
		}else{
			sdev->id = STOR_USB;
		}
		collection_add(&storage_list, sdev);			
		usbproxy_log(LL_NOTICE, "ADD Device  %u [%d/%s/%s] To Storage List", 
				location, sdev->id, sdev->storage, sdev->addr);				
		closedir(dir);
		return sdev->id;
	}

	closedir(dir);

	return 0;
}

int storage_remove(uint32_t location)
{
	uint32_t id = 0;
	/*Check ID Have In List*/
	FOREACH(struct storage_info *dev, &storage_list) {
		if(dev->location == location){
			usbproxy_log(LL_NOTICE, "Remove Storage Device  %u", dev->location);
			id = dev->id;
			collection_remove(&storage_list, dev);
			free(dev);
			return id;
		}
	} ENDFOREACH
	
	return 0;
}


int storage_init(void)
{
	struct stat statbuf;

	if(stat(SYS_CLA_BLK, &statbuf) == 0){
		strcpy(sys_dir, SYS_CLA_BLK);
	}else{
		if(stat(SYS_BLK, &statbuf) == 0){
			strcpy(sys_dir, SYS_BLK);
		}else{
			usbproxy_log(LL_DEBUG, "SYS_CLASS can not find block");
			memset(sys_dir, 0, sizeof(sys_dir));
			return -1;
		}
	}
	
	collection_init(&storage_list);
	return 0;
}

int storage_action_handle(struct storage_action *action, stor_callback callback)
{
	int ret;
	
	if(!strlen(sys_dir) || !action){
		return -1;
	}

	if(action->action == STOR_ADD){
		if((ret =storage_add(sys_dir, action->location)) >0 &&
				callback){
			callback(STOR_ADD, ret);
		}
		return 0;
	}else if(action->action == STOR_REM){
		if((ret = storage_remove(action->location)) > 0 &&
			callback){
			callback(STOR_REM, ret);
		}
	}

	return 0;		
}
