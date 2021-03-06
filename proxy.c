/*
 * libusbmuxd.c
 *
 * Copyright (C) 2009-2014 Martin Szulecki <m.szulecki@libimobiledevice.org>
 * Copyright (C) 2009-2014 Nikias Bassen <nikias@gmx.li>
 * Copyright (C) 2009 Paul Sladen <libiphone@paul.sladen.org>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
#ifdef HAVE_PPOLL
#define _GNU_SOURCE
#endif
#include <poll.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif


#ifdef WIN32
#include <windows.h>
#include <winsock2.h>
#define sleep(x) Sleep(x*1000)
#ifndef EPROTO
#define EPROTO 134
#endif
#ifndef EBADMSG
#define EBADMSG 104
#endif
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>
#endif


#include <unistd.h>
#include <signal.h>

// usbmuxd protocol
#include "usbmuxd-proto.h"
// socket utility functions
#include "socket.h"
// misc utility functions
#include "utils.h"
#include "protocol.h"
#include "proxy.h"
#include "log.h"
#include "storage.h"
#include "preread.h"

#define RELEASE 1
//#define USBHOST_PORT		8080
#define USBHOST_PORT		5555
/*Application send/receive buffer 256KB+512Byte, 
iPhone Send 256KB, 512Byte use for protocol header*/
#define USBHOST_NBUF_SIZE		(262144+512)
#define USBHOST_POLL_TIMER		(1*1000) /*1s*/
#define USBHOST_STORAGE			64
#define STOR_PAYLOAD		1

struct app_client{
	struct usbmuxd_device_record devinfo;
	int connected;
	int commufd; /*Comunication socket fd*/
	unsigned char *ib_buf;
	uint32_t ib_size;
	uint32_t ib_capacity;
	unsigned char *ob_buf;
	uint32_t ob_size;
	uint32_t ob_capacity;
	short events;	
};

struct app_config{
	struct collection *device;
	int listenfd;
	int  storfd;
	pthread_t monitor;
};

enum app_state{
	APP_NOCONNECT = 0,
	APP_CONNECTED,	// connected
	APP_SHUTDOWN,
	APP_DEAD
};

extern int should_exit;
pthread_mutex_t app_mutex;
static struct collection device_list;
static struct app_config app_proxy;
static volatile int use_tag = 0;

/**
 * Creates a socket connection to usbmuxd.
 * For Mac/Linux it is a unix domain socket,
 * for Windows it is a tcp socket.
 */
static int connect_usbmuxd_socket()
{
#if defined(WIN32) || defined(__CYGWIN__)
	return socket_connect("127.0.0.1", USBMUXD_SOCKET_PORT);
#else
	return socket_connect_unix(USBMUXD_SOCKET_FILE);
#endif
}

static int receive_packet(int sfd, struct usbmuxd_header *header, void **payload, int timeout)
{
	int recv_len;
	struct usbmuxd_header hdr;
	char *payload_loc = NULL;

	header->length = 0;
	header->version = 0;
	header->message = 0;
	header->tag = 0;

	recv_len = socket_receive_timeout(sfd, &hdr, sizeof(hdr), 0, timeout);
	if (recv_len < 0) {
		return recv_len;
	} else if ((size_t)recv_len < sizeof(hdr)) {
		return recv_len;
	}

	uint32_t payload_size = hdr.length - sizeof(hdr);
	if (payload_size > 0) {
		payload_loc = (char*)malloc(payload_size);
		uint32_t rsize = 0;
		do {
			int res = socket_receive_timeout(sfd, payload_loc + rsize, payload_size - rsize, 0, 5000);
			if (res < 0) {
				break;
			}
			rsize += res;
		} while (rsize < payload_size);
		if (rsize != payload_size) {
			usbproxy_log(LL_ERROR, "Error receiving payload of size %d (bytes received: %d)", payload_size, rsize);
			free(payload_loc);
			return -EBADMSG;
		}
	}

	if (hdr.message == MESSAGE_PLIST) {
		usbproxy_log(LL_DEBUG, "Receive MESSAGE_PLIST Message[IGNORE]");
	}
	*payload = payload_loc;
	memcpy(header, &hdr, sizeof(hdr));

	return hdr.length;
}

/**
 * Retrieves the result code to a previously sent request.
 */
static int usbmuxd_get_result(int sfd, uint32_t tag, uint32_t *result, void **result_plist, int *result_len)
{
	struct usbmuxd_header hdr;
	int recv_len;
	uint32_t *res = NULL;

	if (!result) {
		return -EINVAL;
	}
	*result = -1;
	if (result_plist) {
		*result_plist = NULL;
	}

	if ((recv_len = receive_packet(sfd, &hdr, (void**)&res, 5000)) < 0) {
		usbproxy_log(LL_ERROR, "Error receiving packet: %d", recv_len);
		if (res)
			free(res);
		return recv_len;
	}
	if ((size_t)recv_len < sizeof(hdr)) {
		usbproxy_log(LL_ERROR, "Received packet is too small-->recv=%d sizeof(hdr)=%d",
				recv_len, sizeof(hdr));
		if (res)
			free(res);
		return -EPROTO;
	}

	if (hdr.message == MESSAGE_RESULT) {
		if (hdr.tag != tag) {
			usbproxy_log(LL_ERROR, "WARNING: tag mismatch (%u != %u). Proceeding anyway.", hdr.tag, tag);
		}
		if (res) {
			memcpy(result, res, sizeof(uint32_t));
			free(res);
			if(result_len){
				*result_len=sizeof(uint32_t);
			}
			return 1;
		}
		if (res)			
			free(res);
		return -1;
	} else if (hdr.message == MESSAGE_PLIST) {
		if (res)			
			free(res);
		usbproxy_log(LL_ERROR, "MESSAGE_PLIST  Not Support !");
		*result = RESULT_OK;
		return 1;
	}else{
		if (!result_plist) {
			usbproxy_log(LL_ERROR, "MESSAGE_PLIST result but result_plist pointer is NULL!");
			return -1;
		}
		*result_plist = res;
		*result = RESULT_OK;
		if(result_len){
			*result_len = hdr.length-sizeof(hdr);
		}
		return 1;
	}

	usbproxy_log(LL_ERROR, "Unexpected message of type %d received!\n", hdr.message);
	if (res)
		free(res);
	return -EPROTO;
}

static int send_packet(int sfd, uint32_t message, uint32_t tag, void *payload, uint32_t payload_size)
{
	struct usbmuxd_header header;

	header.length = sizeof(struct usbmuxd_header);
	header.version = 0; //Use Default Version 0
	header.message = message;
	header.tag = tag;
	if (payload && (payload_size > 0)) {
		header.length += payload_size;
	}
	int sent = socket_send(sfd, &header, sizeof(header));
	if (sent != sizeof(header)) {
		usbproxy_log(LL_ERROR, "ERROR: could not send packet header");
		return -1;
	}
	if (payload && (payload_size > 0)) {
		uint32_t ssize = 0;
		do {
			int res = socket_send(sfd, (char*)payload + ssize, payload_size - ssize);
			if (res < 0) {
				break;
			}
			ssize += res;
		} while (ssize < payload_size);
		sent += ssize;
	}
	if (sent != (int)header.length) {
		usbproxy_log(LL_ERROR, "ERROR: could not send whole packet (sent %d of %d)", sent, header.length);
		socket_close(sfd);
		return -1;
	}
	return sent;
}

static int send_binary_devlist_packet(int sfd, uint32_t tag)
{	
	return  send_packet(sfd, MESSAGE_DEVICE_LIST, tag, NULL, 0);
}

static int send_listen_packet(int sfd, uint32_t tag)
{
	/* binary packet */
	return send_packet(sfd, MESSAGE_LISTEN, tag, NULL, 0);
}

static int send_connect_packet(int sfd, uint32_t tag, uint32_t device_id, uint16_t port)
{
	/* binary packet */
	struct {
		uint32_t device_id;
		uint16_t port;
		uint16_t reserved;
	} conninfo;

	conninfo.device_id = device_id;
	conninfo.port = htons(port);
	conninfo.reserved = 0;
	return send_packet(sfd, MESSAGE_CONNECT, tag, &conninfo, sizeof(conninfo));
}

static int storage_write(struct scsi_head *scsi,  unsigned char *payload)
{
	int wlen, fd, already = 0, res;
	off_t offset;
	char devname[512] = {0};
	
	if(!scsi || !payload){
		return -1;
	}
	if(scsi->len == 0){
		return -1;
	}	
	wlen = scsi->len;
	offset = (off_t)scsi->addr *SCSI_SECTOR_SIZE;

	if(storage_find(scsi->wlun, devname, sizeof(devname)-1) != 1){
		usbproxy_log(LL_ERROR, "No Found Devname: %d", scsi->wlun);
		return -1;
	}

	fd = open(devname, O_RDWR);
	if(fd < 0){
		usbproxy_log(LL_ERROR, "Open %s Error:%s", devname, strerror(errno));
		return -1;
	}
	if(lseek(fd, offset, SEEK_SET) < 0){
		usbproxy_log(LL_ERROR, "Lseek %s Error:%s", devname, strerror(errno));
		close(fd);
		return -1;
	}
	do {
		res  = write(fd, payload + already, wlen - already);
		if (res < 0) {
			if(errno ==  EINTR ||
					errno ==  EAGAIN){
				continue;
			}
			usbproxy_log(LL_ERROR, "Wrie %s Error:%s", devname, strerror(errno));
			close(fd);
			return -1;
		}
		already += res;
	} while (already < wlen);

	close(fd);
	usbproxy_log(LL_ERROR, "Write Finish:wtag=%d\nctrid=%d\naddr=%d\nlen=%d\nwlun=%d",  
			 scsi->wtag, scsi->ctrid, scsi->addr, scsi->len, scsi->wlun);

	return wlen;
}

#ifdef SUPPORT_PREREAD
static int storage_read(struct scsi_head *scsi, struct app_client *client)
{
	int total = 0,  already = 0;
	char *payload = NULL;

	if(!scsi || !client){
		return -1;
	}
	if(scsi->len == 0){
		return -1;
	}
	usbproxy_log(LL_ERROR, "Read begin:wtag=%d\nctrid=%d\naddr=%d\nlen=%d\nwlun=%d",  
			 scsi->wtag, scsi->ctrid, scsi->addr, scsi->len, scsi->wlun);	
	total = scsi->len + SCSI_HEAD_SIZE;
	payload = calloc(1, total);
	if(payload == NULL){
		usbproxy_log(LL_ERROR, "Calloc Memory Error:%s",  strerror(errno));
		return -1;
	}
	/*copy header*/
	memcpy(payload, scsi, sizeof(struct scsi_head));
	already += SCSI_HEAD_SIZE;
	
	if(preread_storage_read(scsi->wlun, scsi->addr, 
			scsi->len, payload+already) < 0){
		free(payload);
		return -1;
	}
	memcpy(client->ob_buf+client->ob_size, payload, total);
	client->ob_size += total;

	usbproxy_log(LL_ERROR, "Read Finish:wtag=%d\nctrid=%d\naddr=%d\nlen=%d\nwlun=%d",  
			 scsi->wtag, scsi->ctrid, scsi->addr, scsi->len, scsi->wlun);
	/*Free Memory*/ 
	free(payload);
	return total;
}
#else
static int storage_read(struct scsi_head *scsi, struct app_client *client)
{
	int wlen, fd, already = 0, res, total = 0, paylen = 0;
	off_t offset;
	char *payload = NULL;
	char devname[512] = {0};
	
	if(!scsi || !client){
		return -1;
	}
	if(scsi->len == 0){
		return -1;
	}
	wlen = scsi->len;
	offset = (off_t)scsi->addr *SCSI_SECTOR_SIZE;
	if(storage_find(scsi->wlun, devname, sizeof(devname)-1) != 1){
		usbproxy_log(LL_ERROR, "No Found Devname: %d", scsi->wlun);
		return -1;
	}

	fd = open(devname, O_RDWR);
	if(fd < 0){
		usbproxy_log(LL_ERROR, "Open %s Error:%s", devname, strerror(errno));
		return -1;
	}
	if(lseek(fd, offset, SEEK_SET) < 0){
		usbproxy_log(LL_ERROR, "Lseek %s Error:%s", devname, strerror(errno));
		close(fd);
		return -1;
	}
	total = wlen + SCSI_HEAD_SIZE;
	payload = calloc(1, total);
	if(payload == NULL){
		usbproxy_log(LL_ERROR, "Calloc Memory Error:%s",  strerror(errno));
		close(fd);
		return -1;
	}
	usbproxy_log(LL_ERROR, "Read begin:wtag=%d\nctrid=%d\naddr=%d\nlen=%d\nwlun=%d",  
			 scsi->wtag, scsi->ctrid, scsi->addr, scsi->len, scsi->wlun);	
	/*copy header*/
	memcpy(payload, scsi, sizeof(struct scsi_head));
	already += SCSI_HEAD_SIZE;
	paylen = 0;
	do {
		res  = read(fd, payload + already, wlen - paylen);
		if (res < 0) {
			if(errno ==  EINTR ||
					errno ==  EAGAIN){
				continue;
			}
			usbproxy_log(LL_ERROR, "Read %s Error:%s",devname, strerror(errno));
			free(payload);
			close(fd);
			return -1;
		}
		already += res;
		paylen += res;
	} while (already < total);
	close(fd);
	memcpy(client->ob_buf+client->ob_size, payload, total);
	client->ob_size += total;
	usbproxy_log(LL_ERROR, "Read Finish:wtag=%d\nctrid=%d\naddr=%d\nlen=%d\nwlun=%d",  
			 scsi->wtag, scsi->ctrid, scsi->addr, scsi->len, scsi->wlun);
	/*Free Memory*/	
	free(payload);
	return total;
}
#endif

static int storage_disklun(struct scsi_head *scsi, struct app_client *client)
{	
	unsigned char disklun=storage_get_disklun();

	if(!scsi || !client){
		return -1;
	}
	if(scsi->len != STOR_PAYLOAD){
		usbproxy_log(LL_ERROR, "Disk Lun Length mismatch[%d/%d]", scsi->len, STOR_PAYLOAD);
		return -1;
	}
	
	memcpy(client->ob_buf+client->ob_size, scsi, SCSI_HEAD_SIZE);
	client->ob_size += SCSI_HEAD_SIZE;
	memcpy(client->ob_buf+client->ob_size, &disklun, STOR_PAYLOAD);
	client->ob_size += STOR_PAYLOAD;
	usbproxy_log(LL_DEBUG, "Disk Lun is [%d]", disklun);

	return 0;
}

static int storage_diskinfo(struct scsi_head *scsi, struct app_client *client)
{
	struct scsi_inquiry_info dinfo;
	int res, inquirylen = 0;
	
	if(!scsi || !client){
		return -1;
	}
	inquirylen = sizeof(struct scsi_inquiry_info);
	if(scsi->len != inquirylen){
		usbproxy_log(LL_ERROR, "Disk Inquiry Length mismatch[%d/%d]", 
				scsi->len, inquirylen);
		return -1;
	}	
	
	memset(&dinfo, 0, inquirylen);
	res = storage_get_diskinfo(scsi->wlun, &dinfo);
	if(res < 0){
		usbproxy_log(LL_ERROR, "Disk Inquiry Error");
		return -1;
	}
	memcpy(client->ob_buf+client->ob_size, scsi, SCSI_HEAD_SIZE);
	client->ob_size += SCSI_HEAD_SIZE;
	memcpy(client->ob_buf+client->ob_size, &dinfo, inquirylen);
	client->ob_size += inquirylen;
	usbproxy_log(LL_DEBUG, "Disk[%d]  \nSize:%lld\nVendor:%s\nProduct:%s\nVersion:%s\nSerical:%s", 
			scsi->wlun, dinfo.size, dinfo.vendor, dinfo.product, dinfo.version, dinfo.serial);

	return 0;
}
static int storage_operation_result(struct scsi_head *scsi, struct app_client *client)
{
	if(!scsi || !client){
		return -1;
	}
	if(client->ob_size +SCSI_HEAD_SIZE > client->ob_capacity){
		usbproxy_log(LL_ERROR, "Out Buffer Is Not Enough");
		return -1;
	}
	memcpy(client->ob_buf+client->ob_size, (void*)scsi, SCSI_HEAD_SIZE);
	client->ob_size += SCSI_HEAD_SIZE;
	return 0;
}

static int system_chkup_firmware(char *firmware)
{
	char md5str[33] = {0}, buffer[512] = {0}, md5cmp[33] = {0};
	char syscmd[1024] = {0};
	char *ptr = NULL;
	int count=10, i;
	FILE *fp;

	if(!firmware){
		return -1;
	}
#define MD5_FLAG			"MD5="
#define SYS_FIRM_SKIP		(64*1024) //skip 64KB
#define SYS_FIRM_UPSCRIP		"/sbin/sysupgrade"
	if(compute_md5(firmware, SYS_FIRM_SKIP, md5str) < 0){
		usbproxy_log(LL_WARNING, "Compute MD5:%s Failed", firmware);
		return -1;
	}
	/*Check md5 value in firmware*/
	fp = fopen(firmware, "r");
	if(!fp){
		usbproxy_log(LL_WARNING, "FOpen:%s Failed", firmware);
		return -1;
	}
	for(i=0; i < count; i++){
		memset(buffer, 0, sizeof(buffer));
		if(fgets(buffer, sizeof(buffer)-1, fp) <= 0){
			usbproxy_log(LL_WARNING, "Read:%s Failed", firmware);
			fclose(fp);
			return -1;
		}
		if(strncmp(buffer, MD5_FLAG, strlen(MD5_FLAG)) == 0){
			usbproxy_log(LL_WARNING, "Found MD5 String:%s", buffer);
			break;
		}
	}
	fclose(fp);
	
	if(i == count){
		usbproxy_log(LL_WARNING, "No Found MD5 String:%s", firmware);
		return -1;
	}
	i = 0;
	ptr = buffer + strlen(MD5_FLAG);
	while(*ptr != '\n' && i < sizeof(md5cmp)){
		md5cmp[i] = *ptr;
		ptr++;
		i++;
	}
	if(strcasecmp(md5str, md5cmp)){
		usbproxy_log(LL_WARNING, "MD5 String Not Same:%s<-->%s", md5str, md5cmp);
		return -1;
	}
	usbproxy_log(LL_WARNING, "Firmware OK MD5 String Same:%s<-->%s", md5str, md5cmp);
	snprintf(syscmd, sizeof(syscmd)-1, "%s %s &", SYS_FIRM_UPSCRIP, firmware);
	system(syscmd);
	return 0;
}

static int system_upfirmware(struct scsi_head *scsi, struct app_client *client)
{
#define USTORAGE_UPPATH			"/tmp/u-storage.firmware"
	static int fd = -1;

	if(!scsi || !client){
		return -1;
	}
	if(scsi->ctrid == SCSI_UPDATE_START){
		usbproxy_log(LL_WARNING, "Prepare To update Firmware");		
		close(fd);
		fd = open(USTORAGE_UPPATH, 
				O_CREAT|O_WRONLY|O_TRUNC, S_IRUSR|S_IWUSR);
		if(fd < 0){
			usbproxy_log(LL_WARNING, "Open %s Failed:%s", 
					USTORAGE_UPPATH, strerror(errno));
			return -1;
		}
		usbproxy_log(LL_WARNING, "Open %s Successful:%d", 
				USTORAGE_UPPATH, fd);
		return 0;
	}else if(scsi->ctrid == SCSI_UPDATE_DATA){
		unsigned char *payload = client->ib_buf+SCSI_HEAD_SIZE;
		int wlen = scsi->len, res, already = 0;
		if(fd < 0){
			usbproxy_log(LL_WARNING, "%s Not Open", USTORAGE_UPPATH);
			return -1;
		}
		do {
			res  = write(fd, payload + already, wlen - already);
			if (res < 0) {
				if(errno ==  EINTR ||
						errno ==  EAGAIN){
					continue;
				}
				usbproxy_log(LL_ERROR, "Write Firmware %s Error:%s", 
						USTORAGE_UPPATH, strerror(errno));
				close(fd);
				return -1;
			}
			already += res;
		} while (already < wlen);
		usbproxy_log(LL_ERROR, "Write Firmware %s Successful:%d", 
						USTORAGE_UPPATH, wlen);
	}else if(scsi->ctrid == SCSI_UPDATE_END){
		close(fd);
		fd = -1;
		usbproxy_log(LL_WARNING, "Check %s MD5", USTORAGE_UPPATH);
		return system_chkup_firmware(USTORAGE_UPPATH);
	}else{
		usbproxy_log(LL_WARNING, "unknown Comannd ID:%d", scsi->ctrid);
		return -1;
	}

	return 0;
}

static int system_getfirmware_info(struct scsi_head *scsi, struct app_client *client)
{
	vs_acessory_parameter dinfo;
	int flen = sizeof(vs_acessory_parameter);
	FILE *fp;
	char buffer[256] = {0}, key[128], value[128];

#define SYS_FIRMCONF		"/etc/firmware"
	if(!scsi || !client){
		return -1;
	}

	if(scsi->len !=  flen){
		usbproxy_log(LL_ERROR, " Firmware scsi_firmware_info mismatch[%d/%d]", 
				scsi->len, flen);
		return -1;
	}	

	memset(&dinfo, 0, flen);
	/*Get Firmware Info*/
	fp = fopen(SYS_FIRMCONF, "r");
	if(fp == NULL){
		usbproxy_log(LL_ERROR, "Open %s Failed:%s", 
						SYS_FIRMCONF, strerror(errno));
		return -1;
	}
	while (fgets(buffer, sizeof(buffer), fp)) {
		memset(key, 0, sizeof(key));
		memset(value, 0, sizeof(value));		
		if (sscanf(buffer, "%[^=]=%[^\n ]",
					key, value) != 2)
			continue;
		if(!strcasecmp(key, "VENDOR")){
			strcpy(dinfo.manufacture, value);
		}else if(!strcasecmp(key, "CURFILE")){
			strcpy(dinfo.model_name, value);
		}else if(!strcasecmp(key, "CURVER")){
			strcpy(dinfo.fw_version, value);
		}else if(!strcasecmp(key, "SN")){
			strcpy(dinfo.sn, value);
		}else if(!strcasecmp(key, "LICENSE")){
			strcpy(dinfo.license, value);
		}
	}
	fclose(fp);
	
	memcpy(client->ob_buf+client->ob_size, scsi, SCSI_HEAD_SIZE);
	client->ob_size += SCSI_HEAD_SIZE;
	memcpy(client->ob_buf+client->ob_size, &dinfo, flen);
	client->ob_size += flen;
	usbproxy_log(LL_DEBUG, "Firmware Info:\nVendor:%s\nProduct:%s\nVersion:%s\nSerical:%s\nLicense:%s", 
					dinfo.manufacture, dinfo.model_name, dinfo.fw_version, dinfo.sn, dinfo.license);

	return 0;
}
static int usbhost_get_tag(void)
{
	if(use_tag == 0x7FFFFFFF){
		use_tag = 0;
	}
	return ++use_tag;
}

static void application_connection_setdown(struct app_client *client)
{
	if(!client){
		return;
	}
	/*Set Conncetion Status to Dead*/
	pthread_mutex_lock(&app_mutex);
	if(client->connected == APP_DEAD){
		usbproxy_log(LL_ERROR, "Connection Have In Dead Status Socket %d", client->commufd);	
	}else{
		client->connected =  APP_SHUTDOWN;
	}
	socket_close(client->commufd);
	pthread_mutex_unlock(&app_mutex);
	usbproxy_log(LL_ERROR, "TearDown Socket %d", client->commufd);	
}

USBHOST_API int usbhost_get_device_list(int sockfd)
{
	int sfd;
	int tag, reslen = 0, curlen=0;
	uint32_t res;
	struct usbmuxd_device_record *dev;
	struct app_client *client = NULL;
	char *response = NULL;

	if(sockfd < 0){
		sfd = connect_usbmuxd_socket();
		if (sfd < 0) {
			usbproxy_log(LL_ERROR, "Error Opening Unix Socket");
			return sfd;
		}
	}else{
		sfd = sockfd;
	}
	
	tag = usbhost_get_tag();
	/*Send to usbhost daemon*/
	if(send_binary_devlist_packet(sfd, tag) < 0){
		usbproxy_log(LL_ERROR, "Error Send device List Request");
		socket_close(sfd);
		return -1;
	}
	/*Decode result*/
	if ((usbmuxd_get_result(sfd, tag, &res, (void **)&response, &reslen) == 1) && (res == 0)) {
		while(curlen < reslen){
			dev = (struct usbmuxd_device_record *)(response+curlen);
			if(dev->padding != USBHOST_DPADDING_MAGIC){
				usbproxy_log(LL_DEBUG, "Magic Mismatch-->0x%2x", dev->padding);
				curlen += sizeof(struct usbmuxd_device_record);
				continue;
			}
			client = calloc(1, sizeof(struct app_client));
			if(client == NULL){
				usbproxy_log(LL_ERROR, "Calloc Memory Error");
				if(response){
					free(response);
				}				
				socket_close(sfd);
				return -1;
			}
			memcpy(&(client->devinfo), dev, sizeof(struct usbmuxd_device_record));
			client->connected = APP_NOCONNECT;
			client->commufd = -1;
			usbproxy_log(LL_DEBUG, "Add Device:\nID:%uProductID:%u\nSerical:%s\nLocation:%u\nPadding:%u\n", 
					client->devinfo.device_id, client->devinfo.product_id, 
					client->devinfo.serial_number, client->devinfo.location, client->devinfo.padding);
			pthread_mutex_lock(&app_mutex);
			collection_add(&device_list, client);
			pthread_mutex_unlock(&app_mutex);			
			curlen += sizeof(struct usbmuxd_device_record);
		}
		if(response){
			free(response);
			response = NULL;
		}
		if(reslen == 0){
			usbproxy_log(LL_DEBUG, "Proxy No Found Device");
		}
	}else{
		usbproxy_log(LL_DEBUG, "Get Result Error:%d", res);		
		/*Close fd*/
		socket_close(sfd);
		return -1;
	}
	/*Close fd*/
	socket_close(sfd);

	return  0;
}

USBHOST_API int usbhost_dead_device_by_udid(uint32_t handle)
{
	pthread_mutex_lock(&app_mutex);
	FOREACH(struct app_client *dev, &device_list) {
		if(dev->devinfo.device_id == handle){
			usbproxy_log(LL_NOTICE, "Set device Dead %d", dev->devinfo.device_id);
			dev->connected = APP_DEAD;
			socket_close(dev->commufd);
			dev->commufd = -1;
			pthread_mutex_unlock(&app_mutex);
			return 1;
		}
	} ENDFOREACH
	pthread_mutex_unlock(&app_mutex);

	return 0;
}

USBHOST_API int usbhost_check_device_by_udid(uint32_t handle)
{
	pthread_mutex_lock(&app_mutex);
	FOREACH(struct app_client *dev, &device_list) {
		if(dev->devinfo.device_id == handle){
			usbproxy_log(LL_NOTICE, "Device %d Have In List", dev->devinfo.device_id);
			pthread_mutex_unlock(&app_mutex);
			return 1;
		}
	} ENDFOREACH
	pthread_mutex_unlock(&app_mutex);

	return 0;
}

USBHOST_API int usbhost_init_device_by_udid(uint32_t handle, int confd)
{
	pthread_mutex_lock(&app_mutex);
	FOREACH(struct app_client *dev, &device_list) {
		if(dev->devinfo.device_id == handle){
			usbproxy_log(LL_NOTICE, "Set device[%d] INIT ", dev->devinfo.device_id);
			dev->connected = APP_CONNECTED;
			dev->commufd = confd;
			dev->ob_buf = malloc(USBHOST_NBUF_SIZE);
			dev->ob_capacity = USBHOST_NBUF_SIZE;
			dev->ob_size = 0;
			dev->ib_buf = malloc(USBHOST_NBUF_SIZE);
			dev->ib_capacity = USBHOST_NBUF_SIZE;
			dev->ib_size = 0;
			dev->events |= POLLIN;
			pthread_mutex_unlock(&app_mutex);
			return 0;
		}
	} ENDFOREACH
	pthread_mutex_unlock(&app_mutex);

	return 1;
}

USBHOST_API void usbhost_device_shutdown(int rmall)
{	
	usbproxy_log(LL_FLOOD, "usbhost_device_shutdown"); 
	pthread_mutex_lock(&app_mutex);
	FOREACH(struct app_client *dev, &device_list) {
		if(rmall == 1 || dev->connected == APP_DEAD
				|| dev->connected == APP_SHUTDOWN){
			if(dev->ib_buf){
				free(dev->ib_buf);
			}
			if(dev->ob_buf){
				free(dev->ob_buf);
			}
			socket_close(dev->commufd);
			if(rmall == 1 || dev->connected == APP_DEAD){				
				usbproxy_log(LL_DEBUG, "Remove Dead Device %d[%s]", 
						dev->devinfo.device_id, dev->devinfo.serial_number);
				collection_remove(&device_list, dev);
				free(dev);
			}else{
				dev->commufd = -1;
				dev->connected = APP_NOCONNECT;
				dev->ib_buf = NULL;
				dev->ob_buf = NULL;
				usbproxy_log(LL_DEBUG, "ShutDown Device %d[%s]", 
						dev->devinfo.device_id, dev->devinfo.serial_number);
			}
		}
	} ENDFOREACH
	pthread_mutex_unlock(&app_mutex);
	if(rmall){
		pthread_mutex_destroy(&app_mutex);
		collection_free(&device_list);
	}
}

void usbhost_client_fds(struct fdlist *list)
{
	pthread_mutex_lock(&app_mutex);
	FOREACH(struct app_client *dev, &device_list) {
		if(dev->connected == APP_CONNECTED){
			fdlist_add(list, FD_CLIENT, dev->commufd, dev->events);
		}
	} ENDFOREACH
	pthread_mutex_unlock(&app_mutex);
}

/**
 * Tries to connect to usbmuxd .
 */
USBHOST_API int usbhost_listen(void)
{
	int sfd;
	uint32_t res = -1;
	int tag;

	sfd = connect_usbmuxd_socket();
	if (sfd < 0) {
		usbproxy_log(LL_ERROR, "Error Opening Unix Socket");
		return -1;
	}
	tag = usbhost_get_tag();
	if(send_listen_packet(sfd, tag) <= 0) {
		usbproxy_log(LL_ERROR, "ERROR: could not send listen packet");
		socket_close(sfd);
		return -1;
	}
	if((usbmuxd_get_result(sfd, tag, &res, NULL, NULL) == 1)&&(res != 0)){
		socket_close(sfd);
		usbproxy_log(LL_ERROR, "ERROR: did not get OK but %d\n", res);
		return -1;
	}
	
	return sfd;
}

USBHOST_API int usbhost_connect(const int handle, const unsigned short port)
{
	int sfd;
	int tag;
	uint32_t res = -1;

	sfd = connect_usbmuxd_socket();
	if (sfd < 0) {
		usbproxy_log(LL_ERROR, "Error Opening Unix Socket");
		return -1;
	}
	tag = usbhost_get_tag();

	if(send_connect_packet(sfd, tag, (uint32_t)handle, (uint16_t)port) <= 0) {
		usbproxy_log(LL_ERROR, "Error Send Connect Request");
		socket_close(sfd);
		return -1;
	} 
	if (usbmuxd_get_result(sfd, tag, &res, NULL, NULL) == 1){
		if(res == RESULT_OK){
			usbproxy_log(LL_DEBUG, "Connect Device %d success!", handle);			
			return sfd;
		}else if(res == RESULT_BADVERSION){
			usbproxy_log(LL_DEBUG, "Connect Device %d Error: BAD Version!", handle);			
		}
	}

	socket_close(sfd);
	return -1;
}

USBHOST_API int usbhost_disconnect(int sfd)
{
	return socket_close(sfd);
}

USBHOST_API int usbhost_socket_send(int sfd, const char *data, uint32_t len, uint32_t *sent_bytes)
{
	int num_sent;

	if (sfd < 0) {
		return -EINVAL;
	}
	
	num_sent = socket_send(sfd, (void*)data, len);
	if (num_sent < 0) {
		*sent_bytes = 0;
		num_sent = errno;		
		usbproxy_log(LL_ERROR, "Error %d when sending: %s", num_sent, strerror(num_sent));
		return -num_sent;
	} else if ((uint32_t)num_sent < len) {
		usbproxy_log(LL_DEBUG, "Warning: Did not send enough (only %d of %d)", num_sent, len);
	}

	*sent_bytes = num_sent;

	return 0;
}

USBHOST_API int usbhost_recv_timeout(int sfd, char *data, uint32_t len, uint32_t *recv_bytes, unsigned int timeout)
{
	int num_recv = socket_receive_timeout(sfd, (void*)data, len, 0, timeout);
	if (num_recv < 0) {
		*recv_bytes = 0;
		return num_recv;
	}

	*recv_bytes = num_recv;

	return 0;
}

USBHOST_API int usbhost_socket_recv(int sfd, char *data, uint32_t len, uint32_t *recv_bytes)
{
	return usbhost_recv_timeout(sfd, data, len, recv_bytes, 5000);
}

/*storage add or remove notify to peer*/
void storage_callbakck(int action, unsigned char diskid)
{
	struct scsi_head header;

	pthread_mutex_lock(&app_mutex);
	FOREACH(struct app_client *lc, app_proxy.device) {
		if(lc->connected == APP_CONNECTED){
			/*Notify to peer*/
			memset(&header, 0, sizeof(header));
			header.head = SCSI_DEVICE_MAGIC;
			if(action == STOR_ADD){
				header.ctrid = SCSI_INPUT;
			}else{
				header.ctrid = SCSI_OUTPUT;
			}
			srand( (unsigned)time( NULL ));
			header.wtag = rand();
			header.len = STOR_PAYLOAD;
			if(lc->ob_size+STOR_PAYLOAD+SCSI_HEAD_SIZE > lc->ob_capacity){
				usbproxy_log(LL_DEBUG, "Warning: Buffer Not enough [%d/%d]", 
						lc->ob_size, lc->ob_capacity);
				continue;
			}
#ifdef RELEASE
			memcpy(lc->ob_buf+lc->ob_size, &header, SCSI_HEAD_SIZE);
			lc->ob_size += SCSI_HEAD_SIZE;
			memcpy(lc->ob_buf+lc->ob_size, &diskid, STOR_PAYLOAD);
			lc->ob_size += STOR_PAYLOAD;
			usbproxy_log(LL_WARNING, "Notify Disk %s--> [%d]", 
					action == STOR_ADD?"Add":"Remove", diskid);
#else
			char buf[256] = {0};
			sprintf(buf, "Storage: Aciton=%d ID=%d", action, diskid);
			memcpy(lc->ob_buf+lc->ob_size, buf,  strlen(buf));
			lc->ob_size += strlen(buf);			
#endif
			lc->events |= POLLOUT;
		}
	} ENDFOREACH
	pthread_mutex_unlock(&app_mutex);
}
/**
 * Waits for an event to occur, i.e. a packet coming from usbmuxd.
 * Calls generate_event to pass the event via callback to the client program.
 */
static int monitor_event(int sfd)
{
	struct usbmuxd_header hdr;
	void *payload = NULL;

	/* block until we receive something */
	if (receive_packet(sfd, &hdr, &payload, 0) < 0){
		return -1;
	}

	if((hdr.length > sizeof(hdr)) && !payload){
		usbproxy_log(LL_ERROR, "Invalid packet received, payload is missing!");
		return -EBADMSG;
	}

	if (hdr.message == MESSAGE_DEVICE_ADD) {
		struct usbmuxd_device_record *dev = payload;
		struct app_client *client = NULL;
		
		if(dev->padding != USBHOST_DPADDING_MAGIC){
			usbproxy_log(LL_DEBUG, "Magic Mismatch-->0x%2x", dev->padding);
			if(payload){
				free(payload);
			}			
			return 0;
		}
		if(usbhost_check_device_by_udid(dev->device_id) == 1){
			if(payload){
				free(payload);
			}			
			return 0;
		}
		client = calloc(1, sizeof(struct app_client));
		if(client == NULL){
			usbproxy_log(LL_ERROR, "Calloc Memory Error");
			if(payload){
				free(payload);
			}				
			return -2;
		}
		memcpy(&(client->devinfo), dev, sizeof(struct usbmuxd_device_record));
		client->connected = APP_NOCONNECT;
		client->commufd = -1;
		usbproxy_log(LL_DEBUG, "Add Device:\nID:%uProductID:%u\nSerical:%s\nLocation:%u\nPadding:%u\n", 
				client->devinfo.device_id, client->devinfo.product_id, 
				client->devinfo.serial_number, client->devinfo.location, client->devinfo.padding);
		pthread_mutex_lock(&app_mutex);
		collection_add(&device_list, client);
		pthread_mutex_unlock(&app_mutex);
	} else if (hdr.message == MESSAGE_DEVICE_REMOVE) {
		uint32_t handle;

		memcpy(&handle, payload, sizeof(uint32_t));
		usbhost_dead_device_by_udid(handle);
	}else if(hdr.length > 0) {
		usbproxy_log(LL_DEBUG, "Unexpected message type %d length %d received!",hdr.message, hdr.length);
	}
	if (payload) {
		free(payload);
	}
	return 0;
}

static void *device_monitor(void* arg)
{
	int res;
	int listenfd = *((int *)arg);
	
	while(!should_exit){
		/*Handle Event*/
		res = monitor_event(listenfd);
		if(res == -1){
			usbproxy_log(LL_ERROR, "Receive Listen Package Error Close socket..");
			socket_close(listenfd);
			listenfd = -1;
			return NULL;
		}
	}
	return NULL;
}

/**
 * Examine the state of a connection's buffers and
 * update all connection flags and masks accordingly.
 * Does not do I/O.
 *
 * @param conn The connection to update.
 */
static void update_app_connection(struct app_client*conn)
{
	if(conn->ob_size &&
			conn->ob_size <= conn->ob_capacity)
		conn->events |= POLLOUT;
	else
		conn->events &= ~POLLOUT;

	if(conn->ib_size < conn->ib_capacity)
		conn->events |= POLLIN;
	else
		conn->events &= ~POLLIN;

	usbproxy_log(LL_SPEW, "Applicaion Update connection: events %d", conn->events);
}
static int protocol_decode(struct app_client *client, struct scsi_head *scsi)
{
	struct scsi_head *shder = NULL;
	uint32_t payload;
	
	if(!scsi || !client){
		return -1;
	}
	shder = (struct scsi_head *)(client->ib_buf);
	if(shder->head != SCSI_PHONE_MAGIC){
		usbproxy_log(LL_ERROR, "Magic Error[0x%x]", shder->head);
		return PRO_BADMAGIC;
	}else if(shder->ctrid &SCSI_WFLAG){
		payload = shder->len + SCSI_HEAD_SIZE;
		if(payload > client->ib_capacity){
			usbproxy_log(LL_ERROR, "WRITE Too Big Package %u/%uBytes", 
					payload, client->ib_capacity);
			return PRO_BADPACKAGE;
		}else if(payload > client->ib_size){
			usbproxy_log(LL_ERROR, "INComplete Package %u/%uBytes", 
					payload, client->ib_size);
			return PRO_INCOMPLTE;
		}
	}else if(shder->ctrid == SCSI_READ){
		payload = shder->len + SCSI_HEAD_SIZE;
		if(payload > client->ob_capacity){
			usbproxy_log(LL_ERROR, "READ Too Big Package %u/%uBytes", 
					payload, client->ob_capacity);
			return PRO_BADPACKAGE;
		}else if(payload > (client->ob_capacity-client->ob_size)){
			usbproxy_log(LL_ERROR, "READ Buffer is Not Enough %u/%uBytes", 
					payload, client->ob_capacity-client->ob_size);
			return PRO_NOSPACE;
		}
	}
	
	memcpy(scsi, shder, sizeof(struct scsi_head));
	return PRO_OK;
}

static void application_update_event(void)
{
	pthread_mutex_lock(&app_mutex);
	FOREACH(struct app_client *lc, app_proxy.device) {
		update_app_connection(lc);
	} ENDFOREACH
	pthread_mutex_unlock(&app_mutex);
}
static int application_command(struct app_client *client)
{
	uint32_t bytes = 0;
	struct scsi_head scsi;
	int res;
	
	usbproxy_log(LL_ERROR, "Receive %u/%uBytes-->addr:%p", 
			client->ib_size, client->ib_capacity, client->ib_buf);
	/*Decode Protocol and wirte to block device*/
	memset(&scsi, 0, sizeof(struct scsi_head));
	res = protocol_decode(client, &scsi);
	if(res == PRO_BADMAGIC ||
			res == PRO_BADPACKAGE){
		/*TearDown*/
		return -1;
	}else if(res == PRO_BADPACKAGE){
		/*TearDown*/
		return -1;
	}else if(res == PRO_INCOMPLTE){
		/*Recevie Not Finish*/
		client->events |= POLLIN;
		if(client->ob_size &&
			client->ob_size <= client->ob_capacity){
			client->events |= POLLOUT;
		}else{
			client->events &= ~POLLOUT;
		}
		return 0;
	}else if(res == PRO_NOSPACE){
		/*Out Buffer Not Enough to read*/
		client->events |= POLLOUT;
		return 0;
	}
	/*Check Buffer is Enough*/
	switch(scsi.ctrid) {
		case SCSI_READ:
			res = storage_read(&scsi, client);
			if(res < 0){
				/*Send to peer notify read failed*/
				scsi.relag = EREAD;
				storage_operation_result(&scsi, client);				
			}			
			break;
		case SCSI_WRITE:
			res = storage_write(&scsi,  client->ib_buf+SCSI_HEAD_SIZE);
			if(res < 0){
				/*Send to peer notify write failed*/
				scsi.relag = EWRITE;
			}			
			bytes = scsi.len;
			storage_operation_result(&scsi, client);
			break;
		case SCSI_TEST:
			/*Just return it*/
			storage_operation_result(&scsi, client);
			break;
		case SCSI_GET_LUN:
			/*Get disk Num*/
			res = storage_disklun(&scsi, client);
			if(res < 0){
				/*Send to peer notify read failed*/
				scsi.relag = EDISKLEN;
				storage_operation_result(&scsi, client);				
			}
			break;
		case SCSI_INQUIRY:
			res = storage_diskinfo(&scsi, client);
			if(res < 0){
				/*Send to peer notify read failed*/
				scsi.relag = EDISKINFO;
				storage_operation_result(&scsi, client);				
			}
			break;
		case SCSI_UPDATE_START:
		case SCSI_UPDATE_DATA:
		case SCSI_UPDATE_END:		
			res = system_upfirmware(&scsi, client);
			if(res < 0){
				/*Send to peer notify read failed*/
				scsi.relag = EUPDATE;
				storage_operation_result(&scsi, client);				
			}
			if(scsi.ctrid == SCSI_UPDATE_DATA){
				bytes = scsi.len;
			}
			storage_operation_result(&scsi, client);			
			break;
		case SCSI_FIRMWARE_INFO:
			system_getfirmware_info(&scsi, client);
			break;
		default:
			usbproxy_log(LL_ERROR, "Unhandle SCSI Type-->%d",  scsi.ctrid);
	}
	/*Offset Buffer*/	
	bytes += SCSI_HEAD_SIZE;
	client->ib_size -= bytes;
	usbproxy_log(LL_ERROR, "Application Handle Finish:\nwtag=%d\nctrid=%d\naddr=%d\nlen=%d\nwlun=%d\nSkip Next:SkipLen:%d\nCntLen:%d",  
			 scsi.wtag, scsi.ctrid, scsi.addr, scsi.len, scsi.wlun, bytes, client->ib_size);	
	memmove(client->ib_buf, client->ib_buf + bytes, client->ib_size);	
	/*Encode Buffer and Send To peer*/
	if(client->ib_size >= SCSI_HEAD_SIZE){
		usbproxy_log(LL_ERROR, "Application Continue To Handle[%u/%uBytes]", client->ib_size, client->ib_capacity);
		return 1;
	}
	/*Update Event flag*/
	update_app_connection(client);
	return 0;
}

static void application_process_recv(struct app_client *client)
{
	int res;

	if(client->ib_size >= client->ib_capacity){
		usbproxy_log(LL_ERROR, "Receive Buffer is Full [%uBytes]", client->ib_capacity);
		while((res = application_command(client)) == 1);
		/*Try to handle buffer, if it is not effect, set down*/
		if(res == -1 || client->ib_size >= client->ib_capacity){
			application_connection_setdown(client);
			return;
		}	
	}
	res = recv(client->commufd, client->ib_buf + client->ib_size, client->ib_capacity - client->ib_size, 0);
	if(res <= 0) {
		if(res < 0)
			usbproxy_log(LL_ERROR, "Receive from client fd %d failed: %s", client->commufd, strerror(errno));
		else
			usbproxy_log(LL_INFO, "Client %d connection closed", client->commufd);
		/*Set Conncetion Status to Dead*/
		application_connection_setdown(client);		
		return;
	}
	client->ib_size += res;
	while((res = application_command(client)) == 1);
	if(res == -1){
	#ifdef RELEASE
		application_connection_setdown(client);
	#else
		int copy_size, free_size;
		free_size = client->ob_capacity-client->ob_size;
		copy_size = client->ib_size> free_size?free_size:client->ib_size;
		if(free_size == 0){
			usbproxy_log(LL_INFO, "USBHOST Test Send Buffer is Full %dBytes", client->ob_size);
			client->events |= POLLOUT;			
			client->events &= ~POLLIN;
			return;
		}
		if(client->ib_size > 1){
			/* resoponse more than 1bytes*/
			memcpy(client->ob_buf+client->ob_size, client->ib_buf,copy_size);
			client->ob_size += copy_size;
			client->events |= POLLOUT;			
			usbproxy_log(LL_INFO, "USBHOST Test Send To Peer %dBytes", copy_size);
		}
		client->ib_size = 0;
		client->events |= POLLIN;	
	#endif
	}
}

static void application_process_send(struct app_client *client)
{
	int res;
	if(!client->ob_size) {
		usbproxy_log(LL_WARNING, "Client %d OUT process but nothing to send?", client->commufd);
		client->events &= ~POLLOUT;
		return;
	}
	res = send(client->commufd, client->ob_buf, client->ob_size, 0);
	if(res <= 0) {
		usbproxy_log(LL_ERROR, "Send to client fd %d failed: %d %s", client->commufd, res, strerror(errno));
		application_connection_setdown(client);
		return;
	}
	usbproxy_log(LL_ERROR, "Send buffer Used Size Change: %uBytes---->%uBytes", client->ob_size, client->ob_size-res);
	if((uint32_t)res == client->ob_size) {
		client->ob_size = 0;
		client->events &= ~POLLOUT;
	} else {
		client->ob_size -= res;
		client->events |= POLLOUT;
		memmove(client->ob_buf, client->ob_buf + res, client->ob_size);
	}
}

static void application_layer_storage(int fd, short events)
{
	usbproxy_log(LL_INFO, "Application Storage  Triger....");
	storage_action_handle(fd, storage_callbakck);
}


static void application_layer_process(int fd, short events)
{
	struct app_client *client = NULL;
	pthread_mutex_lock(&app_mutex);
	FOREACH(struct app_client *lc, app_proxy.device) {
		if(lc->commufd == fd) {
			client = lc;
			break;
		}
	} ENDFOREACH
	pthread_mutex_unlock(&app_mutex);

	if(!client) {
		usbproxy_log(LL_INFO, "application_layer_process: fd %d not found in client list", fd);
		return;
	}

	if(events & POLLIN) {
		application_process_recv(client);
	}
	if(events & POLLOUT) { //not both in case client died as part of process_recv
		application_process_send(client);
	}
}

static int application_try_connect(void)
{
	int connectfd = -1;
	int res;
	struct collection dev_list = {NULL, 0};
	
	/*check and Remove DEAD Device*/		
	usbhost_device_shutdown(0);
	/*Check Device Count Not locket, may be dangerous*/
	if(!collection_count(app_proxy.device)){
		usbproxy_log(LL_ERROR, "No Device Found..");
		return 0;
	}
	pthread_mutex_lock(&app_mutex);
	collection_copy(&dev_list, app_proxy.device);
	pthread_mutex_unlock(&app_mutex);
	/*Loop Device and connect it*/
	FOREACH(struct app_client *dev, &dev_list) {
		if(dev->connected != APP_NOCONNECT){
			continue;
		}
		connectfd = usbhost_connect(dev->devinfo.device_id, USBHOST_PORT);
		if(connectfd > 0){
			res = usbhost_init_device_by_udid(dev->devinfo.device_id, connectfd);
			if(res){
				usbproxy_log(LL_ERROR, "Init Device Connection Error..");
				socket_close(connectfd);
			}else{
				usbproxy_log(LL_ERROR, "Application Device[%u] Connection Successful..", dev->devinfo.device_id);
			}
		}
	} ENDFOREACH
	
	collection_free(&dev_list);
	return 1;
}

static int application_layer_loop()
{	
	int cnt, i;
	struct fdlist pollfds;
	struct timespec tspec;

#ifdef HAVE_PPOLL
	sigset_t empty_sigset;
	sigemptyset(&empty_sigset); // unmask all signals
#endif

	fdlist_create(&pollfds);
	while(!should_exit){
		/*Connect To Device*/
		application_try_connect();
		/*Poll Request*/		
		fdlist_reset(&pollfds);
		usbhost_client_fds(&pollfds);
		/*Add storage FD*/
		if(app_proxy.storfd > 0){
			fdlist_add(&pollfds, FD_USB, app_proxy.storfd, POLLIN);
		}
		if(!pollfds.count){
			usleep(500000);
			continue;
		}
		tspec.tv_sec = USBHOST_POLL_TIMER / 1000;
		tspec.tv_nsec = (USBHOST_POLL_TIMER % 1000) * 1000000;
	#ifdef HAVE_PPOLL
		cnt = ppoll(pollfds.fds, pollfds.count, &tspec, &empty_sigset);
	#else
		cnt = poll(pollfds.fds, pollfds.count, USBHOST_POLL_TIMER);
	#endif
		usbproxy_log(LL_FLOOD, "poll() returned %d", cnt);
		if(cnt == -1) {
			if(errno == EINTR) {
				if(should_exit) {
					usbproxy_log(LL_INFO, "Appclication Event processing interrupted");
					break;
				}
			}
		} else if(cnt == 0) {
			usbhost_device_shutdown(0);
			application_update_event();
		} else {
			for(i=0; i<pollfds.count; i++) {
				if(pollfds.fds[i].revents && pollfds.owners[i] == FD_USB){
					application_layer_storage(pollfds.fds[i].fd, pollfds.fds[i].revents);
				}else if(pollfds.fds[i].revents && pollfds.owners[i] == FD_CLIENT) {
					application_layer_process(pollfds.fds[i].fd, pollfds.fds[i].revents);
				}
			}
		}
	}	
	fdlist_free(&pollfds);

	return 0;
}

USBHOST_API int usbhost_subscribe(void)
{
	int res;

	res = pthread_create(&(app_proxy.monitor), NULL, device_monitor, (void*)(&app_proxy.listenfd));
	if (res != 0) {
		usbproxy_log(LL_ERROR, "ERROR: Could not start device watcher thread!");
		return res;
	}
	return 0;
}

USBHOST_API int usbhost_unsubscribe(void)
{
	if (pthread_kill(app_proxy.monitor, 0) == 0) {
		pthread_cancel(app_proxy.monitor);
		pthread_join(app_proxy.monitor, NULL);
	}
	/*Close listen socket*/
	socket_shutdown(app_proxy.listenfd, SHUT_RDWR);

	return 0;
}

USBHOST_API void usbhost_application_init(void)
{
	usbproxy_log(LL_DEBUG, "application layer init");
	collection_init(&device_list);
	pthread_mutex_init(&app_mutex, NULL);
	/*Init Sorage list*/
	storage_init();
	/*Init Global Var*/
	memset(&app_proxy, 0, sizeof(app_proxy));
	app_proxy.device = &device_list;
	/*Open listen socket*/
	while((app_proxy.listenfd = usbhost_listen()) < 0){
		usbproxy_log(LL_ERROR, "Open Listen Socket Error[%d]..", app_proxy.listenfd);		
		usleep(500000);
		continue;
	}
	/*open storage socket*/
	while((app_proxy.storfd = storage_init_netlink_sock()) < 0){
		usbproxy_log(LL_ERROR, "Open Storage Socket Error..");		
		usleep(500000);
		continue;
	}
	usbproxy_log(LL_WARNING, "Application Layer Init Finish[ListenFD:%d StorageFD:%d]", 
				app_proxy.listenfd, app_proxy.storfd);		
}

USBHOST_API void* usbhost_application_run(void *args)
{
	/*Init*/
	usbhost_application_init();
	/*Get Device List until successful*/
	while(usbhost_get_device_list(-1) < 0){
		usbproxy_log(LL_DEBUG, "Get Device List Failed");
		usleep(800000);
	}
	/*Start Monitor Thread To inotify device add and remove*/
	if(usbhost_subscribe() != 0){
		usbproxy_log(LL_ERROR, "Start Subscribe Failed");
		return NULL;
	}
	/*INIT ReadAhead*/
	preread_storage_init();
	/*Start Main Loop Handle application Task*/
	application_layer_loop();

	/*Handle Exit Status*/
	usbhost_unsubscribe();
	usbhost_device_shutdown(1);
	usbproxy_log(LL_DEBUG, "Appalication Layer Quit");
	return 0;
}

