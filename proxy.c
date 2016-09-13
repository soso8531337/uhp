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

#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef WIN32
  #define USBHOST_API __declspec( dllexport )
#else
  #ifdef HAVE_FVISIBILITY
    #define USBHOST_API __attribute__((visibility("default")))
  #else
    #define USBHOST_API
  #endif
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

#ifdef HAVE_INOTIFY
#include <sys/inotify.h>
#define EVENT_SIZE  (sizeof (struct inotify_event))
#define EVENT_BUF_LEN (1024 * (EVENT_SIZE + 16))
#define USBMUXD_DIRNAME "/var/run"
#define USBMUXD_SOCKET_NAME "usbmuxd"
#endif /* HAVE_INOTIFY */

#include <unistd.h>
#include <signal.h>

// usbmuxd protocol
#include "usbmuxd-proto.h"
// socket utility functions
#include "socket.h"
// misc utility functions
#include "utils.h"

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
	pthread_t monitor;
};

enum app_state{
	APP_NOCONNECT = 0,
	APP_CONNECTED,	// connected
	APP_DEAD
}
pthread_mutex_t device_list_mutex;
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
			usbmuxd_log(LL_ERROR, "Error receiving payload of size %d (bytes received: %d)", payload_size, rsize);
			free(payload_loc);
			return -EBADMSG;
		}
	}

	if (hdr.message == MESSAGE_PLIST) {
		usbmuxd_log(LL_DEBUG, "Receive MESSAGE_PLIST Message[IGNORE]");
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
		usbmuxd_log(LL_ERROR, "Error receiving packet: %d", recv_len);
		if (res)
			free(res);
		return recv_len;
	}
	if ((size_t)recv_len < sizeof(hdr)) {
		usbmuxd_log(LL_ERROR, "Received packet is too small");
		if (res)
			free(res);
		return -EPROTO;
	}

	if (hdr.message == MESSAGE_RESULT) {
		if (hdr.tag != tag) {
			usbmuxd_log(LL_ERROR, "WARNING: tag mismatch (%d != %d). Proceeding anyway.");
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
		usbmuxd_log(LL_ERROR, "MESSAGE_PLIST  Not Support !");
		*result = RESULT_OK;
		return 1;
	}else{
		if (!result_plist) {
			usbmuxd_log(LL_ERROR, "MESSAGE_PLIST result but result_plist pointer is NULL!");
			return -1;
		}
		*result_plist = res;
		*result = RESULT_OK;
		if(result_len){
			*result_len = hdr.length-sizeof(hdr);
		}
		return 1;
	}

	usbmuxd_log(LL_ERROR, "Unexpected message of type %d received!\n", hdr.message);
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
		usbmuxd_log(LL_ERROR, "ERROR: could not send packet header");
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
		usbmuxd_log(LL_ERROR, "ERROR: could not send whole packet (sent %d of %d)", sent, header.length);
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

static int usbhost_get_tag(void)
{
	if(use_tag == 0x7FFFFFFF){
		use_tag = 0;
	}
	return ++use_tag;
}

USBHOST_API int usbhost_get_device_list(int sockfd)
{
	int sfd;
	int tag, reslen = 0, curlen=0;
	uint32_t res;
	struct usbmuxd_device_record *dev;
	struct app_client *client = NULL;
	char *response = NULL;
	int dev_cnt = 0;

	if(sockfd < 0){
		sfd = connect_usbmuxd_socket();
		if (sfd < 0) {
			usbmuxd_log(LL_ERROR, "Error Opening Unix Socket");
			return sfd;
		}
	}else{
		sfd = sockfd;
	}
	
	tag = usbhost_get_tag();
	/*Send to usbhost daemon*/
	if(send_binary_devlist_packet(sfd, tag) < 0){
		usbmuxd_log(LL_ERROR, "Error Send device List Request");
		socket_close(sfd);
		return -1;
	}
	/*Decode result*/
	if ((usbmuxd_get_result(sfd, tag, &res, &response, &reslen) == 1) && (res == 0)) {
		while(curlen < reslen){
			dev = (struct usbmuxd_device_record *)(response+curlen);
			if(dev->padding != USBHOST_DPADDING_MAGIC){
				usbmuxd_log(LL_DEBUG, "Magic Mismatch-->%2f", dev->padding);
				continue;
			}
			client = calloc(1, sizeof(struct app_client));
			if(client == NULL){
				usbmuxd_log(LL_ERROR, "Calloc Memory Error");
				if(response){
					free(response);
				}				
				socket_close(sfd);
				return -1;
			}
			memcpy(&(client->devinfo), dev, sizeof(struct usbmuxd_device_record));
			client->connected = APP_NOCONNECT;
			client->commufd = -1;
			usbmuxd_log(LL_DEBUG, "Add Device:\nID:%uProductID:%u\nSerical:%s\nLocation:%u\nPadding:%u\n", 
					client->devinfo.device_id, client->devinfo.product_id, 
					client->devinfo.serial_number, client->devinfo.location, client->devinfo.padding);
			pthread_mutex_lock(&device_list_mutex);
			collection_add(&device_list, client);
			pthread_mutex_unlock(&device_list_mutex);			
			curlen += sizeof(struct usbmuxd_device_record);
		}
		if(response){
			free(response);
			response = NULL;
		}
	}else{
		usbmuxd_log(LL_DEBUG, "Get Result Error:%d", res);		
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
	pthread_mutex_lock(&device_list_mutex);
	FOREACH(struct app_client *dev, &device_list) {
		if(dev->devinfo.device_id == handle)){
			usbmuxd_log(LL_NOTICE, "Set device Dead %d", dev->devinfo.device_id);
			dev->connected = APP_DEAD;
			socket_close(dev->commufd);
			dev->commufd = -1;
			pthread_mutex_unlock(&device_list_mutex);
			return 1;
		}
	} ENDFOREACH
	pthread_mutex_unlock(&device_list_mutex);

	return 0;
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
		usbmuxd_log(LL_ERROR, "Error Opening Unix Socket");
		return -1;
	}
	tag = usbhost_get_tag();
	if(send_listen_packet(sfd, tag) <= 0) {
		usbmuxd_log(LL_ERROR, "ERROR: could not send listen packet");
		socket_close(sfd);
		return -1;
	}
	if((usbmuxd_get_result(sfd, tag, &res, NULL, NULL) == 1)&&(res != 0)){
		socket_close(sfd);
		usbmuxd_log(LL_ERROR, "ERROR: did not get OK but %d\n", res);
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
		usbmuxd_log(LL_ERROR, "Error Opening Unix Socket");
		return -1;
	}
	tag = usbhost_get_tag();

	if(send_connect_packet(sfd, tag, (uint32_t)handle, (uint16_t)port) <= 0) {
		usbmuxd_log(LL_ERROR, "Error Send Connect Request");
		socket_close(sfd);
		return -1;
	} 
	if (usbmuxd_get_result(sfd, tag, &res, NULL, NULL) == 1){
		if(res == RESULT_OK){
			usbmuxd_log(LL_DEBUG, "Connect Device %d success!", handle);			
			return sfd;
		}else if(res == RESULT_BADVERSION){
			usbmuxd_log(LL_DEBUG, "Connect Device %d Error: BAD Version!", handle);			
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
		usbmuxd_log(LL_ERROR, "Error %d when sending: %s", num_sent, strerror(num_sent));
		return -num_sent;
	} else if ((uint32_t)num_sent < len) {
		usbmuxd_log(LL_DEBUG, "Warning: Did not send enough (only %d of %d)", num_sent, len);
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
		usbmuxd_log(LL_ERROR, "Invalid packet received, payload is missing!");
		return -EBADMSG;
	}

	if (hdr.message == MESSAGE_DEVICE_ADD) {
		struct usbmuxd_device_record *dev = payload;
		struct app_client *client = NULL;
		client = calloc(1, sizeof(struct app_client));
		if(client == NULL){
			usbmuxd_log(LL_ERROR, "Calloc Memory Error");
			if(payload){
				free(payload);
			}				
			return -2;
		}
		memcpy(&(client->devinfo), dev, sizeof(struct usbmuxd_device_record));
		client->connected = APP_NOCONNECT;
		client->commufd = -1;
		usbmuxd_log(LL_DEBUG, "Add Device:\nID:%uProductID:%u\nSerical:%s\nLocation:%u\nPadding:%u\n", 
				client->devinfo.device_id, client->devinfo.product_id, 
				client->devinfo.serial_number, client->devinfo.location, client->devinfo.padding);
		pthread_mutex_lock(&device_list_mutex);
		collection_add(&device_list, client);
		pthread_mutex_unlock(&device_list_mutex);
		generate_event(callback, devinfo, UE_DEVICE_ADD, user_data);
	} else if (hdr.message == MESSAGE_DEVICE_REMOVE) {
		uint32_t handle;

		memcpy(&handle, payload, sizeof(uint32_t));
		usbhost_dead_device_by_udid(handle);
	}else if(hdr.length > 0) {
		usbmuxd_log(LL_DEBUG, "Unexpected message type %d length %d received!",hdr.message, hdr.length);
	}
	if (payload) {
		free(payload);
	}
	return 0;
}

static void device_monitor(void* arg)
{
	int res;
	
	while(1){
		if(app_proxy.listenfd < 0){
			usbmuxd_log(LL_DEBUG, "Open Listen Socket..");
			if((app_proxy.listenfd = usbhost_listen()) < 0){
				usbmuxd_log(LL_ERROR, "Open Listen Socket Error[%d]..", app_proxy.listenfd);
				usleep(500000);
				continue;
			}
		}
		/*Handle Event*/
		res = monitor_event(app_proxy.listenfd);
		if(res == -1){
			usbmuxd_log(LL_ERROR, "Receive Listen Package Error Close socket..");
			socket_close(app_proxy.listenfd);
			app_proxy.listenfd = -1;
			continue;
		}
	}

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
	if(conn->ob_size < conn->ob_capacity)
		conn->events |= POLLOUT;
	else
		conn->events &= ~POLLOUT;

	if(conn->ib_size < conn->ib_capacity)
		conn->events |= POLLIN;
	else
		conn->events &= ~POLLIN;

	usbmuxd_log(LL_SPEW, "update_connection: sendable %d, events %d, flags %d", conn->sendable, conn->events, conn->flags);
}

USBHOST_API int usbhost_subscribe(void)
{
	int res;

	res = pthread_create(&(app_proxy.monitor), NULL, device_monitor, NULL);
	if (res != 0) {
		usbmuxd_log(LL_ERROR, "ERROR: Could not start device watcher thread!");
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
	usbmuxd_log(LL_DEBUG, "application layer init");
	collection_init(&device_list);
	pthread_mutex_init(&device_list_mutex, NULL);
	/*Init Global Var*/
	memset(&app_proxy, 0, sizeof(app_proxy));
	app_proxy.device = &device_list;
	app_proxy.listenfd = -1;
}

USBHOST_API void usbhost_application_run(void)
{

	usbhost_application_init();
	
}

