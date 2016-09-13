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
};

pthread_mutex_t device_list_mutex;
static struct collection device_list;
static usbmuxd_event_cb_t event_cb = NULL;

static volatile int use_tag = 0;

/**
 * Finds a device info record by its handle.
 * if the record is not found, NULL is returned.
 */
static usbmuxd_device_info_t *devices_find(uint32_t handle)
{
	FOREACH(usbmuxd_device_info_t *dev, &devices) {
		if (dev && dev->handle == handle) {
			return dev;
		}
	} ENDFOREACH
	return NULL;
}

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

static struct usbmuxd_device_record* device_record_from_plist(plist_t props)
{
	struct usbmuxd_device_record* dev = NULL;
	plist_t n = NULL;
	uint64_t val = 0;
	char *strval = NULL;

	dev = (struct usbmuxd_device_record*)malloc(sizeof(struct usbmuxd_device_record));
	if (!dev)
		return NULL;
	memset(dev, 0, sizeof(struct usbmuxd_device_record));

	n = plist_dict_get_item(props, "DeviceID");
	if (n && plist_get_node_type(n) == PLIST_UINT) {
		plist_get_uint_val(n, &val);
		dev->device_id = (uint32_t)val;
	}

	n = plist_dict_get_item(props, "ProductID");
	if (n && plist_get_node_type(n) == PLIST_UINT) {
		plist_get_uint_val(n, &val);
		dev->product_id = (uint32_t)val;
	}

	n = plist_dict_get_item(props, "SerialNumber");
	if (n && plist_get_node_type(n) == PLIST_STRING) {
		plist_get_string_val(n, &strval);
		if (strval) {
			strncpy(dev->serial_number, strval, 255);
			free(strval);
		}
	}
	n = plist_dict_get_item(props, "LocationID");
	if (n && plist_get_node_type(n) == PLIST_UINT) {
		plist_get_uint_val(n, &val);
		dev->location = (uint32_t)val;
	}

	return dev;
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

static plist_t create_plist_message(const char* message_type)
{
	plist_t plist = plist_new_dict();
	plist_dict_set_item(plist, "BundleID", plist_new_string(PLIST_BUNDLE_ID));
	plist_dict_set_item(plist, "ClientVersionString", plist_new_string(PLIST_CLIENT_VERSION_STRING));
	plist_dict_set_item(plist, "MessageType", plist_new_string(message_type));
	plist_dict_set_item(plist, "ProgName", plist_new_string(PLIST_PROGNAME));	
	plist_dict_set_item(plist, "kLibUSBMuxVersion", plist_new_uint(PLIST_LIBUSBMUX_VERSION));
	return plist;
}

static int send_listen_packet(int sfd, uint32_t tag)
{
	int res = 0;
	if (proto_version == 1) {
		/* construct message plist */
		plist_t plist = create_plist_message("Listen");

		res = send_plist_packet(sfd, tag, plist);
		plist_free(plist);
	} else {
		/* binary packet */
		res = send_packet(sfd, MESSAGE_LISTEN, tag, NULL, 0);
	}
	return res;
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

static int send_read_buid_packet(int sfd, uint32_t tag)
{
	int res = -1;

	/* construct message plist */
	plist_t plist = create_plist_message("ReadBUID");

	res = send_plist_packet(sfd, tag, plist);
	plist_free(plist);

	return res;
}

static int send_pair_record_packet(int sfd, uint32_t tag, const char* msgtype, const char* pair_record_id, plist_t data)
{
	int res = -1;

	/* construct message plist */
	plist_t plist = create_plist_message(msgtype);
	plist_dict_set_item(plist, "PairRecordID", plist_new_string(pair_record_id));
	if (data) {
		plist_dict_set_item(plist, "PairRecordData", plist_copy(data));
	}
	
	res = send_plist_packet(sfd, tag, plist);
	plist_free(plist);

	return res;
}

/**
 * Generates an event, i.e. calls the callback function.
 * A reference to a populated usbmuxd_event_t with information about the event
 * and the corresponding device will be passed to the callback function.
 */
static void generate_event(usbmuxd_event_cb_t callback, const usbmuxd_device_info_t *dev, enum usbmuxd_event_type event, void *user_data)
{
	usbmuxd_event_t ev;

	if (!callback || !dev) {
		return;
	}

	ev.event = event;
	memcpy(&ev.device, dev, sizeof(usbmuxd_device_info_t));

	callback(&ev, user_data);
}

static int usbmuxd_listen_poll()
{
	int sfd;

	sfd = connect_usbmuxd_socket();
	if (sfd < 0) {
		while (event_cb) {
			if ((sfd = connect_usbmuxd_socket()) >= 0) {
				break;
			}
			sleep(1);
		}
	}

	return sfd;
}

#ifdef HAVE_INOTIFY
static int use_inotify = 1;

static int usbmuxd_listen_inotify()
{
	int inot_fd;
	int watch_d;
	int sfd;

	if (!use_inotify) {
		return -2;
	}

	sfd = connect_usbmuxd_socket();
	if (sfd >= 0)
		return sfd;

	sfd = -1;
	inot_fd = inotify_init ();
	if (inot_fd < 0) {
		DEBUG(1, "%s: Failed to setup inotify\n", __func__);
		return -2;
	}

	/* inotify is setup, listen for events that concern us */
	watch_d = inotify_add_watch (inot_fd, USBMUXD_DIRNAME, IN_CREATE);
	if (watch_d < 0) {
		DEBUG(1, "%s: Failed to setup watch descriptor for socket dir\n", __func__);
		close (inot_fd);
		return -2;
	}

	while (1) {
		ssize_t len, i;
		char buff[EVENT_BUF_LEN] = {0};

		i = 0;
		len = read (inot_fd, buff, EVENT_BUF_LEN -1);
		if (len < 0)
			goto end;
		while (i < len) {
			struct inotify_event *pevent = (struct inotify_event *) & buff[i];

			/* check that it's ours */
			if (pevent->mask & IN_CREATE &&
			    pevent->len &&
			    pevent->name[0] != 0 &&
			    strcmp(pevent->name, USBMUXD_SOCKET_NAME) == 0) {
				/* retry if usbmuxd isn't ready yet */
				int retry = 10;
				while (--retry >= 0) {
					if ((sfd = connect_usbmuxd_socket ()) >= 0) {
						break;
					}
					sleep(1);
				}
				goto end;
			}
			i += EVENT_SIZE + pevent->len;
		}
	}

end:
	inotify_rm_watch(inot_fd, watch_d);
	close(inot_fd);

	return sfd;
}
#endif /* HAVE_INOTIFY */

/**
 * Tries to connect to usbmuxd and wait if it is not running.
 */
static int usbmuxd_listen()
{
	int sfd;
	uint32_t res = -1;
	int tag;

retry:

#ifdef HAVE_INOTIFY
	sfd = usbmuxd_listen_inotify();
	if (sfd == -2)
		sfd = usbmuxd_listen_poll();
#else
	sfd = usbmuxd_listen_poll();
#endif

	if (sfd < 0) {
		DEBUG(1, "%s: ERROR: usbmuxd was supposed to be running here...\n", __func__);
		return sfd;
	}

	tag = ++use_tag;
	if (send_listen_packet(sfd, tag) <= 0) {
		DEBUG(1, "%s: ERROR: could not send listen packet\n", __func__);
		socket_close(sfd);
		return -1;
	}
	if ((usbmuxd_get_result(sfd, tag, &res, NULL) == 1) && (res != 0)) {
		socket_close(sfd);
		if ((res == RESULT_BADVERSION) && (proto_version == 1)) {
			proto_version = 0;
			goto retry;
		}
		DEBUG(1, "%s: ERROR: did not get OK but %d\n", __func__, res);
		return -1;
	}
	return sfd;
}

/**
 * Waits for an event to occur, i.e. a packet coming from usbmuxd.
 * Calls generate_event to pass the event via callback to the client program.
 */
static int get_next_event(int sfd, usbmuxd_event_cb_t callback, void *user_data)
{
	struct usbmuxd_header hdr;
	void *payload = NULL;

	/* block until we receive something */
	if (receive_packet(sfd, &hdr, &payload, 0) < 0) {
		// when then usbmuxd connection fails,
		// generate remove events for every device that
		// is still present so applications know about it
		FOREACH(usbmuxd_device_info_t *dev, &devices) {
			generate_event(callback, dev, UE_DEVICE_REMOVE, user_data);
			collection_remove(&devices, dev);
			free(dev);
		} ENDFOREACH
		return -EIO;
	}

	if ((hdr.length > sizeof(hdr)) && !payload) {
		DEBUG(1, "%s: Invalid packet received, payload is missing!\n", __func__);
		return -EBADMSG;
	}

	if (hdr.message == MESSAGE_DEVICE_ADD) {
		struct usbmuxd_device_record *dev = payload;
		usbmuxd_device_info_t *devinfo = (usbmuxd_device_info_t*)malloc(sizeof(usbmuxd_device_info_t));
		if (!devinfo) {
			DEBUG(1, "%s: Out of memory!\n", __func__);
			free(payload);
			return -1;
		}

		devinfo->handle = dev->device_id;
		devinfo->product_id = dev->product_id;
		memset(devinfo->udid, '\0', sizeof(devinfo->udid));
		memcpy(devinfo->udid, dev->serial_number, sizeof(devinfo->udid));

		if (strcasecmp(devinfo->udid, "ffffffffffffffffffffffffffffffffffffffff") == 0) {
			sprintf(devinfo->udid + 32, "%08x", devinfo->handle);
		}

		collection_add(&devices, devinfo);
		generate_event(callback, devinfo, UE_DEVICE_ADD, user_data);
	} else if (hdr.message == MESSAGE_DEVICE_REMOVE) {
		uint32_t handle;
		usbmuxd_device_info_t *devinfo;

		memcpy(&handle, payload, sizeof(uint32_t));

		devinfo = devices_find(handle);
		if (!devinfo) {
			DEBUG(1, "%s: WARNING: got device remove message for handle %d, but couldn't find the corresponding handle in the device list. This event will be ignored.\n", __func__, handle);
		} else {
			generate_event(callback, devinfo, UE_DEVICE_REMOVE, user_data);
			collection_remove(&devices, devinfo);
			free(devinfo);
		}
	} else if (hdr.length > 0) {
		DEBUG(1, "%s: Unexpected message type %d length %d received!\n", __func__, hdr.message, hdr.length);
	}
	if (payload) {
		free(payload);
	}
	return 0;
}

static void device_monitor_cleanup(void* data)
{
	FOREACH(usbmuxd_device_info_t *dev, &devices) {
		collection_remove(&devices, dev);
		free(dev);
	} ENDFOREACH
	collection_free(&devices);

	socket_close(listenfd);
	listenfd = -1;
}

/**
 * Device Monitor thread function.
 *
 * This function sets up a connection to usbmuxd
 */
static void *device_monitor(void *data)
{
	collection_init(&devices);

#ifndef WIN32
	pthread_cleanup_push(device_monitor_cleanup, NULL);
#endif
	while (event_cb) {

		listenfd = usbmuxd_listen();
		if (listenfd < 0) {
			continue;
		}

		while (event_cb) {
			int res = get_next_event(listenfd, event_cb, data);
			if (res < 0) {
			    break;
			}
		}
	}

#ifndef WIN32
	pthread_cleanup_pop(1);
#else
	device_monitor_cleanup(NULL);
#endif
	return NULL;
}

USBMUXD_API int usbmuxd_subscribe(usbmuxd_event_cb_t callback, void *user_data)
{
	int res;

	if (!callback) {
		return -EINVAL;
	}
	event_cb = callback;

#ifdef WIN32
	res = 0;
	devmon = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)device_monitor, user_data, 0, NULL);
	if (devmon == NULL) {
		res = GetLastError();
	}
#else
	res = pthread_create(&devmon, NULL, device_monitor, user_data);
#endif
	if (res != 0) {
		DEBUG(1, "%s: ERROR: Could not start device watcher thread!\n", __func__);
		return res;
	}
	return 0;
}

USBMUXD_API int usbmuxd_unsubscribe()
{
	event_cb = NULL;

	socket_shutdown(listenfd, SHUT_RDWR);

#ifdef WIN32
	if (devmon != NULL) {
		WaitForSingleObject(devmon, INFINITE);
	}
#else
	if (pthread_kill(devmon, 0) == 0) {
		pthread_cancel(devmon);
		pthread_join(devmon, NULL);
	}
#endif

	return 0;
}

static usbmuxd_device_info_t *device_info_from_device_record(struct usbmuxd_device_record *dev)
{
	if (!dev) {
		return NULL;
	}
	usbmuxd_device_info_t *devinfo = (usbmuxd_device_info_t*)malloc(sizeof(usbmuxd_device_info_t));
	if (!devinfo) {
		DEBUG(1, "%s: Out of memory!\n", __func__);
		return NULL;
	}

	devinfo->handle = dev->device_id;
	devinfo->product_id = dev->product_id;
	memset(devinfo->udid, '\0', sizeof(devinfo->udid));
	memcpy(devinfo->udid, dev->serial_number, sizeof(devinfo->udid));

	if (strcasecmp(devinfo->udid, "ffffffffffffffffffffffffffffffffffffffff") == 0) {
		sprintf(devinfo->udid + 32, "%08x", devinfo->handle);
	}

	return devinfo;
}

static int usbhost_get_tag()
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
			client->connected = 0;			
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

USBHOST_API int usbhost_get_device_by_udid(const char *udid)
{
	if(!udid){
		return 0;
	}
	pthread_mutex_lock(&device_list_mutex);
	FOREACH(struct app_client *dev, &device_list) {
		if(!strcmp(dev->devinfo.serial_number, udid)){
			usbmuxd_log(LL_NOTICE, "Found device %d", dev->devinfo.device_id);
			pthread_mutex_unlock(&device_list_mutex);
			return 1;
		}
	} ENDFOREACH
	pthread_mutex_unlock(&device_list_mutex);

	return 0;
}

USBHOST_API int usbhost_connect(const int handle, const unsigned short port)
{
	int sfd;
	int tag;
	int connected = 0;
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

USBHOST_API int usbhost_send(int sfd, const char *data, uint32_t len, uint32_t *sent_bytes)
{
	int num_sent;

	if (sfd < 0) {
		return -EINVAL;
	}
	
	num_sent = socket_send(sfd, (void*)data, len);
	if (num_sent < 0) {
		*sent_bytes = 0;
		num_sent = errno;
		DEBUG(1, "%s: Error %d when sending: %s\n", __func__, num_sent, strerror(num_sent));
		return -num_sent;
	} else if ((uint32_t)num_sent < len) {
		DEBUG(1, "%s: Warning: Did not send enough (only %d of %d)\n", __func__, num_sent, len);
	}

	*sent_bytes = num_sent;

	return 0;
}

USBHOST_API int usbmuxd_recv_timeout(int sfd, char *data, uint32_t len, uint32_t *recv_bytes, unsigned int timeout)
{
	int num_recv = socket_receive_timeout(sfd, (void*)data, len, 0, timeout);
	if (num_recv < 0) {
		*recv_bytes = 0;
		return num_recv;
	}

	*recv_bytes = num_recv;

	return 0;
}

USBHOST_API int usbmuxd_recv(int sfd, char *data, uint32_t len, uint32_t *recv_bytes)
{
	return usbmuxd_recv_timeout(sfd, data, len, recv_bytes, 5000);
}


USBHOST_API void usbhost_application_init(void)
{
	usbmuxd_log(LL_DEBUG, "application layer init");
	collection_init(&device_list);
	pthread_mutex_init(&device_list_mutex, NULL);
	next_device_id = 1;
}

