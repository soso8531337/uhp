/*
 * client.c
 *
 * Copyright (C) 2009 Hector Martin <hector@marcansoft.com>
 * Copyright (C) 2009 Nikias Bassen <nikias@gmx.li>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 or version 3.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE 1

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <fcntl.h>

#include "log.h"
#include "usb.h"
#include "client.h"
#include "device.h"

#define CMD_BUF_SIZE	0x10000
#define REPLY_BUF_SIZE	0x10000

static struct collection client_list;
pthread_mutex_t client_list_mutex;

/**
 * Receive raw data from the client socket.
 *
 * @param client Client to read from.
 * @param buffer Buffer to store incoming data.
 * @param len Max number of bytes to read.
 * @return Same as recv() system call. Number of bytes read; when < 0 errno will be set.
 */
int client_read(struct mux_client *client, void *buffer, uint32_t len)
{
	usbmuxd_log(LL_SPEW, "client_read fd %d buf %p len %d", client->fd, buffer, len);
	if(client->state != CLIENT_CONNECTED) {
		usbmuxd_log(LL_ERROR, "Attempted to read from client %d not in CONNECTED state", client->fd);
		return -1;
	}
	return recv(client->fd, buffer, len, 0);
}

/**
 * Send raw data to the client socket.
 *
 * @param client Client to send to.
 * @param buffer The data to send.
 * @param len Number of bytes to write.
 * @return Same as system call send(). Number of bytes written; when < 0 errno will be set.
 */
int client_write(struct mux_client *client, void *buffer, uint32_t len)
{
	int sret = -1;

	usbmuxd_log(LL_SPEW, "client_write fd %d buf %p len %d", client->fd, buffer, len);
	if(client->state != CLIENT_CONNECTED) {
		usbmuxd_log(LL_ERROR, "Attempted to write to client %d not in CONNECTED state", client->fd);
		return -1;
	}

	sret = send(client->fd, buffer, len, 0);
	if (sret < 0) {
		if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
			usbmuxd_log(LL_ERROR, "ERROR: client_write: fd %d not ready for writing", client->fd);
		} else {
			usbmuxd_log(LL_ERROR, "ERROR: client_write: sending to fd %d failed: %s", client->fd, strerror(errno));
		}
	}
	return sret;
}

/**
 * Set event mask to use for ppoll()ing the client socket.
 * Typically POLLOUT and/or POLLIN. Note that this overrides
 * the current mask, that is, it is not ORing the argument
 * into the current mask.
 *
 * @param client The client to set the event mask on.
 * @param events The event mask to sert.
 * @return 0 on success, -1 on error.
 */
int client_set_events(struct mux_client *client, short events)
{
	if((client->state != CLIENT_CONNECTED) && (client->state != CLIENT_CONNECTING2)) {
		usbmuxd_log(LL_ERROR, "client_set_events to client %d not in CONNECTED state", client->fd);
		return -1;
	}
	client->devents = events;
	if(client->state == CLIENT_CONNECTED)
		client->events = events;
	return 0;
}

/**
 * Wait for an inbound connection on the usbmuxd socket
 * and create a new mux_client instance for it, and store
 * the client in the client list.
 *
 * @param listenfd the socket fd to accept() on.
 * @return The connection fd for the client, or < 0 for error
 *   in which case errno will be set.
 */
int client_accept(int listenfd)
{
	struct sockaddr_un addr;
	int cfd;
	socklen_t len = sizeof(struct sockaddr_un);
	cfd = accept(listenfd, (struct sockaddr *)&addr, &len);
	if (cfd < 0) {
		usbmuxd_log(LL_ERROR, "accept() failed (%s)", strerror(errno));
		return cfd;
	}

	int flags = fcntl(cfd, F_GETFL, 0);
	if (flags < 0) {
		usbmuxd_log(LL_ERROR, "ERROR: Could not get socket flags!");
	} else {
		if (fcntl(cfd, F_SETFL, flags | O_NONBLOCK) < 0) {
			usbmuxd_log(LL_ERROR, "ERROR: Could not set socket to non-blocking mode");
		}
	}

	struct mux_client *client;
	client = malloc(sizeof(struct mux_client));
	memset(client, 0, sizeof(struct mux_client));

	client->fd = cfd;
	client->ob_buf = malloc(REPLY_BUF_SIZE);
	client->ob_size = 0;
	client->ob_capacity = REPLY_BUF_SIZE;
	client->ib_buf = malloc(CMD_BUF_SIZE);
	client->ib_size = 0;
	client->ib_capacity = CMD_BUF_SIZE;
	client->state = CLIENT_COMMAND;
	client->events = POLLIN;

	pthread_mutex_lock(&client_list_mutex);
	collection_add(&client_list, client);
	pthread_mutex_unlock(&client_list_mutex);

#ifdef SO_PEERCRED
	if (log_level >= LL_INFO) {
		struct ucred cr;
		len = sizeof(struct ucred);
		getsockopt(cfd, SOL_SOCKET, SO_PEERCRED, &cr, &len);

		if (getpid() == cr.pid) {
			usbmuxd_log(LL_INFO, "New client on fd %d (self)", client->fd);
		} else {
			usbmuxd_log(LL_INFO, "New client on fd %d (pid %d)", client->fd, cr.pid);
		}
	}
#else
	usbmuxd_log(LL_INFO, "New client on fd %d", client->fd);
#endif
	return client->fd;
}

void client_close(struct mux_client *client)
{
	usbmuxd_log(LL_INFO, "Disconnecting client fd %d", client->fd);
	if(client->state == CLIENT_CONNECTING1 || client->state == CLIENT_CONNECTING2) {
		usbmuxd_log(LL_INFO, "Client died mid-connect, aborting device %d connection", client->connect_device);
		client->state = CLIENT_DEAD;
		device_abort_connect(client->connect_device, client);
	}
	close(client->fd);
	if(client->ob_buf)
		free(client->ob_buf);
	if(client->ib_buf)
		free(client->ib_buf);
	pthread_mutex_lock(&client_list_mutex);
	collection_remove(&client_list, client);
	pthread_mutex_unlock(&client_list_mutex);
	free(client);
}

void client_get_fds(struct fdlist *list)
{
	pthread_mutex_lock(&client_list_mutex);
	FOREACH(struct mux_client *client, &client_list) {
		fdlist_add(list, FD_CLIENT, client->fd, client->events);
	} ENDFOREACH
	pthread_mutex_unlock(&client_list_mutex);
}

static int send_pkt(struct mux_client *client, uint32_t tag, enum usbmuxd_msgtype msg, void *payload, int payload_length)
{
	struct usbmuxd_header hdr;
	hdr.version = client->proto_version;
	hdr.length = sizeof(hdr) + payload_length;
	hdr.message = msg;
	hdr.tag = tag;
	usbmuxd_log(LL_DEBUG, "send_pkt fd %d tag %d msg %d payload_length %d", client->fd, tag, msg, payload_length);

	uint32_t available = client->ob_capacity - client->ob_size;
	/* the output buffer _should_ be large enough, but just in case */
	if(available < hdr.length) {
		unsigned char* new_buf;
		uint32_t new_size = ((client->ob_capacity + hdr.length + 4096) / 4096) * 4096;
		usbmuxd_log(LL_DEBUG, "%s: Enlarging client %d output buffer %d -> %d", __func__, client->fd, client->ob_capacity, new_size);
		new_buf = realloc(client->ob_buf, new_size);
		if (!new_buf) {
			usbmuxd_log(LL_FATAL, "%s: Failed to realloc.", __func__);
			return -1;
		}
		client->ob_buf = new_buf;
		client->ob_capacity = new_size;
	}
	memcpy(client->ob_buf + client->ob_size, &hdr, sizeof(hdr));
	if(payload && payload_length)
		memcpy(client->ob_buf + client->ob_size + sizeof(hdr), payload, payload_length);
	client->ob_size += hdr.length;
	client->events |= POLLOUT;
	return hdr.length;
}

static int send_result(struct mux_client *client, uint32_t tag, uint32_t result)
{
	int res = -1;
	/* binary packet */
	res = send_pkt(client, tag, MESSAGE_RESULT, &result, sizeof(uint32_t));
	
	return res;
}

int client_notify_connect(struct mux_client *client, enum usbmuxd_result result)
{
	usbmuxd_log(LL_SPEW, "client_notify_connect fd %d result %d", client->fd, result);
	if(client->state == CLIENT_DEAD)
		return -1;
	if(client->state != CLIENT_CONNECTING1) {
		usbmuxd_log(LL_ERROR, "client_notify_connect when client %d is not in CONNECTING1 state", client->fd);
		return -1;
	}
	if(send_result(client, client->connect_tag, result) < 0)
		return -1;
	if(result == RESULT_OK) {
		client->state = CLIENT_CONNECTING2;
		client->events = POLLOUT; // wait for the result packet to go through
		// no longer need this
		free(client->ib_buf);
		client->ib_buf = NULL;
	} else {
		client->state = CLIENT_COMMAND;
	}
	return 0;
}
static int notify_device_add(struct mux_client *client, struct device_info *dev)
{
	int res = -1;
	/* binary packet */
	struct usbmuxd_device_record dmsg;
	memset(&dmsg, 0, sizeof(dmsg));
	dmsg.device_id = dev->id;
	strncpy(dmsg.serial_number, dev->serial, 256);
	dmsg.serial_number[255] = 0;
	dmsg.location = dev->location;
	dmsg.product_id = dev->pid;
	dmsg.padding = USBHOST_DPADDING_MAGIC;
	res = send_pkt(client, 0, MESSAGE_DEVICE_ADD, &dmsg, sizeof(dmsg));

	return res;
}

static int notify_device_remove(struct mux_client *client, uint32_t device_id)
{
	int res = -1;
	/* binary packet */
	res = send_pkt(client, 0, MESSAGE_DEVICE_REMOVE, &device_id, sizeof(uint32_t));

	return res;
}

static int notify_device_remove_stor(struct mux_client *client, uint32_t location)
{
	int res = -1;
	/* binary packet */
	res = send_pkt(client, 0, MESSAGE_DEVICE_REMOVE_STOR, &location, sizeof(uint32_t));

	return res;
}

static int start_listen(struct mux_client *client)
{
	struct device_info *devs = NULL;
	struct device_info *dev;
	int count, i;

	client->state = CLIENT_LISTEN;

	count = device_get_list(0, &devs);
	dev = devs;
	for(i=0; devs && i < count; i++) {
		if(notify_device_add(client, dev++) < 0) {
			free(devs);
			return -1;
		}
	}
	if (devs)
		free(devs);

	return count;
}

static int send_device_list(struct mux_client *client, uint32_t tag)
{
	struct device_info *devs = NULL;
	struct device_info *dev;
	struct usbmuxd_device_record *dmsgs = NULL;
	struct usbmuxd_device_record *dmsg = NULL;
	
	int count, i, res;

	count = device_get_list(0, &devs);
	if(!count){
		res = send_pkt(client, tag, MESSAGE_DEVICE_LIST,
				NULL, 0);
		if (devs)
			free(devs);	
		return res;
	}
	dmsgs = calloc(1, count*sizeof(struct usbmuxd_device_record));
	if(!dmsgs){
		if (devs)
			free(devs);	
		return 0;
	}
	dev = devs;
	dmsg = dmsgs;
	for(i=0; devs && i < count; i++) {
		dmsg->device_id = dev->id;
		dmsg->product_id = dev->pid;
		memcpy(dmsg->serial_number, dev->serial, 256);
		dmsg->padding = USBHOST_DPADDING_MAGIC;
		dmsg->location = dev->location;
		dev++;
		dmsg++;
	}
	if (devs)
		free(devs);

	if(dmsgs){
		free(dmsgs);
	}
	res = send_pkt(client, tag, MESSAGE_DEVICE_LIST,
			dmsgs, count*sizeof(struct usbmuxd_device_record));
	
	return res;

}

static int client_command(struct mux_client *client, struct usbmuxd_header *hdr)
{
	int res, aoa = 0;
	usbmuxd_log(LL_DEBUG, "Client command in fd %d len %d ver %d msg %d tag %d", client->fd, hdr->length, hdr->version, hdr->message, hdr->tag);

	if(client->state != CLIENT_COMMAND) {
		usbmuxd_log(LL_ERROR, "Client %d command received in the wrong state", client->fd);
		if(send_result(client, hdr->tag, RESULT_BADCOMMAND) < 0)
			return -1;
		client_close(client);
		return -1;
	}

	if((hdr->version != 0) && (hdr->version != 1)) {
		usbmuxd_log(LL_INFO, "Client %d version mismatch: expected 0 or 1, got %d", client->fd, hdr->version);
		send_result(client, hdr->tag, RESULT_BADVERSION);
		return 0;
	}

	struct usbmuxd_connect_request *ch;

	switch(hdr->message) {
		case MESSAGE_PLIST:
			usbmuxd_log(LL_DEBUG, "Unsupport MESSAGE_PLIST Type");
			return 0;
		case MESSAGE_LISTEN:
			if(send_result(client, hdr->tag, 0) < 0)
				return -1;
			usbmuxd_log(LL_DEBUG, "Client %d now LISTENING", client->fd);
			return start_listen(client);
		case MESSAGE_CONNECT:
			ch = (void*)hdr;
			usbmuxd_log(LL_DEBUG, "Client %d connection request to device %d port %d", client->fd, ch->device_id, ntohs(ch->port));
			aoa = device_is_aoa(ch->device_id);
			if(aoa == -1){
				usbmuxd_log(LL_DEBUG, "Client %d connection request to device %d port %d But No Device", client->fd, ch->device_id, ntohs(ch->port));
				if(send_result(client, hdr->tag, RESULT_BADDEV) < 0)
					return -1;
			}else if(aoa == 1){
				/*Android AOA Device*/			
				client->connect_tag = hdr->tag;
				client->state = CLIENT_CONNECTING1;
			}
			res = device_start_connect(ch->device_id, ntohs(ch->port), client);
			if(res < 0) {
				client->connect_tag = 0;//set to default szitman
				if(send_result(client, hdr->tag, -res) < 0)
					return -1;
			}else{
				client->connect_tag = hdr->tag;
				client->connect_device = ch->device_id;
				if(!aoa){
					client->state = CLIENT_CONNECTING1;
				}
			}
			return 0;
		case MESSAGE_DEVICE_LIST:
			usbmuxd_log(LL_DEBUG, "Client %d Send DEVICE LIST Request[Tag=%u Len=%u]", 
				client->fd, hdr->tag, hdr->length);
			return send_device_list(client, hdr->tag);
		default:
			usbmuxd_log(LL_ERROR, "Client %d invalid command %d", client->fd, hdr->message);
			if(send_result(client, hdr->tag, RESULT_BADCOMMAND) < 0)
				return -1;
			return 0;
	}
	return -1;
}

static void process_send(struct mux_client *client)
{
	int res;
	if(!client->ob_size) {
		usbmuxd_log(LL_WARNING, "Client %d OUT process but nothing to send?", client->fd);
		client->events &= ~POLLOUT;
		return;
	}
	res = send(client->fd, client->ob_buf, client->ob_size, 0);
	if(res <= 0) {
		usbmuxd_log(LL_ERROR, "Send to client fd %d failed: %d %s", client->fd, res, strerror(errno));
		client_close(client);
		return;
	}
	if((uint32_t)res == client->ob_size) {
		client->ob_size = 0;
		client->events &= ~POLLOUT;
		if(client->state == CLIENT_CONNECTING2) {
			usbmuxd_log(LL_DEBUG, "Client %d switching to CONNECTED state", client->fd);
			client->state = CLIENT_CONNECTED;
			client->events = client->devents;
			// no longer need this
			free(client->ob_buf);
			client->ob_buf = NULL;
		}
	} else {
		client->ob_size -= res;
		memmove(client->ob_buf, client->ob_buf + res, client->ob_size);
	}
}
static void process_recv(struct mux_client *client)
{
	int res;
	int did_read = 0;
	if(client->ib_size < sizeof(struct usbmuxd_header)) {
		res = recv(client->fd, client->ib_buf + client->ib_size, sizeof(struct usbmuxd_header) - client->ib_size, 0);
		if(res <= 0) {
			if(res < 0)
				usbmuxd_log(LL_ERROR, "Receive from client fd %d failed: %s", client->fd, strerror(errno));
			else
				usbmuxd_log(LL_INFO, "Client %d connection closed", client->fd);
			client_close(client);
			return;
		}
		client->ib_size += res;
		if(client->ib_size < sizeof(struct usbmuxd_header))
			return;
		did_read = 1;
	}
	struct usbmuxd_header *hdr = (void*)client->ib_buf;
	if(hdr->length > client->ib_capacity) {
		usbmuxd_log(LL_INFO, "Client %d message is too long (%d bytes)", client->fd, hdr->length);
		client_close(client);
		return;
	}
	if(hdr->length < sizeof(struct usbmuxd_header)) {
		usbmuxd_log(LL_ERROR, "Client %d message is too short (%d bytes)", client->fd, hdr->length);
		client_close(client);
		return;
	}
	if(client->ib_size < hdr->length) {
		if(did_read)
			return; //maybe we would block, so defer to next loop
		res = recv(client->fd, client->ib_buf + client->ib_size, hdr->length - client->ib_size, 0);
		if(res < 0) {
			usbmuxd_log(LL_ERROR, "Receive from client fd %d failed: %s", client->fd, strerror(errno));
			client_close(client);
			return;
		} else if(res == 0) {
			usbmuxd_log(LL_INFO, "Client %d connection closed", client->fd);
			client_close(client);
			return;
		}
		client->ib_size += res;
		if(client->ib_size < hdr->length)
			return;
	}
	client_command(client, hdr);
	client->ib_size = 0;
}

void client_process(int fd, short events)
{
	struct mux_client *client = NULL;
	pthread_mutex_lock(&client_list_mutex);
	FOREACH(struct mux_client *lc, &client_list) {
		if(lc->fd == fd) {
			client = lc;
			break;
		}
	} ENDFOREACH
	pthread_mutex_unlock(&client_list_mutex);

	if(!client) {
		usbmuxd_log(LL_INFO, "client_process: fd %d not found in client list", fd);
		return;
	}

	if(client->state == CLIENT_CONNECTED) {
		usbmuxd_log(LL_SPEW, "client_process in CONNECTED state");
		device_client_process(client->connect_device, client, events);
	} else {
		if(events & POLLIN) {
			process_recv(client);
		} else if(events & POLLOUT) { //not both in case client died as part of process_recv
			process_send(client);
		}
	}

}

void client_device_add(struct device_info *dev)
{
	pthread_mutex_lock(&client_list_mutex);
	usbmuxd_log(LL_DEBUG, "client_device_add: id %d, location 0x%x, serial %s", dev->id, dev->location, dev->serial);
	device_set_visible(dev->id);
	FOREACH(struct mux_client *client, &client_list) {
		if(client->state == CLIENT_LISTEN)
			notify_device_add(client, dev);
	} ENDFOREACH
	pthread_mutex_unlock(&client_list_mutex);
}

void client_device_remove(int device_id)
{
	pthread_mutex_lock(&client_list_mutex);
	uint32_t id = device_id;
	usbmuxd_log(LL_DEBUG, "client_device_remove: id %d", device_id);
	FOREACH(struct mux_client *client, &client_list) {
		if(client->state == CLIENT_LISTEN)
			notify_device_remove(client, id);
	} ENDFOREACH
	pthread_mutex_unlock(&client_list_mutex);
}

void client_device_remove_stor(int location)
{
	pthread_mutex_lock(&client_list_mutex);
	uint32_t id = location;
	usbmuxd_log(LL_DEBUG, "Storage client_device_remove: Location %d", location);
	FOREACH(struct mux_client *client, &client_list) {
		if(client->state == CLIENT_LISTEN)
			notify_device_remove_stor(client, id);
	} ENDFOREACH
	pthread_mutex_unlock(&client_list_mutex);
}

void client_init(void)
{
	usbmuxd_log(LL_DEBUG, "client_init");
	collection_init(&client_list);
	pthread_mutex_init(&client_list_mutex, NULL);
}

void client_shutdown(void)
{
	usbmuxd_log(LL_DEBUG, "client_shutdown");
	FOREACH(struct mux_client *client, &client_list) {
		client_close(client);
	} ENDFOREACH
	pthread_mutex_destroy(&client_list_mutex);
	collection_free(&client_list);
}
