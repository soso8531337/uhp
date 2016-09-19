/*
 * client.h
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

#ifndef CLIENT_H
#define CLIENT_H

#include <stdint.h>
#include "usbmuxd-proto.h"

struct device_info;

enum client_state {
	CLIENT_COMMAND,		// waiting for command
	CLIENT_LISTEN,		// listening for devices
	CLIENT_CONNECTING1,	// issued connection request
	CLIENT_CONNECTING2,	// connection established, but waiting for response message to get sent
	CLIENT_CONNECTED,	// connected
	CLIENT_DEAD
};

struct mux_client {
	int fd;
	unsigned char *ob_buf;
	uint32_t ob_size;
	uint32_t ob_capacity;
	unsigned char *ib_buf;
	uint32_t ib_size;
	uint32_t ib_capacity;
	short events, devents;
	uint32_t connect_tag;
	int connect_device;
	enum client_state state;
	uint32_t proto_version;
};

int client_read(struct mux_client *client, void *buffer, uint32_t len);
int client_write(struct mux_client *client, void *buffer, uint32_t len);
int client_set_events(struct mux_client *client, short events);
void client_close(struct mux_client *client);
int client_notify_connect(struct mux_client *client, enum usbmuxd_result result);

void client_device_add(struct device_info *dev);
void client_device_remove(int device_id);
void client_device_remove_stor(int location);

int client_accept(int fd);
void client_get_fds(struct fdlist *list);
void client_process(int fd, short events);

void client_init(void);
void client_shutdown(void);

#endif
