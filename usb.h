/*
 * usb.h
 *
 * Copyright (C) 2009 Hector Martin <hector@marcansoft.com>
 * Copyright (C) 2009 Nikias Bassen <nikias@gmx.li>
 * Copyright (C) 2009 Martin Szulecki <opensuse@sukimashita.com>
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

#ifndef USB_H
#define USB_H

#include <stdint.h>
#include <libusb-1.0/libusb.h>

#include "utils.h"

#define INTERFACE_CLASS 255
#define INTERFACE_SUBCLASS 254
#define INTERFACE_PROTOCOL 2

// libusb fragments packets larger than this (usbfs limitation)
// on input, this creates race conditions and other issues
#define USB_MRU 16384

// max transmission packet size
// libusb fragments these too, but doesn't send ZLPs so we're safe
// but we need to send a ZLP ourselves at the end (see usb-linux.c)
// we're using 3 * 16384 to optimize for the fragmentation
// this results in three URBs per full transfer, 32 USB packets each
// if there are ZLP issues this should make them show up easily too
#define USB_MTU (3 * 16384)

#define USB_PACKET_SIZE 512

#define VID_APPLE 0x5ac
#define PID_RANGE_LOW 0x1290
#define PID_RANGE_MAX 0x12af

/**********Android AOA***********/
/* Product IDs / Vendor IDs */
#define AOA_ACCESSORY_VID		0x18D1	/* Google */
#define AOA_ACCESSORY_PID		0x2D00	/* accessory */
#define AOA_ACCESSORY_ADB_PID		0x2D01	/* accessory + adb */
#define AOA_AUDIO_PID			0x2D02	/* audio */
#define AOA_AUDIO_ADB_PID		0x2D03	/* audio + adb */
#define AOA_ACCESSORY_AUDIO_PID		0x2D04	/* accessory + audio */
#define AOA_ACCESSORY_AUDIO_ADB_PID	0x2D05	/* accessory + audio + adb */
#define INTERFACE_CLASS_AOA 255
#define INTERFACE_SUBCLASS_AOA 255
/* Android Open Accessory protocol defines */
#define AOA_GET_PROTOCOL		51
#define AOA_SEND_IDENT			52
#define AOA_START_ACCESSORY		53
#define AOA_REGISTER_HID		54
#define AOA_UNREGISTER_HID		55
#define AOA_SET_HID_REPORT_DESC		56
#define AOA_SEND_HID_EVENT		57
#define AOA_AUDIO_SUPPORT		58
/* String IDs */
#define AOA_STRING_MAN_ID		0
#define AOA_STRING_MOD_ID		1
#define AOA_STRING_DSC_ID		2
#define AOA_STRING_VER_ID		3
#define AOA_STRING_URL_ID		4
#define AOA_STRING_SER_ID		5


#define AOA_TCP_PORT				0xFF

enum USB_TYPE{
	USB_STORAGE=0,
	USB_ANDROID=1,
	USB_IOS
};

struct usb_device {
	libusb_device_handle *dev;
	uint8_t bus, address;
	uint16_t vid, pid;
	char serial[256];
	int alive;
	int type;
	uint8_t interface, ep_in, ep_out;
	struct collection rx_xfers;
	struct collection tx_xfers;
	int wMaxPacketSize;
	uint64_t speed;
};

struct mux_connection;

int usb_init(void);
void usb_shutdown(void);
const char *usb_get_serial(struct usb_device *dev);
uint32_t usb_get_location(struct usb_device *dev);
uint16_t usb_get_pid(struct usb_device *dev);
uint64_t usb_get_speed(struct usb_device *dev);
void usb_get_fds(struct fdlist *list);
int usb_get_timeout(void);
int usb_send(struct usb_device *dev, const unsigned char *buf, int length);
int usb_discover(void);
void usb_autodiscover(int enable);
int usb_process(void);
int usb_process_timeout(int msec);
int usb_send_aoa(struct mux_connection *conn, const unsigned char *buf, int length);

#endif
