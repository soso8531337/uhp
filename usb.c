/*
 * usb.c
 *
 * Copyright (C) 2009 Hector Martin <hector@marcansoft.com>
 * Copyright (C) 2009 Nikias Bassen <nikias@gmx.li>
 * Copyright (C) 2009 Martin Szulecki <opensuse@sukimashita.com>
 * Copyright (C) 2014 Mikkel Kamstrup Erlandsen <mikkel.kamstrup@xamarin.com>
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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "usb.h"
#include "log.h"
#include "device.h"
#include "utils.h"

#if (defined(LIBUSB_API_VERSION) && (LIBUSB_API_VERSION >= 0x01000102)) || (defined(LIBUSBX_API_VERSION) && (LIBUSBX_API_VERSION >= 0x01000102))
#define HAVE_LIBUSB_HOTPLUG_API 1
#endif

// interval for device connection/disconnection polling, in milliseconds
// we need this because there is currently no asynchronous device discovery mechanism in libusb
#define DEVICE_POLL_TIME 1000

// Number of parallel bulk transfers we have running for reading data from the device.
// Older versions of usbmuxd kept only 1, which leads to a mostly dormant USB port.
// 3 seems to be an all round sensible number - giving better read perf than
// Apples usbmuxd, at least.
#define NUM_RX_LOOPS 3
/*
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
*/
struct accessory_t {
	uint32_t aoa_version;
	uint16_t vid;
	uint16_t pid;
	char *device;
	char *manufacturer;
	char *model;
	char *description;
	char *version;
	char *url;
	char *serial;
};
static struct accessory_t acc_default = {
	.manufacturer = "i4season",
	.model = "U-Storage",
	.description = "U-Storage",
	.version = "1.0",
	.url = "https://www.simicloud.com/download/index.html",
	.serial = "0000000012345678",
};


static struct collection device_list;

static struct timeval next_dev_poll_time;

static int devlist_failures;
static int device_polling;
static int device_hotplug = 1;

/*
*if device is android device, we must invoke this function firstly, if not, tx_callback_aoa function will segment fault
*/
static void usb_predisconnect_aoa(struct usb_device *dev){
	if(!dev->dev) {
		return;
	}

	// kill the rx xfer and tx xfers and try to make sure the callbacks
	// get called before we free the device
	FOREACH(struct libusb_transfer *xfer, &dev->rx_xfers) {
		usbmuxd_log(LL_DEBUG, "usb_disconnect: cancelling RX xfer %p", xfer);
		libusb_cancel_transfer(xfer);
	} ENDFOREACH

	FOREACH(struct libusb_transfer *xfer, &dev->tx_xfers) {
		usbmuxd_log(LL_DEBUG, "usb_disconnect: cancelling TX xfer %p", xfer);
		libusb_cancel_transfer(xfer);
	} ENDFOREACH

	// Busy-wait until all xfers are closed
	while(collection_count(&dev->rx_xfers) || collection_count(&dev->tx_xfers)) {
		struct timeval tv;
		int res;

		tv.tv_sec = 0;
		tv.tv_usec = 1000;
		if((res = libusb_handle_events_timeout(NULL, &tv)) < 0) {
			usbmuxd_log(LL_ERROR, "libusb_handle_events_timeout for usb_disconnect failed: %d", res);
			break;
		}
	}
}

static void usb_disconnect(struct usb_device *dev)
{
	if(!dev->dev) {
		return;
	}

	// kill the rx xfer and tx xfers and try to make sure the callbacks
	// get called before we free the device
	FOREACH(struct libusb_transfer *xfer, &dev->rx_xfers) {
		usbmuxd_log(LL_DEBUG, "usb_disconnect: cancelling RX xfer %p", xfer);
		libusb_cancel_transfer(xfer);
	} ENDFOREACH

	FOREACH(struct libusb_transfer *xfer, &dev->tx_xfers) {
		usbmuxd_log(LL_DEBUG, "usb_disconnect: cancelling TX xfer %p", xfer);
		libusb_cancel_transfer(xfer);
	} ENDFOREACH

	// Busy-wait until all xfers are closed
	while(collection_count(&dev->rx_xfers) || collection_count(&dev->tx_xfers)) {
		struct timeval tv;
		int res;

		tv.tv_sec = 0;
		tv.tv_usec = 1000;
		if((res = libusb_handle_events_timeout(NULL, &tv)) < 0) {
			usbmuxd_log(LL_ERROR, "libusb_handle_events_timeout for usb_disconnect failed: %d", res);
			break;
		}
	}

	collection_free(&dev->tx_xfers);
	collection_free(&dev->rx_xfers);
	libusb_release_interface(dev->dev, dev->interface);
	libusb_close(dev->dev);
	dev->dev = NULL;
	collection_remove(&device_list, dev);
	free(dev);
}

static void reap_dead_devices(void) {
	FOREACH(struct usb_device *usbdev, &device_list) {
		if(!usbdev->alive) {
			/*judge usbdevice type, if android we invoke usb_predisconnect_aoa*/
			if(usbdev->type == USB_ANDROID){
				usb_predisconnect_aoa(usbdev);
				usbmuxd_log(LL_SPEW, "Android Device PreDisconnect Handle Finish");
			}
			device_remove(usbdev);
			usb_disconnect(usbdev);
		}
	} ENDFOREACH
}

// Callback from write operation
static void tx_callback(struct libusb_transfer *xfer)
{
	struct usb_device *dev = xfer->user_data;
	usbmuxd_log(LL_SPEW, "TX callback dev %d-%d len %d -> %d status %d", dev->bus, dev->address, xfer->length, xfer->actual_length, xfer->status);
	if(xfer->status != LIBUSB_TRANSFER_COMPLETED) {
		switch(xfer->status) {
			case LIBUSB_TRANSFER_COMPLETED: //shut up compiler
			case LIBUSB_TRANSFER_ERROR:
				// funny, this happens when we disconnect the device while waiting for a transfer, sometimes
				usbmuxd_log(LL_INFO, "Device %d-%d TX aborted due to error or disconnect", dev->bus, dev->address);
				break;
			case LIBUSB_TRANSFER_TIMED_OUT:
				usbmuxd_log(LL_ERROR, "TX transfer timed out for device %d-%d", dev->bus, dev->address);
				break;
			case LIBUSB_TRANSFER_CANCELLED:
				usbmuxd_log(LL_DEBUG, "Device %d-%d TX transfer cancelled", dev->bus, dev->address);
				break;
			case LIBUSB_TRANSFER_STALL:
				usbmuxd_log(LL_ERROR, "TX transfer stalled for device %d-%d", dev->bus, dev->address);
				break;
			case LIBUSB_TRANSFER_NO_DEVICE:
				// other times, this happens, and also even when we abort the transfer after device removal
				usbmuxd_log(LL_INFO, "Device %d-%d TX aborted due to disconnect", dev->bus, dev->address);
				break;
			case LIBUSB_TRANSFER_OVERFLOW:
				usbmuxd_log(LL_ERROR, "TX transfer overflow for device %d-%d", dev->bus, dev->address);
				break;
			// and nothing happens (this never gets called) if the device is freed after a disconnect! (bad)
			default:
				// this should never be reached.
				break;
		}
		// we can't usb_disconnect here due to a deadlock, so instead mark it as dead and reap it after processing events
		// we'll do device_remove there too
		dev->alive = 0;
	}
	if(xfer->buffer)
		free(xfer->buffer);
	collection_remove(&dev->tx_xfers, xfer);
	libusb_free_transfer(xfer);
}

static void tx_callback_aoa(struct libusb_transfer *xfer)
{
	struct mux_connection *conn= (struct mux_connection *)xfer->user_data;
	struct usb_device *dev = conn->dev->usbdev;
	usbmuxd_log(LL_SPEW, "TX AOA callback dev %d-%d len %d -> %d status %d", 
			dev->bus, dev->address, xfer->length, xfer->actual_length, xfer->status);
	if(xfer->status == LIBUSB_TRANSFER_COMPLETED){		
		usbmuxd_log(LL_SPEW, "Update AOA rx-ack:%d -> %d", 
				conn->rx_ack, conn->rx_ack+xfer->actual_length);		
		conn->rx_ack += xfer->actual_length;
	}else{
		switch(xfer->status) {
			case LIBUSB_TRANSFER_COMPLETED: //shut up compiler
			case LIBUSB_TRANSFER_ERROR:
				// funny, this happens when we disconnect the device while waiting for a transfer, sometimes
				usbmuxd_log(LL_INFO, "Device %d-%d TX aborted due to error or disconnect", dev->bus, dev->address);
				break;
			case LIBUSB_TRANSFER_TIMED_OUT:
				usbmuxd_log(LL_ERROR, "TX transfer timed out for device %d-%d", dev->bus, dev->address);
				break;
			case LIBUSB_TRANSFER_CANCELLED:
				usbmuxd_log(LL_DEBUG, "Device %d-%d TX transfer cancelled", dev->bus, dev->address);
				break;
			case LIBUSB_TRANSFER_STALL:
				usbmuxd_log(LL_ERROR, "TX transfer stalled for device %d-%d", dev->bus, dev->address);
				break;
			case LIBUSB_TRANSFER_NO_DEVICE:
				// other times, this happens, and also even when we abort the transfer after device removal
				usbmuxd_log(LL_INFO, "Device %d-%d TX aborted due to disconnect", dev->bus, dev->address);
				break;
			case LIBUSB_TRANSFER_OVERFLOW:
				usbmuxd_log(LL_ERROR, "TX transfer overflow for device %d-%d", dev->bus, dev->address);
				break;
			// and nothing happens (this never gets called) if the device is freed after a disconnect! (bad)
			default:
				// this should never be reached.
				break;
		}
		// we can't usb_disconnect here due to a deadlock, so instead mark it as dead and reap it after processing events
		// we'll do device_remove there too
		dev->alive = 0;
	}
	if(xfer->buffer)
		free(xfer->buffer);
	collection_remove(&dev->tx_xfers, xfer);
	libusb_free_transfer(xfer);
}


int usb_send(struct usb_device *dev, const unsigned char *buf, int length)
{
	int res;
	struct libusb_transfer *xfer = libusb_alloc_transfer(0);
	libusb_fill_bulk_transfer(xfer, dev->dev, dev->ep_out, (void*)buf, length, tx_callback, dev, 0);
	if((res = libusb_submit_transfer(xfer)) < 0) {
		usbmuxd_log(LL_ERROR, "Failed to submit TX transfer %p len %d to device %d-%d: %d", buf, length, dev->bus, dev->address, res);
		libusb_free_transfer(xfer);
		return res;
	}
	collection_add(&dev->tx_xfers, xfer);
	if (length % dev->wMaxPacketSize == 0) {
		usbmuxd_log(LL_DEBUG, "Send ZLP");
		// Send Zero Length Packet
		xfer = libusb_alloc_transfer(0);
		void *buffer = malloc(1);
		libusb_fill_bulk_transfer(xfer, dev->dev, dev->ep_out, buffer, 0, tx_callback, dev, 0);
		if((res = libusb_submit_transfer(xfer)) < 0) {
			usbmuxd_log(LL_ERROR, "Failed to submit TX ZLP transfer to device %d-%d: %d", dev->bus, dev->address, res);
			libusb_free_transfer(xfer);
			return res;
		}
		collection_add(&dev->tx_xfers, xfer);
	}
	return 0;
}

int usb_send_aoa(struct mux_connection *conn, const unsigned char *buf, int length)
{
	int res;
	
	struct usb_device *dev = conn->dev->usbdev;
	struct libusb_transfer *xfer = libusb_alloc_transfer(0);
	libusb_fill_bulk_transfer(xfer, dev->dev, dev->ep_out, (void*)buf, length, tx_callback_aoa, conn, 0);
	if((res = libusb_submit_transfer(xfer)) < 0) {
		usbmuxd_log(LL_ERROR, "Failed to submit TX transfer %p len %d to device %d-%d: %d", buf, length, dev->bus, dev->address, res);
		libusb_free_transfer(xfer);
		return res;
	}
	collection_add(&dev->tx_xfers, xfer);
	if (length % dev->wMaxPacketSize == 0) {
		usbmuxd_log(LL_DEBUG, "Send ZLP");
		// Send Zero Length Packet
		xfer = libusb_alloc_transfer(0);
		void *buffer = malloc(1);
		libusb_fill_bulk_transfer(xfer, dev->dev, dev->ep_out, buffer, 0, tx_callback, dev, 0);
		if((res = libusb_submit_transfer(xfer)) < 0) {
			usbmuxd_log(LL_ERROR, "Failed to submit TX ZLP transfer to device %d-%d: %d", dev->bus, dev->address, res);
			libusb_free_transfer(xfer);
			return res;
		}
		collection_add(&dev->tx_xfers, xfer);
	}
	return 0;
}


// Callback from read operation
// Under normal operation this issues a new read transfer request immediately,
// doing a kind of read-callback loop
static void rx_callback(struct libusb_transfer *xfer)
{
	struct usb_device *dev = xfer->user_data;
	usbmuxd_log(LL_SPEW, "RX callback dev %d-%d len %d status %d", dev->bus, dev->address, xfer->actual_length, xfer->status);
	if(xfer->status == LIBUSB_TRANSFER_COMPLETED) {
		device_data_input(dev, xfer->buffer, xfer->actual_length);
		libusb_submit_transfer(xfer);
	} else {
		switch(xfer->status) {
			case LIBUSB_TRANSFER_COMPLETED: //shut up compiler
			case LIBUSB_TRANSFER_ERROR:
				// funny, this happens when we disconnect the device while waiting for a transfer, sometimes
				usbmuxd_log(LL_INFO, "Device %d-%d RX aborted due to error or disconnect", dev->bus, dev->address);
				break;
			case LIBUSB_TRANSFER_TIMED_OUT:
				usbmuxd_log(LL_ERROR, "RX transfer timed out for device %d-%d", dev->bus, dev->address);
				break;
			case LIBUSB_TRANSFER_CANCELLED:
				usbmuxd_log(LL_DEBUG, "Device %d-%d RX transfer cancelled", dev->bus, dev->address);
				break;
			case LIBUSB_TRANSFER_STALL:
				usbmuxd_log(LL_ERROR, "RX transfer stalled for device %d-%d", dev->bus, dev->address);
				break;
			case LIBUSB_TRANSFER_NO_DEVICE:
				// other times, this happens, and also even when we abort the transfer after device removal
				usbmuxd_log(LL_INFO, "Device %d-%d RX aborted due to disconnect", dev->bus, dev->address);
				break;
			case LIBUSB_TRANSFER_OVERFLOW:
				usbmuxd_log(LL_ERROR, "RX transfer overflow for device %d-%d", dev->bus, dev->address);
				break;
			// and nothing happens (this never gets called) if the device is freed after a disconnect! (bad)
			default:
				// this should never be reached.
				break;
		}

		free(xfer->buffer);
		collection_remove(&dev->rx_xfers, xfer);
		libusb_free_transfer(xfer);

		// we can't usb_disconnect here due to a deadlock, so instead mark it as dead and reap it after processing events
		// we'll do device_remove there too
		dev->alive = 0;
	}
}

// Start a read-callback loop for this device
static int start_rx_loop(struct usb_device *dev)
{
	int res;
	void *buf;
	struct libusb_transfer *xfer = libusb_alloc_transfer(0);
	buf = malloc(USB_MRU);
	libusb_fill_bulk_transfer(xfer, dev->dev, dev->ep_in, buf, USB_MRU, rx_callback, dev, 0);
	if((res = libusb_submit_transfer(xfer)) != 0) {
		usbmuxd_log(LL_ERROR, "Failed to submit RX transfer to device %d-%d: %d", dev->bus, dev->address, res);
		libusb_free_transfer(xfer);
		return res;
	}

	collection_add(&dev->rx_xfers, xfer);

	return 0;
}

static int usb_switch_aoa(libusb_device* dev)
{
	int res=-1, j;
	libusb_device_handle *handle;
	struct libusb_config_descriptor *config;
	uint8_t version[2];
	uint8_t bus = libusb_get_bus_number(dev);
	uint8_t address = libusb_get_device_address(dev);

	// potentially blocking operations follow; they will only run when new devices are detected, which is acceptable
	if((res = libusb_open(dev, &handle)) != 0) {
		usbmuxd_log(LL_WARNING, "Could not open device %d-%d: %d", bus, address, res);
		return -1;
	}
	if((res = libusb_get_active_config_descriptor(dev, &config)) != 0) {
		usbmuxd_log(LL_WARNING, "Could not get configuration descriptor for device %d-%d: %d", bus, address, res);
		libusb_close(handle);
		return -1;
	}
	
	for(j=0; j<config->bNumInterfaces; j++) {
		const struct libusb_interface_descriptor *intf = &config->interface[j].altsetting[0];
		if(intf->bInterfaceClass != INTERFACE_CLASS_AOA||
			   intf->bInterfaceSubClass != INTERFACE_SUBCLASS_AOA){
			continue;
		}
		/* Now asking if device supports Android Open Accessory protocol */
		res = libusb_control_transfer(handle,
					      LIBUSB_ENDPOINT_IN |
					      LIBUSB_REQUEST_TYPE_VENDOR,
					      AOA_GET_PROTOCOL, 0, 0, version,
					      sizeof(version), 0);
		if (res < 0) {
			usbmuxd_log(LL_SPEW, "Could not getting AOA protocol %d-%d: %d", bus, address, res);
			libusb_free_config_descriptor(config);
			libusb_close(handle);
			return res;
		}else{
			acc_default.aoa_version = ((version[1] << 8) | version[0]);
			usbmuxd_log(LL_WARNING, "Device[%d-%d] supports AOA %d.0!", bus, address, acc_default.aoa_version);
		}
		/* In case of a no_app accessory, the version must be >= 2 */
		if((acc_default.aoa_version < 2) && !acc_default.manufacturer) {
			usbmuxd_log(LL_SPEW, "Connecting without an Android App only for AOA 2.0[%d-%d]", bus,address);
			libusb_free_config_descriptor(config);
			libusb_close(handle);
			return -1;
		}
		if(acc_default.manufacturer) {
			usbmuxd_log(LL_WARNING, "sending manufacturer: %s", acc_default.manufacturer);
			res = libusb_control_transfer(handle,
						  LIBUSB_ENDPOINT_OUT
						  | LIBUSB_REQUEST_TYPE_VENDOR,
						  AOA_SEND_IDENT, 0,
						  AOA_STRING_MAN_ID,
						  (uint8_t *)acc_default.manufacturer,
						  strlen(acc_default.manufacturer) + 1, 0);
			if(res < 0){
				usbmuxd_log(LL_WARNING, "Could not Set AOA manufacturer %d-%d: %d", bus, address, res);
				libusb_free_config_descriptor(config);
				libusb_close(handle);
				return res;
			}
		}
		if(acc_default.model) {
			usbmuxd_log(LL_WARNING, "sending model: %s", acc_default.model);
			res = libusb_control_transfer(handle,
						  LIBUSB_ENDPOINT_OUT
						  | LIBUSB_REQUEST_TYPE_VENDOR,
						  AOA_SEND_IDENT, 0,
						  AOA_STRING_MOD_ID,
						  (uint8_t *)acc_default.model,
						  strlen(acc_default.model) + 1, 0);
			if(res < 0){
				usbmuxd_log(LL_WARNING, "Could not Set AOA model %d-%d: %d", bus, address, res);
				libusb_free_config_descriptor(config);
				libusb_close(handle);
				return res;
			}
		}
		
		usbmuxd_log(LL_WARNING, "sending description: %s", acc_default.description);
		res = libusb_control_transfer(handle,
					  LIBUSB_ENDPOINT_OUT
					  | LIBUSB_REQUEST_TYPE_VENDOR,
					  AOA_SEND_IDENT, 0,
					  AOA_STRING_DSC_ID,
					  (uint8_t *)acc_default.description,
					  strlen(acc_default.description) + 1, 0);
		if(res < 0){
			usbmuxd_log(LL_WARNING, "Could not Set AOA description %d-%d: %d", bus, address, res);
			libusb_free_config_descriptor(config);
			libusb_close(handle);
			return res;
		}
		usbmuxd_log(LL_WARNING, "sending version string: %s", acc_default.version);
		res = libusb_control_transfer(handle,
					  LIBUSB_ENDPOINT_OUT
					  | LIBUSB_REQUEST_TYPE_VENDOR,
					  AOA_SEND_IDENT, 0,
					  AOA_STRING_VER_ID,
					  (uint8_t *)acc_default.version,
					  strlen(acc_default.version) + 1, 0);
		if(res < 0){
			usbmuxd_log(LL_WARNING, "Could not Set AOA version %d-%d: %d", bus, address, res);
			libusb_free_config_descriptor(config);
			libusb_close(handle);
			return res;
		}
		usbmuxd_log(LL_WARNING, "sending url string: %s", acc_default.url);
		res = libusb_control_transfer(handle,
					  LIBUSB_ENDPOINT_OUT
					  | LIBUSB_REQUEST_TYPE_VENDOR,
					  AOA_SEND_IDENT, 0,
					  AOA_STRING_URL_ID,
					  (uint8_t *)acc_default.url,
					  strlen(acc_default.url) + 1, 0);
		if(res < 0){
			usbmuxd_log(LL_WARNING, "Could not Set AOA url %d-%d: %d", bus, address, res);
			libusb_free_config_descriptor(config);
			libusb_close(handle);
			return res;
		}
		usbmuxd_log(LL_WARNING, "sending serial number: %s", acc_default.serial);
		res = libusb_control_transfer(handle,
					  LIBUSB_ENDPOINT_OUT
					  | LIBUSB_REQUEST_TYPE_VENDOR,
					  AOA_SEND_IDENT, 0,
					  AOA_STRING_SER_ID,
					  (uint8_t *)acc_default.serial,
					  strlen(acc_default.serial) + 1, 0);
		if(res < 0){
			usbmuxd_log(LL_WARNING, "Could not Set AOA serial %d-%d: %d", bus, address, res);
			libusb_free_config_descriptor(config);
			libusb_close(handle);
			return res;
		}
		res = libusb_control_transfer(handle,
					  LIBUSB_ENDPOINT_OUT |
					  LIBUSB_REQUEST_TYPE_VENDOR,
					  AOA_START_ACCESSORY, 0, 0, NULL, 0, 0);
		if(res < 0){
			usbmuxd_log(LL_WARNING, "Could not Start AOA %d-%d: %d", bus, address, res);
			libusb_free_config_descriptor(config);
			libusb_close(handle);
			return res;
		}
		usbmuxd_log(LL_WARNING, "Turning the device %d-%d in Accessory mode Successful", bus, address);
		libusb_free_config_descriptor(config);
		libusb_close(handle);
		return 0;
	}	
	
	libusb_free_config_descriptor(config);
	libusb_close(handle);
	usbmuxd_log(LL_SPEW, "No Found Android Device in %d-%d", bus, address);

	return -1;
}

static int usb_device_add(libusb_device* dev)
{
	int j, res;
	// the following are non-blocking operations on the device list
	uint8_t bus = libusb_get_bus_number(dev);
	uint8_t address = libusb_get_device_address(dev);
	struct libusb_device_descriptor devdesc;
	int found = 0, usb_type=USB_STORAGE;
	FOREACH(struct usb_device *usbdev, &device_list) {
		if(usbdev->bus == bus && usbdev->address == address) {
			usbdev->alive = 1;
			found = 1;
			break;
		}
	} ENDFOREACH
	if(found)
		return 0; //device already found

	if((res = libusb_get_device_descriptor(dev, &devdesc)) != 0) {
		usbmuxd_log(LL_WARNING, "Could not get device descriptor for device %d-%d: %d", bus, address, res);
		return -1;
	}
	if(devdesc.idVendor == VID_APPLE &&
		(devdesc.idProduct >= PID_RANGE_LOW && devdesc.idProduct <= PID_RANGE_MAX)){
		usbmuxd_log(LL_WARNING, "Found IOS device  v/p %04x:%04x at %d-%d", 
				devdesc.idVendor, devdesc.idProduct, bus, address);
		usb_type = USB_IOS;
	}else if(devdesc.idVendor == AOA_ACCESSORY_VID &&
		(devdesc.idProduct >= AOA_ACCESSORY_PID && devdesc.idProduct <= AOA_ACCESSORY_AUDIO_ADB_PID)){
		usbmuxd_log(LL_WARNING, "Found Android AOA device  v/p %04x:%04x at %d-%d", 
				devdesc.idVendor, devdesc.idProduct, bus, address);
		usb_type = USB_ANDROID;
	}else{
		usbmuxd_log(LL_SPEW, "Try To Switch Android AOA Mode  v/p %04x:%04x at %d-%d", 
					devdesc.idVendor, devdesc.idProduct, bus, address);
		usb_switch_aoa(dev);
		return -1;
	}

	libusb_device_handle *handle;
	usbmuxd_log(LL_INFO, "Found new device with v/p %04x:%04x at %d-%d", devdesc.idVendor, devdesc.idProduct, bus, address);
	// potentially blocking operations follow; they will only run when new devices are detected, which is acceptable
	if((res = libusb_open(dev, &handle)) != 0) {
		usbmuxd_log(LL_WARNING, "Could not open device %d-%d: %d", bus, address, res);
		return -1;
	}

	int current_config = 0;
	if((res = libusb_get_configuration(handle, &current_config)) != 0) {
		usbmuxd_log(LL_WARNING, "Could not get configuration for device %d-%d: %d", bus, address, res);
		libusb_close(handle);
		return -1;
	}
	if (current_config != devdesc.bNumConfigurations) {
		struct libusb_config_descriptor *config;
		if((res = libusb_get_active_config_descriptor(dev, &config)) != 0) {
			usbmuxd_log(LL_NOTICE, "Could not get old configuration descriptor for device %d-%d: %d", bus, address, res);
		} else {
			for(j=0; j<config->bNumInterfaces; j++) {
				const struct libusb_interface_descriptor *intf = &config->interface[j].altsetting[0];
				if((res = libusb_kernel_driver_active(handle, intf->bInterfaceNumber)) < 0) {
					usbmuxd_log(LL_NOTICE, "Could not check kernel ownership of interface %d for device %d-%d: %d", intf->bInterfaceNumber, bus, address, res);
					continue;
				}
				if(res == 1) {
					usbmuxd_log(LL_INFO, "Detaching kernel driver for device %d-%d, interface %d", bus, address, intf->bInterfaceNumber);
					if((res = libusb_detach_kernel_driver(handle, intf->bInterfaceNumber)) < 0) {
						usbmuxd_log(LL_WARNING, "Could not detach kernel driver (%d), configuration change will probably fail!", res);
						continue;
					}
				}
			}
			libusb_free_config_descriptor(config);
		}

		usbmuxd_log(LL_INFO, "Setting configuration for device %d-%d, from %d to %d", bus, address, current_config, devdesc.bNumConfigurations);
		if((res = libusb_set_configuration(handle, devdesc.bNumConfigurations)) != 0) {
			usbmuxd_log(LL_WARNING, "Could not set configuration %d for device %d-%d: %d", devdesc.bNumConfigurations, bus, address, res);
			libusb_close(handle);
			return -1;
		}
	}

	struct libusb_config_descriptor *config;
	if((res = libusb_get_active_config_descriptor(dev, &config)) != 0) {
		usbmuxd_log(LL_WARNING, "Could not get configuration descriptor for device %d-%d: %d", bus, address, res);
		libusb_close(handle);
		return -1;
	}

	struct usb_device *usbdev;
	usbdev = malloc(sizeof(struct usb_device));
	memset(usbdev, 0, sizeof(*usbdev));

	for(j=0; j<config->bNumInterfaces; j++) {
		const struct libusb_interface_descriptor *intf = &config->interface[j].altsetting[0];
		if(usb_type == USB_IOS &&
			   (intf->bInterfaceClass != INTERFACE_CLASS ||
			   intf->bInterfaceSubClass != INTERFACE_SUBCLASS ||
			   intf->bInterfaceProtocol != INTERFACE_PROTOCOL)){
			continue;
		}else if(usb_type == USB_ANDROID&&
			   (intf->bInterfaceClass != INTERFACE_CLASS_AOA||
			   intf->bInterfaceSubClass != INTERFACE_SUBCLASS_AOA)){
			continue;
		}
		if(intf->bNumEndpoints != 2) {
			usbmuxd_log(LL_WARNING, "Endpoint count mismatch for interface %d of device %d-%d", intf->bInterfaceNumber, bus, address);
			continue;
		}
		if((intf->endpoint[0].bEndpointAddress & 0x80) == LIBUSB_ENDPOINT_OUT &&
		   (intf->endpoint[1].bEndpointAddress & 0x80) == LIBUSB_ENDPOINT_IN) {
			usbdev->interface = intf->bInterfaceNumber;
			usbdev->ep_out = intf->endpoint[0].bEndpointAddress;
			usbdev->ep_in = intf->endpoint[1].bEndpointAddress;
			usbmuxd_log(LL_INFO, "Found interface %d with endpoints %02x/%02x for device %d-%d", usbdev->interface, usbdev->ep_out, usbdev->ep_in, bus, address);
			break;
		} else if((intf->endpoint[1].bEndpointAddress & 0x80) == LIBUSB_ENDPOINT_OUT &&
		          (intf->endpoint[0].bEndpointAddress & 0x80) == LIBUSB_ENDPOINT_IN) {
			usbdev->interface = intf->bInterfaceNumber;
			usbdev->ep_out = intf->endpoint[1].bEndpointAddress;
			usbdev->ep_in = intf->endpoint[0].bEndpointAddress;
			usbmuxd_log(LL_INFO, "Found interface %d with swapped endpoints %02x/%02x for device %d-%d", usbdev->interface, usbdev->ep_out, usbdev->ep_in, bus, address);
			break;
		} else {
			usbmuxd_log(LL_WARNING, "Endpoint type mismatch for interface %d of device %d-%d", intf->bInterfaceNumber, bus, address);
		}
	}

	if(j == config->bNumInterfaces) {
		usbmuxd_log(LL_WARNING, "Could not find a suitable USB interface for device %d-%d", bus, address);
		libusb_free_config_descriptor(config);
		libusb_close(handle);
		free(usbdev);
		return -1;
	}

	libusb_free_config_descriptor(config);

	if((res = libusb_claim_interface(handle, usbdev->interface)) != 0) {
		usbmuxd_log(LL_WARNING, "Could not claim interface %d for device %d-%d: %d", usbdev->interface, bus, address, res);
		libusb_close(handle);
		free(usbdev);
		return -1;
	}

	if((res = libusb_get_string_descriptor_ascii(handle, devdesc.iSerialNumber, (uint8_t *)usbdev->serial, 256)) <= 0) {
		usbmuxd_log(LL_WARNING, "Could not get serial number for device %d-%d: %d", bus, address, res);
		libusb_release_interface(handle, usbdev->interface);
		libusb_close(handle);
		free(usbdev);
		return -1;
	}
	usbdev->serial[res] = 0;
	usbdev->bus = bus;
	usbdev->address = address;
	usbdev->vid = devdesc.idVendor;
	usbdev->pid = devdesc.idProduct;
	usbdev->speed = 480000000;
	usbdev->dev = handle;
	usbdev->alive = 1;	
	usbdev->type = usb_type;
	usbdev->wMaxPacketSize = libusb_get_max_packet_size(dev, usbdev->ep_out);
	if (usbdev->wMaxPacketSize <= 0) {
		usbmuxd_log(LL_ERROR, "Could not determine wMaxPacketSize for device %d-%d, setting to 64", usbdev->bus, usbdev->address);
		usbdev->wMaxPacketSize = 64;
	} else {
		usbmuxd_log(LL_INFO, "Using wMaxPacketSize=%d for device %d-%d", usbdev->wMaxPacketSize, usbdev->bus, usbdev->address);
	}

	switch (libusb_get_device_speed(dev)) {
		case LIBUSB_SPEED_LOW:
			usbdev->speed = 1500000;
			break;
		case LIBUSB_SPEED_FULL:
			usbdev->speed = 12000000;
			break;
		case LIBUSB_SPEED_SUPER:
			usbdev->speed = 5000000000;
			break;
		case LIBUSB_SPEED_HIGH:
		case LIBUSB_SPEED_UNKNOWN:
		default:
			usbdev->speed = 480000000;
			break;
	}

	usbmuxd_log(LL_INFO, "USB Speed is %g MBit/s for device %d-%d", (double)(usbdev->speed / 1000000.0), usbdev->bus, usbdev->address);

	collection_init(&usbdev->tx_xfers);
	collection_init(&usbdev->rx_xfers);

	collection_add(&device_list, usbdev);

	if(device_add(usbdev) < 0) {
		usb_disconnect(usbdev);
		return -1;
	}

	if(usbdev->type == USB_IOS){
		// Spin up NUM_RX_LOOPS parallel usb data retrieval loops
		// Old usbmuxds used only 1 rx loop, but that leaves the
		// USB port sleeping most of the time
		int rx_loops = NUM_RX_LOOPS;
		for (rx_loops = NUM_RX_LOOPS; rx_loops > 0; rx_loops--) {
			if(start_rx_loop(usbdev) < 0) {
				usbmuxd_log(LL_WARNING, "Failed to start RX loop number %d", NUM_RX_LOOPS - rx_loops);
				break;
			}
		}
		// Ensure we have at least 1 RX loop going
		if (rx_loops == NUM_RX_LOOPS) {
			usbmuxd_log(LL_FATAL, "Failed to start any RX loop for device %d-%d",
						usbdev->bus, usbdev->address);
			device_remove(usbdev);
			usb_disconnect(usbdev);
			return -1;
		} else if (rx_loops > 0) {
			usbmuxd_log(LL_WARNING, "Failed to start all %d RX loops. Going on with %d loops. "
						"This may have negative impact on device read speed.",
						NUM_RX_LOOPS, NUM_RX_LOOPS - rx_loops);
		} else {
			usbmuxd_log(LL_DEBUG, "All %d RX loops started successfully", NUM_RX_LOOPS);
		}
	}else if(usbdev->type == USB_ANDROID){
		if(start_rx_loop(usbdev) < 0) {
			usbmuxd_log(LL_FATAL, "Failed to start any AOA RX loop for device %d-%d",
						usbdev->bus, usbdev->address);
			device_remove(usbdev);
			usb_disconnect(usbdev);
			return -1;
		}
	}

	return 0;
}

int usb_discover(void)
{
	int cnt, i;
	int valid_count = 0;
	libusb_device **devs;

	cnt = libusb_get_device_list(NULL, &devs);
	if(cnt < 0) {
		usbmuxd_log(LL_WARNING, "Could not get device list: %d", cnt);
		devlist_failures++;
		// sometimes libusb fails getting the device list if you've just removed something
		if(devlist_failures > 5) {
			usbmuxd_log(LL_FATAL, "Too many errors getting device list");
			return cnt;
		} else {
			get_tick_count(&next_dev_poll_time);
			next_dev_poll_time.tv_usec += DEVICE_POLL_TIME * 1000;
			next_dev_poll_time.tv_sec += next_dev_poll_time.tv_usec / 1000000;
			next_dev_poll_time.tv_usec = next_dev_poll_time.tv_usec % 1000000;
			return 0;
		}
	}
	devlist_failures = 0;

	usbmuxd_log(LL_SPEW, "usb_discover: scanning %d devices", cnt);

	// Mark all devices as dead, and do a mark-sweep like
	// collection of dead devices
	FOREACH(struct usb_device *usbdev, &device_list) {
		usbdev->alive = 0;
	} ENDFOREACH

	// Enumerate all USB devices and mark the ones we already know
	// about as live, again
	for(i=0; i<cnt; i++) {
		libusb_device *dev = devs[i];
		if (usb_device_add(dev) < 0) {
			continue;
		}
		valid_count++;
	}

	// Clean out any device we didn't mark back as live
	reap_dead_devices();

	libusb_free_device_list(devs, 1);

	get_tick_count(&next_dev_poll_time);
	next_dev_poll_time.tv_usec += DEVICE_POLL_TIME * 1000;
	next_dev_poll_time.tv_sec += next_dev_poll_time.tv_usec / 1000000;
	next_dev_poll_time.tv_usec = next_dev_poll_time.tv_usec % 1000000;

	return valid_count;
}

const char *usb_get_serial(struct usb_device *dev)
{
	if(!dev->dev) {
		return NULL;
	}
	return dev->serial;
}

uint32_t usb_get_location(struct usb_device *dev)
{
	if(!dev->dev) {
		return 0;
	}
	return (dev->bus << 16) | dev->address;
}

uint16_t usb_get_pid(struct usb_device *dev)
{
	if(!dev->dev) {
		return 0;
	}
	return dev->pid;
}

uint64_t usb_get_speed(struct usb_device *dev)
{
	if (!dev->dev) {
		return 0;
	}
	return dev->speed;
}

void usb_get_fds(struct fdlist *list)
{
	const struct libusb_pollfd **usbfds;
	const struct libusb_pollfd **p;
	usbfds = libusb_get_pollfds(NULL);
	if(!usbfds) {
		usbmuxd_log(LL_ERROR, "libusb_get_pollfds failed");
		return;
	}
	p = usbfds;
	while(*p) {
		fdlist_add(list, FD_USB, (*p)->fd, (*p)->events);
		p++;
	}
	free(usbfds);
}

void usb_autodiscover(int enable)
{
	usbmuxd_log(LL_DEBUG, "usb polling enable: %d", enable);
	device_polling = enable;
	device_hotplug = enable;
}

static int dev_poll_remain_ms(void)
{
	int msecs;
	struct timeval tv;
	if(!device_polling)
		return 100000; // devices will never be polled if this is > 0
	get_tick_count(&tv);
	msecs = (next_dev_poll_time.tv_sec - tv.tv_sec) * 1000;
	msecs += (next_dev_poll_time.tv_usec - tv.tv_usec) / 1000;
	if(msecs < 0)
		return 0;
	return msecs;
}

int usb_get_timeout(void)
{
	struct timeval tv;
	int msec;
	int res;
	int pollrem;
	pollrem = dev_poll_remain_ms();
	res = libusb_get_next_timeout(NULL, &tv);
	if(res == 0)
		return pollrem;
	if(res < 0) {
		usbmuxd_log(LL_ERROR, "libusb_get_next_timeout failed: %d", res);
		return pollrem;
	}
	msec = tv.tv_sec * 1000;
	msec += tv.tv_usec / 1000;
	if(msec > pollrem)
		return pollrem;
	return msec;
}

int usb_process(void)
{
	int res;
	struct timeval tv;
	tv.tv_sec = tv.tv_usec = 0;
	res = libusb_handle_events_timeout(NULL, &tv);
	if(res < 0) {
		usbmuxd_log(LL_ERROR, "libusb_handle_events_timeout failed: %d", res);
		return res;
	}

	// reap devices marked dead due to an RX error
	reap_dead_devices();

	if(dev_poll_remain_ms() <= 0) {
		res = usb_discover();
		if(res < 0) {
			usbmuxd_log(LL_ERROR, "usb_discover failed: %d", res);
			return res;
		}
	}
	return 0;
}

int usb_process_timeout(int msec)
{
	int res;
	struct timeval tleft, tcur, tfin;
	get_tick_count(&tcur);
	tfin.tv_sec = tcur.tv_sec + (msec / 1000);
	tfin.tv_usec = tcur.tv_usec + (msec % 1000) * 1000;
	tfin.tv_sec += tfin.tv_usec / 1000000;
	tfin.tv_usec %= 1000000;
	while((tfin.tv_sec > tcur.tv_sec) || ((tfin.tv_sec == tcur.tv_sec) && (tfin.tv_usec > tcur.tv_usec))) {
		tleft.tv_sec = tfin.tv_sec - tcur.tv_sec;
		tleft.tv_usec = tfin.tv_usec - tcur.tv_usec;
		if(tleft.tv_usec < 0) {
			tleft.tv_usec += 1000000;
			tleft.tv_sec -= 1;
		}
		res = libusb_handle_events_timeout(NULL, &tleft);
		if(res < 0) {
			usbmuxd_log(LL_ERROR, "libusb_handle_events_timeout failed: %d", res);
			return res;
		}
		// reap devices marked dead due to an RX error
		reap_dead_devices();
		get_tick_count(&tcur);
	}
	return 0;
}

#ifdef HAVE_LIBUSB_HOTPLUG_API
static libusb_hotplug_callback_handle usb_hotplug_cb_handle;

static int usb_hotplug_cb(libusb_context *ctx, libusb_device *device, libusb_hotplug_event event, void *user_data)
{
	if (LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED == event) {
		if (device_hotplug) {
			usb_device_add(device);
		}
	} else if (LIBUSB_HOTPLUG_EVENT_DEVICE_LEFT == event) {
		uint8_t bus = libusb_get_bus_number(device);
		uint8_t address = libusb_get_device_address(device);
		FOREACH(struct usb_device *usbdev, &device_list) {
			if(usbdev->bus == bus && usbdev->address == address) {
				usbdev->alive = 0;
				device_remove(usbdev);
				break;
			}
		} ENDFOREACH
	} else {
		usbmuxd_log(LL_ERROR, "Unhandled event %d", event);
	}
	return 0;
}
#endif

int usb_init(void)
{
	int res;
	usbmuxd_log(LL_DEBUG, "usb_init for linux / libusb 1.0");

	devlist_failures = 0;
	device_polling = 1;
	res = libusb_init(NULL);
	//libusb_set_debug(NULL, 3);
	if(res != 0) {
		usbmuxd_log(LL_FATAL, "libusb_init failed: %d", res);
		return -1;
	}

	collection_init(&device_list);

#ifdef HAVE_LIBUSB_HOTPLUG_API
	if (libusb_has_capability(LIBUSB_CAP_HAS_HOTPLUG)) {
		usbmuxd_log(LL_INFO, "Registering for libusb hotplug events");
		res = libusb_hotplug_register_callback(NULL, LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED | LIBUSB_HOTPLUG_EVENT_DEVICE_LEFT, LIBUSB_HOTPLUG_ENUMERATE, VID_APPLE, LIBUSB_HOTPLUG_MATCH_ANY, 0, usb_hotplug_cb, NULL, &usb_hotplug_cb_handle);
		if (res == LIBUSB_SUCCESS) {
			device_polling = 0;
		} else {
			usbmuxd_log(LL_ERROR, "ERROR: Could not register for libusb hotplug events (%d)", res);
		}
	} else {
		usbmuxd_log(LL_ERROR, "libusb does not support hotplug events");
	}
#endif
	if (device_polling) {
		res = usb_discover();
		if (res >= 0) {
		}
	} else {
		res = collection_count(&device_list);
	}
	return res;
}

void usb_shutdown(void)
{
	usbmuxd_log(LL_DEBUG, "usb_shutdown");

#ifdef HAVE_LIBUSB_HOTPLUG_API
	libusb_hotplug_deregister_callback(NULL, usb_hotplug_cb_handle);
#endif

	FOREACH(struct usb_device *usbdev, &device_list) {
		device_remove(usbdev);
		usb_disconnect(usbdev);
	} ENDFOREACH
	collection_free(&device_list);
	libusb_exit(NULL);
}
