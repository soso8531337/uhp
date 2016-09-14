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

#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>


#include <unistd.h>
#include <signal.h>

// usbmuxd protocol
#include "usbmuxd-proto.h"
// socket utility functions
#include "socket.h"
// misc utility functions
#include "utils.h"
#include "protocol"

/**/
static int protocol_decode(unsigned char *b_buf, uint32_t b_size, struct scsi_head *scsi)
{
	struct scsi_head *shder = NULL;
	if(!scsi || !b_buf){
		return -1;
	}
	shder = (struct scsi_head *)b_buf;
	if(shder->head != SCSI_PHONE_MAGIC){
		usbmuxd_log(LL_ERROR, "Magic Error[0x%x]", shder->head);
		return PRO_BADMAGIC;
	}
	return PRO_OK;
}




