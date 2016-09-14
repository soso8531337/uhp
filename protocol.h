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

#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>
#include "utils.h"

#define SCSI_PHONE_MAGIC		 0xccddeeff
#define SCSI_DEVICE_MAGIC		 0xaabbccdd
#define SCSI_HEAD_SIZE			sizeof(struct scsi_head)
#define SCSI_SECTOR_SIZE		512
enum {
	SCSI_TEST = 0,
	SCSI_READ  = 0x28,//28
	SCSI_WRITE = 0x2a,//2a
	SCSI_INQUIRY = 0x12,//12
	SCSI_READ_CAPACITY =0x25,//25
};

enum {
	PRO_OK = 0,
	PRO_BADMAGIC,
	PRO_INCOMPLTE,
	PRO_BADPACKAGE,
};

struct scsi_head{
	int32_t head;	/*Receive OR Send*/
	int32_t wtag; /*Task ID*/
	int32_t ctrid; /*Command ID*/
	int32_t addr; /*Offset addr*512   represent sectors */
	int32_t len;
	int16_t wlun;
	int16_t relag; /*Response Code*/
};

#endif
