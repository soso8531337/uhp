/*
 * preread.h
 *
 * Copyright (C) 2009 Hector Martin "marcan" <hector@marcansoft.com>
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

#ifndef PREREAD_H
#define PREREAD_H

#define PREBUFFER_FACTOR		2
#define PREBUFFER_SIZE		(256*1024*PREBUFFER_FACTOR) //prebuffer size limit 256KB

int preread_storage_init(void);
void preread_storage_destory(void);
int preread_storage_read(int16_t wlun, off_t offset, int32_t size, char *payload);


#endif
