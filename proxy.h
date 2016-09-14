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
 */

#ifndef PROXY_H
#define PROXY_H

#include <stdint.h>
#include "utils.h"

#ifdef WIN32
  #define USBHOST_API __declspec( dllexport )
#else
  #ifdef HAVE_FVISIBILITY
    #define USBHOST_API __attribute__((visibility("default")))
  #else
    #define USBHOST_API
  #endif
#endif

USBHOST_API void* usbhost_application_run(void *args);
#endif
