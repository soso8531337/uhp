/*
 * blockdev.h
 *
 * Copyright (C) 2016 Szitman <zhangwei@i4season.com>
 */

#ifndef BLOCKDEV_H
#define BLOCKDEV_H

#ifndef HDIO_GETGEO
#define HDIO_GETGEO 0x0301
struct hd_geometry {
        unsigned char heads;
        unsigned char sectors;
        unsigned short cylinders;       /* truncated */
        unsigned long start;
};
#endif

int blockdev_readahead(char *devname, int readahead);
#endif
