/*
 * blockdev.h
 *
 * Copyright (C) 2016 Szitman <zhangwei@i4season.com>
 */


#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <locale.h>
#include <libintl.h>

#include "blockdev.h"
#include "log.h"

#define SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define BLOCKDEV_NAME		"blockdev"

#ifndef BLKROSET
#define BLKROSET   _IO(0x12,93)
#define BLKROGET   _IO(0x12,94)
#define BLKRRPART  _IO(0x12,95)
#define BLKGETSIZE _IO(0x12,96)
#define BLKFLSBUF  _IO(0x12,97)
#define BLKRASET   _IO(0x12,98)
#define BLKRAGET   _IO(0x12,99)
#define BLKSSZGET  _IO(0x12,104)
#define BLKBSZGET  _IOR(0x12,112,size_t)
#define BLKBSZSET  _IOW(0x12,113,size_t)
#define BLKGETSIZE64 _IOR(0x12,114,size_t)
#endif

struct bdc {
	char *name;
	char *iocname;
	long ioc;
	int argtype;
#define ARGNONE 0
#define ARGINTA 1
#define ARGINTAP 2
#define ARGINTP 3
#define ARGINTG 4
#define ARGLINTG 5
#define ARGLLINTG 6
	long argval;
	char *argname;
	char *help;
} bdcms[] = {
#ifdef BLKROSET
	{ "--setro", "BLKROSET", BLKROSET, ARGINTP, 1, NULL, "set read-only" },
	{ "--setrw", "BLKROSET", BLKROSET, ARGINTP, 0, NULL,"set read-write" },
#endif
#ifdef BLKROGET
	{ "--getro", "BLKROGET", BLKROGET, ARGINTG, -1, NULL, "get read-only" },
#endif
#ifdef BLKSSZGET
	{ "--getss", "BLKSSZGET", BLKSSZGET, ARGINTG, -1, NULL, "get sectorsize" },
#endif
#ifdef BLKBSZGET
	{ "--getbsz", "BLKBSZGET", BLKBSZGET, ARGINTG, -1, NULL, "get blocksize" },
#endif
#ifdef BLKBSZSET
	{ "--setbsz", "BLKBSZSET", BLKBSZSET, ARGINTAP, 0, "BLOCKSIZE", "set blocksize" },
#endif
#ifdef BLKGETSIZE
	{ "--getsize", "BLKGETSIZE", BLKGETSIZE, ARGLINTG, -1, NULL, "get 32-bit sector count" },
#endif
#ifdef BLKGETSIZE64
	{ "--getsize64", "BLKGETSIZE64", BLKGETSIZE64, ARGLLINTG, -1, NULL, "get size in bytes" },
#endif
#ifdef BLKRASET
	{ "--setra", "BLKRASET", BLKRASET, ARGINTA, 0, "READAHEAD", "set readahead" },
#endif
#ifdef BLKRAGET
	{ "--getra", "BLKRAGET", BLKRAGET, ARGLINTG, -1, NULL, "get readahead" },
#endif
#ifdef BLKFLSBUF
	{ "--flushbufs", "BLKFLSBUF", BLKFLSBUF, ARGNONE, 0, NULL, "flush buffers" },
#endif
#ifdef BLKRRPART
	{ "--rereadpt", "BLKRRPART", BLKRRPART, ARGNONE, 0, NULL,"reread partition table" },
#endif
};

static void usage(void) 
{
	int i;
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "  %s -V\n", BLOCKDEV_NAME);
	fprintf(stderr, "  %s --report [devices]\n", BLOCKDEV_NAME);
	fprintf(stderr, "  %s [-v|-q] commands devices\n", BLOCKDEV_NAME);
	fprintf(stderr, "Available commands:\n");
	fprintf(stderr, "\t--getsz\t(%s)\n", "get size in 512-byte sectors");
	for (i = 0; i < SIZE(bdcms); i++) {
		fprintf(stderr, "\t%s", bdcms[i].name);
		if (bdcms[i].argname)
			fprintf(stderr, " %s", bdcms[i].argname);
		if (bdcms[i].help)
			fprintf(stderr, "\t(%s)", bdcms[i].help);
		fprintf(stderr, "\n");
	}
}

static int find_cmd(char *s) {
	int j;

	for (j = 0; j < SIZE(bdcms); j++)
		if (!strcmp(s, bdcms[j].name))
			return j;
	return -1;
}

static int getsize(int fd, long long *sectors) {
	int err;
	long sz;
	long long b;

	err = ioctl (fd, BLKGETSIZE, &sz);
	if (err){
		return err;
	}	
	err = ioctl(fd, BLKGETSIZE64, &b);
	if (err || b == 0 || b == sz){
		*sectors = sz;
	}else{
		*sectors = (b >> 9);
	}
	return 0;
}

static void do_commands(int fd, char **argv, int d) {
	int res, i, j;
	int iarg;
	long larg;
	long long llarg;
	int verbose = 0;

	for (i = 1; i < d; i++) {
		if (!strcmp(argv[i], "-v")) {
			verbose = 1;
			continue;
		}
		if (!strcmp(argv[i], "-q")) {
			verbose = 0;
			continue;
		}

		if (!strcmp(argv[i], "--getsz")) {
			res = getsize(fd, &llarg);
			if (res == 0){
				printf("%lld\n", llarg);
			}else{
				continue;
			}
		}

		j = find_cmd(argv[i]);
		if (j == -1) {
			fprintf(stderr, "%s: Unknown command: %s\n", BLOCKDEV_NAME, argv[i]);
			usage();
		}

		switch(bdcms[j].argtype) {
			default:
			case ARGNONE:
				res = ioctl(fd, bdcms[j].ioc, 0);
				break;
			case ARGINTA:
				if (i == d-1) {
					fprintf(stderr, "%s requires an argument\n",
					bdcms[j].name);
					usage();					
					return;
				}
				iarg = atoi(argv[++i]);
				res = ioctl(fd, bdcms[j].ioc, iarg);
				break;
			case ARGINTAP:
				if (i == d-1) {
					fprintf(stderr, "%s requires an argument\n",
					bdcms[j].name);
					usage();
					return;
				}
				iarg = atoi(argv[++i]);
				res = ioctl(fd, bdcms[j].ioc, &iarg);
				break;
			case ARGINTP:
			case ARGINTG:
				iarg = bdcms[j].argval;
				res = ioctl(fd, bdcms[j].ioc, &iarg);
				break;
			case ARGLINTG:
				larg = bdcms[j].argval;
				res = ioctl(fd, bdcms[j].ioc, &larg);
				break;
			case ARGLLINTG:
				llarg = bdcms[j].argval;
				res = ioctl(fd, bdcms[j].ioc, &llarg);
				break;
		}
		if (res == -1) {
			perror(bdcms[j].iocname);
			if (verbose)
				printf("%s failed.\n", bdcms[j].help);
			return;
		}
		switch(bdcms[j].argtype) {
			case ARGINTG:
				if (verbose){
					printf("%s: %d\n", bdcms[j].help, iarg);
				}else{
					printf("%d\n", iarg);
				}
				break;
			case ARGLINTG:
				if (verbose)
					printf("%s: %ld\n", bdcms[j].help, larg);
				else
					printf("%ld\n", larg);

			case ARGLLINTG:
				if (verbose)
					printf("%s: %lld\n", bdcms[j].help, llarg);
				else    
					printf("%lld\n", llarg);
				break;
			default:
				if (verbose)
					printf("%s succeeded.\n", bdcms[j].help);
				break;
		}
	}
}

int blockdev(int argc, char **argv) {
	int fd, d, j, k;

	d = 0;

	if (argc < 2)
		usage();

	/* -V not together with commands */
	if (!strcmp(argv[1], "-V") || !strcmp(argv[1], "--version")) {
		printf("%s from %s\n", BLOCKDEV_NAME, "3.10.14");
		return 0;
	}

	/* do each of the commands on each of the devices */
	/* devices start after last command */
	for (d = 1; d < argc; d++) {
		j = find_cmd(argv[d]);
		if (j >= 0) {
			if (bdcms[j].argtype == ARGINTA ||
			bdcms[j].argtype == ARGINTAP)
			d++;
			continue;
		}
		if (!strcmp(argv[d], "--getsz"))
			continue;
		if (!strcmp(argv[d], "--")) {
			d++;
			break;
		}
		if (argv[d][0] != '-'){
			break;
		}

		if (d >= argc)
			usage();

		for (k = d; k < argc; k++) {
			fd = open(argv[k], O_RDONLY, 0);
			if (fd < 0) {
				perror(argv[k]);
				return -1;
			}
			do_commands(fd, argv, d);
			close(fd);
		}
	}	

	return 0;
}

int blockdev_readahead(char *devname, int readahead)
{
	int fd;
	long larg;
	
	if(!devname){
		return -1;
	}
	fd = open(devname, O_RDWR);
	if (fd < 0) {
		return -1;
	}
	if(ioctl(fd, BLKRAGET, &larg) == -1){	
		usbproxy_log(LL_WARNING, "Get ReadAhead Error[%s]...", devname);
		close(fd);
		return -1;
	}
	if(ioctl(fd, BLKRASET, readahead) == -1){
		usbproxy_log(LL_WARNING, "Set ReadAhead Error[%s]...", devname);
		close(fd);
		return -1;
	}
	usbproxy_log(LL_WARNING, "Set %s ReadAhead From %ld To %d...", 
				devname, larg, readahead);
	close(fd);

	return 0;
}
