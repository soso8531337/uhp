/*
 * preread.c
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <sys/time.h>
#include <syslog.h>
#include <pthread.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "preread.h"
#include "utils.h"
#include "preread.h"
#include "protocol.h"
#include "storage.h"
#include "blockdev.h"
#include "log.h"

typedef struct preRequst{
	int16_t wlun;
	off_t offset;
	int32_t size;
	char *buffer;
}preRequst;

typedef struct preBuffer{
	int buffSize;
	char *buffBegin;
	char *buffPayload;
	int cacheSize;
	off_t cacheSectorStart;
}preBuffer;

typedef struct preRead{
	off_t offsetLatestRequest;
	int sizeLatestRequest;
	int countRequest;
	int countCached;
	preBuffer buffer;
	int diskfd;
	off_t offset; //represent sector offset
	int wlun;
}preRead;

enum{
	PRE_REQINIT = 0,
	PRE_REQNEW=1, 
	PRE_REQFIN=2,
	PRE_REQERR=3,
};

enum{	
	PRE_REQ256=256*1024,
	PRE_REQ128=128*1024,
	PRE_REQ64=64*1024,
	PRE_REQ32=32*1024,
	PRE_REQ16=16*1024,
	PRE_REQ8=8*1024,
	PRE_REQ4=4*1024,
	PRE_REQ0 = 512,
};

static preRead *pRead[STOR_NUM]= {0};
static preRequst pReadReq;
static volatile uint8_t pReadReqStatus = 0;
pthread_cond_t conPreadReq=PTHREAD_COND_INITIALIZER;
pthread_cond_t conPreadRes=PTHREAD_COND_INITIALIZER;
pthread_mutex_t mutexPreadReq = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutexPreadRes = PTHREAD_MUTEX_INITIALIZER;
pthread_t threadPread;


static int preread_buffer_read(int16_t wlun, off_t offset, int32_t size, char *payload)
{
	int res;
	
	if(!payload || !size){
		return -1;
	}
	/*Lock it*/
	pthread_mutex_lock(&mutexPreadReq);
	/*Set buffer struct*/
	memset(&pReadReq, 0, sizeof(pReadReq));
	pReadReq.wlun = wlun;
	pReadReq.offset = offset;
	pReadReq.size = size;
	pReadReq.buffer = payload;

	pReadReqStatus = PRE_REQNEW;	
	usbproxy_log(LL_WARNING, "Set pReadTrue=1 Wait Thread Return Data");
	pthread_cond_signal(&conPreadReq);
	pthread_mutex_unlock(&mutexPreadReq);
	
	/*Wait Thread Handle Finish, we need to get mutex lock*/
	pthread_mutex_lock(&mutexPreadRes);
	while(pReadReqStatus != PRE_REQFIN &&
			pReadReqStatus !=  PRE_REQERR){
		pthread_cond_wait(&conPreadRes, &mutexPreadRes);
	}
	/*Just for safe*/
	res = pReadReqStatus;
	pReadReqStatus = PRE_REQINIT;
	pthread_mutex_unlock(&mutexPreadRes);
	
	usbproxy_log(LL_WARNING, "PREHEAD Finish--->wlun=%d offset=%lld size=%d payload=%p",
			wlun, offset, size, payload);

	return (res == PRE_REQFIN?0:-1);
}

/*
*offset is sector number
*/
static int preread_buffer_init(preBuffer *pBuffer, int diskfd, off_t offset)
{
	char *payload = NULL;
	
	if(!pBuffer){
		return -1;
	}
	payload = calloc(1, PREBUFFER_SIZE);
	if(!payload){
		usbproxy_log(LL_WARNING, "Buffer Alloc Error:%s...", strerror(errno));
		return -1;
	}
	pBuffer->buffBegin = pBuffer->buffPayload = payload;
	pBuffer->buffSize= PREBUFFER_SIZE;
	/*lseek offset*/
	if(offset && lseek(diskfd, offset*SCSI_SECTOR_SIZE, SEEK_SET) < 0){
		usbproxy_log(LL_ERROR, "Buffer Lseek %lld Error:%s", offset, strerror(errno));
		return -1;
	}
	/*Readahead PREBUFFER_SIZE*/
	if((pBuffer->cacheSize= read(diskfd, pBuffer->buffPayload, pBuffer->buffSize)) < 0){
		usbproxy_log(LL_WARNING, "Buffer Preread Error:%s...", strerror(errno));
		free(payload);
		return -1;
	}
	pBuffer->cacheSectorStart = offset;
	usbproxy_log(LL_WARNING, "Buffer Preread Successful[cache/total=%d/%dBytes]...", 
				pBuffer->cacheSize, pBuffer->buffSize);
		
	return 0;
}

static int preread_buffer_reinit(int wlun, char *diskName)
{
	preRead *pRbuf = NULL;
	int diskNum = wlun;	
	char *payload = NULL;

	if(!diskName){
		return -1;
	}
	pRbuf = calloc(1, sizeof(preRead));
	if(!pRbuf){
		usbproxy_log(LL_WARNING, "REMulti Disk Readahead[%d->%s] Error[%s]...", 
				diskNum, diskName, strerror(errno));
		pRead[diskNum] = NULL;			
		return -1;
	}
	/*Set Value*/
	pRbuf->wlun = diskNum;
	pRbuf->diskfd = open(diskName, O_RDWR);
	if(pRbuf->diskfd < 0){
		usbproxy_log(LL_WARNING, "REMulti Disk open[%d->%s] Error[%s]...", 
				diskNum, diskName, strerror(errno));
		free(pRbuf);
		pRead[diskNum] = NULL;
		return -1;
	}
	/*Init Prebuffer*/
	payload = calloc(1, PREBUFFER_SIZE);
	if(!payload){
		usbproxy_log(LL_WARNING, "Buffer Alloc Error:%s...", strerror(errno));
		close(pRbuf->diskfd);
		free(pRbuf);
		pRead[diskNum] = NULL;
		return -1;
	}
	pRbuf->buffer.buffSize= PREBUFFER_SIZE;
	pRbuf->buffer.cacheSize = 0;
	pRbuf->buffer.buffBegin = pRbuf->buffer.buffPayload = payload;
	pRbuf->buffer.cacheSectorStart = 0;
	/*Set Offset*/
	pRbuf->offset = 0;
	/*Set readahead*/
	blockdev_readahead(diskName, PREBUFFER_SIZE/SCSI_SECTOR_SIZE);	
	/*Set Value*/
	pRead[diskNum] = pRbuf;

	return 0;
}

static int preread_buffer_readfrom_disk(int fd, off_t offset, char *payload, int size)
{
	int already = 0, res;
	
	if(!payload || !size){
		return -1;
	}

	if(lseek(fd, offset, SEEK_SET) < 0){
		usbproxy_log(LL_ERROR, "Lseek %d Error:%s", fd, strerror(errno));
		return -1;
	}
	already = 0;
	do {
		res  = read(fd, payload + already, size - already);
		if (res < 0) {
			if(errno ==  EINTR ||
					errno ==  EAGAIN){
				continue;
			}
			usbproxy_log(LL_ERROR, "Read %d Error:%s",fd, strerror(errno));
			return -1;
		}else if(res == 0){
			usbproxy_log(LL_ERROR, "Read End OF File: offset=%lld readn=%d",
						offset, already);
			return already;
		}
		already += res;
	} while (already < size);

	return size;
}

static int pread_buffer_resetbuf(preBuffer *preBuf)
{
	if(!preBuf){
		return -1;
	}
	preBuf->buffPayload = preBuf->buffBegin;
	preBuf->cacheSectorStart = preBuf->cacheSize = 0;

	return 0;
}

static void pread_buffer_printbuf(preRead *pRbuf)
{
	if(!pRbuf){
		return;
	}
	printf("wlun:%d\nDiskFD:%d\nLatestRequestOffset:%lld\nLatestRequestSize:%d\n"
				"Request:%d\nCached:%d\n", pRbuf->wlun, pRbuf->diskfd, pRbuf->offsetLatestRequest,
					pRbuf->sizeLatestRequest, pRbuf->countRequest, pRbuf->countCached);
	printf("BufferBase:%p\nBufferPayload:%p\nBufferSize:%d\nBufferCache:%d\nBufferSecStart:%lld\n", 
				pRbuf->buffer.buffBegin, pRbuf->buffer.buffPayload, pRbuf->buffer.buffSize,
			pRbuf->buffer.cacheSize, pRbuf->buffer.cacheSectorStart);
}

/*
*return value:
* -1: error
*1:found it cache, no need to preread
*2:found it cache, but it need to preread
*/
static int preread_buffer_getcontent(preRead *pRbuf, preRequst *pReq)
{
	off_t startSec;
	int countSec, freeSize, offsetSize;
	int freeCount;
	
	if(!pRbuf || !pReq){
		return -1;
	}

	startSec = pRbuf->buffer.cacheSectorStart;
	countSec = pRbuf->buffer.cacheSize/SCSI_SECTOR_SIZE;
	offsetSize = (pReq->offset-startSec)*SCSI_SECTOR_SIZE;
	if(offsetSize < 0){
		freeSize = 0;
	}else{
		freeSize = pRbuf->buffer.cacheSize-offsetSize;
	}

	/*Update pRbuf*/
	pRbuf->offsetLatestRequest = pReq->offset;
	pRbuf->sizeLatestRequest = pReq->size;
	pRbuf->countRequest++;
	
	if(!pRbuf->buffer.cacheSize || 
			(startSec+countSec < pReq->offset) ||
			(startSec > pReq->offset) ||
				freeSize < pReq->size){
		usbproxy_log(LL_WARNING, "Readahead Not Cache:wlen=%d offset=%lld size=%d", 
						pReq->wlun, pReq->offset, pReq->size);
		/*Direct read from disk*/
		if(preread_buffer_readfrom_disk(pRbuf->diskfd, (off_t)pReq->offset*SCSI_SECTOR_SIZE, 
				pReq->buffer, pReq->size) < 0){
			usbproxy_log(LL_WARNING, "Read From Disk Error");
			return -1;
		}
		pRbuf->offset =  pReq->offset + pReq->size / SCSI_SECTOR_SIZE;
		/*Reset prebuf*/
		pread_buffer_resetbuf(&(pRbuf->buffer));
		/*continue to preread*/
		return 2;
	}
	/*cached*/
	usbproxy_log(LL_WARNING, "Readahead Cache Info:");
	pread_buffer_printbuf(pRbuf);
	pRbuf->buffer.buffPayload += offsetSize;
	memcpy(pReq->buffer, pRbuf->buffer.buffPayload, pReq->size);
	pRbuf->buffer.buffPayload += pReq->size;
	pRbuf->buffer.cacheSectorStart = pReq->offset+pReq->size/SCSI_SECTOR_SIZE;
	pRbuf->buffer.cacheSize = pRbuf->buffer.cacheSize-offsetSize-pReq->size;
	/*update pRbuf*/	
	pRbuf->countCached++;
	usbproxy_log(LL_WARNING, "Readahead Cache OK:");
	pread_buffer_printbuf(pRbuf);
	
	/*Judge if need to continue preread*/
	freeCount = pRbuf->buffer.cacheSize/pReq->size;
	usbproxy_log(LL_WARNING, "Readahead Cache Analy: CacheSize:%d ReqSize:%d Count:%d",
				pRbuf->buffer.cacheSize, pReq->size, freeCount);
	if(freeCount == 0){
		return 2;
	}else if(pReq->size == PRE_REQ128&&
		freeCount < 1){
		return 2;
	}else if((pReq->size == PRE_REQ64 || pReq->size == PRE_REQ32)&&
		freeCount < 2){
		return 2;
	}else if((pReq->size <= PRE_REQ16 &&pReq->size > PRE_REQ0)&&
		freeCount < 4){
		return 2;
	}else if(pReq->size == PRE_REQ0 &&
		freeCount < 8){
		return 2;
	}	
	usbproxy_log(LL_WARNING, "Readahead Cache Analy Finish[No Need To PreRead]");

	return 1;
}

static int preread_buffer_readaread(preRead *pRbuf)
{
	off_t offset;
	int readSize, readokSize = 0;
	
	if(!pRbuf){
		return -1;
	}
	offset = pRbuf->offsetLatestRequest*SCSI_SECTOR_SIZE+pRbuf->sizeLatestRequest;
	if(pRbuf->sizeLatestRequest >= PRE_REQ128){
		readSize = PRE_REQ256*PREBUFFER_FACTOR;
	}else if(pRbuf->sizeLatestRequest >= PRE_REQ32){
		readSize = PRE_REQ128*PREBUFFER_FACTOR;
	}else if(pRbuf->sizeLatestRequest >= PRE_REQ8){
		readSize = PRE_REQ64*PREBUFFER_FACTOR;
	}else{
		readSize = PRE_REQ16*PREBUFFER_FACTOR;
	}
	pread_buffer_resetbuf(&(pRbuf->buffer));
	pRbuf->buffer.cacheSectorStart = pRbuf->offsetLatestRequest+
						pRbuf->sizeLatestRequest/SCSI_SECTOR_SIZE;
	if((readokSize = preread_buffer_readfrom_disk(pRbuf->diskfd, offset, 
					pRbuf->buffer.buffPayload, readSize)) < 0){
		usbproxy_log(LL_ERROR, "ReadFrom Disk Error:%d:%dBytes", 
						pRbuf->diskfd, readSize);		
		pread_buffer_resetbuf(&(pRbuf->buffer));
		return -1;
	}
	pRbuf->buffer.cacheSize = readokSize;
	usbproxy_log(LL_WARNING, "ReadFrom Disk Successful:");	
	pread_buffer_printbuf(pRbuf);
	
	return 0;
}

void* thread_buffer_readahead(void *args)
{
	preRead *pRbuf;
	int res;
	
	while(1){
		/*Lock it*/
		pthread_mutex_lock(&mutexPreadReq);
		while(pReadReqStatus != PRE_REQNEW){
			pthread_cond_wait(&conPreadReq, &mutexPreadReq);
		}
		/*we lock handle reqeust*/
		usbproxy_log(LL_WARNING, "Readahead Handle Request:wlen=%d offset=%lld size=%d", 
						pReadReq.wlun, pReadReq.offset, pReadReq.size);
		pRbuf = pRead[pReadReq.wlun];
		res = preread_buffer_getcontent(pRbuf, &pReadReq);
		pthread_mutex_unlock(&mutexPreadReq);

		/*notify to request thread*/
		pthread_mutex_lock(&mutexPreadRes);		
		if(res < 0){
			pReadReqStatus = PRE_REQERR;	
		}else{
			pReadReqStatus = PRE_REQFIN;	
		}
		pthread_cond_signal(&conPreadRes);
		pthread_mutex_unlock(&mutexPreadRes);
	
		if(res == 2){
			/*Need to preread*/
			usbproxy_log(LL_WARNING, "Readahead Because OF:wlen=%d offset=%lld size=%d", 
							pReadReq.wlun, pReadReq.offset, pReadReq.size);			
			preread_buffer_readaread(pRbuf);
		}
	}
}

int preread_storage_init(void)
{
	int diskNum = 0;
	preRead *pRbuf = NULL;
	int res;

	memset(pRead, 0, sizeof(pRead));
	for(diskNum = 0; diskNum < STOR_NUM; diskNum++){
		char diskName[512] = {0};
		if(!storage_find(diskNum, diskName, sizeof(diskName)-1)){
			pRead[diskNum] = NULL;
			continue;
		}
		/*Set readahead*/
		blockdev_readahead(diskName, PREBUFFER_SIZE/SCSI_SECTOR_SIZE);		
		/*PreBUffer init*/
		usbproxy_log(LL_WARNING, "Multi Disk Readahead[%d->%s]...", diskNum, diskName);
		pRbuf = calloc(1, sizeof(preRead));
		if(!pRbuf){
			usbproxy_log(LL_WARNING, "Multi Disk Readahead[%d->%s] Error[%s]...", 
					diskNum, diskName, strerror(errno));
			pRead[diskNum] = NULL;			
			continue;
		}
		/*Set Value*/
		pRbuf->wlun = diskNum;
		pRbuf->diskfd = open(diskName, O_RDWR);
		if(pRbuf->diskfd < 0){
			usbproxy_log(LL_WARNING, "Multi Disk open[%d->%s] Error[%s]...", 
					diskNum, diskName, strerror(errno));
			free(pRbuf);
			pRead[diskNum] = NULL;
			continue;
		}
		/*Init Prebuffer*/
		if(preread_buffer_init(&(pRbuf->buffer), pRbuf->diskfd, 0) < 0){
			usbproxy_log(LL_WARNING, "Multi Disk Init Buffer[%d->%s] Error[%s]...", 
					diskNum, diskName, strerror(errno));			
			close(pRbuf->diskfd);
			free(pRbuf);
			pRead[diskNum] = NULL;			
			continue;
		}
		/*Set Offset*/
		pRbuf->offset += pRbuf->buffer.cacheSize;
		/*Set Value*/
		pRead[diskNum] = pRbuf;
		usbproxy_log(LL_WARNING, "Multi Disk Readahead[%d->%s->%dBytes] Successful...", 
					diskNum, diskName, pRbuf->buffer.buffSize);		
	}
	/*Start Readahead thread to preread*/
	res = pthread_create(&threadPread, NULL, thread_buffer_readahead, NULL);
	if (res != 0) {
		usbmuxd_log(LL_ERROR, "ERROR: Could not start readahead thread!");
		preread_storage_destory();
		return -1;
	}
	usbproxy_log(LL_WARNING, "Multi Disk Readahead Init Finish...");
	return 0;
}

void preread_storage_destory(void)
{
	int diskNum = 0;
	preRead *pRbuf = NULL;
	
	for(diskNum=0; diskNum < STOR_NUM; diskNum++){
		pRbuf = pRead[diskNum];
		if(!pRbuf){
			continue;
		}
		usbproxy_log(LL_WARNING, "Multi Disk Destory [%d]...", diskNum);	
		if(pRbuf->buffer.buffBegin){
			free(pRbuf->buffer.buffBegin);
		}
		close(pRbuf->diskfd);
		free(pRbuf);
	}
}

/*
*payload must have memory to store data
*offset is sector offset
*/
int preread_storage_read(int16_t wlun, off_t offset, int32_t size, char *payload)
{
	char diskName[512] = {0};

	if(!payload){
		return -1;
	}
	/*We Check it just for safe*/	
	if(!storage_find(wlun, diskName, sizeof(diskName)-1)){
		usbproxy_log(LL_WARNING, "PreRead Not Found Disk%d...", wlun);	
		return -1;
	}
	/*Check Preread List again*/
	if(!pRead[wlun] &&
			preread_buffer_reinit(wlun, diskName) < 0){
		usbproxy_log(LL_WARNING, "PreRead MayBe Something Error[REINIT %d]...", wlun);
		return -1;
	}
	/*Prepare to read buffer*/
	if(preread_buffer_read(wlun, offset, size, payload) < 0){
		usbproxy_log(LL_WARNING, "PreRead Buffer Read Error...");
		return -1;
	}

	return 0;
}

int preread_plug_handle(int16_t wlun, char *diskName, int action)
{
	preRead *pRbuf = NULL;

	if(action != PRE_ADD &&
			action != PRE_REMOVE){
		usbproxy_log(LL_WARNING, "PreRead Not Handle Event %d...", action);
		return -1;
	}
	if(wlun > STOR_NUM-1){
		usbproxy_log(LL_WARNING, "PreRead Not Handle To Much Disk %d...", wlun);
		return -1;
	}
	
	if(action == PRE_ADD){
		if(pRead[wlun]){
			usbproxy_log(LL_WARNING, "We need to Close Previous DiskInfo[%d]...", wlun);
			close(pRead[wlun]->diskfd);
			pRead[wlun]->diskfd = -1;
			if(pRead[wlun]->buffer.buffBegin){				
				usbproxy_log(LL_WARNING, "Free Previous PreBuffer Memory[%d]...", wlun);
				free(pRead[wlun]->buffer.buffBegin);
			}
			free(pRead[wlun]);
			pRead[wlun] = NULL;
		}
		usbproxy_log(LL_WARNING, "Preread Handle disk %d ADD Event[Calloc Memory]...", wlun);		
		pRbuf = calloc(1, sizeof(preRead));
		if(!pRbuf){
			usbproxy_log(LL_WARNING, "Multi Disk Readahead[%d->%s] Error[%s]...", 
					wlun, diskName, strerror(errno));
			pRead[wlun] = NULL;			
			return -1;
		}
		/*Set readahead*/
		if(diskName){
			blockdev_readahead(diskName, PREBUFFER_SIZE/SCSI_SECTOR_SIZE);		
		}
		/*Set Value*/
		pRbuf->wlun = wlun;
		pRbuf->diskfd = open(diskName, O_RDWR);
		if(pRbuf->diskfd < 0){
			usbproxy_log(LL_WARNING, "Multi Disk open[%d->%s] Error[%s]...", 
					wlun, diskName, strerror(errno));
			free(pRbuf);
			pRead[wlun] = NULL;
			return -1;
		}
		/*Init Prebuffer*/
		if(preread_buffer_init(&(pRbuf->buffer), pRbuf->diskfd, 0) < 0){
			usbproxy_log(LL_WARNING, "Multi Disk Init Buffer[%d->%s] Error[%s]...", 
					wlun, diskName, strerror(errno));			
			close(pRbuf->diskfd);
			free(pRbuf);
			pRead[wlun] = NULL;			
			return -1;
		}
		/*Set Offset*/
		pRbuf->offset += pRbuf->buffer.cacheSize;
		/*Set Value*/
		pRead[wlun] = pRbuf;
		usbproxy_log(LL_WARNING, "Preread Handle disk %d ADD Event[Successful]...", wlun);		
	}else if(action == PRE_REMOVE){
		usbproxy_log(LL_WARNING, "Preread Handle disk %d Remove Event..", wlun);
		/*We just close the fd, not free memory, because read thread may be reading disk*/
		if(!pRead[wlun]){
			usbproxy_log(LL_WARNING, "Preread Handle disk %d Remove Event[Finish Empty]..", wlun);
			return 0;
		}
		close(pRead[wlun]->diskfd);
		pRead[wlun]->diskfd = -1;
		usbproxy_log(LL_WARNING, "Preread Handle disk %d Remove Event[Successful]..", wlun);		
	}

	return 0;
}
