#ifndef _STORAGE_H
#define _STORAGE_H
#include <stdint.h>

struct storage_action{
	int action;
	uint32_t location;
};

typedef void (*stor_callback)(int , int);
enum{
	STOR_ADD,
	STOR_REM
};


int storage_init(void);
int storage_action_handle(struct storage_action *action, stor_callback callback);
int storage_find(int diskID, char *dev, int len);

#endif

