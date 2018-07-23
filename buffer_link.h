#ifndef _BUFFER_LINK_
#define _BUFFER_LINK_
#include <pthread.h>
typedef struct _BUFFER_LINK_DATA {
	char *ptr;
	int len;
	unsigned int timestamp;
	struct _BUFFER_LINK_DATA *next;
}BUFFER_LINK_DATA;

typedef struct _BUFFER_LINK{
	BUFFER_LINK_DATA *data; // 指向链表TOP
	int max; // 链表最大数
	int num; // 链表当前数值
	pthread_mutex_t mutex;
	pthread_cond_t cond;
}BUFFER_LINK;


BUFFER_LINK *buffer_link_new(int len);
void buffer_link_del(BUFFER_LINK *pBufferLink);
void buffer_link_clear(BUFFER_LINK *pBufferLink);
int buffer_link_add(BUFFER_LINK *pBufferLink, char *ptr, int len, unsigned int timestamp=0);
BUFFER_LINK_DATA *buffer_link_get(BUFFER_LINK *pBufferLink);
void buffer_link_lock(BUFFER_LINK *pBufferLink);
void buffer_link_unlock(BUFFER_LINK *pBufferLink);
void buffer_link_wait(BUFFER_LINK *pBufferLink, int timeout);
int buffer_link_isempty(BUFFER_LINK *pBufferLink);
int buffer_link_isfull(BUFFER_LINK *pBufferLink);
int buffer_link_get_length(BUFFER_LINK *pBufferLink);

void buffer_link_data_free(BUFFER_LINK_DATA *pBufferLinkData);

#endif