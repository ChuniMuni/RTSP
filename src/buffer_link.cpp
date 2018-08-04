#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include "buffer_link.h"

BUFFER_LINK * buffer_link_new(int len)
{
	BUFFER_LINK *pBufferLink;
	if (len <= 0)
		return NULL;

	pBufferLink = (BUFFER_LINK*)malloc(sizeof(BUFFER_LINK));
	if (!pBufferLink)
		return NULL;
	memset(pBufferLink, 0x0, sizeof(BUFFER_LINK));
	pBufferLink->max = len;

	pthread_mutex_init(&pBufferLink->mutex, NULL);
	pthread_cond_init(&pBufferLink->cond, NULL);
	return pBufferLink;
}

void buffer_link_del(BUFFER_LINK *pBufferLink)
{
	BUFFER_LINK_DATA *pData;
	if (!pBufferLink)
		return;

	buffer_link_clear(pBufferLink);
	pthread_mutex_destroy(&pBufferLink->mutex);
	pthread_cond_destroy(&pBufferLink->cond);

	free(pBufferLink);
}

void buffer_link_clear(BUFFER_LINK * pBufferLink)
{
	BUFFER_LINK_DATA *pData, *pNext;
	pthread_mutex_lock(&pBufferLink->mutex);
	pData = pBufferLink->data;
	while (pData) {
		if (pData != NULL) {
			free(pData->ptr);
			pNext = pData->next;
			free(pData);
			pData = pNext;
		}
	}
	pBufferLink->data = NULL;
	pBufferLink->num = 0;
	pthread_mutex_unlock(&pBufferLink->mutex);
}


int buffer_link_add(BUFFER_LINK *pBufferLink, char *ptr, int len, unsigned int timestamp)
{
	BUFFER_LINK_DATA *pData, *pTail;
	pthread_mutex_lock(&pBufferLink->mutex);
	if (buffer_link_isfull(pBufferLink)) {
		printf("%s full..\n", __FUNCTION__);
		pthread_mutex_unlock(&pBufferLink->mutex);
		return -1;
	}

	pData = (BUFFER_LINK_DATA *)malloc(sizeof(BUFFER_LINK_DATA));
	if (!pData) {
		printf("malloc fail:%s\n", strerror(errno));
		pthread_mutex_unlock(&pBufferLink->mutex);
		return -1;
	}

	memset(pData, 0, sizeof(BUFFER_LINK_DATA));
	pData->len = len;
	pData->ptr = (char *)malloc(len);
	pData->timestamp = timestamp;
	if (!pData->ptr) {
		printf("malloc fail:%s %d\n", strerror(errno), __LINE__);
		printf("malloc fail:%s %d\n", strerror(errno), __LINE__);
		printf("malloc fail:%s %d\n", strerror(errno), __LINE__);
		free(pData);
		pthread_mutex_unlock(&pBufferLink->mutex);
		return -2;
	}
	memcpy(pData->ptr, ptr, len);

	pTail = pBufferLink->data;
	if (pTail == NULL)
		pBufferLink->data = pData;
	else {
		while (pTail && pTail->next != NULL)
			pTail = pTail->next;
		pTail->next = pData;
	}

	pBufferLink->num++;
	pthread_mutex_unlock(&pBufferLink->mutex);
	pthread_cond_signal(&pBufferLink->cond);
	return 0;
}

BUFFER_LINK_DATA* buffer_link_get(BUFFER_LINK *pBufferLink)
{
	BUFFER_LINK_DATA *pData, *pNext;
	if(NULL == pBufferLink)
		return NULL;

	pthread_mutex_lock(&pBufferLink->mutex);
	if (buffer_link_isempty(pBufferLink)) {
		//printf("empty...\n");
		pthread_mutex_unlock(&pBufferLink->mutex);
		return NULL;
	}

	pData = pBufferLink->data;
	if(NULL == pData)
	{
		pthread_mutex_unlock(&pBufferLink->mutex);
		return NULL;
	}
		
	pBufferLink->data = pData->next;
	pBufferLink->num--;
	pthread_mutex_unlock(&pBufferLink->mutex);
	//printf("%s num:%d\n", __FUNCTION__, pBufferLink->num);

	return pData;
}

void buffer_link_lock(BUFFER_LINK *pBufferLink)
{
	pthread_mutex_lock(&pBufferLink->mutex);
}

void buffer_link_unlock(BUFFER_LINK *pBufferLink)
{
	pthread_mutex_unlock(&pBufferLink->mutex);
}

int buffer_link_isfull(BUFFER_LINK *pBufferLink)
{
	if (pBufferLink->num == pBufferLink->max)
		return 1;
	return 0;
}

int buffer_link_isempty(BUFFER_LINK *pBufferLink)
{
	if (pBufferLink->num == 0)
		return 1;
	return 0;
}

void buffer_link_wait(BUFFER_LINK *pBufferLink, int timeout)
{
	struct timespec abstime;
	if (!buffer_link_isempty(pBufferLink)) {
		//printf("not empty just return\n");
		return;
	}
	if (timeout > 0) {
		clock_gettime(CLOCK_REALTIME, &abstime);
		abstime.tv_sec += timeout / 1000 + (abstime.tv_nsec + timeout * 1000) / 1000000;
		abstime.tv_nsec = (abstime.tv_nsec + timeout * 1000) % 1000000;
		pthread_cond_timedwait(&pBufferLink->cond, &pBufferLink->mutex, &abstime);
	}
	else
		pthread_cond_wait(&pBufferLink->cond, &pBufferLink->mutex);
}

void buffer_link_data_free(BUFFER_LINK_DATA *pBufferLinkData)
{
	if (pBufferLinkData) {
		free(pBufferLinkData->ptr);
		free(pBufferLinkData);
	}
}

int buffer_link_get_length(BUFFER_LINK *pBufferLink)
{
	return pBufferLink->num;
}

