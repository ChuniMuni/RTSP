#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include "RtspService.h"
#include "RtspServer.h"

#define BITSTREAM_LEN (1280*720*3/2)

static unsigned int getSystemTimeUS(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return tv.tv_sec * 1000 * 1000 + tv.tv_usec;
}

RtspService* RtspService::m_pRtspService = NULL;

void *RtspService::OnThread(void *pData)
{
	GetRtspServiceInstance()->OnRun();
	return NULL;
}

RtspService *RtspService::GetInstance()
{
	if(m_nRtspService == NULL)
		m_nRtspService = new RtspService();

	return m_pRtspService;
}

RtspService::RtspService()
:m_nEncType(RTSP_MEDIA_TYPE_H264)
,m_bRunning(false)
,m_bParamChanged(false)
,m_tid(0)
{
	m_nWidth = 1280;
	m_nHeight = 720;
	m_nFramerate = 30;
	m_nBitrate = 1000;
	m_nQuality = 70;
}

RtspService::~RtspService()
{

}

void RtspService::Start()
{

}

void RtspService::Start()
{
	if(m_tid)
	{
		m_bRunning = false;
		pthread_join(m_tid, NULL);
		m_tid = 0;
	}
}

void RtspService::OnRun()
{

}

RtspService *GetRtspServiceInstance()
{
	return RtspService::GetInstance();
}