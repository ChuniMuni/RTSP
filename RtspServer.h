#ifndef _RTSP_SERVER_H_
#define _RTSP_SERVER_H_

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <string>
#include <map>
#include <vector>

#define RTSP_SERVER_PORT 554
#define MAX_CLIENT 32
#define BUFFER_LINK_MAX_LEN 32 // 32
#define RTP_MAX_LEN 1400

#define RTSP_LOCAL_RTP_PORT  60000
#define RTSP_LOCAL_RTCP_PORT 60001

#define RTSP_MEDIA_TYPE_H264 0
#define RTSP_MEDIA_TYPE_MPEG4 1
#define RTSP_MEDIA_TYPE_MJPEG 2

class RtspServerLock{

public:
	RtspServerLock(pthread_mutex_t *pMutex)
	{
		mpMutex = pMutex;
		pthread_mutex_lock(mpMutex);
	}

	~RtspServerLock()
	{
		pthread_mutex_unlock(mpMutex);
	}
private:
	pthread_mutex_t *mpMutex;
};

class RtspClientData{

public:
	RtspClientData(int fd, char *pIp)
	{
		m_nFd = fd;
		m_bPlay = false;
		m_strRemoteIp = std::string(pIp);
		m_nSSRC = random();
		m_bSendSSP = false;
		m_nTimestamp = 0;
		m_nSeq = 0;
		m_nRtpPort = 0;
		m_nDelaySendTick = 5;
		m_bSendKeyFrame = false;
		m_bUseCameraTimestamp = false;
		m_bHttpGet = false;
		m_nEncodeType = RTSP_MEDIA_TYPE_H264;
		m_bLastData = false;
		m_nExpires = 0;
		m_nSendCount = 0;
		// m_strNonce = GetRandomNonce();
	}

public:
	bool m_bPlay;
	bool m_bSendSSP, m_bSendKeyFrame, m_bUseCameraTimestamp;
	bool m_bHttpGet; //是否是HTTP GET 连接
	int m_nFd;
	int m_nSeqNum;
	int m_nMethod;
	int m_nRtpPort, m_nRtcpPort;
	unsigned short m_nTcpPort;
	std::string m_strSessionId;
	std::string m_strClientPort;
	std::string m_strRemoteIp;
	std::map<std::string, std::string> map; //客户端缓存

	char *m_pFrame;
	int *m_nFrameLen;
	int m_nWidth;
	int m_nHeight;
	bool m_bFua;
	int m_nRtpSock, m_nRtcpSock;
	int m_nExpires;
	int m_nSendCount;
	uint32_t m_nSSRC;
	uint32_t m_nTimestamp, m_nStartTimestamp;
	uint32_t m_nSeq;
	int m_nDelaySendTick;
	int m_nEncodeType;
	bool m_bLastData;
	// time_val timeUpdated;
	std::string m_strNonce;
};


#endif