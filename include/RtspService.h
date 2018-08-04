#ifndef _RTSP_SERVICE_H_
#define _RTSP_SERVICE_H_

#include "pthread.h"

/**
* RtspService
*设置参数，获取摄像数据
**/

class RtspService {

public:
	RtspService();
	~RtspService();
	static RtspService *GetInstance();

public:
	//Get the Video stream
	void OnRun();
	void OnRtspVideoData(unsigned char *pData, int len, int nKeyFrame, unsigned int nTimeStamp);
	void OnRtspJPEGData(unsigned char *pData, int len, int nKeyFrame, unsigned int nTimeStamp);
	void OnRtspMPEG4Data(unsigned char *pData, int len, int nKeyFrame, unsigned int nTimeStamp);
	void Start();
	void Stop();
	void SetAuthInfo(bool bEnable, char *pUserName, char *pPassword);
	static void *OnThread(void *pData);
	void SetParams(int nAudioEnable, int nEncType, int nFramerate, int nBitrate, int nWidth, int nHeight, int nQuality);

private:
	pthread_t m_tid;
	static RtspService *m_pRtspService;
	int m_nWidth, m_nHeight;
	int m_nFramerate, m_nBitrate;
	int m_nAudioEnable;
	int m_nEncType;
	int m_nQuality;
	bool m_bRunning;
	bool m_bParseSPS;
	bool m_bParamChanged;

};

RtspService *GetRtspServiceInstance();

void RtspSetAuthInfo(bool bAuth, const char *pUserName, const char *pPassword);

#endif