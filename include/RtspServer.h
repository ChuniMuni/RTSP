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

#include "buffer_link.h"

#define RTSP_SERVER_PORT 554
#define MAX_CLIENT 32
#define BUFFER_LINK_MAX_LEN 32 // 32
#define RTP_MAX_LEN 1400

#define RTSP_LOCAL_RTP_PORT  60000
#define RTSP_LOCAL_RTCP_PORT 60001

#define RTSP_MEDIA_TYPE_H264 0
#define RTSP_MEDIA_TYPE_MPEG4 1
#define RTSP_MEDIA_TYPE_MJPEG 2

#define PTHREAD_LIBVA_DEFAULT_SIZE (40*1024)

#define LOCAL_ETHERNET_NAME "ens33"

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
		m_bTcp = false;
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
		m_strNonce = GetRandomNonce();
	}

	std::string getRandSessionId()
	{
		 std::string strRandSessionId;
		 int i;
		 char buf[2];
		 char c;
		 for(i = 0; i < 20; i++)
		 {
		 	c = random()%16;
		 	sprintf(buf, "%X", c);
		 	strRandSessionId.push_back(buf[0]);
		 }
		 return strRandSessionId;
	}

	std::string getSessionId()
	{
		return map["Session"];
	}

	const char *getRemoteIp()
	{
		return m_strRemoteIp.c_str();
	}

	void Start()
	{
		m_bPlay = true;
	}

	void Stop()
	{
		m_bPlay = false;
	}

	int getRemoteRtpPort()
	{
		return m_nRtpPort;
	}

	bool isPlay()
	{
		return m_bPlay;
	}

	uint32_t getSSRC()
	{
		return m_nSSRC;
	}

	bool isSendSSP()
	{
		return m_bSendSSP;
	}

	bool isSendKeyFrame()
	{
		return m_bSendKeyFrame;
	}

	void setSendKeyFrame(bool bValue)
	{
		m_bSendKeyFrame = bValue;
	}

	void setSendSPS(bool bValue)
	{
		m_bSendSSP = bValue;
	}

	int getRtpSock()
	{
		return m_nRtpSock;
	}

	bool isDelaySendOk()
	{
		if(m_nDelaySendTick > 0)
		{
			m_nDelaySendTick--;
			return false;
		}

		return true;
	}

	int getRtcpSock()
	{
		if(m_bTcp)
			return m_nRtpSock;
		else
			return m_nRtcpSock;
	}

	void setRtpSock(int fd, bool bValue = false)
	{
		m_nRtpSock = fd;
		m_bTcp = bValue;
	}

	void setRtcpSock(int fd)
	{
		m_nRtcpSock = fd;
	}

	bool isTcp()
	{
		return m_bTcp;
	}

	bool isUseCameraTimestamp()
	{
		return m_bUseCameraTimestamp;
	}

	void setUserCameraTimestamp(bool bValue)
	{
		m_bUseCameraTimestamp = bValue;
	}

	void setStartTimestamp(unsigned int nTimestamp)
	{
		m_nStartTimestamp = nTimestamp;
	}

	void setTcpConnectPort(unsigned short nPort)
	{
		m_nTcpPort = nPort;
	}

	void setVideoWidth(unsigned short nWidth)
	{
		m_nWidth = nWidth;
	}

	void setVideoHeight(unsigned short nHeight)
	{
		m_nHeight = nHeight;
	}

	unsigned int getCurTimestamp()
	{
		if(m_bUseCameraTimestamp)
			return (m_nTimestamp - m_nStartTimestamp) * 90;
		else
			return m_nTimestamp;
	}

	void ClearMap()
	{
		map.clear();
	}

	void AddData(std::string strKey, std::string strValue)
	{
		map[strKey] = strValue;
	}

	std::string GetData(std::string strKey)
	{
		std::string strValue;
		if(map.find(strKey) == map.end())
			return strValue;
		strValue = map[strKey];
		return strValue;
	}

	int getEncodeType()
	{
		return m_nEncodeType;
	}

	bool isLastData()
	{
		return m_bLastData;
	}

	std::string GetRandomNonce();
	std::string GetNonce() {return m_strNonce;}

public:
	bool m_bPlay;
	bool m_bSendSSP, m_bSendKeyFrame, m_bUseCameraTimestamp;
	bool m_bTcp;
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
	int m_nFrameLen;
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
	struct timeval timeUpdated;
	std::string m_strNonce;
};


class RtspServer{

public:
	RtspServer();
	~RtspServer();
	static RtspServer *GetInstance();

public:
	int Start();
	int Stop();
	void setRunState(int nState);
	int getRunState();
	int CreateSrvFd();
	void OnRun();
	void OnParseRequest(int fd, std::string strRequest);
	void OnResponseRequest(int fd, RtspClientData *pData);
	int OnHttpPostRequest(int fd, std::string strRequest);
	void addClientDataMap(int fd, RtspClientData *pData);
	void RemoveClientDataMap(int fd);
	void RemoveClientDataMap(char *pszRemoteIp, int nPort);
	bool isClientExpired(RtspClientData *pData);
	bool isClientDataExisted(char *pszRemoteIp, int nPort);
	int RemoveClientDataInSameIp(char *pszRemoteIp, int nPort);
	int RemoveAllClient(bool bSignal = true);
	int FindHttpConnection(unsigned short nHttpPort);
	void UpdateClientDataMap(char *pszRemoteIp, int nPort, int nExpires);
	RtspClientData *getClientDataMap(int fd);

	std::string getLocalIp();
	std::string getRtspStreamType();
	
public:
	void OnRtpRun();
	void lock();
	void unlock();
	int getRtspClientNum();
	int addH264Data(char *nBuf, int nLen, unsigned int nTimestamp);
	int addJPEGData(char *nBuf, int nLen, unsigned int nTimestamp);
	void setH264SPS(char *ptr, int nLen);
	void setH264PPS(char *ptr, int nLen);
	std::string getProfileLevelId();
	std::string getSpropParamterSets();
	void setH264Info(int nWidth, int nHeight, int fps, int bitrate);
	void setVideoInfo(int nWidth, int nHeight, int fps, int bitrate, int quality);
	bool isH264InfoChange(int nWidth, int nHeight, int fps, int bitrate);
	bool isVideoInfoChange(int nWidth, int nHeight, int fps, int bitrate, int quality);
	bool isStart();
	int getRtpSock();
	int getRtcpSock();
	void setEncodeType(int nType);
	int getEncodeType();
	void SetAuthInfo(bool bEnable, char *pUserName, char *pPassword);
	bool GetAuthResult(const char *pAuthorization, const char *pMethod);
	const char *GetMethodString(int nMethod);
	std::string CalcMD5(const char *pContent, int nLen = 0);
	std::string CalcDigiest(const char *pUserName, const char *pPassword, const char *pRealm, 
		const char *pNonce, const char *pMethod, const char *pUri);

public:
	static RtspServer *m_pRtspServer;

public:
#define RTSP_CMD_OPTIONS_STR "OPTIONS"
#define RTSP_CMD_DESCRIBE_STR "DESCRIBE"
#define RTSP_CMD_SETUP_STR "SETUP"
#define RTSP_CMD_TEARDOWN_STR "TEARDOWN"
#define RTSP_CMD_PLAY_STR "PLAY"
#define RTSP_CMD_PAUSE_STR "PAUSE"
#define RTSP_CMD_SET_PARAMETER_STR "SET_PARAMETER"
#define RTSP_CMD_SET_GET_PARAMETER_STR "GET_PARAMETER"
#define RTSP_CMD_GET_METHOD_STR "GET"
#define RTSP_CMD_POST_METHOD_STR "POST"
#define AUDIOBLK 320   //每帧20ms
enum {
	RTSP_CMD_OPTIONS,
	RTSP_CMD_DESCRIBE,
	RTSP_CMD_SETUP,
	RTSP_CMD_TEARDOWN,
	RTSP_CMD_PLAY,
	RTSP_CMD_PAUSE,
	RTSP_CMD_SET_PARAMETER,
	RTSP_CMD_SET_GET_PARAMETER,
	RTSP_CMD_GET,
	RTSP_CMD_POST,
	RTSP_CMD_MAX
};

private:
	pthread_t m_nTid, m_nRtpTid;
	pthread_mutex_t mMutex, mMutexClient;
	int m_nRunState;
	std::map<int, RtspClientData* > mRtspClientDataMap;
	BUFFER_LINK *m_pBufferLink;
	int m_nRtpSock, m_nRtcpSock;
	char *m_pSpsPtr, *m_pPpsPtr;
	int m_nSpsLen, m_nPpsLen;
	int m_nWidth, m_nHeight, m_nFrameRate, m_nBitrate, m_nQuality;
	int m_nEncType;
	bool m_bRemoveAllClient;
	int m_nSrvFD;
	bool m_bAuth;
	std::string m_strAuthUserName, m_strAuthPassword;

};

/**
 * @brief split h264 
 * 
 * @param ptr H264 Buffer
 * @param ptr_len H264 Buffer Len
 * @param len 
 * @return h264 splice ptr
 */
char *get_h264_frame(char *ptr, int ptr_len, int *len);

/**
 * @brief Rtsp Init
 * @return 0
 */
int rtsp_server_init();
/**
 * @brief reload rtsp cfg
 * @return 0 
 */
int rtsp_server_reload();

RtspServer *GetRtspServerInstance();

#endif