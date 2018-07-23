#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string>
#include <sstream>
// #include <devctrl/devctrl.h>
#include <openssl/md5.h>

#include "RtspServer.h"
#include "Base64.h"
// #include "RtspService.h"

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#define RTP_HEADER_LEN 12

static int sock_fds[MAX_CLIENT];


std::string RtspClientData::GetRandomNonce()
{
	struct {
		struct timeval timestamp;
		unsigned counter;
	} seedData;
	gettimeofday(&seedData.timestamp, NULL);
	static unsigned counter = 0;
	seedData.counter = ++counter;

	std::string strNonce = GetRtspServerInstance()->CalcMD5((const char*)&seedData, sizeof(seedData));
	return strNonce;
}

std::string RtspServer::CalcMD5(const char *pContent, int nLen)
{
	std::string strMD5;
	MD5_CTX md5CTX;  
	char szBuf[256] = {0};
	char szTmpBuf[8] = {0};
	unsigned char szMD5[17] = {0};

	MD5_Init(&md5CTX);
	if (nLen == 0)
		nLen = strlen(pContent);
	MD5_Update(&md5CTX, pContent, nLen);
	MD5_Final(szMD5, &md5CTX);

	for (int i=0; i<16; i++) {
		memset(szTmpBuf, 0, sizeof(szTmpBuf));
		sprintf(szTmpBuf, "%02x", szMD5[i]);
		strcat(szBuf, szTmpBuf)	;
	}
	// printf("szBuf:%s\n", szBuf);
	strMD5 = szBuf;
	return strMD5;
}

int fds_get_max(int *fds, int len)
{
	int max = 0;
	int i = 0;
	for (i = 0; i < len; i++)
		if (fds[i] > max)
			max = fds[i];
	return max;
}

int fds_remove(int *fds, int len, int fd)
{
	int i;
	for (i = 0; i < len; i++) {
		if (fds[i] == fd) {
			fds[i] = 0;
			return 0;
		}
	}
	return -1;
}

int fds_add(int *fds, int len, int fd)
{
	int i;
	for (i = 0; i < len; i++) {
		if (fds[i] == 0) {
			fds[i] = fd;
			return 0;
		}
	}
	return -1;
}

int fds_set(int *fds, int len, fd_set *prfds)
{
	int i, tick = 0;
	FD_ZERO(prfds);
	for (i = 0; i < len; i++) {
		if (fds[i] > 0) {
			FD_SET(fds[i], prfds);
			tick++;
		}
	}
	// printf("FD NUM:%d\n", tick);
	return 0;
}

int fds_get_revent(int *fds, int len, fd_set *prfds)
{
	int i;
	for (i = 0; i < len; i++) {
		if (fds[i] > 0) {
			if (FD_ISSET(fds[i], prfds))
				return fds[i];
		}
	}
	return 0;
}

static void string_split(std::string& s, std::string& delim, std::vector< std::string >* ret)
{
	size_t nLast = 0;
	size_t nIndex = s.find(delim, nLast);
	
	while(nIndex != std::string::npos)
	{
		ret->push_back(s.substr(nLast, nIndex - nLast));
		nLast = nIndex + delim.size();
		nIndex = s.find(delim, nLast);
	}
	
	if(nIndex - nLast > 0)
		ret->push_back(s.substr(nLast, nIndex - nLast));
}

static void string_trim_split(std::string &strString, std::string& delim)
{
	if(strString.empty())   
    {  
        return;  
    }
    size_t lastPos = 0;
   	size_t curPos = strString.find(delim, lastPos);
   	
   	while(curPos != std::string::npos)
   	{
   		strString.erase(curPos, delim.size());
   		lastPos=curPos+delim.size();
   		curPos = strString.find(delim, lastPos);
   	}
}

//jepg luminance quantization table
static const unsigned char jpeg_luma_quantizer[64] = {  
	0x0d, 0x09, 0x0a, 0x0b, 0x0a, 0x08, 0x0d, 0x0b, 0x0a, 0x0b, 0x0e, 0x0e, 0x0d, 0x0f, 0x13, 0x20,
  	0x15, 0x13, 0x12, 0x12, 0x13, 0x27, 0x1c, 0x1e, 0x17, 0x20, 0x2e, 0x29, 0x31, 0x30, 0x2e, 0x29,
  	0x2d, 0x2c, 0x33, 0x3a, 0x4a, 0x3e, 0x33, 0x36, 0x46, 0x37, 0x2c, 0x2d, 0x40, 0x57, 0x41, 0x46,
  	0x4c, 0x4e, 0x52, 0x53, 0x52, 0x32, 0x3e, 0x5a, 0x61, 0x5a, 0x50, 0x60, 0x4a, 0x51, 0x52, 0x4f,
};  

//jepg chrominance quantization table
static const unsigned char jpeg_chroma_quantizer[64] = {
	0x0e, 0x0e, 0x0e, 0x13, 0x11, 0x13, 0x26, 0x15, 0x15, 0x26, 0x4f, 0x35, 0x2d, 0x35, 0x4f, 0x4f,
	0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f,
	0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f,
	0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f,
};

struct JPEG_HEADER {
    unsigned char tspec;   /* type-specific field */
    unsigned char off[3];  /* fragment byte offset */
    unsigned char type;    /* id of jpeg decoder params */
    unsigned char q; 	   /* quantization factor (or table id) */
    unsigned char width;   /* frame width in 8 pixel blocks */
    unsigned char height;  /* frame height in 8 pixel blocks */
};

struct JPEG_HEADER_QTABLE {
    unsigned char  mbz;
    unsigned char  precision;
    unsigned short length;
};

int rtp_jpeg(RtspClientData *pData)
{
	if(pData == NULL)
		return -1;
	struct sockaddr_in remote_addr;
	unsigned char rtp_buf[RTP_MAX_LEN*2];
	struct JPEG_HEADER jpegHeader;
	struct JPEG_HEADER_QTABLE jpegHeaderQtable;
	unsigned char *ptr = NULL;
    unsigned int offset = 0;
    unsigned int pos =0;
    unsigned int data_len;
    bool is_tcp;
    char *frame;
	int frame_len;
	int nVideoFlag = 0;
    uint32_t ssrc;
	uint16_t seq;
	uint32_t timestamp;
	int nPayloadOffset=RTP_HEADER_LEN, nRtpOffset=0;
    ssrc = pData->m_nSSRC;
	seq = pData->m_nSeq;
	is_tcp = pData->m_bTcp;
	frame = pData->m_pFrame;
	frame_len = pData->m_nFrameLen;
	timestamp = pData->getCurTimestamp();

	if(is_tcp) {
		// RTSP OVER TCP
		uint16_t rtp_package_len = RTP_HEADER_LEN + frame_len;
		rtp_buf[pos++] = '$'; // magic number
		rtp_buf[pos++] = 0x0; // channel 0 for rtp
		rtp_buf[pos++] = (rtp_package_len>>8) & 0xff;
		rtp_buf[pos++] = (rtp_package_len>>0) & 0xff;
		nPayloadOffset = 4 + RTP_HEADER_LEN;
		nRtpOffset = 4;
	}

	/* Initialize RTP header*/
	rtp_buf[pos++] = 0x80;//version:2
	rtp_buf[pos++] = (0x1A & 0x7f);//payload:26
	rtp_buf[pos++] = (seq>>8) & 0xff; // seq
	rtp_buf[pos++] = (seq>>0) & 0xff;
	rtp_buf[pos++] = (timestamp>>24) &0xff;
	rtp_buf[pos++] = (timestamp>>16) &0xff;
	rtp_buf[pos++] = (timestamp>>8) &0xff;
	rtp_buf[pos++] = (timestamp>>0) &0xff;
	rtp_buf[pos++] = (ssrc>>24) &0xff;
	rtp_buf[pos++] = (ssrc>>16) &0xff;
	rtp_buf[pos++] = (ssrc>>8) &0xff;
	rtp_buf[pos++] = (ssrc>>0) &0xff;

	/* Initialize JPEG header*/
	jpegHeader.tspec = 0;/*解码没有用*/
	jpegHeader.off[0] = 0;/*解码要用*/
	jpegHeader.off[1] = 0;/*解码要用*/
	jpegHeader.off[2] = 0;/*解码要用*/
	jpegHeader.type = 1;
	jpegHeader.q = 0xff;
	jpegHeader.width = (pData->m_nWidth/8)&0xff;
	jpegHeader.height = (pData->m_nHeight/8)&0xff;

	/* Initialize quantization table*/
	jpegHeaderQtable.mbz = 0;
	jpegHeaderQtable.precision = 0; 
	jpegHeaderQtable.length = htons(128); /* 2 64-byte quantization tables */

	/*rtp send socket*/
	int nByteLeft = pData->m_nFrameLen;
	memset(&remote_addr, 0x0, sizeof(remote_addr));

	int sock_fd = pData->getRtpSock();
	char *ip = (char*)pData->getRemoteIp();
	int remote_port = pData->getRemoteRtpPort();

	remote_addr.sin_family = AF_INET;
	remote_addr.sin_port = htons(remote_port);
	remote_addr.sin_addr.s_addr = inet_addr(ip);

	// jpeg数据很大，需要分包发送
	// 分包发送协议详见 RFC2435
	// 基本的包含一个Main JPEG HEADER
   //  0                   1                   2                   3
   //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   // | Type-specific |              Fragment Offset                  |
   // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   // |      Type     |       Q       |     Width     |     Height    |
   // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	while(nByteLeft > 0){
		memset(rtp_buf + nPayloadOffset, 0 , sizeof(rtp_buf) - nPayloadOffset);
		ptr = rtp_buf + nPayloadOffset;
		//add jpeg header
		memcpy(ptr, &jpegHeader, sizeof(jpegHeader));
		ptr += sizeof(jpegHeader);
		//one frame begins
		if(offset == 0){
			//拷贝量化表信息
			memcpy(ptr, &jpegHeaderQtable, sizeof(jpegHeaderQtable));
			//rl_log_err("%s-%d::Q table length %d\n",__FUNCTION__,__LINE__,jpegHeaderQtable.length);
			ptr += sizeof(jpegHeaderQtable);
			memcpy(ptr, jpeg_luma_quantizer, 64);
            ptr += 64;
            memcpy(ptr, jpeg_chroma_quantizer, 64);
            ptr += 64;
		}
		//data length to be sent
		data_len = RTP_MAX_LEN - (ptr - rtp_buf);
		//one frame ends
		if(data_len >= nByteLeft){
			data_len = nByteLeft;
			rtp_buf[1+nRtpOffset] = 0x9A;
		}
		//payload
		memcpy(ptr, pData->m_pFrame + offset, data_len);
		//send
		if (is_tcp) {
			// update rtsp over tcp len
			int nSendLen = (ptr - rtp_buf)+data_len;
			// fprintf(stderr, "== %s %s %d Len:%d data_len:%d== \n", __FILE__, __FUNCTION__, __LINE__, nSendLen, data_len);
			nSendLen -= nRtpOffset ;
			rtp_buf[2] = (nSendLen>>8) & 0xff;
			rtp_buf[3] = (nSendLen>>0) & 0xff;
			send(sock_fd, rtp_buf, (ptr - rtp_buf)+data_len, 0);
		}
		else
		{
			sendto(sock_fd, rtp_buf, (ptr - rtp_buf)+data_len, 0, (struct sockaddr*)&remote_addr, sizeof(remote_addr));
		}

		//更新seq num
		seq = ++pData->m_nSeq;
		rtp_buf[2 + nRtpOffset] = (seq>>8) & 0xff; // seq
		rtp_buf[3 + nRtpOffset] = (seq>>0) & 0xff;
		nByteLeft -= data_len;
		offset += data_len;
		jpegHeader.off[0] = (offset >>16) & 0xff;
		jpegHeader.off[1] = (offset >>8) & 0xff;
		jpegHeader.off[2] = (offset >>0) & 0xff;
	}
	return 0;
}

/**
 * @brief 发送RTP帧(H264)
 * 
 * @param sock_fd udp句柄
 * @param ip 目标IP地址
 * @param port 目标端口
 * @param ssrc 会话标识符
 * @param frame H264数据
 * @param frame_len H264长度
 * @param is_fua 是否H264片段(time不增加)
 * @return <0 出错
 */
int rtp_send(RtspClientData *pData)
{
	char rtp_buf[RTP_MAX_LEN];
	struct sockaddr_in remote_addr;
	int remote_port;
	int pos=0;
	int nVideoFlag = 0;

	// static uint16_t seq = 0; // TODO:
	// static uint32_t timestamp = 0;

	#define TIMESTAMP_INTEVAL 3000 //
	char *frame;
	int frame_len;
	bool is_tcp;
	uint32_t ssrc;
	int sock_fd;
	char *ip;
	uint16_t seq;
	uint32_t timestamp;
	bool is_fua;
	uint32_t nal_type;

	sock_fd = pData->getRtpSock();
	ip = (char*)pData->getRemoteIp();
	remote_port = pData->getRemoteRtpPort();
	frame = pData->m_pFrame;
	frame_len = pData->m_nFrameLen;
	ssrc = pData->m_nSSRC;
	is_tcp = pData->m_bTcp;
	seq = pData->m_nSeq;
	timestamp = pData->getCurTimestamp();
	is_fua = pData->m_bFua;

	if (frame_len>RTP_MAX_LEN) {
		printf("packet too large\n");
		return -1;
	}

	switch(pData->getEncodeType()) {
		case RTSP_MEDIA_TYPE_H264:
		nal_type = frame[0] & 0x1f;
		if ((nal_type == 28 && frame[1]&(1<<6)) ||
			(nal_type == 1) || (nal_type == 5))
			nVideoFlag = 1<<7;
		break;

		case RTSP_MEDIA_TYPE_MPEG4:
		// MJPEG4 传输中使用 Mark来标记是否为最后一个包
		if (pData->isLastData())
			nVideoFlag = 1<<7;
		nal_type = 0x07; // 阻止timestamp增加
		break;
	}


	memset(rtp_buf, 0x0, sizeof(rtp_buf));
	if (is_tcp) {
		uint16_t rtp_package_len = RTP_HEADER_LEN + frame_len;
			rtp_buf[pos++] = '$'; // magic number
			rtp_buf[pos++] = 0x0; // channel 0 for data
			rtp_buf[pos++] = (rtp_package_len>>8) & 0xff;
			rtp_buf[pos++] = (rtp_package_len>>0) & 0xff;
	}
	rtp_buf[pos++] = 0x80;
	rtp_buf[pos++] = 0x60 | nVideoFlag; //payload type
	rtp_buf[pos++] = (seq>>8) & 0xff; // seq
	rtp_buf[pos++] = (seq>>0) & 0xff;
	rtp_buf[pos++] = (timestamp>>24) &0xff;
	rtp_buf[pos++] = (timestamp>>16) &0xff;
	rtp_buf[pos++] = (timestamp>>8) &0xff;
	rtp_buf[pos++] = (timestamp>>0) &0xff;
	rtp_buf[pos++] = (ssrc>>24) &0xff;
	rtp_buf[pos++] = (ssrc>>16) &0xff;
	rtp_buf[pos++] = (ssrc>>8) &0xff;
	rtp_buf[pos++] = (ssrc>>0) &0xff;
	memcpy(rtp_buf+pos, frame, frame_len);



	memset(&remote_addr, 0x0, sizeof(remote_addr));
	remote_addr.sin_family = AF_INET;
	remote_addr.sin_port = htons(remote_port);
	remote_addr.sin_addr.s_addr = inet_addr(ip);

	if (is_tcp) {
		send(sock_fd, rtp_buf, pos+frame_len, 0);
	}
	else
		sendto(sock_fd, rtp_buf, pos+frame_len, 0, (struct sockaddr*)&remote_addr, sizeof(remote_addr));

	if (!is_fua && !(nal_type== 0x07 ||nal_type == 0x08))
		pData->m_nTimestamp += TIMESTAMP_INTEVAL;
	pData->m_nSeq++;

	return 0;
}

int rtp_h264_send(RtspClientData *pData)
{
	#define FRU_MAX_LEN 1300
	char rtp_buf[RTP_MAX_LEN];
	int pos=0;
	int fua_num = 0;
	int frame_pos = 0;
	int i, copy_len;
	uint8_t nal_type;
	bool is_fua;
	//int sock_fd, const char *ip, int port, uint32_t ssrc, char *frame, int frame_len, bool is_tcp)
	char *frame = pData->m_pFrame;
	int frame_len = pData->m_nFrameLen;

	// printf("frame_len:%d\n", frame_len);

	if (frame_len>FRU_MAX_LEN)
		fua_num = frame_len/FRU_MAX_LEN + 1;

	if (fua_num == 0) {
		rtp_send(pData);
		return 0;
	}

	frame_pos = 0;
	nal_type = frame[0] & 0x1f;
	// printf("fua_num:%d nal_type:%d\n", fua_num, nal_type);
	for (i=0; i<fua_num; i++) {
		pos = 0;
		if (i==0) {
			// FU-A Start
			rtp_buf[pos++] = 28 | (frame[0] & 0xE0); // FU identifier
			rtp_buf[pos++] = (1<<7) | nal_type; // start bit
			is_fua = true;
		}
		else if (i==(fua_num-1)) {
			// FU-A END
			rtp_buf[pos++] = 28| (frame[0] & 0xE0); // FU identifier
			rtp_buf[pos++] = (1<<6) | nal_type; // end bit
			is_fua = false;
		}
		else {
			rtp_buf[pos++] = 28 | (frame[0] & 0xE0);
			rtp_buf[pos++] = nal_type;
			is_fua = true;
		}

		if (frame_pos + FRU_MAX_LEN > frame_len-1) 
			copy_len = frame_len - frame_pos - 1;
		else 
			copy_len = FRU_MAX_LEN;

		memcpy(rtp_buf+pos, frame + frame_pos + 1, copy_len);
		pData->m_pFrame = rtp_buf;
		pData->m_nFrameLen = copy_len+2;
		pData->m_bFua = is_fua;
		rtp_send(pData);
		frame_pos += copy_len;
	}

	return 0;
}

int rtp_mpeg4_send(RtspClientData *pData)
{
	char rtp_buf[RTP_MAX_LEN];
	int pos=0;
	int num = 0;
	int frame_pos = 0;
	int i, copy_len;
	char *frame = pData->m_pFrame;
	int frame_len = pData->m_nFrameLen;

	pData->m_nEncodeType = RTSP_MEDIA_TYPE_MPEG4;

	if (frame_len>FRU_MAX_LEN)
		num = frame_len/FRU_MAX_LEN + 1;

	if (num == 0) {
		pData->m_bLastData = true;
		rtp_send(pData);
		return 0;
	}

	frame_pos = 0;
	for (i=0; i<num; i++) {
		copy_len = FRU_MAX_LEN;
		pData->m_bLastData = false;
		if (i==num-1) {
			// last data
			pData->m_bLastData = true;
			copy_len = frame_len - i*FRU_MAX_LEN;
		}

		memcpy(rtp_buf, frame + frame_pos, copy_len);
		pData->m_pFrame = rtp_buf;
		pData->m_nFrameLen = copy_len;
		pData->m_bFua = 0;
		rtp_send(pData);
		frame_pos += copy_len;
	}

	return 0;
}

static void *rtsp_server_func(void *data)
{
	printf("[%s-%d] ==RtspServer Start!!!==\n", __FUNCTION__, __LINE__);
	RtspServer *pRtspServer = (RtspServer *)data;
	pRtspServer->OnRun();
	return NULL;
}

static void *rtsp_server_rtp_func(void *data)
{
	RtspServer *pRtspServer = (RtspServer *)data;
	pRtspServer->OnRtpRun();
	return NULL;
}

RtspServer *RtspServer::m_pRtspServer;
RtspServer::RtspServer()
{
	m_nEncType = RTSP_MEDIA_TYPE_H264;
	m_nTid = 0;
	m_nRunState = 0;
	srandom(time(NULL));
	m_pSpsPtr = NULL;
	m_bRemoveAllClient = false;
	m_pPpsPtr = NULL;
	m_pBufferLink = buffer_link_new(BUFFER_LINK_MAX_LEN);
	pthread_mutex_init(&mMutex, NULL);
	pthread_mutex_init(&mMutexClient, NULL);
	m_bAuth = false;
}

RtspServer::~RtspServer()
{
	pthread_mutex_destroy(&mMutex);
	pthread_mutex_destroy(&mMutexClient);
	buffer_link_del(m_pBufferLink);
}

RtspServer* RtspServer::GetInstance()
{
	if (m_pRtspServer == NULL) {
		m_pRtspServer = new RtspServer();
	}

	return m_pRtspServer;
}

int RtspServer::Start()
{
	if (m_nTid != 0) {
		fprintf(stderr, "== %s %s %d == \n", __FILE__, __FUNCTION__, __LINE__);
		return -1;
	}

	setRunState(1);
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setstacksize(&attr, PTHREAD_LIBVA_DEFAULT_SIZE);	
	pthread_create(&m_nTid, &attr, rtsp_server_func, this);
	pthread_create(&m_nRtpTid, &attr, rtsp_server_rtp_func, this);
	pthread_attr_destroy(&attr);
	buffer_link_clear(m_pBufferLink);

	struct sockaddr_in addr;
	m_nRtpSock = socket(AF_INET, SOCK_DGRAM, 0);
	memset(&addr, 0x0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(RTSP_LOCAL_RTP_PORT);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	bind(m_nRtpSock, (struct sockaddr *)&addr, sizeof(addr));

	m_nRtcpSock = socket(AF_INET, SOCK_DGRAM, 0);
	memset(&addr, 0x0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(RTSP_LOCAL_RTCP_PORT);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	bind(m_nRtcpSock, (struct sockaddr *)&addr, sizeof(addr));
	printf("[%s-%d] ==RtspServer Start!!!==\n", __FUNCTION__, __LINE__);
	return 0;
}

int RtspServer::Stop()
{
	if (m_nTid == 0)
		return -1;

	setRunState(0);
	pthread_join(m_nTid, NULL);
	pthread_join(m_nRtpTid, NULL);
	buffer_link_clear(m_pBufferLink);
	close(m_nRtcpSock);
	close(m_nRtpSock);
	m_nTid = 0;
	m_nRtpTid = 0;
	m_nRtpSock = 0;
	m_nRtcpSock = 0;

	return 0;
}

void RtspServer::setRunState(int state)
{
	pthread_mutex_lock(&mMutex);
	m_nRunState = state;
	pthread_mutex_unlock(&mMutex);
}

int RtspServer::getRunState()
{
	return m_nRunState;
}

int RtspServer::OnHttpPostRequest(int fd, std::string strRequest)
{
	std::vector< std::string > lines;
	std::string strSplit("\r\n");
	RtspClientData *pData = getClientDataMap(fd);
	std::string decodeRequest;
	std::string strBase64;
	unsigned char *postRequest;
	unsigned int nDecLen;
	pData->map.clear();
	string_split(strRequest, strSplit, &lines);
	// 1.POST Method
	//如果是post消息需要把真正的请求转义出来
	if(lines[0].find(RTSP_CMD_POST_METHOD_STR) != std::string::npos){
		pData->m_nMethod = RTSP_CMD_POST;
		// printf("%s-%d::POST MSG last line %s\n",__FUNCTION__,__LINE__,lines[lines.size() - 1].c_str());
		if(lines[lines.size() - 1].find(":") == std::string::npos){
			// printf("%s-%d::POST MSG may contain base64 code\n",__FUNCTION__,__LINE__);
			strRequest.clear();
			strRequest = lines[lines.size() -1];
		}else{
			//不包含Base64消息就直接返回
			// printf("%s-%d::POST MSG not contain base64 code\n",__FUNCTION__,__LINE__);
			return 0;
		}
	}
	else if(pData->m_nMethod == RTSP_CMD_POST){
		// printf("%s-%d:: Receive POST BASE64 MSG, line num %d\n",__FUNCTION__,__LINE__,lines.size());
		if(lines.size() > 0){
			//需要先把换行符去掉
			string_trim_split(strRequest,strSplit);
		}
	}else{
		return -1;
	}
	if(!strRequest.empty()){
		postRequest = base64Decode((char *)strRequest.c_str(), &nDecLen, 1);
		decodeRequest = std::string((const char *)postRequest);
		delete postRequest;
		lines.clear();
		//将真正的请求分离出来
		string_split(decodeRequest, strSplit, &lines);
		//这里需要寻找真正的连接
		int nClientFd = FindHttpConnection(pData->m_nTcpPort);
		if(nClientFd > 0 && !decodeRequest.empty())
			OnParseRequest(nClientFd, decodeRequest);
		return 0;
	}	
	return -1;
}

void RtspServer::OnParseRequest(int fd, std::string strRequest)
{
	int i,j;
	std::vector< std::string > lines;
	std::string strSplit("\r\n");
	RtspClientData *pData = getClientDataMap(fd);
	char szMethod[64];
	char szURL[128];
	char szRtspVer[64];
	char *buf = (char*)strRequest.c_str();

	pData->ClearMap();
	printf("%s", buf);

	// Parse 
	char *ptr_key, *ptr_value, *ptr;
	char *saveptr0, *saveptr1;
	std::string strKey, strValue;

	ptr = strtok_r(buf, "\r\n", &saveptr0);

	// 1. Parse Method
	// DESCRIBE rtsp://192.168.1.220:554/live/ch00_0 RTSP/1.0

	sscanf(ptr, "%s %s %s", szMethod, szURL, szRtspVer);
	pData->AddData("Method", szMethod);
	pData->AddData("URL", szURL);
	pData->AddData("RtspVer", szRtspVer);
	
	const char* cmd_names[] = {RTSP_CMD_OPTIONS_STR, RTSP_CMD_DESCRIBE_STR, RTSP_CMD_SETUP_STR, RTSP_CMD_TEARDOWN_STR, 
		RTSP_CMD_PLAY_STR, RTSP_CMD_PAUSE_STR, RTSP_CMD_SET_PARAMETER_STR, RTSP_CMD_SET_GET_PARAMETER_STR, RTSP_CMD_GET_METHOD_STR,
		RTSP_CMD_POST_METHOD_STR};

	for (int i=0; i<(int)ARRAY_SIZE(cmd_names); i++) {
		if (strcmp(szMethod, cmd_names[i]) == 0) {
			pData->m_nMethod = i;
			break;
		}
	}

	if(pData->m_nMethod == RTSP_CMD_GET)
		pData->m_bHttpGet = true;

	// 过滤掉第一行
	ptr = strtok_r(NULL, "\r\n", &saveptr0);

	// Store Other Info
	while (ptr) {
		#if 1
		ptr_key = strstr(ptr, ":");
		if (ptr_key) {
			*ptr_key = 0;
			ptr_value = ptr_key+1;
			if (*ptr_value == ' ')
				ptr_value +=1;

			ptr_key = ptr;

			strKey = ptr_key;
			strValue = ptr_value;
			pData->AddData(strKey, strValue);
		}
		#else
		ptr_key = strtok_r(ptr, ":", &saveptr1); 
		if (ptr_key) {
			ptr_value = strtok_r(NULL, ":", &saveptr1);
			if (ptr_value) {
				strKey = ptr_key;
				if (*ptr_value == ' ')
					strValue = ptr_value+1;
				else
					strValue = ptr_value;
				pData->AddData(strKey, strValue);
			}
		}
		#endif

		ptr = strtok_r(NULL, "\r\n", &saveptr0);
	}

	// 2.CSeq
	std::string strCSeq = pData->GetData("CSeq");
	pData->m_nSeqNum = atoi(strCSeq.c_str());

	if(pData->m_nMethod != RTSP_CMD_GET && pData->m_nMethod != RTSP_CMD_POST) {
	// 3.others info, store into client data map
		std::string strTransport = pData->GetData("Transport");
		if (strTransport.size()!=0) {
			std::vector<std::string> tmpVector;
			std::string strSplit = ";";
			string_split(strTransport, strSplit, &tmpVector);
			for (j=0; j<(int)tmpVector.size(); j++) {
				if (tmpVector[j].find("client_port")!=std::string::npos) {
					pData->m_strClientPort = tmpVector[j];
					sscanf(pData->m_strClientPort.c_str(), "client_port=%d-%d", &pData->m_nRtpPort, &pData->m_nRtcpPort);
					break;
				}
			}
		}
	}
	
	OnResponseRequest(fd, pData);
}

void RtspServer::OnResponseRequest(int fd, RtspClientData *pData)
{
	std::string strResponse; 
	std::string strSDP;
	char buf[2048] = {0};

	// 增加鉴权方法同Http
	if (m_bAuth) {
		bool bAuthSucc = false;
		std::string strAuthorization = pData->GetData("Authorization");
		if (strAuthorization.size()!=0) 
			bAuthSucc = GetAuthResult(strAuthorization.c_str(), GetMethodString(pData->m_nMethod));

		if (!bAuthSucc && pData->m_nMethod != RTSP_CMD_OPTIONS) {
			sprintf(buf, "RTSP/1.0 401 Unauthorized\r\nCSeq: %d\r\nServer: Easy Rtsp 1.0\r\nWWW-Authenticate: Digest realm=\"Easy RTSP\", nonce=\"%s\", stale=\"FALSE\"\r\n\r\n", pData->m_nSeqNum, pData->GetNonce().c_str());
			goto _response_out;
		}
	}

	switch(pData->m_nMethod) {
		case RTSP_CMD_OPTIONS:
		sprintf(buf, "RTSP/1.0 200 OK\r\nCSeq: %d\r\nServer: Easy Rtsp 1.0\r\nPublic: DESCRIBE, SETUP, TEARDOWN, PLAY, PAUSE, SET_PARAMETER, GET_PARAMETER\r\n\r\n", 
			pData->m_nSeqNum);
		break;

		case RTSP_CMD_DESCRIBE:{
		memset(buf, 0x0, sizeof(buf));
		switch (getEncodeType()) {
			case RTSP_MEDIA_TYPE_MJPEG:
			sprintf(buf, "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=Easy Rtsp 1.0\r\ni=Easy\r\nc=IN IP4 0.0.0.0\r\nt=0 0\r\nm=video 0 RTP/AVP 26\r\nb=AS:5000\r\na=fmtp:26 config=\r\na=control:trackID=0\r\n");
			break;

			case RTSP_MEDIA_TYPE_MPEG4:
			sprintf(buf, "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=Easy Rtsp 1.0\r\ni=Easy\r\nc=IN IP4 0.0.0.0\r\nt=0 0\r\nm=video 0 RTP/AVP 96\r\nb=AS:5000\r\na=rtpmap:96 MP4V-ES/90000\r\na=fmtp:96 profile-level-id=1;config=\r\na=control:trackID=0\r\n");
			break;

			case RTSP_MEDIA_TYPE_H264:
			// sprintf(buf, "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=Easy Rtsp 1.0\r\ni=Easy\r\nc=IN IP4 0.0.0.0\r\nt=0 0\r\nm=video 0 RTP/AVP 96\r\nb=AS:5000\r\na=rtpmap:96 %s/90000\r\na=fmtp:96 %s;packetization-mode=1;%s\r\na=control:trackID=0\r\nm=audio 0 RTP/AVP 97\r\na=rtpmap:97 L16/16000/1\r\na=fmtp:97\r\na=control:trackID=1\r\n", 
			// 	"H264", getProfileLevelId().c_str(), getSpropParamterSets().c_str());
			sprintf(buf, "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=Easy Rtsp 1.0\r\ni=Easy\r\nc=IN IP4 0.0.0.0\r\nt=0 0\r\nm=video 0 RTP/AVP 96\r\nb=AS:5000\r\na=rtpmap:96 %s/90000\r\na=fmtp:96 %s;packetization-mode=1;%s\r\na=control:trackID=0\r\n", 
				"H264", getProfileLevelId().c_str(), getSpropParamterSets().c_str());
			break;
		}

		strSDP = std::string(buf);
		sprintf(buf, "RTSP/1.0 200 OK\r\nCSeq: %d\r\nContent-Type: application/sdp\r\nContent-Base: rtsp://%s:554/live/ch00_0/\r\nContent-Length: %d\r\n\r\n%s", 
			pData->m_nSeqNum, getLocalIp().c_str(), (int)strSDP.size(), strSDP.c_str());
		}
		break;

		case RTSP_CMD_SETUP:
		if (pData->m_strClientPort.size() == 0)
			sprintf(buf, "RTSP/1.0 200 OK\r\nCSeq: %d\r\nCache-Control: no-cache\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1\r\nSession: %s\r\n\r\n", 
				pData->m_nSeqNum, pData->getRandSessionId().c_str());
		else
			sprintf(buf, "RTSP/1.0 200 OK\r\nCSeq: %d\r\nCache-Control: no-cache\r\nTransport: RTP/AVP;unicast;mode=play;%s;server_port=%d-%d\r\nSession: %s\r\n\r\n", 
				pData->m_nSeqNum, pData->m_strClientPort.c_str(), RTSP_LOCAL_RTP_PORT, RTSP_LOCAL_RTCP_PORT, pData->getRandSessionId().c_str());
		break;

		case RTSP_CMD_PLAY:
		sprintf(buf, "RTSP/1.0 200 OK\r\nCSeq: %d\r\nSession: %s\r\nRange: npt=now-\r\nRTP-Info: url=rtsp://%s/live/ch00_0//trackID=0;seq=0;rtptime=0,url=rtsp://%s/live/ch00_0//trackID=0;seq=0;rtptime=0\r\n\r\n",
			pData->m_nSeqNum, pData->getSessionId().c_str(), getLocalIp().c_str(), getLocalIp().c_str());
		if (pData->getRemoteRtpPort() != 0) {
			pData->setRtpSock(m_nRtpSock);
			pData->setRtcpSock(m_nRtcpSock);
		}
		else {
			fprintf(stderr, "== %s %s %d == \n", __FILE__, __FUNCTION__, __LINE__);
			printf("RTSP OVER RTP");
			pData->setRtpSock(pData->m_nFd, true);
		}
		// pData->start();
		break;
		
		case RTSP_CMD_SET_PARAMETER: 
		{
			char time_buf[100] = {0};
			struct tm * timeinfo;
			time_t rawtime;
			time (&rawtime);
			timeinfo = localtime (&rawtime);
			strftime (time_buf, sizeof(time_buf), "%a %b %d %H:%M:%S %Y",timeinfo);
			sprintf(buf, "RTSP/1.0 200 OK\r\nCSeq: %d\r\nDate: %s\r\n\r\n",
				pData->m_nSeqNum, time_buf);
		}
		break;
		
		case RTSP_CMD_SET_GET_PARAMETER: 
		{
			char time_buf[100] = {0};
			struct tm * timeinfo;
			time_t rawtime;
			time (&rawtime);
			timeinfo = localtime (&rawtime);
			strftime (time_buf, sizeof(time_buf), "%a %b %d %H:%M:%S %Y",timeinfo);
			sprintf(buf, "RTSP/1.0 200 OK\r\nCSeq: %d\r\nDate: %s\r\n\r\n",
				pData->m_nSeqNum, time_buf);
		}
		break;

		case RTSP_CMD_TEARDOWN:
			sprintf(buf, "RTSP/1.0 200 OK\r\nCSeq: %d\r\n\r\n",
				pData->m_nSeqNum);
		break;

		case RTSP_CMD_GET:
			memset(buf, 0x0, sizeof(buf));
			sprintf(buf, "HTTP/1.0 200 OK\r\nContent-Type: application/x-rtsp-tunnelled\r\n\r\n");
		break;

	}

_response_out:
	strResponse = std::string(buf);
	printf("\tstrResponse:\n%s\n\n\n", buf);
	if (strResponse.size()>0) {
		write(fd, strResponse.c_str(), strResponse.size());
		if (pData->m_nMethod == RTSP_CMD_PLAY)
			pData->Start();
	}
}

void RtspServer::addClientDataMap(int fd, RtspClientData *pData)
{
	RtspServerLock locker(&mMutexClient);
	mRtspClientDataMap[fd] = pData;
}

void RtspServer::RemoveClientDataMap(int fd)
{
	RtspServerLock locker(&mMutexClient);
	RtspClientData *pData = mRtspClientDataMap[fd];
	mRtspClientDataMap.erase(fd);
	delete(pData);
}

int RtspServer::FindHttpConnection(unsigned short httpport)
{
	RtspServerLock locker(&mMutexClient);
	std::map<int, RtspClientData* >::iterator pIterator;
	for(pIterator=mRtspClientDataMap.begin(); pIterator!=mRtspClientDataMap.end(); pIterator++) 
	{
		int nClientSocketFD = pIterator->first;
		RtspClientData *pData = pIterator->second;
		//找到HTTP GET端口号差小于1000的对应连接
		printf("%s-%d::HTTP GET Conn Port %d\n",__FUNCTION__,__LINE__,pData->m_nTcpPort);
		if(pData->m_bHttpGet && (httpport - pData->m_nTcpPort) < 1000)
			return nClientSocketFD;
	}
	printf("%s-%d::connection not found\n",__FUNCTION__,__LINE__);
	return -1;
}

void RtspServer::RemoveClientDataMap(char *pszRemoteIp, int port)
{
	if(pszRemoteIp == NULL)
	{
		return;
	}

	RtspServerLock locker(&mMutexClient);

	std::map<int, RtspClientData* >::iterator pIterator;
	for(pIterator=mRtspClientDataMap.begin(); pIterator!=mRtspClientDataMap.end();) 
	{
		int nClientSocketFD = pIterator->first;
		RtspClientData *pData = pIterator->second;
		
		/*ip和port匹配，如果port==0则释放所有虚拟的连接*/
		if(((strcmp(pszRemoteIp, pData->getRemoteIp()) == 0) && (port == pData->getRemoteRtpPort()))
			|| ((port == 0) && (nClientSocketFD >= 0xFFFF)))
		{
			mRtspClientDataMap.erase(pIterator++);
			delete(pData);
		}else
			pIterator++;
	}
}

bool RtspServer::isClientDataExisted(char *pszRemoteIp, int port)
{
	bool bExisted = false;
	if(pszRemoteIp == NULL) 
	{
		return false;
	}

	RtspServerLock locker(&mMutexClient);

	std::map<int, RtspClientData* >::iterator pIterator;
	for(pIterator=mRtspClientDataMap.begin(); pIterator!=mRtspClientDataMap.end(); pIterator++) 
	{
		int nClientSocketFD = pIterator->first;
		RtspClientData *pData = pIterator->second;
		
		/*ip和port匹配，如果port==0则释放所有虚拟的连接*/
		if(((strcmp(pszRemoteIp, pData->getRemoteIp()) == 0) && (port == pData->getRemoteRtpPort())))
		{
			//如果IP和端口都相同，则返回存在客户端数?
			bExisted = true;
			break;
		}
	}

	return bExisted;
}

int RtspServer::RemoveClientDataInSameIp(char *pszRemoteIp, int port)
{
	if(pszRemoteIp == NULL) 
	{
		return -1;
	}

	RtspServerLock locker(&mMutexClient);

	std::map<int, RtspClientData* >::iterator pIterator;
	for(pIterator=mRtspClientDataMap.begin(); pIterator!=mRtspClientDataMap.end(); pIterator++) 
	{
		int nClientSocketFD = pIterator->first;
		RtspClientData *pData = pIterator->second;
		
		if(((strcmp(pszRemoteIp, pData->getRemoteIp()) == 0) && (port != pData->getRemoteRtpPort())))
		{
			//如果IP相同但是端口不同则强制销毁
			mRtspClientDataMap.erase(nClientSocketFD);
			delete(pData);
			printf("%s:%s:%d\n", __FUNCTION__, pData->getRemoteIp(), pData->getRemoteRtpPort());
		}
	}

	return 0;
}

int RtspServer::RemoveAllClient(bool bSignal)
{
	if (bSignal) {
		m_bRemoveAllClient = true;
		return 0;
	}

	RtspServerLock locker(&mMutexClient);

	std::map<int, RtspClientData* >::iterator pIterator;
	for(pIterator=mRtspClientDataMap.begin(); pIterator!=mRtspClientDataMap.end(); pIterator++) 
	{
		int nClientSocketFD = pIterator->first;
		RtspClientData *pData = pIterator->second;
		
		fds_remove(sock_fds, ARRAY_SIZE(sock_fds), nClientSocketFD);
		mRtspClientDataMap.erase(nClientSocketFD);
		close(nClientSocketFD);
		delete(pData);
	}

	m_bRemoveAllClient = false;
	return 0;
}

void RtspServer::UpdateClientDataMap(char *pszRemoteIp, int port, int expires)
{
	if(pszRemoteIp == NULL)
	{
		return;
	}

	RtspServerLock locker(&mMutexClient);

	std::map<int, RtspClientData* >::iterator pIterator;
	for(pIterator=mRtspClientDataMap.begin(); pIterator!=mRtspClientDataMap.end(); pIterator++) 
	{
		RtspClientData *pData = pIterator->second;
		
		/*ip和port匹配如果PORT=0则只要是expires不为0就表示匹配上*/
		if(((port == 0) && (pData->m_nExpires > 0))
			|| ((strcmp(pszRemoteIp, pData->getRemoteIp()) == 0) && (port == pData->getRemoteRtpPort())))
		{
			pData->m_nExpires = expires;
			gettimeofday(&pData->timeUpdated, NULL);
			break;
		}
	}
}

RtspClientData *RtspServer::getClientDataMap(int fd)
{
	RtspServerLock locker(&mMutexClient);
	return mRtspClientDataMap[fd];
}

std::string RtspServer::getLocalIp()
{
	return "192.168.199.130";
	int sd;
	char *ip;
	struct sockaddr_in sin;
	struct ifreq ifr;

	sd = socket(AF_INET, SOCK_DGRAM, 0);
	if(-1 == sd)
	{
		printf("socket error:%s\n", strerror(errno));
		return NULL;
	}

	strncpy(ifr.ifr_name, LOCAL_ETHERNET_NAME, IFNAMSIZ);
	ifr.ifr_name[IFNAMSIZ - 1] = 0;

	if(ioctl(sd, SIOCGIFADDR, &ifr) < 0)
	{
		printf("ioctl error:%s\n", strerror(errno));
		close(sd);
		return NULL;
	}

	memcpy(&sin, &ifr.ifr_addr, sizeof(sin));
	snprintf(ip, 16, "%s", inet_ntoa(sin.sin_addr));

	close(sd);
	return ip;
}

int RtspServer::CreateSrvFd()
{
	struct sockaddr_in server_addr;
	int yes, ret, nClientSocketFD, i;

	m_nSrvFD = socket(AF_INET, SOCK_STREAM, 0);
	if (m_nSrvFD < 0) {
		printf("socket error\n");
		return  -1;
	}

	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	server_addr.sin_port = htons(RTSP_SERVER_PORT);
	memset(server_addr.sin_zero, '\0', sizeof(server_addr.sin_zero));

	// 重用
	yes = 1;
	setsockopt(m_nSrvFD, SOL_SOCKET, SO_REUSEADDR, (char*)&yes, sizeof(yes));

	ret = bind(m_nSrvFD, (struct sockaddr*)&server_addr, sizeof(server_addr));
	if (ret < 0) {
		perror("bind error\n");
		return -1;
	}

	// 立即发送
	// yes = 1;
	// setsockopt(m_nSrvFD, IPPROTO_TCP, TCP_NODELAY, (char*)&yes, sizeof(yes));

	listen(m_nSrvFD, MAX_CLIENT);
	memset(sock_fds, 0x0, sizeof(sock_fds));
	fds_add(sock_fds, ARRAY_SIZE(sock_fds), m_nSrvFD);	
	return 0;	
}

void RtspServer::OnRun()
{
	
	int yes, ret, nClientSocketFD, i;
	struct sockaddr_in server_addr;
	struct sockaddr_in client_addr;
	socklen_t client_addr_size;
	fd_set rfds, errfds;
	struct timeval tv;
	char buf[RTP_MAX_LEN];

    printf("[%s-%d] ==RtspServer Start!!!==\n", __FUNCTION__, __LINE__);

    CreateSrvFd();


	while (true){

		if (getRunState() == 0)
			break;

		// select read
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		fds_set(sock_fds, ARRAY_SIZE(sock_fds), &rfds);
		fds_set(sock_fds, ARRAY_SIZE(sock_fds), &errfds);
		ret = select(fds_get_max(sock_fds, ARRAY_SIZE(sock_fds)) + 1, &rfds, NULL, &errfds, &tv);
		if (m_bRemoveAllClient) {
			RemoveAllClient(false);
			// close(m_nSrvFD);
			// CreateSrvFd();
			continue;
		}
		
		if (ret == 0)
			continue;
		else if (ret < 0) {
			printf("select error\n");
			continue;
		}

		// error parse first
		if (FD_ISSET(m_nSrvFD, &errfds)) {
			printf("unknow m_nSrvFD error\n");
		}
		else {
			nClientSocketFD = fds_get_revent(sock_fds, ARRAY_SIZE(sock_fds), &errfds);
			if (nClientSocketFD > 0) {
				close(nClientSocketFD);
				fds_remove(sock_fds, ARRAY_SIZE(sock_fds), nClientSocketFD);
				RemoveClientDataMap(nClientSocketFD);
			}
		}

		// check server socket
		if (FD_ISSET(m_nSrvFD, &rfds)) {
			client_addr_size = sizeof(struct sockaddr_in);
			nClientSocketFD = accept(m_nSrvFD, (struct sockaddr*)&client_addr, &client_addr_size);
			//设置超时
			tv.tv_sec = 1;
			tv.tv_usec = 0;
			setsockopt(nClientSocketFD, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
			fds_add(sock_fds, ARRAY_SIZE(sock_fds), nClientSocketFD);
			RtspClientData *pRtspClientData = new RtspClientData(nClientSocketFD, inet_ntoa(client_addr.sin_addr));
			pRtspClientData->setUserCameraTimestamp(true);
			pRtspClientData->setTcpConnectPort((unsigned short)client_addr.sin_port);
			pRtspClientData->setVideoHeight(m_nHeight);
			pRtspClientData->setVideoWidth(m_nWidth);
			addClientDataMap(nClientSocketFD, pRtspClientData);
		}
		else {
			nClientSocketFD = fds_get_revent(sock_fds, ARRAY_SIZE(sock_fds), &rfds);
			if (nClientSocketFD > 0) {
				memset(buf, 0x0, sizeof(buf));
				ret = read(nClientSocketFD, buf, sizeof(buf));
				if (ret > 0) {
					if (buf[0] == 0x24 || buf[0] == 0xff || buf[0] == 0x80) {
						printf("buf %#x %#x\n", buf[0], buf[1]);
					}
					else {
						// printf("buf:%s\n", buf);
						if (isascii(buf[0])){
							if(OnHttpPostRequest(nClientSocketFD, std::string(buf)) == -1)
								OnParseRequest(nClientSocketFD, std::string(buf));
						}
					}
				}
				else {
					// disconnect ? error?
					close(nClientSocketFD);
					fds_remove(sock_fds, ARRAY_SIZE(sock_fds), nClientSocketFD);
					RemoveClientDataMap(nClientSocketFD);
				}
			}
		}
	}

	{
		RtspServerLock locker(&mMutexClient);
		for (i=0; i<(int)ARRAY_SIZE(sock_fds); i++) {
			if (sock_fds[i]!=0) {
				int fd = sock_fds[i];
				close(fd);
				fds_remove(sock_fds, ARRAY_SIZE(sock_fds), fd);
				RtspClientData *pData = mRtspClientDataMap[fd];
				mRtspClientDataMap.erase(fd);
				delete(pData);
			}
		}
		close(m_nSrvFD);
	}

}

void RtspServer::lock()
{
	pthread_mutex_lock(&mMutex);
}

void RtspServer::unlock()
{
	pthread_mutex_unlock(&mMutex);
}

int RtspServer::getRtspClientNum()
{
	RtspServerLock locker(&mMutexClient);
	return mRtspClientDataMap.size();
}

int RtspServer::addH264Data(char *buf, int len, unsigned int nTimestamp)
{
	if (getRtspClientNum()==0) {
		return -1;
	}
	return buffer_link_add(m_pBufferLink, buf, len, nTimestamp);
}

int RtspServer::addJPEGData(char *buf, int len, unsigned int nTimestamp)
{
	if (getRtspClientNum()==0) {
		return -1;
	}
	return buffer_link_add(m_pBufferLink, buf, len, nTimestamp);
}

void RtspServer::setH264SPS(char *ptr, int len)
{
	if (m_pSpsPtr)
		free(m_pSpsPtr);
	m_pSpsPtr = ptr;
	m_nSpsLen = len;
}

void RtspServer::setH264PPS(char *ptr, int len)
{
	if (m_pPpsPtr)
		free(m_pPpsPtr);
	m_pPpsPtr = ptr;
	m_nPpsLen = len;
}

void RtspServer::setEncodeType(int nType)
{
	m_nEncType = nType;
}

int RtspServer::getEncodeType()
{
	return m_nEncType;
}

void dump_hex(unsigned char *buf, int len);
std::string RtspServer::getProfileLevelId()
{
	char buf[50] = {0};
	if (m_pSpsPtr == NULL)
		sprintf(buf, "profile-level-id=42E01F");
	else {
		sprintf(buf, "profile-level-id=%02X%02X%02X", m_pSpsPtr[5], m_pSpsPtr[6], m_pSpsPtr[7]);
	}
	return std::string(buf);
}

std::string RtspServer::getSpropParamterSets()
{
	char buf[255] = {0};
	char *sps_base64;
	char *pps_base64;

	if (m_pSpsPtr == NULL) 
		sprintf(buf, "sprop-parameter-sets=Z0LAM6tAWgk0IAAAAwAgAAAGUeMGVA==,aM48gA==");
	else {
		sps_base64 = base64Encode(m_pSpsPtr + 4, m_nSpsLen - 4);
		pps_base64 = base64Encode(m_pPpsPtr + 4, m_nPpsLen - 4);
		sprintf(buf, "sprop-parameter-sets=%s,%s", sps_base64, pps_base64);
		delete sps_base64;
		delete pps_base64;
	}
	return std::string(buf);
}

void RtspServer::setH264Info(int width, int height, int fps, int bitrate)
{
	// int mnWidth, mnHeight, mnFrameRate, mnBitrate;
	m_nWidth = width;
	m_nHeight = height;
	m_nFrameRate = fps;
	m_nBitrate = bitrate;
}

void RtspServer::setVideoInfo(int width, int height, int fps, int bitrate, int quality)
{
	m_nWidth = width;
	m_nHeight = height;
	m_nFrameRate = fps;
	m_nBitrate = bitrate;
	m_nQuality = quality;
}

bool RtspServer::isH264InfoChange(int width, int height, int fps, int bitrate)
{
	if (m_nWidth != width ||
		m_nHeight != height || 
		m_nFrameRate != fps ||
		m_nBitrate != bitrate)
		return true;

	return false;
}

bool RtspServer::isVideoInfoChange(int width, int height, int fps, int bitrate, int quality)
{
	if (m_nWidth != width ||
		m_nHeight != height || 
		m_nFrameRate != fps ||
		m_nBitrate != bitrate ||
		m_nQuality != quality)
		return true;

	return false;
}

bool RtspServer::isStart()
{
	return m_nTid != 0;
}

int RtspServer::getRtpSock()
{
	return m_nRtpSock;
}

int RtspServer::getRtcpSock()
{
	return m_nRtcpSock;
}

void RtspServer::OnRtpRun()
{
	#define CAMERA_LED_DELAY_CLOSE_TICK (10*1000/500)
	// int nCameraLedDelayCloseTick =  CAMERA_LED_DELAY_CLOSE_TICK;
    printf("RtspServer Start\n");
	while(true) {
		int nRtspClientNum;
		if (!getRunState())
			break;

		nRtspClientNum = getRtspClientNum();
		// check client nums
		if (nRtspClientNum==0) {
			usleep(500*1000);
			// if (nCameraLedDelayCloseTick>=0 && nCameraLedDelayCloseTick--==0) {
			// 	devctrl_set_camera_led(0);
			// 	nCameraLedDelayCloseTick = -1;
			// }
			continue;
		}

		// nCameraLedDelayCloseTick = CAMERA_LED_DELAY_CLOSE_TICK;
		// devctrl_set_camera_led(1);

		if (m_pBufferLink == NULL) 
			break;
		// wait data
		// fprintf(stderr, "== %s %s %d == \n", __FILE__, __FUNCTION__, __LINE__);
		// buffer_link_wait(m_pBufferLink, 1000);
		// fprintf(stderr, "== %s %s %d == \n", __FILE__, __FUNCTION__, __LINE__);
		// buffer_link_unlock(m_pBufferLink);

		BUFFER_LINK_DATA *pBufferLinkData = buffer_link_get(m_pBufferLink);
		if (pBufferLinkData == NULL) {
			usleep(10000);
			continue;
		}

		{
			RtspServerLock locker(&mMutexClient);
			// parse h264
			char *ptr = pBufferLinkData->ptr;
			int len = pBufferLinkData->len;
			uint8_t nal_type = ptr[0] & 0x1f;


			std::map<int, RtspClientData* >::iterator pIterator;
			for (pIterator=mRtspClientDataMap.begin(); pIterator!=mRtspClientDataMap.end(); pIterator++) {
				int nClientSocketFD = pIterator->first;
				RtspClientData *pData = pIterator->second;
				if (!pData->isPlay()) {
					// fprintf(stderr, "== %s %s %d == \n", __FILE__, __FUNCTION__, __LINE__);
					continue;
				}

				switch (m_nEncType) {
					case RTSP_MEDIA_TYPE_MJPEG:
						pData->m_pFrame = ptr;
						pData->m_nFrameLen = len;
						if (!pData->isSendSSP()){
							// MJPEG 不需要SSP，这里用来初始化 Timestamp
							pData->setStartTimestamp(pBufferLinkData->timestamp);
							pData->setSendSPS(true);
						}
						if (pData->isUseCameraTimestamp())
							pData->m_nTimestamp = pBufferLinkData->timestamp;
						rtp_jpeg(pData);
					break;

					case RTSP_MEDIA_TYPE_MPEG4:
						pData->m_pFrame = ptr;
						pData->m_nFrameLen = len;
						if (!pData->isSendSSP()){
							// MPEG4 不需要SSP，这里用来初始化 Timestamp
							pData->setStartTimestamp(pBufferLinkData->timestamp);
							pData->setSendSPS(true);
						}
						if (pData->isUseCameraTimestamp())
							pData->m_nTimestamp = pBufferLinkData->timestamp;
						rtp_mpeg4_send(pData);
					break;

					case RTSP_MEDIA_TYPE_H264:
						if (!pData->isSendSSP() && m_pSpsPtr) {
							if (nal_type != 0x05)
								continue;
							pData->setStartTimestamp(pBufferLinkData->timestamp);
							pData->m_pFrame = m_pSpsPtr+4;
							pData->m_nFrameLen = m_nSpsLen-4;
							if (pData->isUseCameraTimestamp())
								pData->m_nTimestamp = pBufferLinkData->timestamp;
							rtp_h264_send(pData);

							pData->m_pFrame = m_pPpsPtr+4;
							pData->m_nFrameLen = m_nPpsLen-4;
							if (pData->isUseCameraTimestamp())
								pData->m_nTimestamp = pBufferLinkData->timestamp;
							rtp_h264_send(pData);
							pData->setSendSPS(true);
						}
					// }
					// printf("remote_addr:%s remote_port:%d len:%d\n", pData->getRemoteIp(), pData->getRemoteRtpPort(), len);
					// printf("pData->getRemoteRtpPort():%d nClientSocketFD:%d\n", pData->getRemoteRtpPort(), nClientSocketFD);
						pData->m_pFrame = ptr;
						pData->m_nFrameLen = len;
						if (pData->isUseCameraTimestamp())
							pData->m_nTimestamp = pBufferLinkData->timestamp;
						rtp_h264_send(pData);
					// if (pData->nSeq%8 == 0)
					// 	rtcp_send(pData);
					break;
				}
			}
		}

		// free data
		buffer_link_data_free(pBufferLinkData);
	}
}

RtspServer *GetRtspServerInstance() 
{
	return RtspServer::GetInstance();
}

/**
 * @brief 查找H264帧间隔
 * 
 * @param ptr H264帧
 * @param ptr_len 帧长度
 * @param len 
 * @return 查找到H264帧
 */
char *get_h264_frame(char *ptr, int ptr_len, int *len)
{
	int i, j;
	bool found = false;
	char *ptr_start = NULL;
	char cmp_str[4] = {0x00, 0x00, 0x00, 0x01};
	for (i=0; i<ptr_len; i++) {
		for (j=0; j<4; j++) {
			if (ptr[i+j] != cmp_str[j])
				break;
		}

		if (j==4) {
			if (found) {
				// 包含多个片段
				*len = ptr + i - ptr_start;
				return ptr_start;
			}
			found = true;
			ptr_start = ptr + i;
		}
	}

	if (found) {
		// 只有1个片段
		*len = ptr + i - ptr_start;
		return ptr_start;
	}
	return NULL;
}

void RtspServer::SetAuthInfo(bool bEnable, char *pUserName, char *pPassword)
{
	m_bAuth = bEnable;
	m_strAuthUserName = pUserName;
	m_strAuthPassword = pPassword;
}

bool RtspServer::GetAuthResult(const char *pAuthorization, const char *pMethod)
{
	// Authorization: Digest username="admin", realm="LIVE555 Streaming Media", nonce="f68b9973fcc6503741b2d376b120dd58", uri="rtsp://192.168.1.163:8554/live/ch00_0", response="ae4ddcd0a73b4bdab3d33605261ba0e1"\r\n
	char *pDigest;
	std::string strAuthorization;
	std::vector<std::string> vectorArray;
	std::map<std::string, std::string> map;
	std::string strUserName, strRealm, strNonce, strUri, strResponse;
	std::string strDot = ",";
	std::string strEqual = "=";
	std::string strSpace = " ";
	std::string strYinhao = "\"";

	pDigest = strstr((char *)pAuthorization, "Digest");

	if (!pDigest)
		return false;

	// printf("pAuthorization:%s\n", pAuthorization);
	strAuthorization = pDigest+strlen("Digest")+1;

	string_split(strAuthorization, strDot, &vectorArray);

	// 遍历
	for (int i=0; i<vectorArray.size(); i++) {
		std::string strArray = vectorArray[i];
		// printf("strArray:%s\n", strArray.c_str());
		// 
		std::vector<std::string> vectorTmp;
		string_split(strArray, strEqual, &vectorTmp);
		if (vectorTmp.size()==2) {
			std::string strKey = vectorTmp[0];
			string_trim_split(strKey, strSpace);
			std::string strValue = vectorTmp[1];
			string_trim_split(strValue, strYinhao);
			// printf("key:%s value:%s\n", strKey.c_str(), strValue.c_str());
			map[strKey] = strValue;
		}
	}

	// 赋值
	strUserName = map["username"];
	strRealm = map["realm"];
	strNonce = map["nonce"];
	strUri = map["uri"];
	strResponse = map["response"];

	if (strUserName != m_strAuthUserName)
		return false;

	// 验证
	std::string strDigiest = CalcDigiest(m_strAuthUserName.c_str(), m_strAuthPassword.c_str(), strRealm.c_str(), strNonce.c_str(), pMethod, strUri.c_str());

	if (strResponse.size()>0 && strDigiest.find(strResponse) != std::string::npos) 
		return true;
	return false;
}

const char *RtspServer::GetMethodString(int nMethod)
{
	static const char *pArrayMethod[]  = 
	{
		RTSP_CMD_OPTIONS_STR,
		RTSP_CMD_DESCRIBE_STR,
		RTSP_CMD_SETUP_STR,
		RTSP_CMD_TEARDOWN_STR,
		RTSP_CMD_PLAY_STR,
		RTSP_CMD_PAUSE_STR,
		RTSP_CMD_SET_PARAMETER_STR, 
		RTSP_CMD_SET_GET_PARAMETER_STR, 
		RTSP_CMD_GET_METHOD_STR, 
		RTSP_CMD_POST_METHOD_STR, 
	};
	return pArrayMethod[nMethod];
}

std::string RtspServer::CalcDigiest(const char *pUserName, const char *pPassword, const char *pRealm, 
	const char *pNonce, const char *pMethod, const char *pUri)
{
	// md5=HA1:HD:HA2
	// HA1=md5(username:realm:password)
	// “md5-sess” -> HA1=username:realm:password:nonce:cnonce  
	// qop 存在 则: HD=nonce:noncecount:cnonce:qop  
	// HD=nonce
	// HA2=md5(method:uri)
	std::string strHA1, strHD, strHA2, strAll;
	char szBuf[256];

	// Calc HA1
	memset(szBuf, 0, sizeof(szBuf));
	sprintf(szBuf, "%s:%s:%s", pUserName, pRealm, pPassword);
	strHA1 = CalcMD5(szBuf);
	printf("szBuf:%s strHA1:%s\n", szBuf, strHA1.c_str());

	// Calc HD
	strHD = pNonce;

	// Clac HA2
	memset(szBuf, 0, sizeof(szBuf));
	sprintf(szBuf, "%s:%s", pMethod, pUri);
	strHA2 = CalcMD5(szBuf);
	printf("szBuf:%s strHA1:%s\n", szBuf, strHA2.c_str());

	// Calc ALL
	sprintf(szBuf, "%s:%s:%s", strHA1.c_str(), strHD.c_str(), strHA2.c_str());
	// printf("szBuf:%s\n", szBuf);
	strAll = CalcMD5(szBuf);
	printf("szBuf:%s strAll:%s\n", szBuf, strAll.c_str());
	return strAll;
}

