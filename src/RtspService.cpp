#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/types.h>
#include <linux/videodev2.h>
#include <fcntl.h>
#include <math.h>
#include <malloc.h>
#include <errno.h>
#include <assert.h>

#include "RtspService.h"
#include "RtspServer.h"

#if defined ( __cplusplus)
extern "C"
{
#include "x264.h"
};
#else
#include "x264.h"
#endif

// #define DEVICE_VIDEO "/dev/video0"
#define DEVICE_VIDEO "/dev/v4l/by-id/usb-Generic_FULL_HD_1080P_Webcam_200901010001-video-index0"
// #define DEVICE_VIDEO "/dev/video0"


#define BITSTREAM_LEN (1280*720*3/2)

static unsigned int nBuffer = 0;
static int CameraDeviceFd = -1;
typedef struct{
	void *start;
	int length;
}BUFTYPE;

BUFTYPE *usr_buf;

static unsigned int getSystemTimeUS(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return tv.tv_sec * 1000 * 1000 + tv.tv_usec;
}

static void write_into_file(const char * path, unsigned char *buf, int len)
{
	FILE *fp;
	fp = fopen(path, "ab+");
	if (fp) {
		fwrite(buf, len, 1, fp);
		fclose(fp);
	}
}

//set video capture ways(mmap)
static int init_mmap(int fd)
{
	// to request frame cache, contain requested counts
	struct v4l2_requestbuffers nReqBufs;

	memset(&nReqBufs, 0, sizeof(nReqBufs));
	nReqBufs.count = 4;
	nReqBufs.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	nReqBufs.memory = V4L2_MEMORY_MMAP;

	usr_buf = (BUFTYPE *)calloc(nReqBufs.count, sizeof(BUFTYPE));
	if(usr_buf == NULL)
	{
		printf("Out of Memory!!\n");
		exit(-1);
	}

	if(-1 == ioctl(fd, VIDIOC_REQBUFS, &nReqBufs))
	{
		perror("failed to ioctl VIDEO_REQBUFS!\n");
		exit(EXIT_FAILURE);
	}

	nBuffer = nReqBufs.count;

	// map kernel cache to user process
	for(int i = 0; i < nReqBufs.count; i++)
	{
		// stand for a frame
		struct v4l2_buffer buf;
		memset(&buf, 0, sizeof(buf));
		buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
		buf.memory = V4L2_MEMORY_MMAP;
		buf.index = i;

		// check the information of the kernel cache requested
		if(-1 == ioctl(fd, VIDIOC_QUERYBUF, &buf))
		{
			perror("Failed to ioctl : VIDIOC_QUERYBUF\n");
			exit(EXIT_FAILURE);
		}

		usr_buf[i].length = buf.length;
		usr_buf[i].start = mmap(NULL, buf.length, PROT_READ | 
			PROT_WRITE, MAP_SHARED, fd, buf.m.offset);

		if(MAP_FAILED == usr_buf[i].start)
		{
			perror("Failed to mmap\n");
			exit(EXIT_FAILURE);
		}
	}

}

static int init_camera(int fd)
{
	struct v4l2_capability cap;  // device function, such as video input
	struct v4l2_format tv_fmt;   // frame format
	struct v4l2_fmtdesc fmtdesc; //detail control value
	struct v4l2_frmsizeenum frmsize;
	struct v4l2_frmivalenum frmival;
	struct v4l2_control ctrl;

	int ret;

	// show all the support format
	memset(&fmtdesc, 0, sizeof(fmtdesc));
	fmtdesc.index = 0;  // the number to check
	fmtdesc.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;

	// display the format device support
	printf("\n");
	while(ioctl(fd, VIDIOC_ENUM_FMT, &fmtdesc) == 0)
	{
		frmsize.pixel_format = fmtdesc.pixelformat;
		frmsize.index = 0;
		while(ioctl(fd, VIDIOC_ENUM_FRAMESIZES, &frmsize) >= 0)
		{
			if(frmsize.type == V4L2_FRMSIZE_TYPE_DISCRETE)
			{
				printf("resolution: %dx%d\n", frmsize.discrete.width, frmsize.discrete.height);
			}else if(frmsize.type == V4L2_FRMSIZE_TYPE_STEPWISE){
				printf("resolution: %dx%d\n", frmsize.discrete.width, frmsize.discrete.height);
			}
			frmsize.index++;
		}
		printf("support device %d.%s\n", fmtdesc.index + 1, fmtdesc.description);
		fmtdesc.index++;
	}

	printf("\n");

	// check video device driver capability
	if(ret = ioctl(fd, VIDIOC_QUERYCAP, &cap) < 0)
	{
		perror("failed to ioctl VIDIOC_QUERYCAP\n");
		exit(EXIT_FAILURE);
	}

	// judge whether or not to be a video-get device
	if(!(cap.capabilities & V4L2_CAP_VIDEO_CAPTURE))
	{
		perror("The current device is not a video capture\n");
		exit(EXIT_FAILURE);
	}

	// judge whether or not to supply the form of video steam
	if(!(cap.capabilities & V4L2_CAP_STREAMING))
	{
		perror("The current device dose not support streaming i/o\n");
		exit(EXIT_FAILURE);
	}

	printf("\n");
	printf("camera driver name is : %s\n", cap.driver);
	printf("camera device name is : %s\n", cap.card);
	printf("camera buf information : %s\n", cap.bus_info);

	printf("\n");

	// set the form of camera capture data
	memset(&tv_fmt, 0, sizeof(tv_fmt));
	tv_fmt.type =V4L2_BUF_TYPE_VIDEO_CAPTURE; // v4l2_buf_typea,camera must use V4L2_BUF_TYPE_VIDEO_CAPTURE
	tv_fmt.fmt.pix.width = 1920;
	tv_fmt.fmt.pix.height = 1080;
	tv_fmt.fmt.pix.pixelformat = V4L2_PIX_FMT_MJPEG;  // V4L2_PIX_FMT_YYUV | V4L2_PIX_FMT_RGB24
	tv_fmt.fmt.pix.field = V4L2_FIELD_INTERLACED;
	if(ioctl(fd, VIDIOC_S_FMT, &tv_fmt) < 0)
	{
		perror("VIDIOC_S_FMT set err\n");
		close(fd);
		exit(-1);
	}

	init_mmap(fd);
	
	return 0;
}

static int start_capture(int fd)
{
	unsigned int i;
	enum v4l2_buf_type type;

	// place the kernel cache to a queue
	for(i = 0; i < nBuffer; i++)
	{
		struct v4l2_buffer buf;
		memset(&buf, 0, sizeof(buf));
		buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
		buf.memory = V4L2_MEMORY_MMAP;
		buf.index = i;

		if(-1 == ioctl(fd, VIDIOC_QBUF, &buf))
		{
			perror("Failed to ioctl VIDIOC_QBUF\n");
			exit(EXIT_FAILURE);
		}
	}

	type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	if(-1 == ioctl(fd, VIDIOC_STREAMON, &type))
	{
		printf("i = %d.\n", i);
		perror("VIDIOC_STREAMON\n");
		close(fd);
		exit(EXIT_FAILURE);
	}

	return 0;
}

static void stop_capture(int fd)
{
	enum v4l2_buf_type type;
	type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	if(-1 == ioctl(fd, VIDIOC_STREAMOFF, &type))
	{
		perror("Failed to ioctl VIDIOC_STREAMOFF\n");
		exit(EXIT_FAILURE);
	}
}

static int read_frame(int fd)
{
	struct v4l2_buffer buf;
	unsigned int i;
	memset(&buf, 0, sizeof(buf));
	buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	buf.memory = V4L2_MEMORY_MMAP;
	// put cache from queue
	if(-1 == ioctl(fd, VIDIOC_DQBUF, &buf))
	{
		perror("Failed to ioctl VIDIOC_DQBUF\n");
		exit(EXIT_FAILURE);
	}

	// read process space's data to a output

}

static void open_camera(void)
{
	struct v4l2_input inp;

	CameraDeviceFd = open(DEVICE_VIDEO, O_RDWR | O_NONBLOCK);
	if(CameraDeviceFd < 0)
	{
		printf("Open Video Device %s Failed!\n", DEVICE_VIDEO);
		exit(EXIT_FAILURE);
	}
}

static void close_camera_device()
{
	unsigned int i;
	for(i = 0; i < nBuffer; i++)
	{
		if(-1 == munmap(usr_buf[i].start, usr_buf[i].length))
		{
			exit(-1);
		}
	}

	free(usr_buf);

	if(-1 == close(CameraDeviceFd))
	{
		printf("Faield to close device : %s", DEVICE_VIDEO);
		exit(EXIT_FAILURE);
	}
}

RtspService* RtspService::m_pRtspService = NULL;

void *RtspService::OnThread(void *pData)
{
	GetRtspServiceInstance()->OnRun();
	return NULL;
}

RtspService *RtspService::GetInstance()
{
	if(m_pRtspService == NULL)
		m_pRtspService = new RtspService();

	return m_pRtspService;
}

RtspService::RtspService()
:m_nEncType(RTSP_MEDIA_TYPE_H264)
,m_bRunning(false)
,m_bParamChanged(false)
,m_tid(0)
{
	m_nWidth = 640;
	m_nHeight = 480;
	m_nFramerate = 30;
	m_nBitrate = 1000;
	m_nQuality = 70;
}

RtspService::~RtspService()
{
	stop_capture(CameraDeviceFd);
	close_camera_device();
}

void RtspService::Start()
{
	if(m_tid == 0)
	{
		m_bParseSPS = true;
		pthread_attr_t attr;
		pthread_attr_init(&attr);
		pthread_attr_setstacksize(&attr, PTHREAD_LIBVA_DEFAULT_SIZE);
		pthread_create(&m_tid, &attr, OnThread,  NULL);
		pthread_attr_destroy(&attr);

		// 等待编码线程获取第一个关键帧，该帧用于生成SDP信息
		RtspServer *pRtspServer = GetRtspServerInstance();
		
		pRtspServer->Start();
		//pRtspServer->setH264Info(m_nWidth, m_nHeight, m_nFramerate, m_nBitrate);
		pRtspServer->setVideoInfo(m_nWidth, m_nHeight, m_nFramerate, m_nBitrate, m_nQuality);
	}
}

void RtspService::Stop()
{
	if(m_tid)
	{
		m_bRunning = false;
		stop_capture(CameraDeviceFd);
		close_camera_device();
		pthread_join(m_tid, NULL);
		m_tid = 0;
	}
}

void RtspService::OnRun()
{
	open_camera();
	init_camera(CameraDeviceFd);
	start_capture(CameraDeviceFd);

	fd_set fds;
	struct timeval tv;
	int ret;
	unsigned int inc = 0;

	FD_ZERO(&fds);
	FD_SET(CameraDeviceFd, &fds);

	tv.tv_sec = 2;
	tv.tv_usec = 0;

	m_bRunning = true;
	while(m_bRunning)
	{
		ret = select(CameraDeviceFd + 1, &fds, NULL, NULL, &tv);

		if(-1 == ret)
		{
			if(EINTR == errno)
				continue;
			perror("Failed to select\n");
			exit(EXIT_FAILURE);
		}

		if(0 == ret)
		{
			fprintf(stderr, "Select Timeout\n");
			usleep(1000*1000);
			continue;
		}

		struct v4l2_buffer buf;
		unsigned int i;
		memset(&buf, 0, sizeof(buf));
		buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
		buf.memory = V4L2_MEMORY_MMAP;
		// put cache from queue
		if(-1 == ioctl(CameraDeviceFd, VIDIOC_DQBUF, &buf))
		{
			perror("Failed to ioctl VIDIOC_DQBUF\n");
			exit(EXIT_FAILURE);
		}

		unsigned int pts = inc * 40;
		inc++;

		// read process space's data to an output stream
		// OnRtspVideoData((unsigned char *)usr_buf[buf.index].start, usr_buf[buf.index].length, 0, pts);
		printf("[%s-%d] gz_DEBUG usr_buf length = %d,index = %d", __FUNCTION__, __LINE__, usr_buf[buf.index].length, buf.index);


		if(-1 == ioctl(CameraDeviceFd, VIDIOC_QBUF, &buf))
		{
			perror("Failed to ioctl VIDIOC_QBUF\n");
			exit(EXIT_FAILURE);
		}
	}

	stop_capture(CameraDeviceFd);
	close_camera_device();
	// int ret, i;
 //    char *bitstream_data;
 //    gm_pollfd_t poll_fds[MAX_BITSTREAM_NUM];
 //    gm_enc_multi_bitstream_t multi_bs[MAX_BITSTREAM_NUM];

 //    printf("RtspService Start\n");

 //    gm_encode_init(m_nEncType, m_nWidth, m_nHeight, m_nFramerate, m_nBitrate, m_nQuality);
 //    bitstream_data = (char *)malloc(BITSTREAM_LEN);
 //    if(!bitstream_data)  {
 //    	rl_log_err("### %s %s %d ## error\n", __FILE__, __FUNCTION__, __LINE__);
 //    	return ;
 //    }

 //    memset(bitstream_data, 0, BITSTREAM_LEN);
 //    memset(poll_fds, 0, sizeof(poll_fds));
 //    m_bRunning = true;
 //    while(m_bRunning)
	// {
 //        poll_fds[0].bindfd = g_pBindfd;
 //        poll_fds[0].event = GM_POLL_READ;
 //        ret = gm_poll(poll_fds,MAX_BITSTREAM_NUM, 500);

 //        if (m_bParamChanged) {
 //        	// 
 //        	OnParamChanged();
 //        	continue;
 //        }

 //        if (ret == GM_TIMEOUT)
 //        {
 //            rl_log_err("Poll timeout!!");
 //            continue;
 //        }

 //        memset(multi_bs, 0, sizeof(multi_bs));  //clear all mutli bs
 //        i = 0;
 //        if (poll_fds[i].revent.event != GM_POLL_READ)
 //        	continue;
 //        if (poll_fds[i].revent.bs_len > BITSTREAM_LEN)
 //        {
 //        	rl_log_err("bitstream buffer length is not enough! %d, %d\n",
 //        		poll_fds[i].revent.bs_len, BITSTREAM_LEN);
 //        	continue;
 //        }

 //        multi_bs[i].bindfd = poll_fds[i].bindfd;
 //        multi_bs[i].bs.bs_buf = bitstream_data;  // set buffer point
 //        multi_bs[i].bs.bs_buf_len = BITSTREAM_LEN;  // set buffer length
 //        multi_bs[i].bs.mv_buf = 0;  // not to recevie MV data
 //        multi_bs[i].bs.mv_buf_len = 0;  // not to recevie MV data

 //        if ((ret = gm_recv_multi_bitstreams(multi_bs, MAX_BITSTREAM_NUM)) < 0)
 //        {
 //            rl_log_err("Video Error return value %d\n", ret);
 //            continue;
 //        }
 //        else
 //        {
 //        	if ((multi_bs[0].retval < 0) && multi_bs[i].bindfd)
 //        	{
 //        		printf("CH%d Error to receive bitstream. ret=%d\n", i, multi_bs[i].retval);
 //        	}
 //        	else if (multi_bs[i].retval == GM_SUCCESS)
 //        	{
 //        		switch(m_nEncType) {
 //        			case RTSP_MEDIA_TYPE_H264:
	// 	        		OnRtspVideoData((unsigned char *)multi_bs[0].bs.bs_buf, multi_bs[0].bs.bs_len, 
	// 	        			multi_bs[0].bs.keyframe, multi_bs[0].bs.timestamp);
 //        			break;
 //        			case RTSP_MEDIA_TYPE_MJPEG:
	//         			OnRtspJPEGData((unsigned char *)multi_bs[0].bs.bs_buf, multi_bs[0].bs.bs_len, 
	//         			multi_bs[0].bs.keyframe, multi_bs[0].bs.timestamp);
 //        			break;
 //        			case RTSP_MEDIA_TYPE_MPEG4:
	//         			OnRtspMPEG4Data((unsigned char *)multi_bs[0].bs.bs_buf, multi_bs[0].bs.bs_len, 
	//         			multi_bs[0].bs.keyframe, multi_bs[0].bs.timestamp);
 //        			break;
 //        		}
 //        	}
 //        }
 //    }

 //    free(bitstream_data);
	// gm_encode_destory();
}

void RtspService::OnRtspJPEGData(unsigned char*pData, int len, int nKeyFrame, unsigned int nTimestamp)
{
	if (pData)
		GetRtspServerInstance()->addJPEGData((char*)pData, len, nTimestamp);
}

void RtspService::OnRtspVideoData(unsigned char*pData, int len, int nKeyFrame, unsigned int nTimestamp)
{
	char *pFrame = NULL;
	int nFrameLen = 0;
	int nTotallen = 0;

	int nNalType = pData[4] &0x1f;

	if (m_bParseSPS && (nNalType == 0x08 || nNalType == 0x07)){
		m_bParseSPS = false;
		char *ssp_ptr = NULL;
		char *ptr_frame = NULL;
		int frame_len, total_len=0;
		int sps_len = len;
		char *ptr;

		ssp_ptr = (char *)pData;
		if (sps_len>0) {
		// SPS 
			ptr_frame = get_h264_frame(ssp_ptr+total_len, sps_len-total_len, &frame_len);
			if (ptr_frame) {
				ptr = (char*)malloc(frame_len);
				memcpy(ptr, ptr_frame, frame_len);
				GetRtspServerInstance()->setH264SPS(ptr, frame_len);
			}

		// PPS
			total_len += frame_len;
			ptr_frame = get_h264_frame(ssp_ptr+total_len, sps_len-total_len, &frame_len);
			if (ptr_frame) {
				ptr = (char*)malloc(frame_len);
				memcpy(ptr, ptr_frame, frame_len);
				GetRtspServerInstance()->setH264PPS(ptr, frame_len);
			}
			total_len += frame_len;

			pData = (unsigned char *)(ptr_frame+frame_len);
			len = sps_len-total_len;
		}
	}

	while(1) {
		pFrame = get_h264_frame((char*)(pData+nTotallen), len-nTotallen, &nFrameLen);
		// printf("[%s-%d] get_h264_frame\n", __FUNCTION__, __LINE__);
		if (pFrame) {
			printf("[%s-%d] addH264Data\n", __FUNCTION__, __LINE__);
			GetRtspServerInstance()->addH264Data(pFrame+4, nFrameLen-4, nTimestamp);
		}
		nTotallen += nFrameLen;
		if (nTotallen>=len)
			break;
	}
}

void RtspService::OnRtspMPEG4Data(unsigned char*pData, int len, int nKeyFrame, unsigned int nTimestamp)
{
	GetRtspServerInstance()->addH264Data((char*)pData, len, nTimestamp);	
}

void RtspService::SetParams(int nAudioEnable, int nEncType, int nFramerate, int nBitrate, int nWidth, int nHeight, int nQuality)
{

}

void RtspService::SetAuthInfo(bool bEnable, char *pUserName, char *pPassword)
{
	GetRtspServerInstance()->SetAuthInfo(bEnable, pUserName, pPassword);
}

RtspService *GetRtspServiceInstance()
{
	return RtspService::GetInstance();
}

