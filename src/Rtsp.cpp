#include <stdio.h>

#include "RtspServer.h"
#include "RtspService.h"

int main(int argc, char *argv[])
{
	RtspService *pRtspService = GetRtspServiceInstance();
	pRtspService->Start();
	while(1)
	{
		usleep(10000);
		continue;
	}
	return 0;
}