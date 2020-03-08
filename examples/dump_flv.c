
//https://blog.csdn.net/leixiaohua1020/article/details/42104893
// 参考原文是windows下的工程，改成linux下的工程 

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include "librtmp/rtmp_sys.h"
#include "librtmp/log.h"


int main(int argc, char* argv[])
{
    int nRead;
    //is live stream ?
    bool bLiveStream = TRUE;

    int bufsize = 1024 * 1024 * 10;
    char *buf = (char *)malloc(bufsize);
    memset(buf, 0, bufsize);
    long countbufsize = 0;

    FILE *fp = fopen("receive.flv", "wb");
    if (!fp) {
        RTMP_LogPrintf("Open File Error.\n");
        return -1;
    }

    /* set log level */
    //RTMP_LogLevel loglvl = RTMP_LOGDEBUG;
    //RTMP_LogSetLevel(loglvl)

    RTMP *rtmp = RTMP_Alloc();
    RTMP_Init(rtmp);

    //设置超时时间，默认30秒
    rtmp->Link.timeout = 10;
    if (!RTMP_SetupURL(rtmp, "rtmp://localhost/live/stream")) {
        RTMP_Log(RTMP_LOGERROR, "SetupURL Err\n");
        RTMP_Free(rtmp);
        return -1;
    }

    if (bLiveStream) {
        rtmp->Link.lFlags |= RTMP_LF_LIVE;
    }

    //1hour
    RTMP_SetBufferMS(rtmp, 3600*1000);

    if (!RTMP_Connect(rtmp, NULL)) {
        RTMP_Log(RTMP_LOGERROR, "Connect Err\n");
        RTMP_Free(rtmp);
        return -1;
    }
    
    if (!RTMP_ConnectStream(rtmp, 0)) {
        RTMP_Log(RTMP_LOGERROR, "ConnectStream Err\n");
        RTMP_Close(rtmp);
        RTMP_Free(rtmp);
        return -1;
    }

    while ((nRead = RTMP_Read(rtmp, buf, bufsize)))
    {
        fwrite(buf, 1, nRead, fp);
        countbufsize += nRead;
        RTMP_LogPrintf("Receive: %5dByte, Total: %5.2fkB\n", nRead, countbufsize*1.0/1024);
    }
    
    if(fp)
		fclose(fp);
 
	if(buf){
		free(buf);
	}
 
	if(rtmp){
		RTMP_Close(rtmp);
		RTMP_Free(rtmp);
		rtmp=NULL;
	}
	return 0;
}