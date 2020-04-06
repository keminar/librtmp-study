// 阅读代码前可以先看下原理
// https://blog.csdn.net/leixiaohua1020/article/details/17934487
// 或 examples/doc/FLV封装格式分析.docx

// 源码参考如下，参考原文是windows下的工程，我改成了linux下的工程
// https://blog.csdn.net/leixiaohua1020/article/details/42104945
// https://blog.csdn.net/u013470102/article/details/89473763

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#include "librtmp/rtmp_sys.h"
#include "librtmp/log.h"

#define HTON16(x) ((x >> 8 & 0xff) | (x << 8 & 0xff00))
#define HTON24(x) ((x >> 16 & 0xff) | (x << 16 & 0xff0000) | (x & 0xff00))
#define HTON32(x) ((x >> 24 & 0xff) | (x >> 8 & 0xff00) | \
                   (x << 8 & 0xff0000) | (x << 24 & 0xff000000))
#define HTONTIME(x) ((x >> 16 & 0xff) | (x << 16 & 0xff0000) | (x & 0xff00) | (x & 0xff000000))

char *filename = "test.flv";
char *rtmpserver = "rtmp://127.0.0.1/live/stream";

/*读1字节*/
int ReadU8(uint32_t *u8, FILE *fp)
{
    if (fread(u8, 1, 1, fp) != 1)
        return 0;
    return 1;
}

/*读2个字节*/
int ReadU16(uint32_t *u16, FILE *fp)
{
    if (fread(u16, 2, 1, fp) != 1)
    {
        return 0;
    }
    *u16 = HTON16(*u16);
    return 1;
}

/*读3个字节*/
int ReadU24(uint32_t *u24, FILE *fp)
{
    if (fread(u24, 3, 1, fp) != 1)
    {
        return 0;
    }
    *u24 = HTON24(*u24);
    return 1;
}

/*读4个字节*/
int ReadU32(uint32_t *u32, FILE *fp)
{
    if (fread(u32, 4, 1, fp) != 1)
    {
        return 0;
    }
    *u32 = HTON32(*u32);
    return 1;
}

/*读1个字节，再回退1个字节*/
int PeekU8(uint32_t *u8, FILE *fp)
{
    if (fread(u8, 1, 1, fp) != 1)
    {
        return 0;
    }
    fseek(fp, -1, SEEK_CUR);
    return 1;
}

/*读4个字节，转换为时间格式*/
int ReadTime(uint32_t *utime, FILE *fp)
{
    if (fread(utime, 4, 1, fp) != 1)
    {
        return 0;
    }
    *utime = HTONTIME(*utime);
    return 1;
}

int publish_using_packet()
{
    RTMP *rtmp = NULL;
    RTMPPacket *packet = NULL;
    uint32_t start_time = 0;
    uint32_t now_time = 0;
    //上一帧时间
    long pre_frame_time = 0;
    long lasttime = 0;
    //下一帧是否是关键帧
    int bNextIsKey = 1;
    uint32_t preTagSize = 0;

    //packet attributes
    uint32_t type = 0;
    uint32_t datalength = 0;
    uint32_t timestamp = 0;
    uint32_t streamid = 0;

    //设置日志级别
    //RTMP_LogLevel loglvl = RTMP_LOGDEBUG;
    //RTMP_LogSetLevel(loglvl);

    //为结构体分配内存
    rtmp = RTMP_Alloc();
    if (!rtmp)
    {
        RTMP_LogPrintf("RTMP_Alloc failed\n");
        return -1;
    }
    //初始化RTMP中的成员变量
    RTMP_Init(rtmp);
    // 设置连接超时，默认为30秒
    rtmp->Link.timeout = 500;
    if (!RTMP_SetupURL(rtmp, rtmpserver))
    {
        RTMP_Log(RTMP_LOGERROR, "SetupURL Err\n");
        RTMP_Free(rtmp);
        return -1;
    }
    printf("tcUrl=%.*s, app=%.*s, playpath0=%.*s\n", rtmp->Link.tcUrl.av_len, rtmp->Link.tcUrl.av_val, rtmp->Link.app.av_len, rtmp->Link.app.av_val, rtmp->Link.playpath0.av_len, rtmp->Link.playpath0.av_val);
    //设置为发布流，默认AMF命令为播放流
    RTMP_EnableWrite(rtmp);
    //建立RTMP连接，创建一个RTMP协议规范中的NetConnection
    if (!RTMP_Connect(rtmp, NULL))
    {
        RTMP_Log(RTMP_LOGERROR, "Connect Err\n");
        RTMP_Free(rtmp);
        return -1;
    }
    //创建一个RTMP规范中的NetStream
    if (!RTMP_ConnectStream(rtmp, 0))
    {
        RTMP_Log(RTMP_LOGERROR, "ConnectStream Err\n");
        RTMP_Close(rtmp);
        RTMP_Free(rtmp);
        return -1;
    }

    packet = (RTMPPacket *)malloc(sizeof(RTMPPacket));
    RTMPPacket_Alloc(packet, 1024 * 64);
    RTMPPacket_Reset(packet);

    packet->m_hasAbsTimestamp = 0;
    packet->m_nChannel = 0x04;//音视频
    packet->m_nInfoField2 = rtmp->m_stream_id;

    RTMP_LogPrintf("Start to send data ...\n");

    FILE *fp = NULL;
    fp = fopen(filename, "rb");
    if (!fp)
    {
        RTMP_LogPrintf("Open File Error.\n");
        RTMP_Close(rtmp);
        RTMP_Free(rtmp);
        return -1;
    }

    //跳过flv的9个头字节
    fseek(fp, 9, SEEK_SET);
    //跳过previousTagSize所占的4个字节
    fseek(fp, 4, SEEK_CUR);
    start_time = RTMP_GetTime();
    while (1)
    {
        //如果下一帧是关键帧，且上一帧的时间进度比系统推流过去的时间长，说明推流速度过快了，可以延时下
        now_time = RTMP_GetTime();
        if (((now_time - start_time) < (pre_frame_time)) && bNextIsKey)
        {
            //发送的太快了，休息1秒, 机制并不好
            if (pre_frame_time > lasttime)
            {
                RTMP_LogPrintf("TimeStamp:%8lu ms\n", pre_frame_time);
                lasttime = pre_frame_time;
            }
            sleep(1);
            continue;
        }

        // 读取包的各个属性
        // 读取type
        if (!ReadU8(&type, fp))
        {
            break;
        }
        //读取datalength的长度
        if (!ReadU24(&datalength, fp))
        {
            break;
        }
        //从flv的head读时间戳
        if (!ReadTime(&timestamp, fp))
        {
            break;
        }
        //读取streamid的类型， 一般总是0
        if (!ReadU24(&streamid, fp))
        {
            break;
        }

        // 0x08 音频，0x09视频， 0x12 script data
        // 网上的其它demo都是有下面这段的，但测试这里不应该跳过，Script 类型也应该发到服务端
        // 不然播放时会报 missing picture in access unit with size
        // Script类型Tag通常被称为Metadata Tag，会放一些FLV视频和音频的元数据信息如：duration、width、height等
        // 通常该类型Tag会跟在File Header后面作为第一个Tag出现，而且只有一个

        // 检查是不是音频和视频
        //if (type != 0x08 && type != 0x09) {
        //  //跳过脚本和脚本后的previousTagSize
        //  fseek(fp, datalength + 4, SEEK_CUR);
        //  continue;
        //}

        //把flv的音频和视频数据写入到packet的body中
        if (fread(packet->m_body, 1, datalength, fp) != datalength)
        {
            break;
        }

        packet->m_headerType = RTMP_PACKET_SIZE_LARGE;
        packet->m_nTimeStamp = timestamp;
        packet->m_packetType = type;
        packet->m_nBodySize = datalength;
        //把包读取到的时戳赋值给上一帧时间戳变量
        pre_frame_time = timestamp;
        // 确认连接
        if (!RTMP_IsConnected(rtmp))
        {
            RTMP_Log(RTMP_LOGERROR, "rtmp is not connect\n");
            break;
        }

        //RTMP_Log(RTMP_LOGINFO, "send packet\n");
        // 发送一个RTMP数据包
        if (!RTMP_SendPacket(rtmp, packet, 0))
        {
            RTMP_Log(RTMP_LOGERROR, "Send Error\n");
            break;
        }

        // 读取下一个包的previousTagSize
        if (!ReadU32(&preTagSize, fp))
        {
            break;
        }

        // 读下一帧的类型，并回退
        if (!PeekU8(&type, fp))
        {
            break;
        }
        // 如果下一帧是视频
        if (type == 0x09)
        {
            // 跳过Tag header
            if (fseek(fp, 11, SEEK_CUR) != 0)
            {
                break;
            }
            //视频tag data的第一个字节用来表示视频数据的参数信息
            if (!PeekU8(&type, fp))
            {
                break;
            }
            //如果视频帧是关键帧
            if (type == 0x17)
            {
                bNextIsKey = 1;
            }
            else
            {
                bNextIsKey = 0;
            }
            // 回退
            fseek(fp, -11, SEEK_CUR);
        }
    }
    RTMP_LogPrintf("\nSend Data Over!\n");
    if (fp)
    {
        fclose(fp);
    }

    if (rtmp != NULL)
    {
        //关闭RTMP连接
        RTMP_Close(rtmp);
        //释放结构体RTMP
        RTMP_Free(rtmp);
        rtmp = NULL;
    }
    if (packet != NULL)
    {
        RTMPPacket_Free(packet);
        free(packet);
        packet = NULL;
    }
    return 0;
}

//Publish using RTMP_Write()
int publish_using_write()
{
    uint32_t start_time = 0;
    uint32_t now_time = 0;
    long pre_frame_time = 0;
    uint32_t lasttime = 0;
    int bNextIsKey = 0;
    char *pFileBuf = NULL;

    //read from tag header
    uint32_t type = 0;
    uint32_t datalength = 0;
    uint32_t timestamp = 0;

    RTMP *rtmp = NULL;

    FILE *fp = NULL;
    fp = fopen(filename, "rb");
    if (!fp)
    {
        RTMP_LogPrintf("Open File Error.\n");
        return -1;
    }

    rtmp = RTMP_Alloc();
    RTMP_Init(rtmp);
    //set connection timeout,default 30s
    rtmp->Link.timeout = 500;
    if (!RTMP_SetupURL(rtmp, rtmpserver))
    {
        RTMP_Log(RTMP_LOGERROR, "SetupURL Err\n");
        RTMP_Free(rtmp);
        return -1;
    }
    printf("tcUrl=%.*s, app=%.*s, playpath0=%.*s\n", rtmp->Link.tcUrl.av_len, rtmp->Link.tcUrl.av_val, rtmp->Link.app.av_len, rtmp->Link.app.av_val, rtmp->Link.playpath0.av_len, rtmp->Link.playpath0.av_val);
    RTMP_EnableWrite(rtmp);
    //1hour
    RTMP_SetBufferMS(rtmp, 3600 * 1000);
    if (!RTMP_Connect(rtmp, NULL))
    {
        RTMP_Log(RTMP_LOGERROR, "Connect Err\n");
        RTMP_Free(rtmp);
        return -1;
    }

    if (!RTMP_ConnectStream(rtmp, 0))
    {
        RTMP_Log(RTMP_LOGERROR, "ConnectStream Err\n");
        RTMP_Close(rtmp);
        RTMP_Free(rtmp);
        return -1;
    }

    printf("Start to send data ...\n");

    //jump over FLV Header
    fseek(fp, 9, SEEK_SET);
    //jump over previousTagSizen
    fseek(fp, 4, SEEK_CUR);
    start_time = RTMP_GetTime();
    while (1)
    {
        if ((((now_time = RTMP_GetTime()) - start_time) < (pre_frame_time)) && bNextIsKey)
        {
            //wait for 1 sec if the send process is too fast
            //this mechanism is not very good,need some improvement
            if (pre_frame_time > lasttime)
            {
                RTMP_LogPrintf("TimeStamp:%8lu ms\n", pre_frame_time);
                lasttime = pre_frame_time;
            }
            sleep(1);
            continue;
        }

        //jump over type
        fseek(fp, 1, SEEK_CUR);
        if (!ReadU24(&datalength, fp))
            break;
        if (!ReadTime(&timestamp, fp))
            break;
        //jump back
        fseek(fp, -8, SEEK_CUR);

        pFileBuf = (char *)malloc(11 + datalength + 4);
        memset(pFileBuf, 0, 11 + datalength + 4);
        if (fread(pFileBuf, 1, 11 + datalength + 4, fp) != (11 + datalength + 4))
            break;

        pre_frame_time = timestamp;

        if (!RTMP_IsConnected(rtmp))
        {
            RTMP_Log(RTMP_LOGERROR, "rtmp is not connect\n");
            break;
        }
        if (!RTMP_Write(rtmp, pFileBuf, 11 + datalength + 4))
        {
            RTMP_Log(RTMP_LOGERROR, "Rtmp Write Error\n");
            break;
        }

        free(pFileBuf);
        pFileBuf = NULL;

        if (!PeekU8(&type, fp))
            break;
        if (type == 0x09)
        {
            if (fseek(fp, 11, SEEK_CUR) != 0)
                break;
            if (!PeekU8(&type, fp))
            {
                break;
            }
            if (type == 0x17)
                bNextIsKey = 1;
            else
                bNextIsKey = 0;
            fseek(fp, -11, SEEK_CUR);
        }
    }

    RTMP_LogPrintf("\nSend Data Over\n");

    if (fp)
        fclose(fp);

    if (rtmp != NULL)
    {
        RTMP_Close(rtmp);
        RTMP_Free(rtmp);
        rtmp = NULL;
    }

    if (pFileBuf)
    {
        free(pFileBuf);
        pFileBuf = NULL;
    }
    return 0;
}

int main(int argc, char *argv[])
{
    if (argc > 1)
    {
        RTMP_LogPrintf("start packet\n");
        publish_using_packet();
    }
    else
    {
        RTMP_LogPrintf("start write\n");
        publish_using_write();
    }
    return 0;
}
