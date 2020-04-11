// 参考
// https://blog.csdn.net/leixiaohua1020/article/details/84491802
// https://blog.csdn.net/xwjazjx1314/article/details/54693766
// https://blog.csdn.net/yeyumin89/article/details/7932585
// https://blog.csdn.net/huangyimo/article/details/83858620
// https://wenku.baidu.com/view/cdc944114afe04a1b171de86.html

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/times.h>

// 握手中随机数的长度（C1,C2,S1,S2）长度
#define RTMP_SIG_SIZE 1536

// basic header + msg header最大长度
#define RTMP_MAX_HEADER_SIZE 18

// 字符串结构体
typedef struct AVal
  {
    char *av_val;
    int av_len;
  } AVal;
//转换为字符串结构体
#define AVC(str)	{str,sizeof(str)-1}
// 字符串结构体比较
#define AVMATCH(a1,a2)	((a1)->av_len == (a2)->av_len && !memcmp((a1)->av_val,(a2)->av_val,(a1)->av_len))

//定义字符串结构体
#define SAVC(x) static const AVal av_##x = AVC(#x)

//字符串常量转为字符串结构
#define STR2AVAL(av, str) \
  av.av_val = str;  \
  av.av_len = strlen(av.av_val)

typedef enum
{ AMF_NUMBER = 0, AMF_BOOLEAN, AMF_STRING, AMF_OBJECT,
  AMF_MOVIECLIP,		/* reserved, not used */
  AMF_NULL, AMF_UNDEFINED, AMF_REFERENCE, AMF_ECMA_ARRAY, AMF_OBJECT_END,
  AMF_STRICT_ARRAY, AMF_DATE, AMF_LONG_STRING, AMF_UNSUPPORTED,
  AMF_RECORDSET,		/* reserved, not used */
  AMF_XML_DOC, AMF_TYPED_OBJECT,
  AMF_AVMPLUS,		/* switch to AMF3 */
  AMF_INVALID = 0xff
} AMFDataType;

//声明对象
struct AMFObjectProperty;

//对象key=val
typedef struct AMFObject
{
  int o_num;
  struct AMFObjectProperty *o_props;
} AMFObject;

//定义对象值
typedef struct AMFObjectProperty
{
  AVal p_name;
  AMFDataType p_type;
  union
  {
    double p_number;
    AVal p_aval;
    AMFObject p_object;
  } p_vu;
  int16_t p_UTCoffset;
} AMFObjectProperty;

//无效对象
static const AMFObject AMFObj_Invalid = {0, 0};

//rtmp包信息
typedef struct RTMPPacket
{
    uint8_t m_headerType; //basic header 中的type头字节，值为（0，1，2，3） 表示ChunkMsgHeader的类型（4种）
    int m_nChannel;       //块流ID  ，通过设置ChannelID来设置Basic stream id的长度和值

    uint32_t m_nTimeStamp;                                              // Timestamp  完整包时为绝对时间，非完整时为相对时间？
    uint32_t m_nBodySize;                                               //指数据部分的消息总长度
    uint8_t m_packetType;                                               // Chunk Msg Header中的package Type类型
    int32_t m_nInfoField2; /* last 4 bytes in a long header,消息流ID */ //Chunk Msg Header中msg StreamID

    char *m_body;

    uint32_t m_nBytesRead;                                         //已读取长度
    uint8_t m_hasAbsTimestamp; /* Timestamp 是绝对值还是相对值? */ //用于收消息时
} RTMPPacket;

// 显示错误
void error_handling(char *message);

//握手
void handshake_server(int clnt_sock);

//反解object
int AMF_Decode(AMFObject *obj, const char *pBuffer, int nSize, int bDecodeName);
//反解value
int AMFProp_Decode(AMFObjectProperty *prop, const char *pBuffer, int nSize, int bDecodeName);
//添加到对象
void AMF_AddProp(AMFObject *obj, const AMFObjectProperty *prop);

//解析命令参数
void ServeInvoke(AMFObject *obj);

// 对connect进行回应
static int SendConnectResult(int clnt_sock, double txn);

// 从rtmpdump精简的时间函数，不用跨平台
uint32_t
RTMP_GetTime()
{
    struct tms t;
    static int clk_tck;
    // 原函数此处有一个缓存，这里为了演示去掉了
    clk_tck = sysconf(_SC_CLK_TCK);
    return times(&t) * 1000 / clk_tck;
}

static int
DecodeInt32LE(const char *data)
{
  unsigned char *c = (unsigned char *)data;
  unsigned int val;

  val = (c[3] << 24) | (c[2] << 16) | (c[1] << 8) | c[0];
  return val;
}

/* Data is Big-Endian */
unsigned short
AMF_DecodeInt16(const char *data)
{
  unsigned char *c = (unsigned char *)data;
  unsigned short val;
  val = (c[0] << 8) | c[1];
  return val;
}

unsigned int
AMF_DecodeInt24(const char *data)
{
  unsigned char *c = (unsigned char *)data;
  unsigned int val;
  val = (c[0] << 16) | (c[1] << 8) | c[2];
  return val;
}

unsigned int
AMF_DecodeInt32(const char *data)
{
  unsigned char *c = (unsigned char *)data;
  unsigned int val;
  val = (c[0] << 24) | (c[1] << 16) | (c[2] << 8) | c[3];
  return val;
}

void AMF_DecodeString(const char *data, AVal *bv)
{
  bv->av_len = AMF_DecodeInt16(data);
  bv->av_val = (bv->av_len > 0) ? (char *)data + 2 : NULL;
}
void AMF_DecodeLongString(const char *data, AVal *bv)
{
  bv->av_len = AMF_DecodeInt32(data);
  bv->av_val = (bv->av_len > 0) ? (char *)data + 4 : NULL;
}

int AMF_DecodeBoolean(const char *data)
{
  return *data != 0;
}
double
AMF_DecodeNumber(const char *data)
{
  double dVal;
#if __FLOAT_WORD_ORDER == __BYTE_ORDER
#if __BYTE_ORDER == __BIG_ENDIAN
  memcpy(&dVal, data, 8);
#elif __BYTE_ORDER == __LITTLE_ENDIAN
  unsigned char *ci, *co;
  ci = (unsigned char *)data;
  co = (unsigned char *)&dVal;
  co[0] = ci[7];
  co[1] = ci[6];
  co[2] = ci[5];
  co[3] = ci[4];
  co[4] = ci[3];
  co[5] = ci[2];
  co[6] = ci[1];
  co[7] = ci[0];
#endif
#else
#if __BYTE_ORDER == __LITTLE_ENDIAN /* __FLOAT_WORD_ORER == __BIG_ENDIAN */
  unsigned char *ci, *co;
  ci = (unsigned char *)data;
  co = (unsigned char *)&dVal;
  co[0] = ci[3];
  co[1] = ci[2];
  co[2] = ci[1];
  co[3] = ci[0];
  co[4] = ci[7];
  co[5] = ci[6];
  co[6] = ci[5];
  co[7] = ci[4];
#else                               /* __BYTE_ORDER == __BIG_ENDIAN && __FLOAT_WORD_ORER == __LITTLE_ENDIAN */
  unsigned char *ci, *co;
  ci = (unsigned char *)data;
  co = (unsigned char *)&dVal;
  co[0] = ci[4];
  co[1] = ci[5];
  co[2] = ci[6];
  co[3] = ci[7];
  co[4] = ci[0];
  co[5] = ci[1];
  co[6] = ci[2];
  co[7] = ci[3];
#endif
#endif
  return dVal;
}

int AMF_DecodeArray(AMFObject *obj, const char *pBuffer, int nSize,
                    int nArrayLen, int bDecodeName)
{
  int nOriginalSize = nSize;
  int bError = false;

  obj->o_num = 0;
  obj->o_props = NULL;
  while (nArrayLen > 0)
  {
    AMFObjectProperty prop;
    int nRes;
    nArrayLen--;

    if (nSize <= 0)
    {
      bError = true;
      break;
    }
    nRes = AMFProp_Decode(&prop, pBuffer, nSize, bDecodeName);
    if (nRes == -1)
    {
      bError = true;
      break;
    }
    else
    {
      nSize -= nRes;
      pBuffer += nRes;
      AMF_AddProp(obj, &prop);
    }
  }
  if (bError)
    return -1;

  return nOriginalSize - nSize;
}

// 把nVal转大端字节序并存入output
char *
AMF_EncodeInt16(char *output, char *outend, short nVal)
{
  if (output + 2 > outend)
    return NULL;

  output[1] = nVal & 0xff;
  output[0] = nVal >> 8;
  return output + 2;
}

char *
AMF_EncodeInt24(char *output, char *outend, int nVal)
{
  if (output + 3 > outend)
    return NULL;

  output[2] = nVal & 0xff;
  output[1] = nVal >> 8;
  output[0] = nVal >> 16;
  return output + 3;
}

char *
AMF_EncodeInt32(char *output, char *outend, int nVal)
{
  if (output + 4 > outend)
    return NULL;

  output[3] = nVal & 0xff;
  output[2] = nVal >> 8;
  output[1] = nVal >> 16;
  output[0] = nVal >> 24;
  return output + 4;
}

char *
AMF_EncodeString(char *output, char *outend, const AVal *bv)
{
  // 检查加上字符串会不会超过总长度,1为type长度，2为datasize长度
  if ((bv->av_len < 65536 && output + 1 + 2 + bv->av_len > outend) ||
      output + 1 + 4 + bv->av_len > outend)
    return NULL;

  if (bv->av_len < 65536)
  {
    // 写上字符串类型（AMFType）
    *output++ = AMF_STRING;
    // 将内容长度av_len大端转换并写入output
    output = AMF_EncodeInt16(output, outend, bv->av_len);
  }
  else
  {
    //宽字符串类型
    *output++ = AMF_LONG_STRING;

    output = AMF_EncodeInt32(output, outend, bv->av_len);
  }
  // 写上bv的内容
  memcpy(output, bv->av_val, bv->av_len);
  // 指针位置移到尾部
  output += bv->av_len;

  return output;
}

char *
AMF_EncodeNumber(char *output, char *outend, double dVal)
{
  //检查溢出，1为type长度，8为objvalue长度
  if (output + 1 + 8 > outend)
    return NULL;

  // 写上类型
  *output++ = AMF_NUMBER; /* type: Number */

#if __FLOAT_WORD_ORDER == __BYTE_ORDER
#if __BYTE_ORDER == __BIG_ENDIAN
  memcpy(output, &dVal, 8);
#elif __BYTE_ORDER == __LITTLE_ENDIAN
  {
    unsigned char *ci, *co;
    ci = (unsigned char *)&dVal;
    co = (unsigned char *)output;
    co[0] = ci[7];
    co[1] = ci[6];
    co[2] = ci[5];
    co[3] = ci[4];
    co[4] = ci[3];
    co[5] = ci[2];
    co[6] = ci[1];
    co[7] = ci[0];
  }
#endif
#else
#if __BYTE_ORDER == __LITTLE_ENDIAN /* __FLOAT_WORD_ORER == __BIG_ENDIAN */
  {
    unsigned char *ci, *co;
    ci = (unsigned char *)&dVal;
    co = (unsigned char *)output;
    co[0] = ci[3];
    co[1] = ci[2];
    co[2] = ci[1];
    co[3] = ci[0];
    co[4] = ci[7];
    co[5] = ci[6];
    co[6] = ci[5];
    co[7] = ci[4];
  }
#else                               /* __BYTE_ORDER == __BIG_ENDIAN && __FLOAT_WORD_ORER == __LITTLE_ENDIAN */
  {
    unsigned char *ci, *co;
    ci = (unsigned char *)&dVal;
    co = (unsigned char *)output;
    co[0] = ci[4];
    co[1] = ci[5];
    co[2] = ci[6];
    co[3] = ci[7];
    co[4] = ci[0];
    co[5] = ci[1];
    co[6] = ci[2];
    co[7] = ci[3];
  }
#endif
#endif

  return output + 8;
}

char *
AMF_EncodeBoolean(char *output, char *outend, int bVal)
{
  //检查溢出，1为type长度，1为objvalue长度
  if (output + 2 > outend)
    return NULL;

  *output++ = AMF_BOOLEAN;

  *output++ = bVal ? 0x01 : 0x00;

  return output;
}

// MAP类型，值string
char *
AMF_EncodeNamedString(char *output, char *outend, const AVal *strName, const AVal *strValue)
{
  // 2为strName的长度的占用
  if (output + 2 + strName->av_len > outend)
    return NULL;
  // strName就是AMF数据的ObjType
  // 存入strName的长度  
  output = AMF_EncodeInt16(output, outend, strName->av_len);
  // 存入strName的值
  memcpy(output, strName->av_val, strName->av_len);
  output += strName->av_len;

  // strValue是AMF数据的ObjValue
  // 存入strValue
  return AMF_EncodeString(output, outend, strValue);
}

// MAP类型，值Number
char *
AMF_EncodeNamedNumber(char *output, char *outend, const AVal *strName, double dVal)
{
  if (output + 2 + strName->av_len > outend)
    return NULL;
  output = AMF_EncodeInt16(output, outend, strName->av_len);

  memcpy(output, strName->av_val, strName->av_len);
  output += strName->av_len;

  return AMF_EncodeNumber(output, outend, dVal);
}

// MAP类型，值Bool
char *
AMF_EncodeNamedBoolean(char *output, char *outend, const AVal *strName, int bVal)
{
  if (output + 2 + strName->av_len > outend)
    return NULL;
  output = AMF_EncodeInt16(output, outend, strName->av_len);

  memcpy(output, strName->av_val, strName->av_len);
  output += strName->av_len;

  return AMF_EncodeBoolean(output, outend, bVal);
}


int RTMPPacket_Alloc(RTMPPacket *p, uint32_t nSize)
{
  char *ptr;
  if (nSize > SIZE_MAX - RTMP_MAX_HEADER_SIZE)
    return 0;
  ptr = calloc(1, nSize + RTMP_MAX_HEADER_SIZE);
  if (!ptr)
    return 0;
  p->m_body = ptr + RTMP_MAX_HEADER_SIZE;
  p->m_nBytesRead = 0;
  return 1;
}


void handshake_server(int clnt_sock)
{
    // C0和S0长度都是1
    //1+1536
    char c0c1[1 + RTMP_SIG_SIZE];
    //1+1536*2
    char s0s1s2[1 + RTMP_SIG_SIZE * 2];
    //1536
    char c2[RTMP_SIG_SIZE];
    //定义两个指针方便操作
    char *s1s2;
    char *c1;
    // 服务器时间
    uint32_t server_time;
    // 客户端时间
    uint32_t client_time;
    int bMatch;
    int i;

    //从客户端接收 c0c1
    if (read(clnt_sock, c0c1, sizeof(c0c1)) == 0)
    {
        error_handling("read c0c1 error");
    }
    printf("C0 Version: %d\n", c0c1[0]);
    if (c0c1[0] != 3)
    {
        error_handling("not rtmp connection");
    }

    //将数组下标向右移一位跳过c0，指针将指到c1
    c1 = c0c1 + 1;
    // 将c1前4位时间取出
    memcpy(&client_time, c1, 4);
    //网络字节序转换为时间
    client_time = ntohl(client_time);
    printf("C1 Client time: %d\n", client_time);
    printf("C1 FMS Version: %d.%d.%d.%d\n", c1[4], c1[5], c1[6], c1[7]);
    printf("C1 Rand: ");
    for (i = 8; i < RTMP_SIG_SIZE; i++)
    {
        printf("%d.", c1[i]);
    }
    printf("\n\n");

    //初始化s0
    s0s1s2[0] = 3;
    printf("S0 Version: %d\n", s0s1s2[0]);

    //可以通过sleep观察客户端与服务端时间变化，真实服务中不需要
    //sleep(10);

    //将数组下标向右移一位跳过s0，指针将指到s1和s2
    s1s2 = s0s1s2 + 1;
    //获取时间并转换为网络字节序
    server_time = RTMP_GetTime();
    printf("S1 Server time: %d\n", server_time);
    server_time = htonl(server_time);
    //初始化s1的开头4个字节为time
    memcpy(s1s2, &server_time, 4);
    //初始化s1中间4个字节为4个0
    memset(&s1s2[4], 0, 4);
    //初始化s1的最后1528个字节为随机数
    printf("S1 Rand: ");
    for (i = 8; i < RTMP_SIG_SIZE; i++)
    {
        s1s2[i] = (char)(rand() % 256); //'a';
        printf("%d.", s1s2[i]);
    }
    printf("\n\n");

    //把c1 拷贝到s2, 为了简单这里没有按协议分别计算time和time2，因为好像也没什么用
    printf("S2 Rand: ");
    memcpy(&s1s2[RTMP_SIG_SIZE], c1, RTMP_SIG_SIZE);
    for (i = RTMP_SIG_SIZE + 8; i < RTMP_SIG_SIZE * 2; i++)
    {
        printf("%d.", s1s2[i]);
    }
    printf("\n\n");

    //发送 s0s1s2 到客户端
    write(clnt_sock, s0s1s2, sizeof(s0s1s2));

    //从客户端接收 c2, 注意长度
    if (read(clnt_sock, c2, RTMP_SIG_SIZE) == 0)
    {
        error_handling("read c2 error");
    }
    // 将c1前4位时间取出
    memcpy(&server_time, c2, 4);
    //网络字节序转换为时间
    server_time = ntohl(server_time);
    printf("C2 time: %d\n", server_time);
    printf("C2 Rand: ");
    for (i = 8; i < RTMP_SIG_SIZE; i++)
    {
        printf("%d.", c2[i]);
    }
    printf("\n\n");

    // 比较C2 与 S1值是否一样
    bMatch = (memcmp(c2, s1s2, RTMP_SIG_SIZE) == 0);
    if (!bMatch)
    {
        error_handling("signature does not match!");
    }
    printf("hanshake success\n");
}

// 读取包数据
int RTMP_ReadPacket(int clnt_sock, RTMPPacket *packet)
{
    // 头数组
    uint8_t hbuf[RTMP_MAX_HEADER_SIZE] = {0};
    // 头指针
    char *header = (char *)hbuf;
    // 头长度
    int nSize, hSize;
    int nBytes;
    int nChunk;
    AVal method;
    char *ptr;

    nBytes = recv(clnt_sock, header, 1, 0);
    if (nBytes == -1)
    {
        error_handling("recv returned");
    }

    packet->m_headerType = (hbuf[0] & 0xc0) >> 6;
    packet->m_nChannel = (hbuf[0] & 0x3f);
    printf("header type=%d, basic stream id=%d\n", (int)packet->m_headerType, packet->m_nChannel);
    header++;

    // msg header + basic header 为总的header长度
    hSize = 12;
    // 不算header type
    nSize = hSize - 1;
    recv(clnt_sock, header, nSize, 0);

    //则取时间戳
    packet->m_nTimeStamp = AMF_DecodeInt24(header);

    //取body size
    packet->m_nBodySize = AMF_DecodeInt24(header + 3);

    // 取packet type
    packet->m_packetType = header[6];

    // 取msg streamID
    packet->m_nInfoField2 = DecodeInt32LE(header + 7); 

    packet->m_body = NULL;
    if (!RTMPPacket_Alloc(packet, packet->m_nBodySize))
    {
        error_handling(" failed to allocate packet");
    }

    // 如果一个packet第一次读取，要通过m_nBytesRead来移动指针
    nChunk = packet->m_nBodySize;

    printf("packetType=0x%x, chunk len=%d\n", packet->m_packetType, nChunk);

    // 这里长度没超过128，为了示例一次读取，如果长度大于128，需要多次读取并去掉每片前的head_type的1个字节
    // m_nBodySize的长度是body的长度再加上每个分片的header的长度。官方是在循环调用RTMP_ReadPacket函数
    // 默认分包长度是128 ，后面音视频流发送前可能会被改成其它值
    nBytes = recv(clnt_sock, packet->m_body, nChunk, 0);
    if (nBytes != nChunk)
    {
        printf("recv bytes=%d\n", nBytes);
        error_handling("failed to read body");
    }
    packet->m_nBytesRead = nChunk;
    
    // 包体指针向前移一步，跳过method类型字段
    ptr = packet->m_body + 1;
    // 解析method名字
    AMF_DecodeString(ptr, &method);
    printf("read body method type=%d, Invoking=%.*s\n", packet->m_body[0] , method.av_len, method.av_val);

    AMFObject obj;
    //反解到object
    AMF_Decode(&obj, packet->m_body, packet->m_nBodySize, false);
    //解决命令参数
    ServeInvoke(&obj);
    double txn = obj.o_props[1].p_vu.p_number;
    SendConnectResult(clnt_sock, txn);
    return 0;
}

int RTMP_SendPacket(int clnt_sock, RTMPPacket *packet)
{
  int nSize;
  int hSize;
  char *header, *hptr, *hend, c;
  char *buffer;
  int nChunkSize;
 
  // 块头初始大小 = 基本头(1字节) + 块消息头大小(11/7/3/0) = [12, 8, 4, 1]
  /**
   * hSize表示块头大小
   * +-----------+-----------------+----------------+--------------------+
   * | head type |timestamp(3字节) |body size(3字节) | packet type(1字节) |
   * +-----------+-----------------+----------------+--------------------+ 
   */
  hSize = 8;

  // m_body是指向负载数据首地址的指针；“-”号用于指针前移
  // 块头的首指针(含头信息)
  header = packet->m_body - hSize;
  // 块头的尾指针, 为了后面计算会不会溢出的
  hend = packet->m_body;
     
  // hptr指到Basic Header头部
  hptr = header;
  // 把ChunkBasicHeader的Fmt类型左移6位
  c = packet->m_headerType << 6;
  // 把ChunkBasicHeader的低6位设置成ChunkStreamID( cs id )
  c |= packet->m_nChannel;
     
  // 将c的值设到basic header第一个字节
  // 可以拆分成两句*hptr=c; hptr++，此时hptr指向第2个字节
  *hptr++ = c;
 // 将时间戳(相对或绝对)转化为3个字节存入hptr，如果时间戳超过0xffffff,则后面还要填入Extend Timestamp
  hptr = AMF_EncodeInt24(hptr, hend, packet->m_nTimeStamp);

  // ChunkMsgHeader长度为11、7，都含有 msg length + msg type id
  // 将消息长度(msg length)转化为3个字节存入hptr
  hptr = AMF_EncodeInt24(hptr, hend, packet->m_nBodySize);
  *hptr++ = packet->m_packetType; 

  // 到此为止，已经将块头填写好了
  // 此时nSize表示负载数据的长度
  nSize = packet->m_nBodySize;
  // buffer是指向负载数据区的指针
  buffer = packet->m_body;
  //Chunk大小，默认是128字节
  nChunkSize = 128;
  
  // 消息的负载 + 头
  while (nSize + hSize)
  {
    int wrote;
    // 消息负载大小 < Chunk默认大小(128字节）（不用分块）
    if (nSize < nChunkSize)
      nChunkSize = nSize;// Chunk可能小于设定值

    // 直接将负载数据和块头数据发送出去
    wrote = write(clnt_sock, header, nChunkSize + hSize);
    if (!wrote)
      return false;

    // 消息负载长度 - Chunk负载长度
    nSize -= nChunkSize;
    // buffer指针前移1个Chunk负载长度
    buffer += nChunkSize;
    // 重置块头大小为0，后续的块只需要有基本头(或加上扩展时间戳)即可
    hSize = 0;

    // 如果消息负载数据还没有发完，准备填充下一个块的块头数据
    if (nSize > 0)
    {
      // 空出包头的位置
      header = buffer - 1;
      // 因为分包也加了头，所以实际发出去的比packet->m_nBodySize要大。
      /**
       * hSize表示块头大小
       * +--------------------+
       * | head type(1字节) |
       * +--------------------+ 
       */
      // 包头大小为1
      hSize = 1;
      
      //写入head_type
      *header = (0xc0 | c);
    }
  }
  
  return true;
}

static int
SendConnectResult(int clnt_sock, double txn)
{
    RTMPPacket packet;
    //定义一个数组，并且定义一个指针指到数组尾
    char pbuf[384], *pend = pbuf + sizeof(pbuf);
    //定义一个字符串结构
    AVal av;

    printf("txn=%f\n", txn);

    packet.m_nChannel = 0x03;//通过设置ChannelID来设置Basic stream id的长度和值
    packet.m_headerType = 1; // Basic header的head type为1，表明msg header长度为7字节
    packet.m_packetType = 0x14;//消息类型ID为20，表示为Invoke方法调用
    packet.m_nTimeStamp = 0;// Chunk Msg Header中的时间戳
    packet.m_nInfoField2 = 0;// Chunk Msg Header中的消息流id Msg StreamID
    packet.m_hasAbsTimestamp = 0;// m_nTimeStamp是否为相对时间
    packet.m_body = pbuf + RTMP_MAX_HEADER_SIZE;

    SAVC(_result);
    
    char *enc = packet.m_body;
    enc = AMF_EncodeString(enc, pend, &av__result);
    enc = AMF_EncodeNumber(enc, pend, txn);

    // 定义AMF对象开始 , 以下的对象不是必须的
    *enc++ = 3;
    SAVC(fmsVer);
    SAVC(capabilities);
    SAVC(mode);
    STR2AVAL(av, "FMS/3,5,1,525");
    enc = AMF_EncodeNamedString(enc, pend, &av_fmsVer, &av);
    enc = AMF_EncodeNamedNumber(enc, pend, &av_capabilities, 31.0);
    enc = AMF_EncodeNamedNumber(enc, pend, &av_mode, 1.0);
    // 标记AMF对象结束
    *enc++ = 0;
    *enc++ = 0;
    *enc++ = 9;
    
    packet.m_nBodySize = enc - packet.m_body;
    RTMP_SendPacket(clnt_sock, &packet);

    return 0;
}

void ServeInvoke(AMFObject *obj)
{
    AMFObject cobj;
    AVal pname, pval;
    int i;

    // 定义av_app等变量
    SAVC(app);
    SAVC(flashVer);
    SAVC(swfUrl);
    SAVC(pageUrl);
    SAVC(tcUrl);
    SAVC(audioCodecs);
    SAVC(videoCodecs);
    SAVC(objectEncoding);

    // 取得第3个参数
    if ((&obj->o_props[2])->p_type == AMF_OBJECT)
      cobj = (&obj->o_props[2])->p_vu.p_object;
    else
      cobj = AMFObj_Invalid;

    for (i = 0; i < cobj.o_num; i++)
    {
      pname = cobj.o_props[i].p_name;
      pval.av_val = NULL;
      pval.av_len = 0;
      if (cobj.o_props[i].p_type == AMF_STRING)
        pval = cobj.o_props[i].p_vu.p_aval;
      if (AVMATCH(&pname, &av_app))
      {
        printf("app=%.*s\n", pval.av_len, pval.av_val);
        pval.av_val = NULL;
      }
      else if (AVMATCH(&pname, &av_flashVer))
      {
        printf("flashVer=%.*s\n", pval.av_len, pval.av_val);
        pval.av_val = NULL;
      }
      else if (AVMATCH(&pname, &av_swfUrl))
      {
        printf("swfUrl=%.*s\n", pval.av_len, pval.av_val);
        pval.av_val = NULL;
      }
      else if (AVMATCH(&pname, &av_tcUrl))
      {
        printf("tcUrl=%.*s\n", pval.av_len, pval.av_val);
        pval.av_val = NULL;
      }
      else if (AVMATCH(&pname, &av_pageUrl))
      {
        printf("pageUrl=%.*s\n", pval.av_len, pval.av_val);
        pval.av_val = NULL;
      }
      else if (AVMATCH(&pname, &av_audioCodecs))
      {
        printf("AudioCodecs=%f\n", cobj.o_props[i].p_vu.p_number);
      }
      else if (AVMATCH(&pname, &av_videoCodecs))
      {
        printf("VideoCodecs=%f\n", cobj.o_props[i].p_vu.p_number);
      }
      else if (AVMATCH(&pname, &av_objectEncoding))
      {
        printf("Encoding=%f\n", cobj.o_props[i].p_vu.p_number);
      }
    }
    //如果还有更多参数
    /* Still have more parameters? Copy them */
    if (obj->o_num > 3)
    {
      int i = obj->o_num - 3;
      printf("extras.o_num = %d\n", i);
    }
}

int AMF_Decode(AMFObject *obj, const char *pBuffer, int nSize, int bDecodeName)
{
    int nOriginalSize = nSize;
    int bError = false;

    obj->o_num = 0;
    obj->o_props = NULL;
    while (nSize > 0)
    {
      AMFObjectProperty prop;
      int nRes;

      // 检查是不是obj结束
      if (nSize >= 3 && AMF_DecodeInt24(pBuffer) == AMF_OBJECT_END)
      {
        nSize -= 3;
        break;
      }

      if (bError)
      {
        printf("DECODING ERROR, IGNORING BYTES UNTIL NEXT KNOWN PATTERN!\n");
        nSize--;
        pBuffer++;
        continue;
      }
      //解析属性
      nRes = AMFProp_Decode(&prop, pBuffer, nSize, bDecodeName);
      if (nRes == -1)
      {
        bError = true;
        continue;
      }
      else
      {
        nSize -= nRes;
        if (nSize < 0)
        {
          bError = true;
          continue;
        }
        pBuffer += nRes;
        AMF_AddProp(obj, &prop);
      }
    }
    if (bError)
      return -1;

    return nOriginalSize - nSize;
}

void AMF_AddProp(AMFObject *obj, const AMFObjectProperty *prop)
{
  if (!(obj->o_num & 0x0f))
    obj->o_props =
        realloc(obj->o_props, (obj->o_num + 16) * sizeof(AMFObjectProperty));
  memcpy(&obj->o_props[obj->o_num++], prop, sizeof(AMFObjectProperty));
}

/**
 * pBuffer 包体数据
 * nSize 包体大小
 * bDecodeName 是否有p_name需要解析，object类型需要
 */
int AMFProp_Decode(AMFObjectProperty *prop, const char *pBuffer, int nSize, int bDecodeName)
{
  int nOriginalSize = nSize;
  int nRes;

  prop->p_name.av_len = 0;
  prop->p_name.av_val = NULL;

  if (nSize == 0 || !pBuffer)
  {
    printf("%s: Empty buffer/no buffer pointer!\n", __FUNCTION__);
    return -1;
  }
  //如果是object类型
  if (bDecodeName)
  {
    //key长度占用2个字节，key最少一个字节，data最少一个字节
    if (nSize < 4) {/* at least name (length + at least 1 byte) and 1 byte of data */
      printf("%s: Not enough data for decoding with name, less than 4 bytes!\n", __FUNCTION__);
      return -1;
    }
    //解析key的长度
    unsigned short nNameSize = AMF_DecodeInt16(pBuffer);
    //总长度至少要有key的大小+2(key长度占用)
    if ( nSize < nNameSize + 2)
    {
      printf("%s: Name size out of range: namesize (%d) > len (%d) - 2\n",
               __FUNCTION__, nNameSize, nSize);
      return -1;
    }

    //解析key
    AMF_DecodeString(pBuffer, &prop->p_name);
    //总长度减去key和key长度占用为value长度
    nSize -= (2 + nNameSize);
    //指针移到value
    pBuffer += (2 + nNameSize);
  }

  if (nSize == 0)
  {
    return -1;
  }

  // 去掉value的类型占用
  nSize--;
  // 取类型
  prop->p_type = *pBuffer++;
  switch (prop->p_type)
  {
  case AMF_NUMBER:
    if (nSize < 8)
      return -1;
    prop->p_vu.p_number = AMF_DecodeNumber(pBuffer);
    nSize -= 8;
    break;
  case AMF_BOOLEAN:
    if (nSize < 1)
      return -1;
    prop->p_vu.p_number = (double)AMF_DecodeBoolean(pBuffer);
    nSize--;
    break;
  case AMF_STRING:
  {
    unsigned short nStringSize = AMF_DecodeInt16(pBuffer);

    if (nSize < (long)nStringSize + 2)
      return -1;
    AMF_DecodeString(pBuffer, &prop->p_vu.p_aval);
    nSize -= (2 + nStringSize);
    break;
  }
  case AMF_OBJECT:
  {
    nRes = AMF_Decode(&prop->p_vu.p_object, pBuffer, nSize, true);
    if (nRes == -1)
      return -1;
    nSize -= nRes;
    break;
  }
  case AMF_MOVIECLIP:
  {
    printf("AMF_MOVIECLIP reserved!\n");
    return -1;
    break;
  }
  case AMF_NULL:
  case AMF_UNDEFINED:
  case AMF_UNSUPPORTED:
    prop->p_type = AMF_NULL;
    break;
  case AMF_REFERENCE:
  {
    printf("AMF_REFERENCE not supported!\n");
    return -1;
    break;
  }
  case AMF_ECMA_ARRAY:
  {
    nSize -= 4;

    /* next comes the rest, mixed array has a final 0x000009 mark and names, so its an object */
    nRes = AMF_Decode(&prop->p_vu.p_object, pBuffer + 4, nSize, true);
    if (nRes == -1)
      return -1;
    nSize -= nRes;
    break;
  }
  case AMF_OBJECT_END:
  {
    return -1;
    break;
  }
  case AMF_STRICT_ARRAY:
  {
    unsigned int nArrayLen = AMF_DecodeInt32(pBuffer);
    nSize -= 4;

    nRes = AMF_DecodeArray(&prop->p_vu.p_object, pBuffer + 4, nSize,
                           nArrayLen, false);
    if (nRes == -1)
      return -1;
    nSize -= nRes;
    break;
  }
  case AMF_DATE:
  {
    printf("AMF_DATE\n");

    if (nSize < 10)
      return -1;

    prop->p_vu.p_number = AMF_DecodeNumber(pBuffer);
    prop->p_UTCoffset = AMF_DecodeInt16(pBuffer + 8);

    nSize -= 10;
    break;
  }
  case AMF_LONG_STRING:
  case AMF_XML_DOC:
  {
    unsigned int nStringSize = AMF_DecodeInt32(pBuffer);
    if (nSize < (long)nStringSize + 4)
      return -1;
    AMF_DecodeLongString(pBuffer, &prop->p_vu.p_aval);
    nSize -= (4 + nStringSize);
    if (prop->p_type == AMF_LONG_STRING)
      prop->p_type = AMF_STRING;
    break;
  }
  case AMF_RECORDSET:
  {
    printf("AMF_RECORDSET reserved!\n");
    return -1;
    break;
  }
  case AMF_TYPED_OBJECT:
  {
    printf("AMF_TYPED_OBJECT not supported!\n");
    return -1;
    break;
  }
  case AMF_AVMPLUS:
  {
    //AMF3 要引入好几个函数，先不加
    printf("AMF3 not supported!\n");
    return -1;
    break;
  }
  default:
    printf("%s - unknown datatype 0x%02x, @%p\n", __FUNCTION__,
             prop->p_type, pBuffer - 1);
    return -1;
  }

  return nOriginalSize - nSize;
}

int main(int argc, char *argv[])
{
    // tcp server
    int serv_sock;
    int clnt_sock;
    struct sockaddr_in serv_addr;
    struct sockaddr_in clnt_addr;
    socklen_t clnt_addr_size;
    RTMPPacket packet;

    //先做一个简单的tcp server
    serv_sock = socket(PF_INET, SOCK_STREAM, 0);
    if (serv_sock == -1)
    {
        error_handling("socket() error");
    }
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(1935);

    if (bind(serv_sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1)
    {
        error_handling("bind() error");
    }
    if (listen(serv_sock, 5) == -1)
    {
        error_handling("listen() error");
    }
    clnt_addr_size = sizeof(clnt_addr);
    clnt_sock = accept(serv_sock, (struct sockaddr *)&clnt_addr, &clnt_addr_size);
    if (clnt_sock == -1)
    {
        error_handling("accept() error");
    }
    handshake_server(clnt_sock);
    
    RTMP_ReadPacket(clnt_sock, &packet);

    //销毁内存, 下一个循环要读取新数据包了
    if (packet.m_body)
    {
        //申请内存时有多申请RTMP_MAX_HEADER_SIZE，指针要前移
        free(packet.m_body - RTMP_MAX_HEADER_SIZE);
        packet.m_body = NULL;
    }
    close(clnt_sock);
    close(serv_sock);
    return 0;
}

void error_handling(char *message)
{
    fputs(message, stderr);
    fputc('\n', stderr);
    exit(1);
}