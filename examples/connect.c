#include <stdint.h>

// 参考
// https://blog.csdn.net/leixiaohua1020/article/details/84491802
// https://blog.csdn.net/xwjazjx1314/article/details/54693766
// https://blog.csdn.net/yeyumin89/article/details/7932585
// https://blog.csdn.net/huangyimo/article/details/83858620
// https://wenku.baidu.com/view/cdc944114afe04a1b171de86.html


#define RTMP_MAX_HEADER_SIZE 18


//Chunk信息  
typedef struct RTMPPacket  
{  
  uint8_t m_headerType;//basic header 中的type头字节，值为（0，1，2，3） 表示ChunkMsgHeader的类型（4种）  
  uint8_t m_packetType;// Chunk Msg Header中的package Type类型 
  uint8_t m_hasAbsTimestamp;  /* Timestamp 是绝对值还是相对值? */  //用于收消息时
  int m_nChannel;         //块流ID  ，通过设置ChannelID来设置Basic stream id的长度和值
  uint32_t m_nTimeStamp;  // Timestamp  完整包时为绝对时间，非完整时为相对时间？
  int32_t m_nInfoField2;  /* last 4 bytes in a long header,消息流ID */  //Chunk Msg Header中msg StreamID
  uint32_t m_nBodySize;   //指数据部分的消息总长度  
  uint32_t m_nBytesRead;  //已读取长度
  char *m_body;  
} RTMPPacket;
