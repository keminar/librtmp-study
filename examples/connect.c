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
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/times.h>

// 握手中随机数的长度（C1,C2,S1,S2）长度
#define RTMP_SIG_SIZE 1536

// 显示错误
void error_handling(char *message);

void handshake_server(int clnt_sock);

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

// basic header + msg header最大长度
#define RTMP_MAX_HEADER_SIZE 18

//rtmp包信息  
typedef struct RTMPPacket  
{  
  uint8_t m_headerType;//basic header 中的type头字节，值为（0，1，2，3） 表示ChunkMsgHeader的类型（4种）  
  int m_nChannel;         //块流ID  ，通过设置ChannelID来设置Basic stream id的长度和值

  uint32_t m_nTimeStamp;  // Timestamp  完整包时为绝对时间，非完整时为相对时间？
  uint32_t m_nBodySize;   //指数据部分的消息总长度  
  uint8_t m_packetType;// Chunk Msg Header中的package Type类型 
  int32_t m_nInfoField2;  /* last 4 bytes in a long header,消息流ID */  //Chunk Msg Header中msg StreamID
  
  char *m_body;

  uint32_t m_nBytesRead;  //已读取长度
  uint8_t m_hasAbsTimestamp;  /* Timestamp 是绝对值还是相对值? */  //用于收消息时
} RTMPPacket;

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
    if (read(clnt_sock, c0c1, sizeof(c0c1)) == 0) {
        error_handling("read c0c1 error");
    }
    printf("C0 Version: %d\n", c0c1[0]);
    if (c0c1[0] != 3) {
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
    for (i=8; i<RTMP_SIG_SIZE; i++) {
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
    for (i=8; i<RTMP_SIG_SIZE; i++) {
        s1s2[i] = (char)(rand() % 256);
        printf("%d.", s1s2[i]);
    }
    printf("\n\n");

    //把c1 拷贝到s2, 为了简单这里没有按协议分别计算time和time2，因为好像也没什么用
    printf("S2 Rand: ");
    memcpy(&s1s2[RTMP_SIG_SIZE], c1, RTMP_SIG_SIZE);
    for (i=RTMP_SIG_SIZE+8; i<RTMP_SIG_SIZE*2; i++) {
        printf("%d.", s1s2[i]);
    }
    printf("\n\n");

    //发送 s0s1s2 到客户端
    write(clnt_sock, s0s1s2, sizeof(s0s1s2));
    
    //从客户端接收 c2
    if (read(clnt_sock, c2, sizeof(c0c1)) == 0) {
        error_handling("read c2 error");
    }
    // 将c1前4位时间取出
    memcpy(&server_time, c2, 4);
    //网络字节序转换为时间
    server_time = ntohl(server_time);
    printf("C2 time: %d\n", server_time);
    printf("C2 Rand: ");
    for (i=8; i<RTMP_SIG_SIZE; i++) {
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
  int hsize;
  int nBytes;

  nBytes = recv(clnt_sock, header, 1, 0);
  if (nBytes == -1) {
      error_handling("recv returned");
  }
  printf("%d", hbuf);
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
    while (clnt_sock != -1 && RTMP_ReadPacket(clnt_sock, &packet)) {
        // 连续的包还没有读完
        if (packet.m_nBytesRead != packet.m_nBodySize) {
          continue;
        }
        //显示读到的数据

        //销毁内存
        if (packet.m_body) {
          //申请内存时有多申请RTMP_MAX_HEADER_SIZE，指针要前移
          free(packet.m_body - RTMP_MAX_HEADER_SIZE);
          packet.m_body = NULL;
        }
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