// 参考：
// https://my.oschina.net/ginter/blog/634999
// https://segmentfault.com/a/1190000018582522?utm_source=tag-newest
// https://github.com/gwuhaolin/livego 源码的HandshakeServer 方法
// ./examples/doc/handshake_simple.jpg

/*
RTMP 简单握手
第一步， Client -> Server，内容是 C0+C1
第二步， Server -> Client，内容是 S0+S1+S2
第三步， Client -> Server，内容是 C2

      C1 与 S1
    +-+-+-+-+-+-+-+-+-+-+
    |   time (4 bytes)  |
    +-+-+-+-+-+-+-+-+-+-+
    |   zero (4 bytes)  |
    +-+-+-+-+-+-+-+-+-+-+
    |   random bytes    |
    +-+-+-+-+-+-+-+-+-+-+
    |random bytes(cont) |
    |       ....        |
    +-+-+-+-+-+-+-+-+-+-+

         C2 与 S2
    +-+-+-+-+-+-+-+-+-+-+
    |   time (4 bytes)  |
    +-+-+-+-+-+-+-+-+-+-+
    |   time2(4 bytes)  |
    +-+-+-+-+-+-+-+-+-+-+
    |   random bytes    |
    +-+-+-+-+-+-+-+-+-+-+
    |random bytes(cont) |
    |       ....        |
    +-+-+-+-+-+-+-+-+-+-+
*/
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

int main(int argc, char *argv[])
{
    // tcp server
    int serv_sock;
    int clnt_sock;
    struct sockaddr_in serv_addr;
    struct sockaddr_in clnt_addr;
    socklen_t clnt_addr_size;
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
    int i;
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

    //把c1 拷贝到s2, 为了简单这里没有再按协议分别计算time和time2
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
    printf("C2 Server time: %d\n", server_time);
    printf("C2 Rand: ");
    for (i=8; i<RTMP_SIG_SIZE; i++) {
        printf("%d.", c2[i]);
    }
    printf("\n\n");

    printf("hanshake success\n");
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