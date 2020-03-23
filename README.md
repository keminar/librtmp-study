rtmpdump
==
下载rtmp到本地文件

rtmpgw
==
把RTMP 拉流转成 HTTP 拉流的代理程序

rtmpsrv
==
简单的rtmp服务端完成了音视频发送前的握手和命令交换环节，当前版本是解析客户端请求触发一条rtmpdump命令。

可以结合wireshark查看学习如下流程

Handshake -> connect-> _result -> releaseStream -> FCPublish -> createStream -> _result -> publish

rtmpsuck
==
RTMP拉流代理

examples
==
学习的一些示例程序