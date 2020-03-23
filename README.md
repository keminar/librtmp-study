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
RTMP本地代理，需要结合iptables才能使用，用iptables将浏览器请求的外部服务器1935端口的TCP流 重定向

到本地的rtmpsuck代理 ，rtmpsuck解析出请求出的参数信息以供rtmpdump使用。
```
#添加规则
iptables -t nat -A OUTPUT -p tcp --dport 1935 -m owner \! --uid-owner root  -j REDIRECT
#移除之前添加的规则
iptables -t nat -D OUTPUT -p tcp --dport 1935 -m owner \! --uid-owner root -j REDIRECT
```

examples
==
学习的一些示例程序