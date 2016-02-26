# 依赖包
>   由于从netfilter接受数据包需要用到第三方库libnetfilter_queue。
>   包含的三个文件夹即为依赖包，在运行本系统之前首先需要进行依赖包的安装，在终端下输入命令 sudo ./install_module.sh 运行安装shell即可。

# 运行
>   linux下系统均可。
>   在已经与运行配套的文件系统的前提下。首先进行编译，在终端输入命令 make。然后输入命令 sudo ./load.sh 运行启动shell即可。

# 模块功能
>   c编写的一个中间件，部署于dns递归服务器上。实时接受传出去的dns响应报文，提取其中的域名和ip，与同时部署的文件系统进行交互，获得该域名的ip信息。ip信息来源于之前探测获取存储于数据库中。
>   若该域名不存在关键域名列表中或者无ip找到，则直接将该报文发送出去。否则将提取的ip与返回来的ip集合进行比对，若提取ip不存在ip集合中，则使用ip集合中的第一个ip修改报文中的第一个响应ip。

# 实现功能
>   对DNS递归服务器端缓存投毒攻击进行防护。

# 运行效果
##  未开启中间件
>    使用dig命令获取搭建于本地的DNS递归服务器上www.icbc.com.cn的ip。结果如图：
![image](https://github.com/zhangkaiyang/Dnsfilter/blob/master/dig1.png)

##  开启中间件后
>    再次使用dig命令获取搭建于本地的DNS递归服务器上www.icbc.com.cn的ip。中间件运行如图：
![image](https://github.com/zhangkaiyang/Dnsfilter/blob/master/dnsfilter1.png)

>   结果如图：

![image](https://github.com/zhangkaiyang/Dnsfilter/blob/master/dig2.png)

# 接口
>   dnsfilter.c为main函数所在文件。
    在main函数中创建多线程，每个多线程堵塞等待ip数据包的到来。
    多线程接收到数据包后首先调用dns_analyze.
    c文件。

>   dns_analyze.
    c文件中函数提取出域名及ip，然后与文件系统进行交互获得相关的数据。

>   若需要修改原dns报文，则调用dns_modify.c函数传入数据包地址及ip即可，修改后再调用udpcheck.c中函数将udp报文的校验和置为0。

# 输出
>   1.输出文件data.log中保存着所有接受到的dns报文中提取出来的域名及ip，可作为数据源。

>   2.输出文件error.log中保存着程序运行过程中出现的错误及发生错误的时间。

# 更多
>   如程序有问题可联系本人QQ:787653759。
