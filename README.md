# Luna —Sscan for Security

[![Name](https://img.shields.io/badge/Name-Luna-blue.svg)](https://www.tokula.com)    [![Python 2.6|2.7](https://img.shields.io/badge/python-2.6|2.7-orange.svg)](https://www.python.org/)    [![Author](https://img.shields.io/badge/Author-tokula.com-yellow.svg)](https://www.tokula.com)    [![Sec](https://img.shields.io/badge/Web-Security-brightgreen.svg)]()

Luna 是一款开源的自动化web漏洞扫描工具，利用最轻量的代码构建被动式扫描框架。主要用途是实现对漏洞扫描策略的快速验证，验证源来自burpsuite中收集的httplog，扫描策略来自独立的python插件。

**郑重声明**：Luna仅供网络安全爱好者学习和探讨使用，一切利用本工具和基于本工具二次开发的工具进行非法攻击的行为与Luna无关。

Luna is an open-source web security scanner which is based on reduced-code passive scanning framework. You can write a simple python plugin to prove your great ideas with Luna. The format of httplog is the plaintext saved by Burpsuite. And thanks to PortSwigger Ltd.

**Disclaimer**:  Luna is a study demo for web security fans. Anyone who attacks website through Luna(or rewrite by Luna) which breaks the law will take the full responsibility by himself. 

## Screenshots
![logo](https://user-images.githubusercontent.com/32926900/34332221-6ae1e398-e969-11e7-954f-f3c1756f82d9.png)



![structure](https://user-images.githubusercontent.com/32926900/34332292-fd28d8c4-e969-11e7-8f7b-39df47652438.png)

![luna_arch](https://user-images.githubusercontent.com/32926900/34368738-2b6602b0-eaf1-11e7-8f60-2bd2f80970b9.png)

![running](https://user-images.githubusercontent.com/32926900/34332254-b0f9e09c-e969-11e7-9b7b-5df3013d34e7.jpg)

![report](https://user-images.githubusercontent.com/32926900/34332277-def11baa-e969-11e7-9a91-63319f38544c.png)



## Installation

下载 [Luna](https://github.com/toyakula/luna/) 源码包 

或直接使用git下载安装

    git clone  https://github.com/toyakula/luna.git

Luna运行在python  **2.6.x** 和 **2.7.x** 环境下。



Download [Luna](https://github.com/toyakula/luna/) package

Preferably, you can download Luna by using git

    git clone  https://github.com/toyakula/luna.git

Luna works out of the box with [Python](http://www.python.org/download/) version **2.6.x** and **2.7.x** on any platform.

## Usage

1. 使用burpsuite 收集httplog ，或将其他格式的httplog 转为burpsuite httplog格式。 保存在 'lunahttplog.txt' 中。

   Save httplog from burp suite or you can also convert other httplog to burpsuite-requestlog format. Save it in the 'lunahttplog.txt'.

   ![b2ff4819-b6df-44eb-879b-7d2f728d9000](https://user-images.githubusercontent.com/32926900/34333628-c76aafb8-e979-11e7-8b8a-3372229fe705.jpeg)


2. 修改'conf/lunaconf.py'

    `host_port=[['127.0.0.1','80'],]` 
    `http_log = 'lunahttplog.txt'`

    设置扫描目标的域名和端口，指定存放httplog的文件。


 Modify 'conf/lunaconf.py'

    `host_port=[['127.0.0.1','80'],]` 
    `http_log = 'lunahttplog.txt'`
    
    Set the target(['host','port']) and set the file which httplog saved in.

3.  python luna.py



## Contact

**Gmail** ： [luna.pyc@gmail.com](mailto:luna.pyc@gmail.com)

**Blog** ： [https://tokula.com](https://tokula.com)
