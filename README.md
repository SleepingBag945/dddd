# 工具简介

![](https://socialify.git.ci/SleepingBag945/dddd/image?description=1&font=Inter&forks=1&name=1&owner=1&pattern=Circuit%20Board&stargazers=1&theme=Light)



# 特点

* 自动识别输入类型，无需手动分类
* 便于拓展的主动/被动指纹识别
* 指纹支持复杂 与/或/非/括号 逻辑运算。人类友好。
* Nuclei v3支持
* 便于拓展的指纹漏洞映射数据库，尽量避免无效发包
* 高效的子域名枚举/爆破，精准的泛解析过滤
* Hunter、Fofa、Quake支持
* Hunter 低感知模式
* 低依赖，多系统开箱即用
* 高效的HTML报表
* 审计日志，敏感环境必备



# 快速开始

### 安装

```
任意文件夹:
    - config 
    	- ...
    - dddd.exe
```

Release中下载config.zip与您操作系统对应的二进制文件。将config.zip中的config文件夹解压至二进制文件相同的目录即可。



### 最简使用

扫描IP

`dddd -t 192.168.0.1`

扫描网段

`dddd -t 192.168.0.1/24`

`dddd -t 192.168.0.0-192.168.0.12`

扫描网站

`dddd -t http://test.com`



### 输出文件

默认漏洞输出结果文件名为   `当前时间戳.html`

日志保存在  `audit.log`

**-a** 参数开启审计日志功能，记录详细扫描行为。

**扫描可以随时终止**，当有指纹识别、漏扫结果输出时，会实时保存在文件内。 



### 更多信息

若您想知道如何**添加指纹**，**添加Poc**，更多用法或漏洞报表截图。请点击下边的链接。

[更多信息](details.md)



# 更新历史

[更新历史](Update.md)



# 免责声明

本工具仅面向**合法授权**的企业安全建设行为，如您需要测试本工具的可用性，请自行搭建靶机环境。

在使用本工具进行检测时，您应确保该行为符合当地的法律法规，并且已经取得了足够的授权。**请勿对非授权目标进行扫描。**

如您在使用本工具的过程中存在任何非法行为，您需自行承担相应后果，我们将不承担任何法律及连带责任。

在安装并使用本工具前，请您**务必审慎阅读、充分理解各条款内容**，限制、免责条款或者其他涉及您重大权益的条款可能会以加粗、加下划线等形式提示您重点注意。 除非您已充分阅读、完全理解并接受本协议所有条款，否则，请您不要安装并使用本工具。您的使用行为或者您以其他任何明示或者默示方式表示接受本协议的，即视为您已阅读并同意本协议的约束。



# 参考链接

https://github.com/shadow1ng/fscan

https://github.com/lcvvvv/kscan

https://github.com/lcvvvv/gonmap

https://github.com/projectdiscovery/nuclei

https://github.com/projectdiscovery/subfinder

https://github.com/projectdiscovery/httpx

https://github.com/projectdiscovery/naabu

https://github.com/chainreactors/gogo

https://github.com/zan8in/afrog



## Star History Chart

[![Star History Chart](https://api.star-history.com/svg?repos=SleepingBag945/dddd&type=Date)](https://star-history.com/#SleepingBag945/dddd&Date)

<img align='right' src="https://profile-counter.glitch.me/neo-regeorg/count.svg" width="200">
