# 更新日志

## 2023.1.3

紧急修复一个因为resp为空导致读空指针的问题。

嘎掉log.txt的记录，有审计日志就没必要存在了。

修复时区异常处理的问题。(https://github.com/SleepingBag945/dddd/issues/25)



## 2023.1.2

更新到1.6版本

1. 优化Tomcat爆破的探测逻辑。优化碰撞路径(XXL-JOB/phpMyAdmin)

2. 更新了 **-ni** 参数，用于禁用反连平台。不出网的内网就没必要用反连平台了，容易拖慢扫描速度，且在敏感环境建议开启避免外连至国外地址造成不必要的麻烦。（敏感肌也能用！）
3. 新增审计日志输出。默认关闭，使用 **-a** 参数(audit)开启。时间、请求地址、响应包、请求包等写至audit.log (可以通过 **-alf** 参数自定义名称)，~~便于甩锅~~ 。避免日志过大，**Golang Poc中爆破不会显示详细数据包，只显示时间、目标、账号与密码。**在敏感环境建议开启，尽管会占用一些磁盘，但能让自己安全一点总归是好事。
4. 审计功能可以当做debug使用。会在日志中写入详细的运行过程/数据包。便于调试poc/workflow。
5. 启动时可通过 **-pt** 参数开启代理验证，验证失败程序退出。**-ptu** 参数指定访问的代理测试url，默认为https://www.baidu.com。（https://github.com/SleepingBag945/dddd/issues/24）
6. 修复了fofa请求的base64编码问题。 （https://github.com/SleepingBag945/dddd/issues/23）

7. 更新53个热点Poc。

   

由于基本是我自己个人在维护这个项目，实在没有那么多精力同时维护代码和持续跟踪热点漏洞、找漏洞、复现、写poc。

这些热点poc可能不是特别全，见谅兄弟们。

```
apache-ofbiz-programexport-rce (Apache-OFBiz ProgramExport 远程命令执行)
亿赛通 /CDGServer3/DBAjax JDBC反序列化
金和OA C6 GetHomeInfo SQL注入
IP网络对讲广播系统 /php/ping.php 远程命令执行
yonyou-u8-crm-solr-log-infoleak
hikvision-isecure-center-files-fileread
tosei-washing-machine-network-test-rce 日本tosei自助洗衣机rce
kingdee-eas-uploadlogo-fileupload (金蝶EAS uploadlogo 任意文件上传)
jeespringcloud-uploadfile-fileupload (JeeSpringCloud uploadFile.jsp 文件上传漏洞)
erpnext-default-login (ERPNEXT 默认密码)
esafenet-getvalidateloginuserservice-xstream-deserialzation-rce
esafenet-checkclientservelt-xstream-deserialzation-rce
jeecg-druid-unauth
edusoho-education-open-fileread
advantech-webaccess-default-login
jinher-oa-sap-b1config-unauth
bifrost-user-update-authbypass (bifrost 用户添加)
Kuaipu-M6 整合管理平台系统SQL注入漏洞
philip-m6-salaryaccounting-sqli (快普整合管理平台系统 SalaryAccounting.asmx SQL注入)
freerdp-webconnect-fileread (FreeRDP WebConnect Url 任意文件读取)
yonyou-turbo-crm-help2-fileread （用友 TurboCRM /pub/help2.php 接口任意文件读取）
yonyou-turbo-crm-help-fileread（用友 TurboCRM /pub/help.php 接口任意文件读取）
yonyou-turbo-crm-downloadfile-fileread （用友 TurboCRM /pub/downloadfile.php 接口任意文件读取）
tongda-oa-action-crawler-fileupload (通达OA action_crawler.php 任意文件上传)
realor-rapagent-sqli （瑞友天翼虚拟化 rapagent SQL注入）
cdg-decryptapplicationservice2-arbitrary-file-upload （亿赛通 decryptapplicationservice2 任意文件上传）
esafenet-cdg-user-fastjson-rce （亿赛通 user fastjson RCE）
esafenet-emailauditservice-xstream-deserialzation-rce (亿赛通 emailauditservice xstream 反序列化)
dahua-dss-s2-045-rce (大华DSS s2-045远程命令执行漏洞)
kingdee-eas-extweb-fileread (金蝶EAS extweb 任意文件读取)
idocview-url-fileread (I Doc View /view/url 接口任意文件读取)
idocview-cmd-rce (I Doc View CMD 远程命令执行)
宏景hcm loadhistroyorgtree SQL注入
logbase-test-qrcide-b-rce (LogBase堡垒机 RCE)
weaver-ebridge-addtaste-sqli 泛微云桥SQL注入
dahua-smart-park-download-fileread (大华智慧园区综合管理平台 download 任意文件读取)
hikvision-ivms8700-getpic-fileupload (海康威视 ivms8700 getPic 任意文件上传)
CNVD-2023-59457 (亿赛通电子文档安全管理系统 LinkFilterService 远程代码执行漏洞)
CVD-2023-1718 (Panabit Panalog sprog_deletevent.php SQL 注入漏洞)
tongweb-selectapp-fileupload (东方通 TongWeb selectApp.jsp 任意文件上传)
iclock-weaklogin (时间精细化管理平台弱口令)
yonyou-u8-cloud-appletinvoke-cacheinvokeservlet-rce (用友U8 Cloud com.ufsoft.iufo.web.appletinvoke.CacheInvokeServlet 反序列化)
CVE-2023-49070 (Apache OFBiz < 18.12.10 - Arbitrary Code Execution 带DNSLog利用链确认)
webui-js-oem-sslvpn-client-fileupload （某OEM厂商的rce2文件上传)
CVD-2023-2868 (广联达 linkworks GB/LK/ArchiveManagement/Js/GWGDWebService.asmx 文件上传漏洞)
jinher-oa-saveasotherformatservlet-fileupload (金和OA saveAsOtherFormatServlet 任意文件上传)
webui-js-oem-file-read (OEM厂商的洞任意文件读取)
seeyon-wpsassistservlet-filetype-fileread (致远OA wpsAssistServlet fileType参数任意文件读取)
yonyou-nc-icustomerexporttocrmservice-sqli (用友NC ICustomerExportToCrmService SQL注入)
hjhost-hcm-get-org-tree-sqli (宏景人力资源管理系统 get_org_tree.jsp SQL注入漏洞)
CVD-2022-1170 (泛微 E-Office login.wsdl.php 文件 SQL 注入漏洞)
yonyou-nc-monitorservlet-rce (用友NC nc.bs.framework.mx.monitor.MonitorServlet 反序列化漏洞)
CVD-2022-5298 (泛微 E-Office sample 权限绕过 file-upload 后台文件上传漏洞)
```



## 2023.12.14

更新到1.5.1版本。

优化Quake数据拉取功能，会员可以直接拉url了。

这里感谢iamHuFei提供的Hunter账号。



优化一下ReadMe的布局。



## 2023.12.11

新增Quake资产拉取功能。使用参数如下。

```
./dddd -t 'ip:"127.0.0.1"' -quake
```

​    

新增TCP存活探测

进行icmp探测后，不存活的再进行tcp探活（80,443,3389,445,22）。

```
./dddd -t 127.0.0.1 -tcpp
```

​    

不进行icmp探测，直接用tcp探测存活。

```
./dddd -t 127.0.0.1 -tcpp -nicmp
```

​    

原来的使用方式没变，默认进行icmp探测,-Pn屏蔽所有探活

```
./dddd -t 127.0.0.1
```

​    

新增Tags匹配

在workflow中填写 "Tags@" 开头的poc名称，则代表匹配所有带此tag的nuclei poc

```
nginx:
  type:
    - root
  pocs:
    - Tags@nginx
```

​    

上述workflow的意思是匹配所有带nginx tags的poc。

修复非标准端口redis协议的识别问题。

感谢qiwentaidi。



新增低感知模式参数lpm。即将原来的本机请求信息的流程改为直接改为全部从搜索引擎拉。

当前只支持从hunter获取数据。(看了下fofa的，居然要商业版本才支持拉取http响应体。这对我这穷屌丝可太不友好了)。

用法也很简单，配置好hunter api，然后目标写hunter的语法。

例如

```
./dddd -t 'ip="xxx.xxx.xxx.xxx"' -lpm
```

​    

拉取到hunter信息后可以直接进入指纹识别、漏洞扫描阶段。



## 2023.11.28

修复非标准端口redis协议的识别问题。

感谢qiwentaidi。



## 2023.11.27

新增低感知模式参数lpm。即将原来的本机请求信息的流程改为直接改为全部从搜索引擎拉。

当前只支持从hunter获取数据。(看了下fofa的，居然要商业版本才支持拉取http响应体)。

用法也很简单，配置好hunter api，然后目标写hunter的语法。

例如

```
./dddd -t 'ip="xxx.xxx.xxx.xxx"' -lpm
```

拉取到hunter信息后可以直接进入指纹识别、漏洞扫描阶段。

很快，但缺点也很明显。很容易漏指纹与资产。



## 2023.11.24

新增参数 npoc 。只进行信息收集，不进行漏洞探测。安全第一！



新增用法 当fofa,hunter参数同时使用时，先使用hunter进行查询，后使用fofa进行ip开放端口补充查询。

有人会问为什么要增加这个看似无用的功能呢，hunter查完后fofa再查一遍不是脱裤子放屁吗？

实际上类似redis的这种非web端口使用icp.name="xxx"的语法是查询不到的，要是在攻防中忽略了原本可能是未授权访问的redis那绝对血亏啊。另一个原因是单个搜索引擎的端口不一定全，使用另一个进行补充查询更接近真实端口开放情况。



## 2023.11.23

更新了如下135个poc，包含近期热点漏洞。have fun~

```
CNVD-2023-12632 (泛微V9 SQL注入) 原来的检测条件有问题，已修改。
idocview-2word-rce (iDocView /html/2word 远程代码执行漏洞)
yonyou-nc-jiuqiclientreqdispatch-rce (用友 NC com.ufsoft.iufo.jiuqi.JiuQiClientReqDispatch 远程代码执行漏洞)
feiqi-fe-officeserver-file-upload （飞企互联-FE业务协作平台 OfficeServer 任意文件上传）
CVD-2023-2425 (万户网络 ezOFFICE senddocument_import.jsp 文件上传漏洞)
yonyou-mobile-uploadapk-fileupload （用友移动系统管理 uploadApk 任意文件上传）
yonyou-mobile-maportal-unauth (用友-移动系统管理 maportal 未授权访问)
CVE-2023-3121 (大华智慧园区综合管理平台 image ssrf 漏洞)
CVD-2023-1870 (大华智慧园区综合管理平台 itcbulletin SQL注入)
dahua-smart-park-deleteftp-rce (大华智慧园区综合管理平台 deleteFtp RCE)
yonyou-u8c-registerservlet-sqli (用友U8C Cloud RegisterServlet SQL注入)
wanhu-wpsservlet-fileupload (万户OA wpsservlet 任意文件上传)
xxl-job-executor-default-token-rce (XXL-JOB执行器 默认Token 远程命令执行漏洞)
kingdee-scpsupreghandler-upload (金蝶云星空 scpsupreghandler 任意文件上传漏洞)
yonyou-u8-grp-slbmbygr-sqli (用友U8-GRP slbmbygr sql注入)
yonyou-u8-grp-selectdmje-sqli (用友GRP-U8 SelectDMJE.jsp SQL注入漏洞)
dahua-icc-default-login (dahua icc 默认密码)
entersoft-fileupload-upload (浙大恩特客户资源管理系统 fileupload.jsp 任意文件上传漏洞)
entersoft-customeraction-entphone-upload (浙大恩特客户资源管理系统 entphone 任意文件上传)
seeyon-oa-saveexcelinbase-fileupload (致远oa 任意文件上传 最近新爆的)
lionfish-cms-wxapp-php-upload （狮子鱼cms，任意文件上传）
magicflow-lfi (MagicFlow-防火墙网关任意文件读取)
trs-test-command-executor-rce (拓尔思 TRS testCommandExecutor.jsp 远程命令执行漏洞)
milesight-vpn-serverjs-fileread (Milesight VPN server.js 任意文件读取漏洞)
mingyuan-erp-apiupdate-fileupload （明源erp 文件上传）
netentsec-ns-asg-rce (NS-ASG安全网关 远程命令执行)
newcape-campus-system-service-rce (新开普智慧校园系统 service.action 远程代码执行漏洞)
hfs-rce (hfs远程命令执行)
hikvision-gateway-data-file-read (HIKVISION 视频编码设备接入网关 $DATA 任意文件读取)
hikvision-showfile-file-read (HIKVISION 视频编码设备接入网关 showFile.php 任意文件下载漏洞)
CVD-2023-1212 (红帆-ioffice iorepsavexml.aspx 任意文件上传漏洞)
hongyun-808gps-filedownload (鸿运主动安全监控云平台任意文件下载)
huace-handler-filedownload (华测监测预警系统任意文件下载)
huace-mews-config-xml-infoleak (华测监测预警系统 config.xml 信息泄露)
iceflow-vpn-disclosure (ICEFlow VPN 信息泄露漏洞)
jeeplus-sql-injection (Jeeplus SQL注入，三个接口)
jinher-c6-getsqldata-sqli (金和OA C6-GetSqlData.aspx SQL注入,可rce)
jinpan-weichatcfg-disclosure (金盘微信管理平台 getsysteminfo信息泄露)
jumpserver-unauth-rce (Jumpserver堡垒机RCE)
kedacom-mts-file-read （科达-MTS转码服务器任意文件读取）
kingdee-commonfileserver-fileread (金蝶云星空任意文件读取)
kingsoft-v8-file-read (金山v8任意文件读取)
kingsoft-get-file-content-file-read (金山终端安全v8/v9任意文件读取)
kingsoft-v8-rce (金山终端安全v8远程代码执行)
konga-default-jwt-key (konga 默认key)
CVD-2023-1304 (科荣 AIO 管理系统 UtilServlet 文件 fileName 参数文件读取漏洞)
landray-eis-saveimg-fileupload (蓝凌EIS智慧协同平台任意文件上传)
landray-oa-datajson-rce (蓝凌OA RCE 新增两种利用方式)
leadsec-acm-bottomframe-cgi-sqli (网御 ACM 上网行为管理系统bottomframe.cgi SQL 注入漏洞)
esafenet-update-sqli (亿赛通文档安全管理系统 update.jsp sql注入)
seeyon-m1-usertokenservice-rce (致远M1 userTokenService反序列化远程代码执行)
evolucare-ecsimaging-file-download (Evolucare Ecsimaging download_stats_dicom.php 任意文件读取漏洞)
evolucare-ecsimaging-rce (Evolucare Ecsimaging new_movie.php 远程命令执行漏洞)
ezeip-info-leakage （ezEIP 4.1.0 信息泄露）
facemeeting-struts2-rce (飞视美 视频会议系统 Struts2 远程命令执行漏洞)
feiqi-fe-showimageservlet-fileread (飞企互联-FE业务协作平台 任意文件读取)
flir-ax8-download-read-file (FLIR AX8红外热像仪 任意文件读取)
glodon-linkworks-getuserbyusercode-sqli (广联达oa Linkworks Getuserbyusercode SQL注入)
glodon-linkworks-service-disclosure (广联达oa Linkworks 信息泄露)
glodon-linkworks-getimdirectionary-sqli (广联达 Linkworks GetIMDictionary SQL 注入)
go-fastdfs-unauth (go-fastdfs 认证绕过)
h3c-miniware-web-disclosure (H3C-Miniware-Webs 设备敏感信息泄露，可登录后台开telnet执行命令)
h3c-jquery-172-file-read (H3C 用户网管登录系统 jQuery-1.7.2 任意文件读取)
hand-china-srm-tomcat-jsp-login-bypass (汉得 SRM tomcat.jsp 登录绕过漏洞)
haofeng-firewall-setdomain-unauth (皓峰防火墙 setdomain.php 越权访问漏洞)
e-office-v10-sql-inject (泛微 eoffice v10 前台SQL注入)
yonyou-nc-api-disclosure (在野0day,但危害不大)(用友nc api接口泄露) 
weaver-e-message-decorator-file-read (在野0day)(泛微 E-message 任意文件读取)
qianxin-tianqing-getsimilarlist-sqli （奇安信360天擎 getsimilarlist SQL注入漏洞)
weaver-eoffice-webservice-upload-fileupload (泛微-E-office webservice 任意文件上传)
easycvr-userlist-info-disclosure (视频监控汇聚平台 EasyCVR 用户信息泄漏)
ip-guard-webserver-rce （1day）(ip-guard 远程命令执行)
ecology-e-office-getselectlist-crm-sqli (泛微e-office getSelectList_Crm SQL注入)
ecology-ifnewscheckoutbycurrentuser-dwr-sqli (2023hvv)(泛微 E-Cology ifnewscheckoutbycurrentuser.dwr SQL 注入)
ecology-dbconfigreader-info-leak (泛微ecology OA DBconfigReader 数据库配置信息泄露)
egroupware-rce (eGroupWare spellchecker.php 远程命令执行)
enjoyscm-file-upload (enjoyscm 供应链管理系统 UploadFile任意文件上传)
esafenet-dataimport-rce (亿赛通电子文档安全系统 dataimport rce)
esafenet-xstream-deserialzation-rce (亿赛通电子文档安全系统 xstream rce)
esafenet-cdg-importfiletype-upload （亿赛通电子文档安全系统importfiletype任意文件上传)
esafenet-client-ajax-download (亿赛通电子文档安全系统 ClientAjax 任意文件读取)
cxcms-arbitrary-file-read (CXCMS任意文件读取)
dss-download-fileread (大华城市安防监控系统平台管理任意文件读取)
dahua-smart-park-ipms-rce (大华智慧园区综合管理平台 ipms 远程代码执行漏洞)
dahua-smart-park-poi-upload (大华智慧园区综合管理平台 poi 任意文件上传)
das-ngfw-aaa-rce (安恒 明御安全网关 aaa_portal_auth_local_submit 远程命令执行漏洞)
das-mingyu-report-user-bypass (安恒明御Web应用防火墙认证绕过)
dlink-dar-8000-rce (D-Link DAR-8000 远程命令执行漏洞)
dlink-sharecenter-dns-320-rce (D-Link ShareCenter DNS-320 system_mgr.cgi 远程命令执行漏洞)
doc-cms-keyword-sql-injection (DocCMS keyword SQL注入漏洞)
dotnetcms-sqli (DotnetCMS SQL注入)
ds-store-file (DS_Store 文件泄露)
baiteng-default-login (百腾客户关系-弱口令)
bithighway-default-login (碧海威L7云路由默认密码)
bohuawanglong-cmd-php-rce (博华网龙防火墙 cmd.php 远程命令执行漏洞(OEM))
bohuawanglong-users-xml-password-leak (博华网龙防火墙 users.xml 未授权访问)
byzoro-smart-importhtml-rce (百卓Smart/百卓安全网关 importhtml.php 远程命令执行漏洞)
casdoor-static-fileread (Casdoor 任意文件读取)
china-mobile-export-settings-info-leak (中移铁通-禹路由信息泄露)
china-mobile-simple-index-asp-unauth (中移铁通-禹路由未授权访问)
activemq-path-disclosure (ActiveMQ物理路径泄漏漏洞)
alibaba-canal-info-leak （Alibaba Canal config云密钥信息泄露）
avtech-dvr-exposure (Avtech AVC798HA DVR 信息泄露)
dedecms-radminpass-disclosure (织梦CMS radminpass.php密码修改文件泄露)
huawei-router-auth-bypass (Huawei DG8045 deviceinfo 信息泄漏漏洞)
kyan-credential-exposure (Kyan 网络监控设备 hosts 账号密码泄露)
openvpn-monitor-disclosure (OpenVPN 监视页面泄露)
phpinfo-files （phpinfo泄露检测）
ruijie-eg-login-rce （Ruijie-EG易网关默认密码）
ruijie-nbr1300g-exposure (锐捷NBR 1300G路由器 越权CLI命令执行漏洞，guest账户可以越权获取管理员账号密码)
druid-default-login (alibaba-druid默认密码)
unauthenticated-frp (frp web未授权访问)
frp-default-login (frp web默认密码)
jeecg-boot-unauth (Jeecg Boot未授权访问)
ruoyi-druid-unauth (若依管理系统druid未授权访问)
springboot未授权访问添加至nacos指纹下
tensorboard-unauth (Tensorboard 未授权访问)
exposed-zookeeper (Apache ZooKeeper未授权访问)
1panel-loadfile-fileread (1panel面板任意文件读取)
amtt-hiboss-language-sqli (安美数字酒店宽带运营系统SQL注入漏洞)
amtt-hiboss-server-ping-rce （安美数字酒店宽带运营系统server ping远程命令执行）
arcgis-rest-service-directory-traversal (Arcgis REST 服务目录遍历)
panabit-applist-rce (Panabit-Panalog applist RCE)
aolynk-br304-default-password (华为Aolynk BR304+ 智能安全路由器默认口令)
datahub-metadata-default-login (DataHub Metadata默认口令)
hikvision-intercom-service-default-password (海康威视群组对讲服务配置平台默认密码)
kingsoft-v8-default-password (金山V8+终端安全系统默认密码)
openerp-default-password (OpenERP 默认密码)
openfire-default-password (OpenFire 默认密码)
CVE-2023-22518 (atlassian-confluence-restore-rce)
dahua-icc-readpic-fileread (大华ICC 任意文件读取)
sangfor-ngaf-login-rce (深信服下一代防火墙rce)
eosine-reportfile-file-upload (易思无人值守智能物流系统reportfile文件上传)
clamav-unauth (ClamAV未授权访问)
seeyon-wpsassist-servlet-fileread (致远OA任意文件读取)
travis-ci-disclosure
```







## 2023.11.1

**同步nuclei引擎至v3.0.2,方便支持nuclei官方最新模板。**

同步nuclei poc v9.6.4

其中以*打头的为从用户自定义模板更换工作流至nuclei官方的模板。

```
CVE-2023-41892 (CraftCMS < 4.4.15 - Unauthenticated Remote Code Execution)
CVE-2023-39677 (PrestaShop MyPrestaModules - PhpInfo Disclosure)
CVE-2023-39676 (PrestaShop fieldpopupnewsletter Module - Cross Site Scripting)
CVE-2023-30943 (Moodle - Cross-Site Scripting/Remote Code Execution)
CVE-2023-25573 (Metersphere - Arbitrary File Read)
CVE-2023-22463 (KubePi JwtSigKey 登陆绕过漏洞)
CVE-2022-0342 (Zyxel - Authentication Bypass)
phpldapadmin-xss

*CNVD-C-2023-76801 (UFIDA NC uapjs - RCE vulnerability)
*CNVD-2022-43245 (Weaver OA XmlRpcServlet - Arbitary File Read)
*CNVD-2021-33202 (Weaver OA E-Cology LoginSSO.jsp - SQL Injection)
*chanjet-tplus-rce (Chanjet TPlus GetStoreWarehouseByStore - Remote Command Execution)
*landray-oa-sysSearchMain-editParam-rce
*landray-oa-treexml-rce
*aic-intelligent-password-exposure
*cloud-oa-system-sqli
*cmseasy-crossall-sqli
*comai-ras-cookie-bypass
*huiwen-bibliographic-info-leak
*sanhui-smg-file-read
*seeyon-oa-log4j
*zhixiang-oa-msglog-sqli
*secsslvpn-auth-bypass（奇xx VPN认证绕过）
*realor-gwt-system-sqli
*ruijie-nbr-fileupload.yaml
*sangfor-login-rce （应用交付）
*secgate-3600-file-upload
*seeyon-config-exposure
*seeyon-createmysql-exposure
*seeyon-initdata-exposure
*seeyon-oa-fastjson-rce
*seeyon-oa-setextno-sqli
*shiziyu-cms-apicontroller-sqli
*seeyon-oa-sp2-file-upload
*smartbi-deserialization
*jolokia-logback-jndi-rce
*tongda-action-uploadfile
*tongda-api-file-upload
*tongda-arbitrary-login
*tongda-contact-list-exposure
*tongda-getdata-rce
*tongda-getway-rfi
*tongda-insert-sqli
*tongda-login-code-authbypass
*tongda-meeting-unauth
*tongda-oa-swfupload-sqli
*tongda-report-func-sqli
*tongda-video-file-read
*topsec-topacm-rce
*topsec-topapplb-auth-bypass
*wanhu-documentedit-sqli
*wanhu-download-ftp-file-read
*wanhu-download-old-file-read
*wanhu-oa-fileupload-controller-arbitrary-file-upload
*wanhu-teleconferenceservice-xxe
*wanhuoa-officeserverservlet-file-upload
*wanhuoa-smartupload-file-upload
*ecology-jqueryfiletree-traversal
*ecology-verifyquicklogin-auth-bypass
*ecology-oa-byxml-xxe
*weaver-checkserver-sqli
*weaver-e-cology-validate-sqli
*weaver-e-mobile-rce
*weaver-ebridge-lfi
*weaver-ecology-bshservlet-rce
*weaver-ecology-getsqldata-sqli
*weaver-ecology-hrmcareer-sqli
*weaver-group-xml-sqli
*weaver-jquery-file-upload
*weaver-ktreeuploadaction-file-upload
*weaver-lazyuploadify-file-upload
*weaver-login-sessionkey
*weaver-mysql-config-info-leak
*weaver-office-server-file-upload
*weaver-officeserver-lfi
*weaver-signaturedownload-lfi
*weaver-sptmforportalthumbnail-lfi
*weaver-uploadify-file-upload
*weaver-uploadoperation-file-upload
*weaver-userselect-unauth
*wechat-info-leak
*chanjet-gnremote-sqli
*chanjet-tplus-checkmutex-sqli
*chanjet-tplus-file-read (Downloadproxy)
*chanjet-tplus-fileupload
*chanjet-tplus-ufida-sqli
*grp-u8-uploadfiledata-fileupload
*yonyou-fe-directory-traversal
*yonyou-filereceiveservlet-fileupload
*yonyou-grp-u8-xxe
*yonyou-nc-accept-fileupload
*yonyou-nc-baseapp-deserialization
*yonyou-nc-dispatcher-fileupload
*yonyou-nc-grouptemplet-fileupload
*yonyou-nc-info-leak
*yonyou-nc-ncmessageservlet-rce
*yonyou-u8-crm-fileupload
*yonyou-u8-crm-lfi
*dlink-centralized-default-login
*o2oa-default-login
*aruba-instant-default-login
*ciphertrust-default-login
*cnzxsoft-default-login
*supershell-default-login
*seeyon-a8-default-login
*seeyon-monitor-default-login
*smartbi-default-login
*ac-weak-login (wayos)
```



同步nuclei poc v9.6.5

```
CVE-2023-43261 (Milesight Routers - Information Disclosure)
CVE-2023-42793 (JetBrains TeamCity < 2023.05.4 - Remote Code Execution)
CVE-2023-42442 (JumpServer > 3.6.4 - Information Disclosure)
CVE-2023-37474 (Copyparty <= 1.8.2 - Directory Traversal)
CVE-2023-36845 (Juniper J-Web - Remote Code Execution)
CVE-2023-35813 (Sitecore - Remote Code Execution)
CVE-2023-34259 (Kyocera TASKalfa printer - Path Traversal)
CVE-2023-33831 (FUXA - Unauthenticated Remote Code Execution)
CVE-2023-31465 （TimeKeeper by FSMLabs - Remote Code Execution）
CVE-2023-30013 （TOTOLink - Unauthenticated Command Injection）
CVE-2023-29357 （Microsoft SharePoint - Authentication Bypass）
CVE-2023-22515 （Atlassian Confluence - Privilege Escalation）
CVE-2023-5074 (D-Link D-View 8 v2.0.1.28 - Authentication Bypass)
CVE-2023-4568 (PaperCut NG Unauthenticated XMLRPC Functionality)
CVE-2023-2766 (Weaver OA 9.5 - Information Disclosure)
xploitspy-default-login
mercurial-hgignore
sangfor-nextgen-lfi
yonyou-u8-sqli (Yonyou U8 bx_historyDataCheck - SQL Injection)

*CVE-2022-25568 (MotionEye Config Info Disclosure)
```



同步nuclei poc v9.6.6

```
CVE-2022-47075 (Smart Office Web 20.28 - Information Disclosure)
CVE-2023-40779 (IceWarp Mail Server Deep Castle 2 v.13.0.1.2 - Open Redirect)
CVE-2023-39110 (rConfig 3.9.4 - Server-Side Request Forgery)
CVE-2023-39109 (rConfig 3.9.4 - Server-Side Request Forgery)
CVE-2023-39108 (rConfig 3.9.4 - Server-Side Request Forgery)
CVE-2023-34756 (Bloofox v0.5.2.1 - SQL Injection)
CVE-2023-34755 (bloofoxCMS v0.5.2.1 - SQL Injection)
CVE-2023-34753 (bloofoxCMS v0.5.2.1 - SQL Injection)
CVE-2023-34752 (bloofoxCMS v0.5.2.1 - SQL Injection)
CVE-2023-34751 (bloofoxCMS v0.5.2.1 - SQL Injection)
CVE-2021-29006 (rConfig 3.9.6 - Local File Inclusion)
CVE-2023-4974 （Academy LMS 6.2 - SQL Injection）
CVE-2023-3710 （Honeywell PM43 Printers - Command Injection）
CVE-2023-0947 (Flatpress < 1.3 - Path Traversal)
CVE-2023-0777 （modoboa  2.0.4 - Admin TakeOver）
CVE-2021-41749 （CraftCMS SEOmatic - Server-Side Template Injection）
CVE-2020-13638 （rConfig 3.9 - Authentication Bypass(Admin Login)）
CVE-2020-13851 （Artica Pandora FMS 7.44 - Remote Code Execution）
CVE-2020-6950 （Eclipse Mojarra - Local File Read）
CVE-2018-7282 (TITool PrintMonitor - Blind SQL Injection)
joomla-com-booking-component
joomla-iproperty-real-estate-xss
joomla-joombri-careers-xss
joomla-jvtwitter-xss
joomla-marvikshop-sqli
joomla-marvikshop-xss
joomla-solidres-xss
doorgets-info-disclosure
kingsoft-vgm-lfi
sound4-impact-auth-bypass
sound4-impact-password-auth-bypass
stackposts-sqli
servicenow-widget-misconfig
batflat-default-login
etl3100-default-login
rconfig-default-login
timekeeper-default-login
wazuh-default-login
```



nuclei poc v9.6.7 无可同步poc



同步nuclei poc v9.6.8

```
CVE-2023-46747 (F5 BIG-IP - Unauthenticated RCE via AJP Smuggling)
CVE-2023-45852 （Viessmann Vitogate 300 - Remote Code Execution）
CVE-2023-37679 （NextGen Mirth Connect - Remote Code Execution）
CVE-2023-4966 （Citrix Bleed - Leaking Session Tokens）
CVE-2022-36553 （Hytec Inter HWL-2511-SS - Remote Command Execution）
tiny-file-manager-unauth
opache-control-panel (Opache control Panel - Unauthenticated Access)
cisco-broadworks-log4j-rce
citrix-xenapp-log4j-rce
f-secure-policymanager-log4j-rce
flexnet-log4j-rce
fortiportal-log4j-rce
livebos-file-read
logstash-log4j-rce
okta-log4j-rce
papercut-log4j-rce
openshift-log4j-rce
pega-log4j-rce
splunk-enterprise-log4j-rce
symantec-sepm-log4j-rce
```



嘎了nuclei ignore找不到的报错



## 2023.9.16

同步nuclei引擎 **v2.9.14**

现在workflow中填写可以添加.yaml后缀也可以不填了

添加整个程序结束后的提示



更新poc

同步nuclei poc至v9.6.3



添加Poc

```
CVE-2023-39600 (IceWarp 11.4.6.0 - Cross-Site Scripting)
CVE-2023-39598 (IceWarp Email Client - Cross Site Scripting)
CVE-2023-39361 (Cacti 1.2.24 - SQL Injection)
CVE-2023-36844 (Juniper Devices - Remote Code Execution)
CVE-2023-34192 (Zimbra Collaboration Suite (ZCS) v.8.8.15 - Cross-Site Scripting)
CVE-2023-34124 (SonicWall GMS and Analytics Web Services - Shell Injection)
CVE-2023-30150 (PrestaShop leocustomajax 1.0 & 1.0.0 - SQL Injection)
CVE-2023-27034 (Blind SQL injection vulnerability in Jms Blog)
CVE-2023-2648 (Weaver E-Office 9.5 - Remote Code Execution)
CVE-2023-26469 (Jorani 1.0.0 - Remote Code Execution)
CVE-2023-20073 (Cisco VPN Routers - Unauthenticated Arbitrary File Upload)
CVE-2022-22897 (PrestaShop Ap Pagebuilder <= 2.4.4 SQL Injection)
CVE-2021-46107 (Ligeo Archives Ligeo Basics - Server Side Request Forgery)
CVE-2020-11798 (Mitel MiCollab AWV 8.1.2.4 and 9.1.3 - Directory Traversal)
CVE-2020-10220 (rConfig 3.9 - SQL injection)
CVE-2018-17153 (Western Digital MyCloud NAS - Authentication Bypass)
CVE-2016-10108 (Western Digital MyCloud NAS - Command Injection)
jorani-benjamin-xss (Jorani v1.0.3-2014-2023 Benjamin BALET - Cross-Site Scripting)
prestashop-apmarketplace-sqli (PrestaShop Ap Marketplace SQL Injection)
ecology-info-leak (Ecology  - Information Exposure)
php-debugbar-exposure (Php Debug Bar - Exposure)
```



部分Poc移动至Nuclei官方模版

```
CNVD-2021-32799 (360 Xintianqing - SQL Injection)
hikvision-fastjson-rce (HIKVISION applyCT Fastjson - Remote Command Execution)
```





## 2023.9.15

9月13号的更新报告写入有问题，现在修了。



## 2023.9.13

根据 **hanbufei**大哥的pr，添加模糊搜索poc，并跳过指纹识别、路径爆破直接打poc的功能。

同步nuclei引擎 v2.9.14的yaml poc结构。准备同步最新官方nuclei poc



## 2023.9.4

修复大量目标进行主动指纹探测时协程调度异常导致资源占用过高的问题。

新增web探针线程、超时命令行参数。

新增跳过Golang Poc的命令行参数。



## 2023.9.2

部分2023 hvv漏洞更新

```
renwoxing-crm-smsdatalist-sqli (感谢h0nayuzu)
jeecg-boot-ssti-rce
dahua-smart-park-getfacecapture-sqli(感谢h0nayuzu)
dahua-smart-park-video-upload
dahua-user-getuserinfobyusername-getpassword(感谢h0nayuzu)
cdg-uploadfilefromclientserviceforclient-file-upload (亿赛通文件上传)
officeweb365-file-upload
yonyou-turbocrm-getemaildata-fileread
```



## 2023.8.30

同步Nuclei模板至v9.6.2.将部分user目录下的Poc指向Nuclei官方Poc

```
CVE-2023-36346
CNVD-2022-86535
leostream-default-login
pyload-default-login
unauth-temporal-web-ui
apache-dubbo-unauth
apache-rocketmq-broker-unauth
collibra-properties
CVE-2023-29300
CVE-2023-29298
CVE-2023-24489
CVE-2022-40127
CVE-2023-37270
CVE-2020-17463
CVE-2017-7925
yealink-default-login
CVE-2023-38646
CVE-2023-37265
CVE-2023-37266
CVE-2023-35885
CVE-2023-37462
CVE-2023-38205
CVE-2023-3836
CVE-2023-3765
CVE-2021-44139
CVE-2021-27670
CVE-2018-20608
elasticsearch-default-login
jupyter-notebook-rce
skype-blind-ssrf
tongda-auth-bypass (Tongda OA 11.7 - Authentication Bypass)
alibaba-anyproxy-lfi
nginxwebui-runcmd-rce
CVE-2023-39143
CVE-2023-26067
CVE-2023-22480
CVE-2022-40843
CVE-2021-22707
CVE-2020-28185
CVE-2019-7192
CVE-2019-15642
CVE-2018-18809
CVE-2018-12909
CVE-2017-8229
CNVD-2021-43984
CNVD-2021-41972
bsphp-info (BSPHP - Information Disclosure)
discuz-api-pathinfo (Discuz! X2.5 - Path Disclosure)
joomla-department-sqli
netmizer-cmd-rce
netmizer-data-listing
acti-video-lfi
avcon6-execl-lfi
eaa-app-lfi (EAA Application Access System - Arbitary File Read)
easyimage-downphp-lfi
ecology-oa-file-sqli (E-cology FileDownloadForOutDocSQL - SQL Injection)
kedacom-network-lfi
panabit-ixcache-rce
sangfor-cphp-rce
sangfor-download-lfi
sangfor-sysuser-conf
tamronos-user-creation
wisegiga-nas-lfi
zzzcms-info-disclosure
zzzcms-ssrf
apache-solr-rce
bloofoxcms-default-login
openmediavault-default-login
webmin-default-login
socks5-vpn-config (惠尔顿-e地通VPN Socks5 VPN - Sensitive File Disclosure)
bitbucket-auth-bypass
casdoor-users-password
yzmcms-installer
mobsf-framework-exposure
openstack-config
sonarqube-projects-disclosure
CVE-2023-39141
CVE-2023-38035
CVE-2022-46463
CVE-2022-39986
CVE-2021-41460
CVE-2019-17662
CVE-2019-1898
CNVD-2023-08743
74cms-weixin-sqli
fine-report-v9-file-upload
jinhe-oa-c6-lfi
apache-druid-log4j
aspcms-commentlist-sqli
caimore-gateway-rce
h3c-cvm-arbitrary-file-upload
hanta-rce
hongfan-ioffice-lfi
hongfan-ioffice-rce
hongfan-ioffice-sqli
landray-oa-erp-data-rce
maltrail-rce
ruijie-excu-shell
apache-couchdb-unauth
chatgpt-web-unauth
feiyuxing-info-leak
hikivision-env
unauth-redis-insight
kylin-default-login
caimore-default-login
easyreport-default-login
nacos-default-login
```

