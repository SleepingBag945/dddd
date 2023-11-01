# 更新日志



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

