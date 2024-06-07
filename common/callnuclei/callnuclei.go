package callnuclei

import (
	"embed"
	"fmt"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"os"
	"os/signal"
	"runtime"
	"runtime/pprof"
	"strings"
	"time"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/exportrunner"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/common/dsl"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	errorutil "github.com/projectdiscovery/utils/errors"
	fileutil "github.com/projectdiscovery/utils/file"
)

var (
	cfgFile    string
	memProfile string // optional profile file path
	options    = &types.Options{}
)

type NucleiParams struct {
	TargetAndPocsName map[string][]string
	Proxy             string
	CallBack          func(result output.ResultEvent)
	NameForSearch     string
	NoInteractsh      bool
	Fs                embed.FS
	NP                string
	ExcludeTags       []string
	Severities        []string
	InteractshServer  string
	InteractshToken   string
}

func CallNuclei(param NucleiParams) []output.ResultEvent {

	// 设置结果回调
	output.AddResultCallback = param.CallBack
	if err := exportrunner.ExportRunnerConfigureOptions(); err != nil {
		gologger.Fatal().Msgf("Could not initialize options: %s\n", err)
	}

	readConfig(param)
	// configPath, _ := flagSet.GetConfigFilePath()

	if options.ListDslSignatures {
		gologger.Info().Msgf("The available custom DSL functions are:")
		fmt.Println(dsl.GetPrintableDslFunctionSignatures(options.NoColor))
		return []output.ResultEvent{}
	}

	// Profiling related code
	if memProfile != "" {
		f, err := os.Create(memProfile)
		if err != nil {
			gologger.Fatal().Msgf("profile: could not create memory profile %q: %v", memProfile, err)
		}
		old := runtime.MemProfileRate
		runtime.MemProfileRate = 4096
		gologger.Print().Msgf("profile: memory profiling enabled (rate %d), %s", runtime.MemProfileRate, memProfile)

		defer func() {
			_ = pprof.Lookup("heap").WriteTo(f, 0)
			f.Close()
			runtime.MemProfileRate = old
			gologger.Print().Msgf("profile: memory profiling disabled, %s", memProfile)
		}()
	}

	exportrunner.ExportRunnerParseOptions(options)

	nucleiRunner, err := exportrunner.ExportRunnerNew(options)
	if err != nil {
		gologger.Fatal().Msgf("Could not create runner: %s\n", err)
	}
	if nucleiRunner == nil {
		return []output.ResultEvent{}
	}

	nucleiRunner.EmbedPocsFS = param.Fs
	nucleiRunner.EnableSeverities = param.Severities

	// Setup graceful exits
	resumeFileName := types.DefaultResumeFilePath()
	c := make(chan os.Signal, 1)
	defer close(c)
	signal.Notify(c, os.Interrupt)
	go func() {
		for range c {
			gologger.Info().Msgf("CTRL+C pressed: Exiting\n")
			nucleiRunner.Close()
			os.Exit(1)
		}
	}()

	if err := nucleiRunner.RunEnumeration(param.TargetAndPocsName); err != nil {
		if options.Validate {
			gologger.Fatal().Msgf("Could not validate templates: %s\n", err)
		} else {
			gologger.Fatal().Msgf("Could not run nuclei: %s\n", err)
		}
	}
	nucleiRunner.Close()
	// on successful execution remove the resume file in case it exists
	if fileutil.FileExists(resumeFileName) {
		os.Remove(resumeFileName)
	}
	return output.Results
}

func readConfig(param NucleiParams) {

	pwd, _ := os.Getwd()

	// target URLs/hosts to scan
	// 扫描目标
	var targets []string
	for k, _ := range param.TargetAndPocsName {
		targets = append(targets, k)
	}
	options.Targets = targets

	options.ExcludeTargets = []string{}

	// path to file containing a list of target URLs/hosts to scan (one per line)
	// 包含要扫描的目标URL/主机列表的文件路径(每行一个)
	options.TargetsFilePath = ""

	// resume scan using resume.cfg (clustering will be disabled)
	// 使用resume.cfg恢复扫描(将禁用群集)
	options.Resume = ""

	// scan all the IP's associated with dns record
	// 扫描与DNS记录相关联的所有IP
	options.ScanAllIPs = false

	// IP version to scan of hostname (4,6) - (default 4)
	// 要扫描主机名的IP版本(4，6)-(默认为4)
	options.IPVersion = nil

	// run only new templates added in latest nuclei-templates release
	// 仅运行在最新版本的nuclei-templates中添加的新模板
	options.NewTemplates = false

	// run new templates added in specific version
	// 运行指定版本添加的模板
	options.NewTemplatesWithVersion = nil

	// automatic web scan using wappalyzer technology detection to tags mapping
	// 使用wappalyzer技术检测tags，自动web扫描
	// 这里被魔改了,根据提供的目标与Pocs的映射进行自动扫描
	// 必须设置为true
	options.AutomaticScan = true

	// list of template or template directory to run (comma-separated, file)
	// 要运行的模板或模板目录列表(逗号分隔，文件)   -t 指定的模板目录
	// 不嵌入可执行文件是为了方便增删poc。
	// dddd v2.0开始默认支持内嵌，此文件夹内的pocs做补充处理

	if strings.HasPrefix(param.NP, "/") || param.NP[1] == ':' {
		// unix绝对路径，windows绝对路径
		options.Templates = []string{param.NP}
	} else {
		// 相对路径转绝对路径
		options.Templates = []string{pwd + "/" + param.NP}
	}

	// list of template urls to run (comma-separated, file)
	// 要运行的模板url列表(逗号分隔，文件)
	options.TemplateURLs = nil

	// list of workflow or workflow directory to run (comma-separated, file)
	// 要运行的工作流或工作流目录列表(逗号分隔，文件) -w 指定
	options.Workflows = nil

	// list of workflow urls to run (comma-separated, file)
	// 要运行的工作流URL列表(逗号分隔，文件)
	options.WorkflowURLs = nil

	// validate the passed templates to nuclei
	// 验证通过的模板
	options.Validate = false

	// disable strict syntax check on templates
	// 禁用模板的严格检查
	options.NoStrictSyntax = false

	// displays the templates content
	// 显示模板内容
	options.TemplateDisplay = false

	// list all available templates
	// 列出所有可用的模板
	options.TemplateList = false

	// allowed domain list to load remote templates from
	// 允许域列表从以下位置加载远程模板
	options.RemoteTemplateDomainList = []string{"templates.nuclei.sh"}

	// templates to run based on authors (comma-separated, file)
	// 执行指定作者的模板（逗号分隔，文件）
	options.Authors = nil

	// templates to run based on tags (comma-separated, file)
	// 执行有标记的模板子集（逗号分隔，文件）
	options.Tags = nil

	// templates to exclude based on tags (comma-separated, file)
	// 排除执行带有标记的模板（逗号分隔，文件）
	options.ExcludeTags = param.ExcludeTags

	// tags to be executed even if they are excluded either by default or configuration
	// 执行默认或者配置排除的标记模板
	options.IncludeTags = nil

	// templates to run based on template ids (comma-separated, file)
	// 执行指定ID的模板（逗号分隔，文件）
	options.IncludeIds = nil

	// templates to exclude based on template ids (comma-separated, file)
	// 执行排除指定ID的模板（逗号分隔，文件）
	options.ExcludeIds = nil

	// templates to be executed even if they are excluded either by default or configuration
	// 执行默认或配置中排除的模板
	options.IncludeTemplates = nil

	// template or template directory to exclude (comma-separated, file)
	// 要排除的模板或者模板目录（逗号分隔，文件）
	options.ExcludedTemplates = nil

	// template matchers to exclude in result
	// 在结果中排除指定模板
	options.ExcludeMatchers = nil

	// templates to run based on severity
	// 根据严重程度运行模板，可候选的值有：info,low,medium,high,critical
	// 不好使，不走这里了
	options.Severities = nil

	// templates to exclude based on severity
	// 根据严重程度排除模板，可候选的值有：info,low,medium,high,critical
	options.ExcludeSeverities = nil

	// templates to run based on protocol type
	// 根据协议运行模板，可候选的值有：dns, file, http, headless, network, workflow, ssl, websocket, whois
	options.Protocols = nil

	// templates to exclude based on protocol type
	// 根据协议排除模板，可候选的值有：dns, file, http, headless, network, workflow, ssl, websocket, whois
	options.ExcludeProtocols = nil

	// templates to run based on expression condition
	// 根据表达式运行模板
	options.IncludeConditions = nil

	// output file to write found issues/vulnerabilities
	// 输出发现的问题到文件  -o 参数
	options.Output = ""

	// store all request/response passed through nuclei to output directory
	// 是否将nuclei的所有请求和响应输出到目录
	options.StoreResponse = false

	// store all request/response passed through nuclei to custom directory
	// 将nuclei的所有请求和响应输出到指定目录（默认：output）
	options.StoreResponseDir = "output"

	// display findings only
	// 只显示结果
	options.Silent = false

	// disable output content coloring (ANSI escape codes)
	// 禁用输出内容着色（ANSI转义码）
	options.NoColor = false

	// write output in JSON(Lines) format
	// 输出为jsonL（ines）
	options.JSONL = false

	// include request/response pairs in the JSONL output (for findings only)
	// 在JSON中输出对应的请求和相应（仅结果）
	options.JSONRequests = false

	// disable printing result metadata in cli output
	// 不显示匹配的元数据
	options.NoMeta = false

	// enables printing timestamp in cli output
	options.Timestamp = false

	// nuclei reporting database (always use this to persist report data)
	options.ReportingDB = ""

	// display match failure status
	// 显示匹配失败状态
	options.MatcherStatus = false

	// directory to export results in markdown format
	// 以markdown导出结果
	options.MarkdownExportDirectory = ""

	// file to export results in SARIF format
	// 以SARIF导出结果
	options.SarifExport = ""

	// file to export results in JSON format
	options.JSONExport = ""

	// 指定Nuclei的配置文件
	cfgFile = ""

	// 为HTTP模板启用重定向
	options.FollowRedirects = false

	// 在同一主机上重定向
	options.FollowHostRedirects = false

	// HTTP模板最大重定向次数（默认：10）
	options.MaxRedirects = 10

	// 为HTTP模板禁用重定向
	options.DisableRedirects = false

	// 指定Nuclei报告模板文件
	options.ReportingConfig = ""

	// 指定header、cookie，以header:value的方式（cli，文件）
	options.CustomHeaders = nil

	// 通过key=value指定var值
	options.Vars = goflags.RuntimeMap{}

	// 指定Nuclei的解析文件
	options.ResolversFile = ""

	// 当DNS错误时使用系统DNS
	options.SystemResolvers = false

	options.DisableClustering = false

	// 启用被动扫描处理HTTP响应
	options.OfflineHTTP = false

	// 在模板中使用环境变量
	options.EnvironmentVariables = false

	// 用于对扫描的主机进行身份验证的客户端证书文件（PEM 编码）
	options.ClientCertFile = ""

	// 用于对扫描的主机进行身份验证的客户端密钥文件（PEM 编码）
	options.ClientKeyFile = ""

	// 用于对扫描的主机进行身份验证的客户端证书颁发机构文件（PEM 编码）
	options.ClientCAFile = ""

	// 显示文件模板的匹配值，只适用于提取器
	options.ShowMatchLine = false

	// 对ztls自动退回到tls13
	options.ZTLS = false

	// 指定tls sni的主机名（默认为输入的域名）
	options.SNI = ""

	options.AllowLocalFileAccess = false

	options.RestrictLocalNetworkAccess = false

	// 指定网卡
	options.Interface = ""

	// type of payload combinations to perform (batteringram,pitchfork,clusterbomb)
	// 指定payload 组合方式
	options.AttackType = ""

	// 源IP
	options.SourceIP = ""

	// 最大读取响应大小（默认：10 * 1024 * 1024字节）
	options.ResponseReadSize = 10 * 1024 * 1024

	// 最大储存响应大小（默认：1 * 1024 * 1024字节）
	options.ResponseSaveSize = 1 * 1024 * 1024

	options.TlsImpersonate = false

	// 使用interactsh反连检测平台（默认为oast.pro,oast.live,oast.site,oast.online,oast.fun,oast.me）
	options.InteractshURL = param.InteractshServer

	// 指定反连检测平台的身份凭证
	options.InteractshToken = param.InteractshToken

	// 指定保存在交互缓存中的请求数（默认：5000）
	options.InteractionsCacheSize = 5000

	// 从缓存中删除请求前等待的时间（默认为60秒）
	options.InteractionsEviction = 60

	// 每个轮询前等待时间（默认为5秒）
	options.InteractionsPollDuration = 5

	// 退出轮询前的等待时间（默认为5秒）
	options.InteractionsCoolDownPeriod = 5

	// 禁用反连检测平台，同时排除基于反连检测的模板
	options.NoInteractsh = param.NoInteractsh

	// overrides fuzzing type set in template (replace, prefix, postfix, infix)
	// 覆盖模板中设置的模糊类型(替换、前缀、后缀、中缀)
	options.FuzzingType = ""

	// overrides fuzzing mode set in template (multiple, single)
	// 覆盖模板中设置的模糊模式(多个、单个)
	options.FuzzingMode = ""

	// 启用网络空间搜索引擎
	options.Uncover = false
	// 网络空间搜索引擎请求
	options.UncoverQuery = nil
	// 网络空间搜索引擎 fofa/shodan
	options.UncoverEngine = nil
	// uncover fields to return (ip,port,host)
	options.UncoverField = "ip:port"
	// uncover results to return
	options.UncoverLimit = 100
	// delay between uncover query requests in seconds (0 to disable)
	options.UncoverRateLimit = 60

	// 每秒最大请求量（默认：150）
	options.RateLimit = 150
	// 每分钟最大请求量
	options.RateLimitMinute = 0
	// 每个模板最大并行检测数（默认：25）
	options.BulkSize = 64
	// 并行执行的最大模板数量（默认：25）
	options.TemplateThreads = 64
	// 每个模板并行运行的无头主机最大数量（默认：10）
	options.HeadlessBulkSize = 10
	// 并行指定无头主机最大数量（默认：10）
	options.HeadlessTemplateThreads = 10

	// 超时时间（默认为10秒）
	options.Timeout = 12
	// 重试次数（默认：1）设置2为降低糟糕网络环境的影响
	options.Retries = 2
	// 指定HTTP/HTTPS默认端口（例如：host:80，host:443）
	options.LeaveDefaultPorts = false
	// 某主机扫描失败次数，跳过该主机（默认：30）
	options.MaxHostError = 50
	// 将给定错误添加到最大主机错误监视列表（标准、文件）
	options.TrackError = nil
	// 关闭主机基于错误的跳过
	options.NoHostErrors = false
	// 使用项目文件夹避免多次发送同一请求
	options.Project = false // 去重复，导致file missing
	// 设置特定的项目文件夹
	options.ProjectPath = os.TempDir()
	// 得到一个结果后停止（或许会中断模板和工作流的逻辑）
	options.StopAtFirstMatch = false
	// 流模式 - 在不整理输入的情况下详细描述
	options.Stream = false
	// 扫描策略  auto/host-spray/template-spray
	// options.ScanStrategy = "auto"
	options.ScanStrategy = "auto"
	// 输入读取超时时间（默认：3分钟）
	options.InputReadTimeout = time.Duration(3 * time.Minute)
	// 禁用httpx
	options.DisableHTTPProbe = true
	// 禁用标准输入
	options.DisableStdin = false

	// 启用需要无界面浏览器的模板
	options.Headless = false
	// 在无界面下超时秒数（默认：20）
	options.PageTimeout = 20
	// 在无界面浏览器运行模板时，显示浏览器
	options.ShowBrowser = false
	// 不使用Nuclei自带的浏览器，使用本地浏览器
	options.UseInstalledChrome = false
	// 展示无界面浏览器的操作
	options.ShowActions = false

	// 显示所有请求和响应
	options.Debug = gologger.Audit
	// 显示所有请求
	options.DebugRequests = false
	// 显示所有响应
	options.DebugResponse = false
	// 使用http/socks5代理（逗号分隔，文件）
	if param.Proxy == "" {
		options.Proxy = nil
	} else {
		options.Proxy = []string{param.Proxy}
	}
	// 代理所有请求
	options.ProxyInternal = false
	// 列出所有支持的DSL函数签名
	options.ListDslSignatures = false
	// 写入跟踪日志到文件
	options.TraceLogFile = ""
	// 写入错误日志到文件
	options.ErrorLogFile = ""
	// 启用Nuclei的监控
	options.HangMonitor = false
	// 显示详细信息
	options.Verbose = false
	//  将Nuclei的内存转储成文件
	memProfile = ""
	// 显示额外的详细信息
	options.VerboseVerbose = false
	// 启用pprof调试服务器
	options.EnablePprof = false
	// 运行诊断检查
	options.HealthCheck = false

	config.DefaultConfig.DisableUpdateCheck()

	// 更新Nuclei模板到最新版
	options.UpdateTemplates = false
	// 覆盖安装模板
	options.NewTemplatesDirectory = pwd + "/config/pocs/nuclei-templates/"

	// 显示正在扫描的统计信息
	options.EnableProgressBar = true
	// 将统计信息以JSONL格式输出到文件
	options.StatsJSON = false
	// 显示统计信息更新的间隔秒数（默认：5）
	options.StatsInterval = 20
	// 显示Nuclei端口信息
	options.Metrics = false
	// 更改Nuclei默认端口（默认：9092）
	options.MetricsPort = 9092

	options.OmitTemplate = false

	// network请求超时时间
	options.DialerTimeout = 0

	// network请求的keep-alive持续时间
	options.DialerKeepAlive = 0

	// 启用加载基于代码协议的模板
	options.EnableCodeTemplates = false

	// 将扫描结果上传到pdcp仪表板 敏感环境高危
	options.EnableCloudUpload = false

	options.SignTemplates = false

	options.PocNameForSearch = param.NameForSearch

	gologger.DefaultLogger.SetTimestamp(options.Timestamp, levels.LevelDebug)

	cleanupOldResumeFiles()
}

// cleanupOldResumeFiles cleans up resume files older than 10 days.
func cleanupOldResumeFiles() {
	root := config.DefaultConfig.GetConfigDir()
	filter := fileutil.FileFilters{
		OlderThan: 24 * time.Hour * 10, // cleanup on the 10th day
		Prefix:    "resume-",
	}
	_ = fileutil.DeleteFilesOlderThan(root, filter)
}

func init() {
	// print stacktrace of errors in debug mode
	if os.Getenv("DEBUG") != "" {
		errorutil.ShowStackTrace = true
	}
}
