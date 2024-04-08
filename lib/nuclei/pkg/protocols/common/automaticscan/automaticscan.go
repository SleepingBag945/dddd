package automaticscan

import (
	"embed"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/loader"
	"github.com/projectdiscovery/nuclei/v3/pkg/core"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/http/httpclientpool"
	httputil "github.com/projectdiscovery/nuclei/v3/pkg/protocols/utils/http"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
	"github.com/projectdiscovery/retryablehttp-go"
	sliceutil "github.com/projectdiscovery/utils/slice"
	wappalyzer "github.com/projectdiscovery/wappalyzergo"
	"gopkg.in/yaml.v2"
)

// Service is a service for automatic scan execution
type Service struct {
	opts          protocols.ExecutorOptions
	store         *loader.Store
	engine        *core.Engine
	target        core.InputProvider
	wappalyzer    *wappalyzer.Wappalyze
	childExecuter *core.ChildExecuter
	httpclient    *retryablehttp.Client

	results            bool
	allTemplates       []string
	technologyMappings map[string]string
}

// Options contains configuration options for automatic scan service
type Options struct {
	ExecuterOpts protocols.ExecutorOptions
	Store        *loader.Store
	Engine       *core.Engine
	Target       core.InputProvider
}

const mappingFilename = "wappalyzer-mapping.yml"

func getTemplatePathByFS(f embed.FS) ([]string, error) {
	files := []string{}

	err := fs.WalkDir(f, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && (strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml")) {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}

// New takes options and returns a new automatic scan service
func New(opts Options) (*Service, error) {
	wappalyzer, err := wappalyzer.New()
	if err != nil {
		return nil, err
	}

	var mappingData map[string]string
	config := config.DefaultConfig

	mappingFile := filepath.Join(config.TemplatesDirectory, mappingFilename)
	if file, err := os.Open(mappingFile); err == nil {
		_ = yaml.NewDecoder(file).Decode(&mappingData)
		file.Close()
	}

	if opts.ExecuterOpts.Options.Verbose {
		gologger.Verbose().Msgf("Normalized mapping (%d): %v\n", len(mappingData), mappingData)
	}
	var defaultTemplatesDirectories []string

	// adding custom template path if available
	if len(opts.ExecuterOpts.Options.Templates) > 0 {
		defaultTemplatesDirectories = append(defaultTemplatesDirectories, opts.ExecuterOpts.Options.Templates...)
	}
	// Collect path for default directories we want to look for templates in
	var allTemplates []string

	for _, directory := range defaultTemplatesDirectories {
		tps, _ := opts.ExecuterOpts.Catalog.GetTemplatePath(directory)
		allTemplates = append(allTemplates, tps...)
	}

	tps, err := getTemplatePathByFS(opts.ExecuterOpts.EmbedPocs)
	if err != nil {
		return nil, errors.Wrap(err, "could not get templates in embed directory")
	}
	for _, v := range tps {
		flag := false
		for _, a := range allTemplates {
			if a == v {
				flag = true
				break
			}
		}
		if !flag {
			allTemplates = append(allTemplates, v)
		}
	}

	childExecuter := opts.Engine.ChildExecuter()

	httpclient, err := httpclientpool.Get(opts.ExecuterOpts.Options, &httpclientpool.Configuration{
		Connection: &httpclientpool.ConnectionConfiguration{
			DisableKeepAlive: httputil.ShouldDisableKeepAlive(opts.ExecuterOpts.Options),
		},
	})
	if err != nil {
		return nil, errors.Wrap(err, "could not get http client")
	}

	return &Service{
		opts:               opts.ExecuterOpts,
		store:              opts.Store,
		engine:             opts.Engine,
		target:             opts.Target,
		wappalyzer:         wappalyzer,
		allTemplates:       allTemplates,
		childExecuter:      childExecuter,
		httpclient:         httpclient,
		technologyMappings: mappingData,
	}, nil
}

// Close closes the service
func (s *Service) Close() bool {
	results := s.childExecuter.Close()
	if results.Load() {
		s.results = true
	}
	return s.results
}

// Execute performs the execution of automatic scan on provided input
func (s *Service) Execute() {
	if err := s.executeWappalyzerTechDetection(); err != nil {
		gologger.Error().Msgf("无法执行基于指纹的智能检测: %s", err)
	}
}

const maxDefaultBody = 2 * 1024 * 1024

// executeWappalyzerTechDetection implements the logic to run the wappalyzer
// technologies detection on inputs which returns tech.
//
// The returned tags are then used for further execution.
func (s *Service) executeWappalyzerTechDetection() error {
	gologger.Info().Msgf("Nuclei引擎启动")

	// Iterate through each target making http request and identifying fingerprints
	inputPool := s.engine.WorkPool().InputPool(types.HTTPProtocol)

	s.target.Scan(func(value *contextargs.MetaInput) bool {
		inputPool.WaitGroup.Add()

		go func(input *contextargs.MetaInput) {
			defer inputPool.WaitGroup.Done()

			s.processWappalyzerInputPair(input)
		}(value)
		return true
	})
	inputPool.WaitGroup.Wait()
	return nil
}

func (s *Service) processWappalyzerInputPair(input *contextargs.MetaInput) {
	var templatesList []*templates.Template
	if s.opts.Options.PocNameForSearch != "" {
		templatesList = s.store.LoadTemplatesWithNames(s.opts.EmbedPocs, s.allTemplates,
			[]string{s.opts.Options.PocNameForSearch}, s.opts.Options.ExcludeTags, s.opts.EnableSeverities, true)
	} else {
		pocs, ok := s.opts.TargetAndPocsName[input.Input]
		if !ok || len(pocs) == 0 {
			return
		}
		uniquePocs := sliceutil.Dedupe(pocs)
		templatesList = s.store.LoadTemplatesWithNames(s.opts.EmbedPocs, s.allTemplates, uniquePocs, s.opts.Options.ExcludeTags, s.opts.EnableSeverities, false)
	}

	// gologger.Info().Msgf("Executing tags (%v) for host %s (%d templates)", strings.Join(uniquePocs, ","), input, len(templatesList))
	for _, t := range templatesList {
		s.opts.Progress.AddToTotal(int64(t.Executer.Requests()))

		if s.opts.Options.VerboseVerbose {
			gologger.Print().Msgf("%s\n", templates.TemplateLogMessage(t.ID,
				t.Info.Name,
				t.Info.Authors.ToSlice(),
				t.Info.SeverityHolder.Severity))
		}
		s.childExecuter.Execute(t, input)
	}
}

func normalizeAppName(appName string) string {
	if strings.Contains(appName, ":") {
		if parts := strings.Split(appName, ":"); len(parts) == 2 {
			appName = parts[0]
		}
	}
	return strings.ToLower(appName)
}
