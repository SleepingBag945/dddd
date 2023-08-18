package gonmap

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

type match struct {
	//match <Service> <pattern> <patternopt> [<versioninfo>]
	soft          bool
	service       string
	pattern       string
	patternRegexp *regexp.Regexp
	versionInfo   *FingerPrint
}

var matchLoadRegexps = []*regexp.Regexp{
	regexp.MustCompile("^([a-zA-Z0-9-_./]+) m\\|([^|]+)\\|([is]{0,2})(?: (.*))?$"),
	regexp.MustCompile("^([a-zA-Z0-9-_./]+) m=([^=]+)=([is]{0,2})(?: (.*))?$"),
	regexp.MustCompile("^([a-zA-Z0-9-_./]+) m%([^%]+)%([is]{0,2})(?: (.*))?$"),
	regexp.MustCompile("^([a-zA-Z0-9-_./]+) m@([^@]+)@([is]{0,2})(?: (.*))?$"),
}

var matchVersionInfoRegexps = map[string]*regexp.Regexp{
	"PRODUCTNAME": regexp.MustCompile("p/([^/]+)/"),
	"VERSION":     regexp.MustCompile("v/([^/]+)/"),
	"INFO":        regexp.MustCompile("i/([^/]+)/"),
	"HOSTNAME":    regexp.MustCompile("h/([^/]+)/"),
	"OS":          regexp.MustCompile("o/([^/]+)/"),
	"DEVICE":      regexp.MustCompile("d/([^/]+)/"),
}

var matchVersionInfoHelperRegxP = regexp.MustCompile(`\$P\((\d)\)`)
var matchVersionInfoHelperRegx = regexp.MustCompile(`\$(\d)`)

func parseMatch(s string, soft bool) *match {
	var m = &match{}
	var regx *regexp.Regexp

	for _, r := range matchLoadRegexps {
		if r.MatchString(s) {
			regx = r
		}
	}

	if regx == nil {
		panic(errors.New("match 语句参数不正确"))
	}

	args := regx.FindStringSubmatch(s)
	m.soft = soft
	m.service = args[1]
	m.service = FixProtocol(m.service)
	m.pattern = args[2]
	m.patternRegexp = m.getPatternRegexp(m.pattern, args[3])
	m.versionInfo = &FingerPrint{
		ProbeName:        "",
		MatchRegexString: "",
		Service:          m.service,
		ProductName:      m.getVersionInfo(s, "PRODUCTNAME"),
		Version:          m.getVersionInfo(s, "VERSION"),
		Info:             m.getVersionInfo(s, "INFO"),
		Hostname:         m.getVersionInfo(s, "HOSTNAME"),
		OperatingSystem:  m.getVersionInfo(s, "OS"),
		DeviceType:       m.getVersionInfo(s, "DEVICE"),
	}
	return m
}

func (m *match) getPatternRegexp(pattern string, opt string) *regexp.Regexp {
	pattern = strings.ReplaceAll(pattern, `\0`, `\x00`)
	if opt != "" {
		if strings.Contains(opt, "i") == false {
			opt += "i"
		}
		if pattern[:1] == "^" {
			pattern = fmt.Sprintf("^(?%s:%s", opt, pattern[1:])
		} else {
			pattern = fmt.Sprintf("(?%s:%s", opt, pattern)
		}
		if pattern[len(pattern)-1:] == "$" {
			pattern = fmt.Sprintf("%s)$", pattern[:len(pattern)-1])
		} else {
			pattern = fmt.Sprintf("%s)", pattern)
		}
	}
	//pattern = regexp.MustCompile(`\\x[89a-f][0-9a-f]`).ReplaceAllString(pattern,".")
	return regexp.MustCompile(pattern)
}

func (m *match) getVersionInfo(s string, regID string) string {
	if matchVersionInfoRegexps[regID].MatchString(s) {
		return matchVersionInfoRegexps[regID].FindStringSubmatch(s)[1]
	} else {
		return ""
	}
}

func (m *match) makeVersionInfo(s string, f *FingerPrint) {
	f.Info = m.makeVersionInfoSubHelper(s, m.versionInfo.Info)
	f.DeviceType = m.makeVersionInfoSubHelper(s, m.versionInfo.DeviceType)
	f.Hostname = m.makeVersionInfoSubHelper(s, m.versionInfo.Hostname)
	f.OperatingSystem = m.makeVersionInfoSubHelper(s, m.versionInfo.OperatingSystem)
	f.ProductName = m.makeVersionInfoSubHelper(s, m.versionInfo.ProductName)
	f.Version = m.makeVersionInfoSubHelper(s, m.versionInfo.Version)
	f.Service = m.makeVersionInfoSubHelper(s, m.versionInfo.Service)
}

func (m *match) makeVersionInfoSubHelper(s string, pattern string) string {
	if len(m.patternRegexp.FindStringSubmatch(s)) == 1 {
		return pattern
	}
	if pattern == "" {
		return pattern
	}
	sArr := m.patternRegexp.FindStringSubmatch(s)

	if matchVersionInfoHelperRegxP.MatchString(pattern) {
		pattern = matchVersionInfoHelperRegxP.ReplaceAllStringFunc(pattern, func(repl string) string {
			a := matchVersionInfoHelperRegxP.FindStringSubmatch(repl)[1]
			return "$" + a
		})
	}

	if matchVersionInfoHelperRegx.MatchString(pattern) {
		pattern = matchVersionInfoHelperRegx.ReplaceAllStringFunc(pattern, func(repl string) string {
			i, _ := strconv.Atoi(matchVersionInfoHelperRegx.FindStringSubmatch(repl)[1])
			return sArr[i]
		})
	}
	pattern = strings.ReplaceAll(pattern, "\n", "")
	pattern = strings.ReplaceAll(pattern, "\r", "")
	return pattern
}
