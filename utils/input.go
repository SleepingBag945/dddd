package utils

import (
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
)

import "dddd/structs"

// IsIPv4 IsIP checks if a string is either IP version 4 Alias for `net.ParseIP`
func IsIPv4(str string) bool {
	for i := 0; i < len(str); i++ {
		if str[i] == '.' {
			return net.ParseIP(str) != nil
		}
	}
	return false
}

// IsIPv6 IsIP checks if a string is either IP version 4 Alias for `net.ParseIP`
func IsIPv6(str string) bool {
	for i := 0; i < len(str); i++ {
		if str[i] == ':' {
			return net.ParseIP(str) != nil
		}
	}
	return false
}

// IsCIDR checks if the string is an valid CIDR notation (IPV4)
func IsCIDR(str string) bool {
	_, _, err := net.ParseCIDR(str)
	return err == nil
}

func IsIPPort(str string) bool {
	if !strings.Contains(str, ":") {
		return false
	}
	t := strings.Split(str, ":")
	if len(t) != 2 {
		return false
	}
	if !IsIPv4(t[0]) {
		return false
	}
	if !IsPort(t[1]) {
		return false
	}
	return true
}

// IsPort checks if a string represents a valid port
func IsPort(str string) bool {
	if i, err := strconv.Atoi(str); err == nil && i > 0 && i < 65536 {
		return true
	}
	return false
}

var (
	domainRootString = `[a-z]{2,5}`
	domainRegx       = regexp.MustCompile(`^([a-zA-Z0-9][-a-zA-Z0-9]{0,62}(?:\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})*\.(?:` + domainRootString + `))$`)
)

// stringContainsCTLByte reports whether s contains any ASCII control character.
func stringContainsCTLByte(s string) bool {
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b < ' ' || b == 0x7f {
			return true
		}
	}
	return false
}

func IsDomain(str string) bool {
	if stringContainsCTLByte(str) == true {
		return false
	}
	if ok := domainRegx.MatchString(str); ok == false {
		return false
	}
	return true
}

// IsDomainPort checks if a string is Domain:Port
func IsDomainPort(str string) bool {
	r := strings.Split(str, ":")
	if len(r) != 2 {
		return false
	}
	domain := r[0]
	port := r[1]
	return IsDomain(domain) && IsPort(port)
}

func IsIPRange(str string) bool {
	r := strings.Split(str, "-")
	return (len(r) == 2) && IsIPv4(strings.TrimSpace(r[0])) && IsIPv4(strings.TrimSpace(r[1]))
}

func IsProtocol(str string) bool {
	ok, _ := regexp.MatchString("^[-a-z0-9A-Z]{1,20}$", str)
	return ok
}

func IsNetloc(str string) bool {
	return IsDomain(str) || IsIPv4(str)
}

// IsNetlocPort checks if a string is [Domain or IP]:Port
func IsNetlocPort(str string) bool {
	r := strings.Split(str, ":")
	if len(r) != 2 {
		return false
	}
	netloc := r[0]
	port := r[1]
	return IsNetloc(netloc) && IsPort(port)
}

// IsHostPath checks if a string is :
// netloc/path
// netloc:port/path
func IsHostPath(str string) bool {
	index := strings.Index(str, "/")
	if index == -1 {
		return false
	}
	str = str[:index]
	if strings.Contains(str, ":") == true {
		return IsNetlocPort(str)
	} else {
		return IsNetloc(str)

	}
}

// IsURL checks if a string is :
// protocol://netloc/path
// protocol://netloc:port/path
func IsURL(str string) bool {
	if stringContainsCTLByte(str) == true {
		return false
	}
	index := strings.Index(str, "://")
	if index == -1 {
		return false
	}
	protocol := str[:index]
	if IsProtocol(protocol) == false {
		return false
	}
	str = str[index+3:]
	if IsNetloc(str) {
		return true
	}
	if IsNetlocPort(str) {
		return true
	}
	if IsHostPath(str) {
		return true
	}
	return false
}

func RemoveDuplicateElement(input []string) []string {
	temp := map[string]struct{}{}
	var result []string
	for _, item := range input {
		if _, ok := temp[item]; !ok {
			temp[item] = struct{}{}
			result = append(result, item)
		}
	}
	return result
}

func RemoveDuplicateElementInt(input []int) []int {
	temp := map[int]struct{}{}
	var result []int
	for _, item := range input {
		if _, ok := temp[item]; !ok {
			temp[item] = struct{}{}
			result = append(result, item)
		}
	}
	return result
}

func IsFileNameValid(name string) bool {
	_, err := os.Stat(name)
	if err == nil {
		return true
	}
	return false
}

func GetInputType(input string) int {
	if IsIPv6(input) {
		return structs.TypeUnSupport
	} else if IsIPv4(input) {
		return structs.TypeIP
	} else if IsIPRange(input) {
		return structs.TypeIPRange
	} else if IsCIDR(input) {
		return structs.TypeCIDR
	} else if IsIPPort(input) {
		return structs.TypeIPPort
	} else if IsDomainPort(input) {
		return structs.TypeDomainPort
	} else if IsDomain(input) {
		return structs.TypeDomain
	} else if IsURL(input) {
		return structs.TypeURL
	}

	return structs.TypeUnSupport
}

func GetItemInArray(a []string, s string) int {
	for index, v := range a {
		if v == s {
			return index
		}
	}
	return -1
}

func DeleteReportWithNoResult() {
	fileInfo, err := os.Stat(structs.GlobalConfig.ReportName)
	if err == nil {
		fileSize := fileInfo.Size()
		// 简单粗暴判断文件大小
		if fileSize < 99360 {
			_ = os.Remove(structs.GlobalConfig.ReportName)
		}
	}
}
