package gonmap

import (
	"regexp"
	"strconv"
	"strings"
)

var portRangeRegx = regexp.MustCompile("^(\\d+)(?:-(\\d+))?$")
var portGroupRegx = regexp.MustCompile("^(\\d+(?:-\\d+)?)(?:,\\d+(?:-\\d+)?)*$")

type PortList []int

var emptyPortList = PortList([]int{})

func parsePortList(express string) PortList {
	var list = PortList([]int{})
	if portGroupRegx.MatchString(express) == false {
		panic("port expression string invalid")
	}
	for _, expr := range strings.Split(express, ",") {
		rArr := portRangeRegx.FindStringSubmatch(expr)
		var startPort, endPort int
		startPort, _ = strconv.Atoi(rArr[1])
		if rArr[2] != "" {
			endPort, _ = strconv.Atoi(rArr[2])
		} else {
			endPort = startPort
		}
		for num := startPort; num <= endPort; num++ {
			list = append(list, num)
		}
	}
	list = list.removeDuplicate()
	return list
}

func (p PortList) removeDuplicate() PortList {
	result := make([]int, 0, len(p))
	temp := map[int]struct{}{}
	for _, item := range p {
		if _, ok := temp[item]; !ok { //如果字典中找不到元素，ok=false，!ok为true，就往切片中append元素。
			temp[item] = struct{}{}
			result = append(result, item)
		}
	}
	return result
}

func (p PortList) exist(port int) bool {
	for _, num := range p {
		if num == port {
			return true
		}
	}
	return false
}

func (p PortList) append(ports ...int) PortList {
	p = append(p, ports...)
	p = p.removeDuplicate()
	return p
}
