package ddout

import (
	"encoding/json"
	"fmt"
	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/gologger"
	"os"
	"strings"
)

var (
	OutputType     string
	OutputFileName string
)

type WebInfo struct {
	Status string `json:"status,omitempty"`
	Title  string `json:"title,omitempty"`
}

type GoPocsResultType struct {
	PocName     string `json:"poc_name,omitempty"`
	Security    string `json:"security,omitempty"`
	Description string `json:"description,omitempty"`
	Target      string `json:"target,omitempty"`
	InfoLeft    string `json:"info_left,omitempty"`
	InfoRight   string `json:"info_right,omitempty"`
	ShowMsg     string `json:"show_msg,omitempty"`
}

type OutputMessage struct {
	Type          string           `json:"type,omitempty"`
	IP            string           `json:"ip,omitempty"`
	IPs           []string         `json:"ips,omitempty"`
	Port          string           `json:"port,omitempty"`
	Protocol      string           `json:"protocol,omitempty"`
	Web           WebInfo          `json:"web,omitempty"`
	Finger        []string         `json:"finger,omitempty"`
	Domain        string           `json:"domain,omitempty"`
	GoPoc         GoPocsResultType `json:"go_poc,omitempty"`
	URI           string           `json:"uri,omitempty"`
	City          string           `json:"city,omitempty"`
	AdditionalMsg string           `json:"am,omitempty"`
	Show          string           `json:"-"`
	Nuclei        string           `json:"nuclei,omitempty"`
}

func (o *OutputMessage) ToString() (string, error) {
	r := ""
	var err error

	// IP存活验证
	if o.Type == "IPAlive" {
		r = "[Alive] " + o.IP
	} else if o.Type == "PortScan" {
		r = "[PortScan] " + o.IP + ":" + o.Port
	} else if o.Type == "Nmap" {
		r = fmt.Sprintf("[Nmap] %s://%s:%s", o.Protocol, o.IP, o.Port)
	} else if o.Type == "Web" {
		r = fmt.Sprintf("[Web] [%v] %s", o.Web.Status, o.URI)
		if o.Web.Title != "" {
			r += " [" + o.Web.Title + "]"
		}
	} else if o.Type == "DNS-Brute" {
		r = "[Brute] " + o.Domain
	} else if o.Type == "DNS-SubFinder" {
		r = "[SubFinder] " + o.Domain
	} else if o.Type == "CDN-Domain" {
		r = "[CDN-Domain] " + o.Domain
	} else if o.Type == "RealIP" {
		r = "[RealIP] " + o.Domain + " => "
		for _, v := range o.IPs {
			r += v + ","
		}
		r = r[:len(r)-1]
	} else if o.Type == "GoPoc" {
		r = "[GoPoc] " + o.GoPoc.ShowMsg
	} else if o.Type == "Finger" {
		//msg := "[Finger] " + fullURL + " "
		//msg += fmt.Sprintf("[%d] [", pathEntity.StatusCode)
		//for _, r := range results {
		//	msg += aurora.Cyan(r).String() + ","
		//}
		//msg = msg[:len(msg)-1] + "]"
		//if pathEntity.Title != "" {
		//	msg += fmt.Sprintf(" [%s]", pathEntity.Title)
		//}
		//gologger.Silent().Msg(msg)

		r = "[Finger] " + o.URI + " "
		if o.Web.Status != "" {
			r += fmt.Sprintf("[%s] ", o.Web.Status)
		}
		r += "["
		for _, c := range o.Finger {
			r += aurora.Cyan(c).String() + ","
		}
		r = r[:len(r)-1] + "]"
		if o.Web.Title != "" {
			r += fmt.Sprintf(" [%s]", o.Web.Title)
		}
	} else if o.Type == "Active-Finger" {
		r = "[Active-Finger] " + o.URI + " ["
		for _, c := range o.Finger {
			r += aurora.Cyan(c).String() + ","
		}
		r = r[:len(r)-1] + "]"
	} else if o.Type == "Domain-Bind" {
		r = "[Domain-Bind] [" + o.Web.Status + "] " + o.URI
	} else if o.Type == "Hunter" {
		r = "[Hunter] "
		if o.URI == "" {
			r += o.Protocol + "://" + o.IP + ":" + o.Port
		} else {
			r += fmt.Sprintf("[%v] %s [%s] [%s]", o.Web.Status, o.URI, o.Web.Title, o.City)
		}
	} else if o.Type == "Fofa" {
		r = o.Show
	} else if o.Type == "Quake" {
		r = "[Quake] " + o.Show
	} else if o.Type == "Nuclei" {
		r = "[Nuclei] " + o.Show
	} else {
		err = fmt.Errorf("error OutputMessage Type: %s", o.Type)
	}

	if err == nil && o.AdditionalMsg != "" {
		r += " [" + o.AdditionalMsg + "]"
	}

	return r, err
}

func (o *OutputMessage) ToJson() (string, error) {
	b, err := json.Marshal(o)
	return string(b), err
}

func writeFile(result string) {
	filename := OutputFileName

	var text = []byte(result + "\n")
	fl, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		fmt.Printf("Open %s error, %v\n", filename, err)
		return
	}
	_, err = fl.Write(text)
	fl.Close()
	if err != nil {
		fmt.Printf("Write %s error, %v\n", filename, err)
	}
}

func FormatOutput(o OutputMessage) {
	if OutputFileName == "" {
		return
	}
	s, err := o.ToString()
	if err != nil {
		return
	}
	if o.Type != "Nuclei" {
		gologger.Silent().Msg(s)
	}

	if s == "" {
		return
	}

	if OutputType == "text" {
		// 去掉指纹识别给的颜色
		if strings.Contains(s, "\033[36m") {
			s = strings.ReplaceAll(s, "\033[36m", "")
			s = strings.ReplaceAll(s, "\033[0m", "")
		}
		writeFile(s)
	} else if OutputType == "json" {
		j, e := o.ToJson()
		if e == nil {
			writeFile(j)
		}
	}

}
