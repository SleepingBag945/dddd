package masscan

import (
	"bytes"
	"encoding/xml"
	"github.com/pkg/errors"
	"io"
	"os/exec"
)

type Address struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}
type State struct {
	State     string `xml:"state,attr"`
	Reason    string `xml:"reason,attr"`
	ReasonTTL string `xml:"reason_ttl,attr"`
}
type Host struct {
	XMLName xml.Name `xml:"host"`
	Endtime string   `xml:"endtime,attr"`
	Address Address  `xml:"address"`
	Ports   Ports    `xml:"ports>port"`
}
type Ports []struct {
	Protocol string  `xml:"protocol,attr"`
	Portid   string  `xml:"portid,attr"`
	State    State   `xml:"state"`
	Service  Service `xml:"service"`
}
type Service struct {
	Name   string `xml:"name,attr"`
	Banner string `xml:"banner,attr"`
}

type Masscan struct {
	SystemPath string
	Args       []string
	Ports      string
	FileName   string
	Rate       string
	Exclude    string
	Result     []byte
}

func (m *Masscan) SetSystemPath(systemPath string) {
	if systemPath != "" {
		m.SystemPath = systemPath
	}
}
func (m *Masscan) SetArgs(arg ...string) {
	m.Args = arg
}
func (m *Masscan) SetPorts(ports string) {
	m.Ports = ports
}
func (m *Masscan) SetFileName(name string) {
	m.FileName = name
}

func (m *Masscan) SetRate(rate string) {
	m.Rate = rate
}
func (m *Masscan) SetExclude(exclude string) {
	m.Exclude = exclude
}

// Start scanning
func (m *Masscan) Run() error {
	var (
		cmd        *exec.Cmd
		outb, errs bytes.Buffer
	)
	if m.Rate != "" {
		m.Args = append(m.Args, "--rate")
		m.Args = append(m.Args, m.Rate)
	}
	if m.FileName != "" {
		m.Args = append(m.Args, "-iL")
		m.Args = append(m.Args, m.FileName)
	}
	if m.Ports != "" {
		m.Args = append(m.Args, "-p")
		m.Args = append(m.Args, m.Ports)
	}
	if m.Exclude != "" {
		m.Args = append(m.Args, "--exclude")
		m.Args = append(m.Args, m.Exclude)
	}
	m.Args = append(m.Args, "-oX")
	m.Args = append(m.Args, "-")
	cmd = exec.Command(m.SystemPath, m.Args...)
	cmd.Stdout = &outb
	cmd.Stderr = &errs
	err := cmd.Run()
	if err != nil {
		if errs.Len() > 0 {
			return errors.New(errs.String())
		}
		return err
	}
	m.Result = outb.Bytes()
	return nil
}

// Parse scans result.
func (m *Masscan) Parse() ([]Host, error) {
	var hosts []Host
	decoder := xml.NewDecoder(bytes.NewReader(m.Result))
	for {
		t, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if t == nil {
			break
		}
		switch se := t.(type) {
		case xml.StartElement:
			if se.Name.Local == "host" {
				var host Host
				err := decoder.DecodeElement(&host, &se)
				if err == io.EOF {
					break
				}
				if err != nil {
					return nil, err
				}
				hosts = append(hosts, host)
			}
		default:
		}
	}
	return hosts, nil
}
func New(SystemPath string) *Masscan {
	return &Masscan{
		SystemPath: SystemPath,
	}
}
