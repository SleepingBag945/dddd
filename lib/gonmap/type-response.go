package gonmap

const (
	Closed     Status = 0x000a1
	Open              = 0x000b2
	Matched           = 0x000c3
	NotMatched        = 0x000d4
	Unknown           = 0x000e5
)

type Status int

func (s Status) String() string {
	switch s {
	case Closed:
		return "Closed"
	case Open:
		return "Open"
	case Matched:
		return "Matched"
	case NotMatched:
		return "NotMatched"
	case Unknown:
		return "Unknown"
	default:
		return "Unknown"
	}
}

type Response struct {
	Raw         string
	TLS         bool
	FingerPrint *FingerPrint
}

var dnsResponse = Response{Raw: "DnsServer", TLS: false,
	FingerPrint: &FingerPrint{
		Service: "dns",
	},
}
