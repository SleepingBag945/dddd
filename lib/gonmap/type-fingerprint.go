package gonmap

type FingerPrint struct {
	ProbeName        string
	MatchRegexString string

	Service         string
	ProductName     string
	Version         string
	Info            string
	Hostname        string
	OperatingSystem string
	DeviceType      string
	//  p/vendorproductname/
	//	v/version/
	//	i/info/
	//	h/hostname/
	//	o/operatingsystem/
	//	d/devicetype/
}
