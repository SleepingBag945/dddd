package gonmap

import (
	"fmt"
	"testing"
	"time"
)

func TestScan(t *testing.T) {
	var scanner = New()
	host := "192.168.100.144"
	port := 5001
	status, response := scanner.ScanTimeout(host, port, time.Second*30)
	fmt.Println(status, response.FingerPrint.Service, host, ":", port)
	port = 22
	status, response = scanner.ScanTimeout(host, port, time.Second*30)

	fmt.Println(status, response.FingerPrint.Service, host, ":", port)
	port = 5000
	status, response = scanner.ScanTimeout(host, port, time.Second*30)
	fmt.Println(status, response.FingerPrint.Service, host, ":", port)
	port = 445
	status, response = scanner.ScanTimeout(host, port, time.Second*30)
	fmt.Println(status, response.FingerPrint.Service, host, ":", port)
}
