package simplenet

import (
	"fmt"
	"regexp"
	"strconv"
	"testing"
	"time"
)

func TestName(t *testing.T) {
	response, err := Send("tcp", false, "192.168.217.1:25", "", time.Second*3, 2048)
	if err != nil {
		fmt.Println(err)
		return
	}
	responseBuf := []byte(response)
	printStr := ""
	for _, charBuf := range responseBuf {
		if strconv.IsPrint(rune(charBuf)) {
			if charBuf > 0x7f {
				printStr += "?"
			} else {
				printStr += string(charBuf)
			}
			continue
		}
		printStr += fmt.Sprintf("\\x%x", string(charBuf))
	}

	r := regexp.MustCompile(`.\x00\x00\x00\x0a([\d.-]+)-MariaDB\x00.*mysql_native_password\x00`)
	fmt.Println(printStr)
	fmt.Println(r.MatchString(response))

}

//func convData(s string) string {
//	b := []byte(s)
//	var r []rune
//	for _, i := range b {
//		r = append(r, rune(i))
//	}
//	return string(r)
//}

func TestRuneALl(t *testing.T) {
	for i := 0; i <= 0xffff; i++ {
		fmt.Println(string(rune(i)), " ", fmt.Sprintf("\\%x", i))
	}
}

//func IsPrint(r rune) bool {
//	if r < 20 {
//		return false
//	}
//	if r > 0x7f {
//		return false
//	}
//	return true
//}

func TestUDPSend(t *testing.T) {
	byteString := "\x88\x2a\x5e\xe7\xee\x66\x88\x66\x5a\x3b\x08\x4f\x08\x00\x45\x00\x00\x3b\xa5\xa7\x00\x00\x40\x11\xfd\x6c\xc0\xa8\x32\x11\x72\x72\x72\x72\xcc\x42\x00\x35\x00\x27\xc0\x91\xde\xf7\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03\x77\x77\x77\x05\x62\x61\x69\x64\x75\x03\x63\x6f\x6d\x00\x00\x01\x00\x01"

	fmt.Printf("%x", byteString)
	response, err := Send("udp", false, "114.114.114.114:53", byteString, time.Second*30, 512)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(response)
}
