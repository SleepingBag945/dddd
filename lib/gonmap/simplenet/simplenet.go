package simplenet

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"time"
)

func tcpSend(protocol string, netloc string, data string, duration time.Duration, size int) (string, error) {
	protocol = strings.ToLower(protocol)
	conn, err := net.DialTimeout(protocol, netloc, duration)
	if err != nil {
		//fmt.Println(conn)
		return "", errors.New(err.Error() + " STEP1:CONNECT")
	}
	defer conn.Close()
	_, err = conn.Write([]byte(data))
	if err != nil {
		return "", errors.New(err.Error() + " STEP2:WRITE")
	}
	//读取数据
	var buf []byte              // big buffer
	var tmp = make([]byte, 256) // using small tmo buffer for demonstrating
	var length int
	for {
		//设置读取超时Deadline
		_ = conn.SetReadDeadline(time.Now().Add(time.Second * 3))
		length, err = conn.Read(tmp)
		buf = append(buf, tmp[:length]...)
		if length < len(tmp) {
			break
		}
		if err != nil {
			break
		}
		if len(buf) > size {
			break
		}
	}
	if err != nil && err != io.EOF {
		return "", errors.New(err.Error() + " STEP3:READ")
	}
	if len(buf) == 0 {
		return "", errors.New("STEP3:response is empty")
	}
	return string(buf), nil
}

func tlsSend(protocol string, netloc string, data string, duration time.Duration, size int) (string, error) {
	protocol = strings.ToLower(protocol)
	config := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
	}
	dialer := &net.Dialer{
		Timeout:  duration,
		Deadline: time.Now().Add(duration * 2),
	}
	conn, err := tls.DialWithDialer(dialer, protocol, netloc, config)
	if err != nil {
		return "", errors.New(err.Error() + " STEP1:CONNECT")
	}
	defer conn.Close()
	_, err = io.WriteString(conn, data)
	if err != nil {
		return "", errors.New(err.Error() + " STEP2:WRITE")
	}
	//读取数据
	var buf []byte              // big buffer
	var tmp = make([]byte, 256) // using small tmo buffer for demonstrating
	var length int
	for {
		//设置读取超时Deadline
		_ = conn.SetReadDeadline(time.Now().Add(time.Second * 3))
		length, err = conn.Read(tmp)
		buf = append(buf, tmp[:length]...)
		if length < len(tmp) {
			break
		}
		if err != nil {
			break
		}
		if len(buf) > size {
			break
		}
	}
	if err != nil && err != io.EOF {
		return "", errors.New(err.Error() + " STEP3:READ")
	}
	if len(buf) == 0 {
		return "", errors.New("STEP3:response is empty")
	}
	return string(buf), nil
}

func Send(protocol string, tls bool, netloc string, data string, duration time.Duration, size int) (string, error) {
	if tls {
		return tlsSend(protocol, netloc, data, duration, size)
	} else {
		return tcpSend(protocol, netloc, data, duration, size)
	}
}
