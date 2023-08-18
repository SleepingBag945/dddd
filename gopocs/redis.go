package gopocs

import (
	"dddd/common"
	"dddd/structs"
	"dddd/utils"
	_ "embed"
	"fmt"
	"github.com/projectdiscovery/gologger"
	"net"
	"strings"
	"time"
)

var (
	dbfilename string
	dir        string
)

var redisUserPasswdDict string

func RedisScan(info *structs.HostInfo) (tmperr error) {
	starttime := time.Now().Unix()
	flagA, errA := RedisUnauth(info)
	if flagA == true && errA == nil {
		return errA
	}

	var upList []string
	for _, v := range info.UserPass {
		_, p := splitUserPass(v)
		upList = append(upList, p)
	}
	for _, v := range strings.Split(redisUserPasswdDict, "\n") {
		upList = append(upList, v)
	}
	upList = utils.RemoveDuplicateElement(upList)

	var passwdList []string
	// 统计变形后的字典
	for _, oriPass := range upList {
		oriPass = strings.TrimSuffix(oriPass, "\r")
		if strings.Contains(oriPass, "{{key}}") {
			for _, sKey := range info.InfoStr {
				newKeys := generateKeys(sKey)
				for _, nKey := range newKeys {
					newPass := strings.Replace(oriPass, "{{key}}", nKey, -1)
					passwdList = append(passwdList, newPass)
				}

			}
			newKeys := generateKeys("redis")
			for _, nKey := range newKeys {
				newPass := strings.Replace(oriPass, "{{key}}", nKey, -1)
				passwdList = append(passwdList, newPass)
			}
		} else {
			passwdList = append(passwdList, oriPass)
		}
	}
	passwdList = utils.RemoveDuplicateElement(passwdList)

	for _, pass := range passwdList {
		flag, err := RedisConn(info, pass)
		if flag == true && err == nil {
			return err
		} else {
			tmperr = err
			if CheckErrs(err) {
				return err
			}
			if time.Now().Unix()-starttime > (int64(len(passwdList)) * 6) {
				return err
			}
		}
	}

	return tmperr
}

func RedisConn(info *structs.HostInfo, pass string) (flag bool, err error) {
	flag = false
	realhost := fmt.Sprintf("%s:%v", info.Host, info.Ports)
	conn, err := common.WrapperTcpWithTimeout("tcp", realhost, time.Duration(6)*time.Second)
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()
	if err != nil {
		return flag, err
	}
	err = conn.SetReadDeadline(time.Now().Add(time.Duration(6) * time.Second))
	if err != nil {
		return flag, err
	}
	_, err = conn.Write([]byte(fmt.Sprintf("auth %s\r\n", pass)))
	if err != nil {
		return flag, err
	}
	reply, err := readreply(conn)
	if err != nil {
		return flag, err
	}
	if strings.Contains(reply, "+OK") {
		flag = true

		result := fmt.Sprintf("Redis:%s %s", realhost, pass)
		gologger.Silent().Msg("[GoPoc] " + result)

		showData := fmt.Sprintf("Host: %v\nPassword: %v\n", realhost, pass)

		GoPocWriteResult(structs.GoPocsResultType{
			PocName:     "Redis-Login",
			Security:    "HIGH",
			Target:      realhost,
			InfoLeft:    showData,
			InfoRight:   reply,
			Description: "Redis未授权/弱口令",
		})

	}
	return flag, err
}

func RedisUnauth(info *structs.HostInfo) (flag bool, err error) {
	flag = false
	realhost := fmt.Sprintf("%s:%v", info.Host, info.Ports)
	conn, err := common.WrapperTcpWithTimeout("tcp", realhost, time.Duration(6)*time.Second)
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()
	if err != nil {
		return flag, err
	}
	err = conn.SetReadDeadline(time.Now().Add(time.Duration(6) * time.Second))
	if err != nil {
		return flag, err
	}
	_, err = conn.Write([]byte("info\r\n"))
	if err != nil {
		return flag, err
	}
	reply, err := readreply(conn)
	if err != nil {
		return flag, err
	}
	if strings.Contains(reply, "redis_version") {
		flag = true

		result := fmt.Sprintf("Redis:%s %s", realhost, "Unauthorized")
		gologger.Silent().Msg("[GoPoc] " + result)

		showData := fmt.Sprintf("Host: %v\nUnauthorized\n", realhost)

		GoPocWriteResult(structs.GoPocsResultType{
			PocName:     "Redis-Login",
			Security:    "HIGH",
			Target:      realhost,
			InfoLeft:    showData,
			InfoRight:   reply,
			Description: "Redis未授权/弱口令",
		})

	}
	return flag, err
}

func readreply(conn net.Conn) (result string, err error) {
	size := 5 * 1024
	buf := make([]byte, size)
	for {
		count, err := conn.Read(buf)
		if err != nil {
			break
		}
		result += string(buf[0:count])
		if count < size {
			break
		}
	}
	return result, err
}
