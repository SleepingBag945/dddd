package gopocs

import (
	"dddd/structs"
	_ "embed"
	"fmt"
	"github.com/jlaffaye/ftp"
	"github.com/projectdiscovery/gologger"
	"time"
)

var ftpUserPasswdDict string

func FtpScan(info *structs.HostInfo) (tmperr error) {
	starttime := time.Now().Unix()

	// 先检测匿名访问
	flag, err := FtpConn(info, "anonymous", "")
	if flag == true && err == nil {
		return err
	} else {
		tmperr = err
		if CheckErrs(err) {
			return err
		}
	}

	userPasswdList := sortUserPassword(info, ftpUserPasswdDict, []string{"ftp"})

	// 暴力破解
	for _, userPass := range userPasswdList {
		ftpFlag, ftpErr := FtpConn(info, userPass.UserName, userPass.Password)
		if ftpFlag == true && ftpErr == nil {
			return ftpErr
		} else {
			tmperr = ftpErr
			if CheckErrs(ftpErr) {
				return ftpErr
			}
			if time.Now().Unix()-starttime > (int64(len(userPasswdList)) * 6) {
				return err
			}
		}
	}

	return tmperr
}

func FtpConn(info *structs.HostInfo, user string, pass string) (flag bool, err error) {
	flag = false
	Host, Port, Username, Password := info.Host, info.Ports, user, pass
	conn, err := ftp.DialTimeout(fmt.Sprintf("%v:%v", Host, Port), time.Duration(6)*time.Second)
	if err == nil {
		err = conn.Login(Username, Password)
		if err == nil {
			flag = true

			result := fmt.Sprintf("FTP://%v:%v:%v %v", Host, Port, Username, Password)
			dirs, err := conn.List("")
			//defer conn.Logout()
			if err == nil {
				if len(dirs) > 0 {
					for i := 0; i < len(dirs); i++ {
						if len(dirs[i].Name) > 50 {
							result += "\n      - " + dirs[i].Name[:50]
						} else {
							result += "\n      - " + dirs[i].Name
						}
						if i == 5 {
							break
						}
					}
				}
			}

			gologger.Silent().Msgf("[GoPoc] " + result)

			GoPocWriteResult(structs.GoPocsResultType{
				PocName:     "FTP-Login",
				Security:    "HIGH",
				Target:      fmt.Sprintf("%v:%v", Host, Port),
				InfoLeft:    result,
				Description: "FTP未授权访问或弱口令",
			})

		}
	}
	return flag, err
}
