package gopocs

import (
	"database/sql"
	"dddd/ddout"
	"dddd/structs"
	_ "embed"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"github.com/projectdiscovery/gologger"
	"time"
)

//go:embed dict/mysql.txt
var mysqlUserPasswdDict string

func MysqlScan(info *structs.HostInfo) (tmperr error) {
	if structs.GlobalConfig.NoServiceBruteForce {
		return
	}
	starttime := time.Now().Unix()

	userPasswdList := sortUserPassword(info, mysqlUserPasswdDict, []string{"mysql"})

	for _, userPass := range userPasswdList {
		flag, err := MysqlConn(info, userPass.UserName, userPass.Password)
		if flag == true && err == nil {
			return err
		} else {
			tmperr = err
			if CheckErrs(err) {
				return err
			}
			if time.Now().Unix()-starttime > (int64(len(userPasswdList)) * 6) {
				gologger.AuditTimeLogger("[Go] [MYSQL] Timeout,break! %s:%v", info.Host, info.Ports)
				return err
			}
		}
	}
	gologger.AuditTimeLogger("[Go] [MYSQL] done! %s:%v", info.Host, info.Ports)
	return tmperr
}

func MysqlConn(info *structs.HostInfo, user string, pass string) (flag bool, err error) {
	flag = false
	Host, Port, Username, Password := info.Host, info.Ports, user, pass
	dataSourceName := fmt.Sprintf("%v:%v@tcp(%v:%v)/mysql?charset=utf8&timeout=%v", Username, Password, Host, Port, time.Duration(6)*time.Second)
	gologger.AuditTimeLogger("[Go] [MYSQL-Brute] start try %s", dataSourceName)
	db, err := sql.Open("mysql", dataSourceName)
	if err == nil {
		db.SetConnMaxLifetime(time.Duration(6) * time.Second)
		db.SetConnMaxIdleTime(time.Duration(6) * time.Second)
		db.SetMaxIdleConns(0)
		defer db.Close()
		err = db.Ping()
		if err == nil {
			result := fmt.Sprintf("Mysql://%v:%v:%v %v", Host, Port, Username, Password)
			// gologger.Silent().Msg("[GoPoc] " + result)

			showData := fmt.Sprintf("Host: %v:%v\nUsername: %v\nPassword: %v\n", Host, Port, Username, Password)

			msg := ""
			osVersion := ""
			machineArch := ""
			rows, queryErr := db.Query("select @@version_compile_os, @@version_compile_machine;")
			if queryErr == nil {
				defer rows.Close()
				for rows.Next() {
					var vco string
					var vcm string
					if rowErr := rows.Scan(&vco, &vcm); rowErr != nil {
						continue
					}
					if vco != "" {
						osVersion = vco
					}
					if vcm != "" {
						machineArch = vcm
					}
				}
			}
			msg += "系统版本: " + osVersion + "\n系统架构: " + machineArch + "\n"

			msg += "\nSQL# SHOW DATABASES;\n"

			rows, queryErr = db.Query("SHOW DATABASES;")
			if queryErr == nil {
				defer rows.Close()
				for rows.Next() {
					var dbname string
					if rowErr := rows.Scan(&dbname); rowErr != nil {
						continue
					}
					msg += "     " + dbname + "\n"
				}
			}
			gologger.AuditLogger("[Go] [MYSQL-Brute] %s Result:\n%s", showData, msg)

			ddout.FormatOutput(ddout.OutputMessage{
				Type:     "GoPoc",
				IP:       "",
				IPs:      nil,
				Port:     "",
				Protocol: "",
				Web:      ddout.WebInfo{},
				Finger:   nil,
				Domain:   "",
				GoPoc: ddout.GoPocsResultType{PocName: "Mysql-Login",
					Security:    "High",
					Target:      Host + ":" + Port,
					InfoLeft:    showData,
					InfoRight:   msg,
					Description: "Mysql弱口令",
					ShowMsg:     result},
				AdditionalMsg: "",
			})

			GoPocWriteResult(structs.GoPocsResultType{
				PocName:     "Mysql-Login",
				Security:    "High",
				Target:      Host + ":" + Port,
				InfoLeft:    showData,
				InfoRight:   msg,
				Description: "Mysql弱口令",
			})

			flag = true
		}
	}
	return flag, err
}
