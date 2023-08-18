package gopocs

import (
	"database/sql"
	"dddd/structs"
	_ "embed"
	"fmt"
	"github.com/projectdiscovery/gologger"
	_ "github.com/sijms/go-ora/v2"
	"time"
)

var oracleUserPasswdDict string

func OracleScan(info *structs.HostInfo) (tmperr error) {
	starttime := time.Now().Unix()

	userPasswdList := sortUserPassword(info, oracleUserPasswdDict, []string{"oracle"})

	for _, userPass := range userPasswdList {
		flag, err := OracleConn(info, userPass.UserName, userPass.Password)
		if flag == true && err == nil {
			return err
		} else {
			tmperr = err
			if CheckErrs(err) {
				return err
			}
			if time.Now().Unix()-starttime > (int64(len(userPasswdList)) * 6) {
				return err
			}
		}
	}

	return tmperr
}

func OracleConn(info *structs.HostInfo, user string, pass string) (flag bool, err error) {
	flag = false
	Host, Port, Username, Password := info.Host, info.Ports, user, pass
	dataSourceName := fmt.Sprintf("oracle://%s:%s@%s:%s/orcl", Username, Password, Host, Port)
	db, err := sql.Open("oracle", dataSourceName)
	if err == nil {
		db.SetConnMaxLifetime(time.Duration(6) * time.Second)
		db.SetConnMaxIdleTime(time.Duration(6) * time.Second)
		db.SetMaxIdleConns(0)
		defer db.Close()
		err = db.Ping()
		if err == nil {
			result := fmt.Sprintf("Oracle://%v:%v:%v %v", Host, Port, Username, Password)
			gologger.Silent().Msg("[GoPoc] " + result)

			showData := fmt.Sprintf("Host: %v:%v\nUsername: %v\nPassword: %v\n", Host, Port, Username, Password)

			GoPocWriteResult(structs.GoPocsResultType{
				PocName:     "Oracle-Login",
				Security:    "High",
				Target:      Host + ":" + Port,
				InfoLeft:    showData,
				Description: "Oracle弱口令",
			})

			flag = true
		}
	}
	return flag, err
}
