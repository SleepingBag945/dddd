package gopocs

import (
	"database/sql"
	"dddd/structs"
	_ "embed"
	"fmt"
	_ "github.com/lib/pq"
	"github.com/projectdiscovery/gologger"
	"strings"
	"time"
)

var postgreSQLUserPasswdDict string

func PostgresScan(info *structs.HostInfo) (tmperr error) {
	starttime := time.Now().Unix()

	userPasswdList := sortUserPassword(info, postgreSQLUserPasswdDict, []string{"Postgres"})

	for _, userPass := range userPasswdList {
		flag, err := PostgresConn(info, userPass.UserName, userPass.Password)
		if err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "no connection could be made because the target machine actively refused it") {
				continue
			}
		}

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

func PostgresConn(info *structs.HostInfo, user string, pass string) (flag bool, err error) {
	flag = false
	Host, Port, Username, Password := info.Host, info.Ports, user, pass
	dataSourceName := fmt.Sprintf("postgres://%v:%v@%v:%v/%v?sslmode=%v", Username, Password, Host, Port, "postgres", "disable")
	db, err := sql.Open("postgres", dataSourceName)
	if err == nil {
		db.SetConnMaxLifetime(time.Duration(5) * time.Second)
		defer db.Close()
		err = db.Ping()
		if err == nil {
			result := fmt.Sprintf("PostgreSQL://%v:%v %v %v", Host, Port, Username, Password)
			gologger.Silent().Msg("[GoPoc] " + result)

			showData := fmt.Sprintf("Host: %v:%v\nUsername: %v\nPassword: %v\n", Host, Port, Username, Password)

			GoPocWriteResult(structs.GoPocsResultType{
				PocName:     "PostgreSQL-Login",
				Security:    "CRITICAL",
				Target:      Host + ":" + Port,
				InfoLeft:    showData,
				Description: "PostgreSQL弱口令",
			})

		}
	}
	return flag, err
}
