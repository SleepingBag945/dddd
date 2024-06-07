package gopocs

import (
	"database/sql"
	"dddd/ddout"
	"dddd/structs"
	_ "embed"
	"fmt"
	_ "github.com/denisenkom/go-mssqldb"
	"github.com/projectdiscovery/gologger"
	"time"
)

//go:embed dict/mssql.txt
var mssqlUserPasswdDict string

func MssqlScan(info *structs.HostInfo) (tmperr error) {
	if structs.GlobalConfig.NoServiceBruteForce {
		return
	}
	starttime := time.Now().Unix()

	userPasswdList := sortUserPassword(info, mssqlUserPasswdDict, []string{"mssql", "sqlserver"})

	for _, userPass := range userPasswdList {
		flag, err := MssqlConn(info, userPass.UserName, userPass.Password)
		if flag == true && err == nil {
			return err
		} else {
			tmperr = err
			if CheckErrs(err) {
				return err
			}
			if time.Now().Unix()-starttime > (int64(len(userPasswdList)) * 6) {
				gologger.AuditTimeLogger("[Go] [MSSQL] Timeout,break! %s:%v", info.Host, info.Ports)
				return err
			}
		}
	}
	gologger.AuditTimeLogger("[Go] [MSSQL] done! %s:%v", info.Host, info.Ports)
	return tmperr
}

func PrintRow(colsdata []interface{}) (err error, result string) {
	result = ""
	for _, val := range colsdata {
		switch v := (*(val.(*interface{}))).(type) {
		case nil:
			//fmt.Print("NULL")
		case bool:
			if v {
				fmt.Print("True")
			} else {
				fmt.Print("False")
			}
		case []byte:
			fmt.Print(string(v))
		default:
			result += fmt.Sprintf("%v\n", v)
		}
	}
	return err, result
}

func MssqlCMD(sqlstr string, conn *sql.DB) ([]interface{}, string) {

	stmt, err := conn.Prepare(sqlstr)
	if err != nil {
		return nil, ""
	}
	defer stmt.Close()

	rows, err := stmt.Query()
	if err != nil {
		return nil, ""
	}

	cols, _ := rows.Columns()
	var colsdata = make([]interface{}, len(cols))
	for i := 0; i < len(cols); i++ {
		colsdata[i] = new(interface{})
	}

	result := ""
	for rows.Next() {
		rows.Scan(colsdata...) //将查到的数据写入到这行中
		_, r := PrintRow(colsdata)
		result += r
	}
	defer rows.Close()
	return colsdata, result
}

func verifyMssql(conn *sql.DB) string {
	ver := "SQL-Shell> SELECT @@VERSION;\n"
	_, r := MssqlCMD(`SELECT @@VERSION;`, conn)
	ver += r + "\n"

	ver += "SQL-Shell> Select Name FROM Master.dbo.SysDatabases orDER BY Name;\n"
	_, r = MssqlCMD(`Select Name FROM Master.dbo.SysDatabases orDER BY Name`, conn)
	ver += r + "\n"
	return ver
}

func MssqlConn(info *structs.HostInfo, user string, pass string) (flag bool, err error) {
	flag = false
	Host, Port, Username, Password := info.Host, info.Ports, user, pass
	dataSourceName := fmt.Sprintf("server=%s;user id=%s;password=%s;port=%v;encrypt=disable;timeout=%v",
		Host, Username, Password, Port, time.Duration(6)*time.Second)
	gologger.AuditTimeLogger("[Go] [MSSQL-Brute] start try %s", dataSourceName)
	db, err := sql.Open("mssql", dataSourceName)
	if err == nil {
		db.SetConnMaxLifetime(time.Duration(6) * time.Second)
		db.SetConnMaxIdleTime(time.Duration(6) * time.Second)
		db.SetMaxIdleConns(0)
		defer db.Close()
		err = db.Ping()
		if err == nil {
			result := fmt.Sprintf("Mssql://%v:%v:%v %v", Host, Port, Username, Password)
			// gologger.Silent().Msg(result)

			showData := fmt.Sprintf("Host: %v:%v\nUsername: %v\nPassword: %v\n", Host, Port, Username, Password)
			r := verifyMssql(db)
			gologger.AuditLogger("[Go] [MSSQL-Brute] %s Result:\n%s", showData, r)

			ddout.FormatOutput(ddout.OutputMessage{
				Type:     "GoPoc",
				IP:       "",
				IPs:      nil,
				Port:     "",
				Protocol: "",
				Web:      ddout.WebInfo{},
				Finger:   nil,
				Domain:   "",
				GoPoc: ddout.GoPocsResultType{PocName: "Mssql-Login",
					Security:    "CRITICAL",
					Target:      Host + ":" + Port,
					InfoLeft:    showData,
					InfoRight:   r,
					Description: "Mssql弱口令",
					ShowMsg:     result},
				AdditionalMsg: "",
			})

			GoPocWriteResult(structs.GoPocsResultType{
				PocName:     "Mssql-Login",
				Security:    "CRITICAL",
				Target:      Host + ":" + Port,
				InfoLeft:    showData,
				InfoRight:   r,
				Description: "Mssql弱口令",
			})

			flag = true
		}
	}
	return flag, err
}
