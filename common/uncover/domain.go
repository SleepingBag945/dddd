package uncover

import "dddd/structs"

func AddIPDomainMap(ip string, domain string) {
	structs.GlobalIPDomainMapLock.Lock()
	_, ok := structs.GlobalIPDomainMap[ip]
	structs.GlobalIPDomainMapLock.Unlock()
	if ok {
		// 存在于这个Map中
		structs.GlobalIPDomainMapLock.Lock()
		dms, _ := structs.GlobalIPDomainMap[ip]
		structs.GlobalIPDomainMapLock.Unlock()
		flag := false
		for _, dm := range dms {
			if dm == domain {
				flag = true
				break
			}
		}
		if !flag { // 没有这个域名
			structs.GlobalIPDomainMapLock.Lock()
			structs.GlobalIPDomainMap[ip] = append(structs.GlobalIPDomainMap[ip],
				domain)
			structs.GlobalIPDomainMapLock.Unlock()
		}
	} else {
		structs.GlobalIPDomainMapLock.Lock()
		structs.GlobalIPDomainMap[ip] = []string{domain}
		structs.GlobalIPDomainMapLock.Unlock()
	}
}
