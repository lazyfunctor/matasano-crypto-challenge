package main

import (
	"fmt"
	"strings"
	"bytes"
	"./cryptutils"
)


func ParseEncodedURL(url string) map[string]string {
	res := make(map[string]string)
	pairs := strings.Split(url, "&")
	for _, p := range(pairs) {
		vals := strings.Split(p, "=")
		res[vals[0]] = vals[1]
	}
	return res
}

func profileFor(emailBytes []byte) []byte {
	meta := map[byte]int {'&': 1, '=': 1}
	out := []byte {}
	for i := range(emailBytes) {
		_, exists := meta[emailBytes[i]]
		if ! exists {
			out = append(out, emailBytes[i])
		}
	}
	res := fmt.Sprintf("email=%s&uid=10&role=user", out)
	encrypted_str := cryptutils.EncryptECB([]byte(res), cryptutils.GlobalKey)
	return encrypted_str
}

func decodeProfile(cipher []byte) map[string]string {
	encodedProfile := cryptutils.DecryptECB(cipher, cryptutils.GlobalKey)
	return ParseEncodedURL(string(encodedProfile))
}


func setAdmin() {
	adminBytes := bytes.Repeat([]byte{byte(11)}, 16)
	copy(adminBytes[:5], []byte("admin"))
	padding := bytes.Repeat([]byte{'A'}, 10)
	cipher1 := profileFor(append(padding, adminBytes...))
	sourceBlock := cipher1[16:32]
	fmt.Println(cipher1)

	padding2 := bytes.Repeat([]byte{'A'}, 13)
	cipher2 := profileFor(padding2)
	target := cipher2[32:48]
	copy(target, sourceBlock)
	fmt.Println(decodeProfile(cipher2))

}

func main() {
	//fmt.Println(ParseEncodedURL("foo=bar&baz=qux&zap=zazzle"))
	val := decodeProfile(profileFor([]byte("ab&&&==hi=nav.&kaushik@gmail.com&run=test")))
	fmt.Println(val)
	setAdmin()
}
