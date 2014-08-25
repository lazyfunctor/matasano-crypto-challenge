package main

import (
	"fmt"
	"strings"
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

func profileFor(email string) string {
	meta := map[byte]int {[]byte("&")[0]: 1, []byte("=")[0]: 1}
	emailBytes := []byte(email)
	out := []byte {}
	for i := range(emailBytes) {
		_, exists := meta[emailBytes[i]]
		if ! exists {
			out = append(out, emailBytes[i])
		}
	}
	res := fmt.Sprintf("email=%s&uid=10&role=user", out)
	encrypted_str := cryptutils.EncryptECB([]byte(res), cryptutils.GlobalKey)
	return string(encrypted_str)
}

func decodeProfile(encrypted string) map[string]string {
	encodedProfile := cryptutils.DecryptECB([]byte(encrypted), cryptutils.GlobalKey)
	return ParseEncodedURL(string(encodedProfile))
}

func main() {
	fmt.Println(ParseEncodedURL("foo=bar&baz=qux&zap=zazzle"))
	fmt.Println(decodeProfile(profileFor("ab&&&==hi=nav.&kaushik@gmail.com&run=test")))
}
