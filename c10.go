package main

import (
	"fmt"
	"./cryptutils"
	"io/ioutil"
	"encoding/base64"
)



func main() {
	key := []byte("YELLOW SUBMARINE")
	iv := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,}
	rawDat, err := ioutil.ReadFile("c10.txt")
	if err != nil {
		panic("file error")
	}
	dat, decErr := base64.StdEncoding.DecodeString(string(rawDat))
	if decErr != nil  {
		panic("base64 error")
	}
	dec, _ := cryptutils.DecryptCBC(dat, key, iv)
	fmt.Println(string(dec))
}
