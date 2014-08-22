package main

import (
	"crypto/aes"
	"io/ioutil"
	"encoding/base64"
	"fmt"
)

func DecryptAES(cipher, key []byte) []byte {
	res := make([]byte, len(cipher))
	bs := aes.BlockSize
	inp := make([]byte, bs)
	out := make([]byte, bs)
	c, _ := aes.NewCipher(key)
	blockCount := 1
	size := len(cipher)
	for (blockCount * bs <= size) {
		copy(inp, cipher[(blockCount - 1) * bs: (blockCount * bs)])
		c.Decrypt(out, inp)
		copy(res[(blockCount - 1) * bs: (blockCount * bs)], out)
		blockCount += 1
	}
	return res
}
	
func main() {
	rawDat, err := ioutil.ReadFile("c7.txt")
	if err != nil  {
		panic("problem in reading file")
	}
	dat, decErr := base64.StdEncoding.DecodeString(string(rawDat))
	if decErr != nil  {
		panic("problem in reading file")
	}
	key := []byte("YELLOW SUBMARINE")
	fmt.Println(string(DecryptAES(dat, key)))
}
