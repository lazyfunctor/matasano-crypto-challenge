package main

import (
	"fmt"
	"bufio"
	"os"
	"./cryptutils"
	"encoding/base64"
)

var nonce = []byte {0, 0, 0, 0, 0, 0, 0, 0}
var encKey []byte

func init() {
	encKey, _ = cryptutils.GenerateRandomKey(16)
}

func readCipherText() (cipherList [][]byte, minLen int) {
	f, err := os.Open("c20.txt")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer f.Close()
	r := bufio.NewReader(f)
	line, _, err := r.ReadLine()
	pt, _ := base64.StdEncoding.DecodeString(string(line))
	ct, _ := cryptutils.EncryptCTR(pt, encKey, nonce)
	minLen = len(ct)
	for err == nil {
		cipherList = append(cipherList, ct)
		if len(ct) < minLen {
			minLen = len(ct)
		}
		fmt.Println(">>", string(ct))
		line, _, err = r.ReadLine()
		pt, _ = base64.StdEncoding.DecodeString(string(line))
		ct, _ = cryptutils.EncryptCTR(pt, encKey, nonce)
	}
	for idx := range(cipherList) {
		cipherList[idx] = cipherList[idx][:minLen]
	}
	return
}

func GuessKey(keySize int, dat []byte) []byte {
	blocks := make([][]byte, keySize)
	//fmt.Println(len(dat))
	for idx, byt := range(dat) {
		blocks[idx % keySize] = append(blocks[idx % keySize], byt)
	}

	guess := []byte {}
	for _, block := range(blocks) {
		key, _, _, _ := cryptutils.DecryptMsg(block)
		guess = append(guess, key)
	}
	return guess
}


func main() {
	cipherList, smallest := readCipherText()
	var cipher []byte
	for _, item := range(cipherList) {
		cipher = append(cipher, item...)
	}
	fmt.Println(cipher)
	key := GuessKey(smallest, cipher)
	fmt.Println("Key=>", key)
	fmt.Println(string(cryptutils.RepeatXOR(cipher, key)))
}
