package main

import (
	"fmt"
	"crypto/rand"
	"math/big"
	"./cryptutils"
)



func main() {
	b := make([]byte, 16)
	n, err := rand.Read(b)
	fmt.Println(b, n, err)
	fmt.Println(rand.Int(rand.Reader, big.NewInt(6)))
	var oracle cryptutils.BlackBox
	oracle = cryptutils.Oracle{}
	fmt.Println(cryptutils.DetectionOracle(oracle))
	//fmt.Println(oracle.EncryptionOracle([]byte("hurray!!!!!!")))
}
