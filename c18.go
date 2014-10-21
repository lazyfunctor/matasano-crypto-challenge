package main

import (
	"fmt"
	"./cryptutils"
	"encoding/base64"
)


func main() {
	key := []byte("YELLOW SUBMARINE")
	nonce := []byte {0, 0, 0, 0, 0, 0, 0, 0}
	cipher, _ := base64.StdEncoding.DecodeString("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
	plain, _ := cryptutils.DecryptCTR(cipher, key, nonce)
	fmt.Println(string(plain))

	pt := []byte("test run nrown fox jumps over the lazy dog. The quick one!!!!!!")
	ct, _ := cryptutils.EncryptCTR(pt, key, nonce)
	val, _ := cryptutils.DecryptCTR(ct, key, nonce)
	fmt.Println(string(val))
}
