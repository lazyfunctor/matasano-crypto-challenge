package main

import (
	"fmt"
	"crypto/rand"
	"./cryptutils"
	"math/big"
)

var plainText = [10]string {
	"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
	"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
	"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
	"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
	"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
	"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
	"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
	"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
	"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
	"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
}

var encKey []byte

func encrypt() (ctext []byte, iv []byte, err error) {
	encKey, err = cryptutils.GenerateRandomKey(16)
	if err != nil {
		return
	}
	//encKey = []byte("YELLOW SUBMARINE")
	iv, err = cryptutils.GenerateRandomKey(16)
	if err != nil {
		return
	}
	//iv = []byte("YELLOW SUBMARINE")
	count, err := rand.Int(rand.Reader, big.NewInt(10))
	if err != nil {
		return
	}
	ptext := plainText[int(count.Int64())]
	fmt.Println(count)
	//ptext := plainText[1]
	ctext, err = cryptutils.EncryptCBC([]byte(ptext), encKey, iv)
	return
}

func oracle(ctext []byte, iv []byte) (valid bool) {
	_, err := cryptutils.DecryptCBC(ctext, encKey, iv)
	//fmt.Println(err)
	valid = (err == nil)
	return
}
	

func guessAdjBlocks(cipherText []byte, ivInit []byte, blockNum int) (block [16]byte, err error) {
	iv := make([]byte, 16)
	cBlock := make([]byte, 16)
	copy(cBlock, cipherText[(blockNum-1)*16:blockNum*16])
	if blockNum > 1 {
		ivInit = cipherText[(blockNum-2)*16:(blockNum-1)*16]
	}
	for pos := 1; pos <= 16; pos++ {
		//fmt.Println("pos", pos)
		for b := 0; b <= 255; b++ {
			copy(iv, ivInit)
			//b = 1
			iv[16-pos] = iv[16-pos] ^ byte(b) ^ byte(pos)
			//fmt.Println(iv[16-pos])
			for i := 1; i < pos; i++ {
				//fmt.Println(16-i)
				iv[16-i] = iv[16-i] ^ block[16-i] ^ byte(pos)
			}
			//crafted := append(iv, cBlock...)
			if valid := oracle(cBlock, iv); valid {
				block[16-pos] = byte(b)
				//fmt.Println("Byte", b)
				//break
			}
		}
		//panic("foo")
	}
	return
}


func main() {
	ctext, iv, err := encrypt()
	if err != nil {
		panic(err)
	}
	// iv[15] = byte(43)
	// plain, err := cryptutils.DecryptCBC(ctext[:16], encKey, iv)
	// fmt.Println(string(plain), err)

	fmt.Println(ctext)
	blockLen := len(ctext)/16
	fmt.Println(blockLen)

	// val, _ := guessAdjBlocks(ctext, iv, 5)
	// fmt.Println(val)
	var result []byte
	for i:= 1; i <= blockLen; i++ {
		val, _ := guessAdjBlocks(ctext, iv, i)
		result = append(result, val[:]...)
	}
	final, _ := cryptutils.Unpad(result)
	fmt.Println(string(final))

	// cipher, err := cryptutils.EncryptCBC([]byte(plainText[0]), encKey, iv)
	// fmt.Println(cipher)
	// plain, err := cryptutils.DecryptCBC(cipher, encKey, iv)
	// fmt.Println(string(plain), err)


}
