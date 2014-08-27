package main

import (
	"fmt"
	"./cryptutils"
	"bytes"
)

func encode(dat []byte) ([]byte, error) {
	meta := map[byte]int {
		[]byte(";")[0]: 1,
		[]byte("=")[0]: 1,
	}
	prefix := "comment1=cooking%20MCs;userdata="
	suffix := ";comment2=%20like%20a%20pound%20of%20bacon"
	out := []byte(prefix)
	for idx := range(dat) {
		if _, exists := meta[dat[idx]]; exists {
			val := []byte(fmt.Sprintf("%%%d", dat[idx]))
			out = append(out, val...)
		} else {
			out = append(out, dat[idx])
		}
	}
	out = append(out, []byte(suffix)...)
	return cryptutils.EncryptCBC(out, cryptutils.GlobalKey, cryptutils.GlobalIV)
}

func isAdmin(cipher []byte) (bool, error) {
	dat, err := cryptutils.DecryptCBC(cipher, cryptutils.GlobalKey, cryptutils.GlobalIV)
	if err != nil {
		return false, err
	}
	fmt.Println(string(dat))
	return bytes.Index(dat, []byte(";admin=true;")) >= 0, nil
}

func test() {
	x := bytes.Repeat([]byte("A"), 16)
	y := bytes.Repeat([]byte("B"), 16)
	z := append(x, y...)
	cipher, _ := cryptutils.EncryptCBC(z, cryptutils.GlobalKey, cryptutils.GlobalIV)
	cipher[0] ^= 1 << 2
	out, _ := cryptutils.DecryptCBC(cipher, cryptutils.GlobalKey, cryptutils.GlobalIV)
	fmt.Println(z)
	fmt.Println(out)
}


func setAdmin() {
	payload := []byte(";admin=true")
	// flipping one bit each in problematic bytes ; and =
	payload[0] ^= 1 << 0
	payload[6] ^= 1 << 0
	fmt.Println(string(payload))
	// assuming prefix length between 0 and 100
	for preLen := 1; preLen <= 100; preLen++ {
		padLen := (16 - (preLen % 16)) % 16
		preBlocks := (preLen + padLen)/16
		padding := bytes.Repeat([]byte("A"), padLen)
		finalPayload := append(padding, payload...)
		cipher, _ := encode(finalPayload)
		target := cipher[(preBlocks - 1) * 16: preBlocks * 16]
		target[0] ^= 1 << 0
		target[6] ^= 1 << 0
		done, _ := isAdmin(cipher)
		if done {
			fmt.Printf("Admin set. Prefix length was %d\n", preLen)
			break
		}
	}


}

func main() {
	cipher, _ := encode([]byte(";admin=true;"))
	fmt.Println(isAdmin(cipher))
	test()
	setAdmin()
}
