package main

import "encoding/hex"
import "fmt"

func FixedXor(s1 string, s2 string) (string, error) {
	b1, err := hex.DecodeString(s1)
	if err != nil {
		return "", err
	}
	b2, err := hex.DecodeString(s2)
	if err != nil {
		return "", err
	}
	b3 := make([]byte, len(b1))
	for i := range(b1) {
		b3[i] = b1[i] ^ b2[i]
	}
	return hex.EncodeToString(b3), nil
}


func main() {
	fmt.Println(FixedXor("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965"))
}
