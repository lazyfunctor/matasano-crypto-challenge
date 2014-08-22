package main

import "encoding/hex"
import "encoding/base64"
import "fmt"

func HexToBase(src string) string {
	b, err := hex.DecodeString(src)
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(b)
}

func main() {
	fmt.Println(HexToBase("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"))
}
