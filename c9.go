package main

import "fmt"
import "./cryptutils"

func main() {
	padded := cryptutils.PKCS7Padding([]byte("YELLOW SUBMARINE"), 16)
	unpadded, _ := cryptutils.Unpad(padded)
	fmt.Println(unpadded)
}
