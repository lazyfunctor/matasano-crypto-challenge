package main

import "fmt"
import "./cryptutils"

func main() {
	fmt.Println(cryptutils.PKCS7Padding([]byte("YELLOW SUBMARINE"), 10))
}
