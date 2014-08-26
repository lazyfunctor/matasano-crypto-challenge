package main

import "fmt"
import "./cryptutils"

// test commit	
func main() {
	fmt.Println(cryptutils.PKCS7Padding([]byte("YELLOW SUBMARINE"), 10))
}
