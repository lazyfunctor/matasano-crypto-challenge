package main

import (
	"encoding/hex"
	"fmt"
)

func main() {
	x := []byte("abhinav")
	fmt.Println(x)
	y := make([]byte, hex.EncodedLen(len(x)))
	fmt.Println(hex.Encode(y, x))
	fmt.Println(y)
	fmt.Println([]byte("\xb4"))
}
