package main

import (
	"encoding/hex"
	"fmt"
	"./cryptutils"
)

func main() {
	txt := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	cgram, err := hex.DecodeString(txt)
	if err != nil {
		panic("hex decode problem")
	}
	fmt.Println(cryptutils.DecryptMsg(cgram))
}
