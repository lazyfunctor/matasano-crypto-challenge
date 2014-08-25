package main

import "fmt"
import "encoding/hex"


func RepeatXOR(data []byte, key []byte) []byte {
	keyLength := len(key)
	out := make([]byte, len(data))
	for idx, val := range(data) {
		out[idx] = key[idx % keyLength] ^ val
	}
	return out
}


func main() {
	inp1 := "tets string"
	//fmt.Println(hex.EncodeToString(RepeatXOR([]byte(inp), []byte("ICE"))))
	fmt.Println(hex.EncodeToString(RepeatXOR([]byte(inp2), []byte("ICE"))))
  
}

