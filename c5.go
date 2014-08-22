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
	// inp := "Burning 'em, if you ain't quick and nimble\n" +
	// 	"I go crazy when I hear a cymbal"
	/*
	inp := `Hi Shyam,

How are you doing? Are you planning to go for kayaking this weekend?

Regards,
Abhinav`
*/
	inp := `Hi Abinav

No I am not since I have guests at home.

How was your Bhutan trip ?
`
	inp2 := `Hi Abhinav!

So nice to connect with you on LinkedIn. :) Hope you do remember me! :)`
	fmt.Println(hex.EncodeToString(RepeatXOR([]byte(inp), []byte("ICE"))))
	fmt.Println(hex.EncodeToString(RepeatXOR([]byte(inp2), []byte("ICE"))))
  
}

