package main

import (
	"fmt"
	"./cryptutils"
)

func main() {
	s1 := "ICE ICE BABY\x04\x04\x04\x04"
	//s2 := "ICE ICE BABY\x05\x05\x05\x05"
	//s3 := "ICE ICE BABY\x01\x02\x03\x04"
	unpadded, err := cryptutils.Unpad([]byte(s1))
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(unpadded))
}
