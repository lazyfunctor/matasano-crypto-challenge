package main

import (
	"fmt"
	"./cryptutils"
)

func main() {
	oracle3 := cryptutils.Oracle3{}
	//fmt.Println(oracle3.EncryptionOracle([]byte("test again")))
	pl, _ := cryptutils.BreakECBHarder(oracle3)
	fmt.Println(string(pl))
}
