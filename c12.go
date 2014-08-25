package main

import (
	"fmt"
	"./cryptutils"
)

func main() {
	//var oracle cryptutils.BlackBox
	oracle2 := cryptutils.Oracle2{}
	payload, _ := cryptutils.BreakECB(oracle2)
	fmt.Println(string(payload))
	fmt.Println(payload)

}
