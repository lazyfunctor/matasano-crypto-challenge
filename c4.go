package main

import (
 	"encoding/hex"
	"bufio"
	"io"
	"os"
	"log"
	"fmt"
	"./cryptutils"
)

func ReadFile() error {
	f, err := os.Open("1_4.txt")
	if err != nil {
		fmt.Println(err)
		return err
	}
	bf := bufio.NewReader(f)
	max := -99999999.0
	msg := ""
	key := byte(0)
	for {
		line, isPrefix, err := bf.ReadLine()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatal(err)
		}
		if isPrefix {
			log.Fatal("Error: Unexpected long line reading", f.Name())
		}
		//fmt.Println(string(line))
		cgram, err := hex.DecodeString(string(line))
		if err != nil {
			panic("hex decode failed")
		}
		k, m, s, _ := cryptutils.DecryptMsg(cgram)
		if s > max {
			msg = m
			max = s
			key = k
		}
	}
	fmt.Println(msg, max, key)
	return nil
}

func main() {
	//fmt.Println(DecryptMsg("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"))
	ReadFile()
}
