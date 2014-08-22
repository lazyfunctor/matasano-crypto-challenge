package main

import (
	"fmt"
	"bufio"
	"encoding/hex"
	"io"
	"os"
	"log"
)


func ReadFile() error {
	f, err := os.Open("c8.txt")
	if err != nil {
		fmt.Println(err)
		return err
	}
	bf := bufio.NewReader(f)
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
		cipher, err := hex.DecodeString(string(line))
		if err != nil {
			return err
		}
		//fmt.Println("-----------------")
		analyze(cipher)
		//fmt.Println(len(cipher))
		//fmt.Println("-----------------")
	}
	return nil
}


func analyze(cipher []byte) {
	size := len(cipher)
	counter := make(map[string]int)
	bs := 16
	bc := 1
	for bc*bs <= size {
		key := string(cipher[(bc-1)*bs: bc*bs])
		counter[key] += 1
		bc += 1
	}
	for k, v := range(counter) {
		if v > 1 {
			fmt.Println(v)
			fmt.Println(cipher)
			fmt.Println([]byte(k))
		}
	}
}

func main() {
	ReadFile()
}
