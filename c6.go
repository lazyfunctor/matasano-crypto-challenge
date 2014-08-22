package main

import (
	"fmt"
	"io/ioutil"
	"encoding/base64"
	"./cryptutils"
)

// naive way to count set bits. improve this
func popCountNaive(b byte) int {
	mask := byte(1)
	cnt := 0
	for i := 0; i <= 7; i++ {
		//fmt.Println(b & (mask << uint8(i)))
		if (b & (mask << byte(i))) > 0 {
			cnt += 1
		}
	}
	return cnt
}

func CalcHamming(b1 []byte, b2 []byte) int {
	hamming := 0
	for i := 0; i < len(b1); i++ {
		b := b1[i] ^ b2[i]
		hamming += popCountNaive(b)
	}
	return hamming
}
	

func GuessKeySize(dat []byte) int {
	minimumDist := 99999999.0
	guessedSize := 0
	for ks := 2; ks <= 40; ks++ {
		firstBlock := dat[:ks]
		secondBlock := dat[ks:2*ks]
		thirdBlock := dat[2*ks:3*ks]
		fourthBlock := dat[3*ks:4*ks]
		editDist1 := float64(CalcHamming(firstBlock, secondBlock))/float64(ks)
		editDist2 := float64(CalcHamming(secondBlock, thirdBlock))/float64(ks)
		editDist3 := float64(CalcHamming(thirdBlock, fourthBlock))/float64(ks)
		editDist4 := float64(CalcHamming(firstBlock, thirdBlock))/float64(ks)
		editDist5 := float64(CalcHamming(firstBlock, fourthBlock))/float64(ks)
		editDist6 := float64(CalcHamming(secondBlock, fourthBlock))/float64(ks)
		meanDist := (editDist1 + editDist2 + editDist3 + editDist4 + editDist5 + editDist6)/6.0
		if meanDist < minimumDist {
			minimumDist = meanDist
			guessedSize = ks
		}
	}
	return guessedSize
}

func GuessKey(keySize int, dat []byte) []byte {
	blocks := make([][]byte, keySize)
	//fmt.Println(len(dat))
	for idx, byt := range(dat) {
		blocks[idx % keySize] = append(blocks[idx % keySize], byt)
	}

	guess := []byte {}
	for _, block := range(blocks) {
		key, _, _, _ := cryptutils.DecryptMsg(block)
		guess = append(guess, key)
	}
	return guess
}

func main() {
	s1 := []byte("this is a test")
	s2 := []byte("wokka wokka!!!")
	fmt.Println("Hamming", CalcHamming(s1, s2))
	rawDat, err := ioutil.ReadFile("c6.txt")
	if err != nil  {
		panic("problem in reading file")
	}
	dat, decErr := base64.StdEncoding.DecodeString(string(rawDat))
	//fmt.Println(string(dat))
	if decErr != nil  {
		panic("problem in reading file")
	}
	keySize := GuessKeySize(dat)
	key := GuessKey(keySize, dat)
	fmt.Println("Key=>", string(key))
	fmt.Println(string(cryptutils.RepeatXOR(dat, key)))
}
