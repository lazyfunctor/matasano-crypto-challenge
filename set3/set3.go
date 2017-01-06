package set3

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/lazyfunctor/matasano-crypto-challenge/cryptutils"
)

var encKey []byte

func encrypt(ptext []byte) (ctext []byte, iv []byte, err error) {
	encKey, err = cryptutils.GenerateRandomKey(16)
	if err != nil {
		return
	}
	iv, err = cryptutils.GenerateRandomKey(16)
	if err != nil {
		return
	}
	ctext, err = cryptutils.EncryptCBC(ptext, encKey, iv)
	return
}

func oracle(ctext []byte, iv []byte) (valid bool) {
	_, err := cryptutils.DecryptCBC(ctext, encKey, iv)
	valid = (err == nil)
	return
}

func guessAdjBlocks(cipherText []byte, ivInit []byte, blockNum int) (block [16]byte, err error) {
	iv := make([]byte, 16)
	cBlock := make([]byte, 16)
	copy(cBlock, cipherText[(blockNum-1)*16:blockNum*16])
	if blockNum > 1 {
		ivInit = cipherText[(blockNum-2)*16 : (blockNum-1)*16]
	}
	for pos := 1; pos <= 16; pos++ {
		for b := 0; b <= 255; b++ {
			copy(iv, ivInit)
			iv[16-pos] = iv[16-pos] ^ byte(b) ^ byte(pos)
			for i := 1; i < pos; i++ {
				iv[16-i] = iv[16-i] ^ block[16-i] ^ byte(pos)
			}
			if valid := oracle(cBlock, iv); valid {
				block[16-pos] = byte(b)
			}
		}
	}
	return
}

func readCipherText() (cipherList [][]byte, minLen int) {
	var nonce = []byte{0, 0, 0, 0, 0, 0, 0, 0}
	key, _ := cryptutils.GenerateRandomKey(16)
	f, err := os.Open("c20.txt")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer f.Close()
	r := bufio.NewReader(f)
	line, _, err := r.ReadLine()
	pt, _ := base64.StdEncoding.DecodeString(string(line))
	ct, _ := cryptutils.EncryptCTR(pt, key, nonce)
	minLen = len(ct)
	for err == nil {
		cipherList = append(cipherList, ct)
		if len(ct) < minLen {
			minLen = len(ct)
		}
		fmt.Println(">>", string(ct))
		line, _, err = r.ReadLine()
		pt, _ = base64.StdEncoding.DecodeString(string(line))
		ct, _ = cryptutils.EncryptCTR(pt, key, nonce)
	}
	for idx := range cipherList {
		cipherList[idx] = cipherList[idx][:minLen]
	}
	return
}

func GuessKey(keySize int, dat []byte) []byte {
	blocks := make([][]byte, keySize)
	//fmt.Println(len(dat))
	for idx, byt := range dat {
		blocks[idx%keySize] = append(blocks[idx%keySize], byt)
	}

	guess := []byte{}
	for _, block := range blocks {
		key, _, _, _ := cryptutils.DecryptMsg(block)
		guess = append(guess, key)
	}
	return guess
}

type MersaineTwist struct {
	index int
	state [624]uint32
}

const F uint32 = 1812433253

func (mt *MersaineTwist) Initialize(seed uint32) {
	mt.index = 624
	mt.state[0] = seed
	for i := 1; i <= 623; i++ {
		mt.state[i] = F*(mt.state[i-1]^(mt.state[i-1]>>30)) + uint32(i)
		// val := int32(int64(1812433253) * (int64((mt.state[i-1])) ^ int64(mt.state[i-1])>>30 + int64(i)))
		// mt.state[i] = val
	}
}

func (mt *MersaineTwist) Extract() uint32 {
	var y uint32
	if mt.index >= 624 {
		mt.twist()
	}
	y = mt.state[mt.index]
	y = y ^ y>>11
	// Shift y left by 7 and take the bitwise and of 2636928640
	y = y ^ y<<7&2636928640
	// Shift y left by 15 and take the bitwise and of y and 4022730752
	y = y ^ y<<15&4022730752
	// Right shift by 18 bits
	y = y ^ y>>18
	mt.index++
	return y

}

func (mt *MersaineTwist) twist() {
	for i := 0; i <= 623; i++ {
		y := (mt.state[i] & 0x80000000) + (mt.state[(i+1)%624] & 0x7fffffff)
		mt.state[i] = mt.state[(i+397)%624] ^ y>>1
		if y%2 != 0 {
			mt.state[i] = mt.state[i] ^ 0x9908b0df
		}
	}
	mt.index = 0
	fmt.Println("Twist")
}
