package set3

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"
	"testing"

	"github.com/lazyfunctor/matasano-crypto-challenge/cryptutils"
)

func TestCBCPaddingOracle(t *testing.T) {

	plainText := [10]string{
		"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
		"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
		"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
		"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
		"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
		"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
		"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
		"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
		"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
		"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
	}
	count, err := rand.Int(rand.Reader, big.NewInt(10))
	if err != nil {
		return
	}
	ptext := plainText[int(count.Int64())]
	ctext, iv, err := encrypt([]byte(ptext))
	if err != nil {
		panic(err)
	}
	fmt.Println(ctext)
	blockLen := len(ctext) / 16
	fmt.Println(blockLen)
	var result []byte
	for i := 1; i <= blockLen; i++ {
		val, _ := guessAdjBlocks(ctext, iv, i)
		result = append(result, val[:]...)
	}
	final, _ := cryptutils.Unpad(result)
	fmt.Println(string(final))
	if string(final) != ptext {
		t.Error("CBC padding test failed")
	}

}

func TestCTR(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")
	nonce := []byte{0, 0, 0, 0, 0, 0, 0, 0}
	cipher, _ := base64.StdEncoding.DecodeString("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
	plain, _ := cryptutils.DecryptCTR(cipher, key, nonce)
	expectedPlain := "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby "
	if string(plain) != expectedPlain {
		t.Error("CTR test failed")
	}

	pt := []byte("test run - random text!!!")
	ct, _ := cryptutils.EncryptCTR(pt, key, nonce)
	val, _ := cryptutils.DecryptCTR(ct, key, nonce)
	fmt.Println(string(val))
}

func TestBreakCTR(t *testing.T) {
	cipherList, smallest := readCipherText()
	var cipher []byte
	for _, item := range cipherList {
		cipher = append(cipher, item...)
	}
	fmt.Println(cipher)
	key := GuessKey(smallest, cipher)
	fmt.Println("Key=>", key)
	fmt.Println(string(cryptutils.RepeatXOR(cipher, key)))
}

func TestMT(t *testing.T) {
	mt := &MersaineTwist{}
	seed := uint32(900)
	mt.Initialize(seed)
	if mt.Extract() != 1860586390 {
		t.Error("PRNG test failed for MT19937")
	}
	if mt.Extract() != 3915136241 {
		t.Error("PRNG test failed for MT19937")
	}
	if mt.Extract() != 1319963422 {
		t.Error("PRNG test failed for MT19937")
	}
	if mt.Extract() != 398731448 {
		t.Error("PRNG test failed for MT19937")
	}
}
