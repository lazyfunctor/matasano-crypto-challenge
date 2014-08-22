package cryptutils

import (
	"fmt"
	"crypto/aes"
	"errors"
	"math/big"
	"crypto/rand"
)


var charFreq = map[byte]float64 {
	byte("a"[0]): 0.08167,
	byte("A"[0]): 0.08167,
	byte("b"[0]): 0.01492,
	byte("B"[0]): 0.01492,
	byte("c"[0]): 0.02782,
	byte("C"[0]): 0.02782,
	byte("d"[0]): 0.04253,
	byte("D"[0]): 0.04253,
	byte("e"[0]): 0.12702,
	byte("E"[0]): 0.12702,
	byte("f"[0]): 0.02228,
	byte("F"[0]): 0.02228,
	byte("g"[0]): 0.02015,
	byte("G"[0]): 0.02015,
	byte("h"[0]): 0.06094,
	byte("H"[0]): 0.06094,
	byte("i"[0]): 0.06966,
	byte("I"[0]): 0.06966,
	byte("j"[0]): 0.00153,
	byte("J"[0]): 0.00153,
	byte("k"[0]): 0.00772,
	byte("K"[0]): 0.00772,
	byte("l"[0]): 0.04025,
	byte("L"[0]): 0.04025,
	byte("m"[0]): 0.02406,
	byte("M"[0]): 0.02406,
	byte("n"[0]): 0.06749,
	byte("N"[0]): 0.06749,
	byte("o"[0]): 0.07507,
	byte("O"[0]): 0.07507,
	byte("p"[0]): 0.01929,
	byte("P"[0]): 0.01929,
	byte("q"[0]): 0.00095,
	byte("Q"[0]): 0.00095,
	byte("r"[0]): 0.05987,
	byte("R"[0]): 0.05987,
	byte("s"[0]): 0.06327,
	byte("S"[0]): 0.06327,
	byte("t"[0]): 0.09056,
	byte("T"[0]): 0.09056,
	byte("u"[0]): 0.02758,
	byte("U"[0]): 0.02758,
	byte("v"[0]): 0.00978,
	byte("V"[0]): 0.00978,
	byte("w"[0]): 0.0236,
	byte("W"[0]): 0.0236,
	byte("x"[0]): 0.0015,
	byte("X"[0]): 0.0015,
	byte("y"[0]): 0.01974,
	byte("Y"[0]): 0.01974,
	byte("z"[0]): 0.00074,
	byte("Z"[0]): 0.00074,
	byte(","[0]): 0.0,
	byte("."[0]): 0.0,
	byte(" "[0]): 0.0,
	byte("'"[0]): 0.0,
}
const penalty = 0.127

func calcScore(val []byte) float64 {
	score := 0.0
	counter := make(map[byte]int)
	for _, v := range(val) {
		counter[v] += 1
	}
	
	for ch, freq := range(counter) {
		lf, exists := charFreq[ch]
		if exists {
			score += lf * (float64(freq)/float64(len(val)))
		} else {
			score -= penalty * (float64(freq)/float64(len(val)))
		}
	}
	return score
}

func attempt(inp []byte, key byte) (score float64, msg string) {
	n := len(inp)
	out := make([]byte, n)
	for i := range(inp) {
		out[i] = inp[i] ^ key
	}
	msg = string(out)
	score = calcScore(out)
	return
}

func DecryptMsg(cgram []byte) (byte, string, float64, error) {
	maxScore := -9999.0
	guessMsg := ""
	guessKey := byte(0)
	for k := 1; k < 257; k++ {
		score, msg := attempt(cgram, byte(k))
		//fmt.Println(score)
		if score > maxScore {
			guessMsg = msg
			guessKey = byte(k)
			maxScore = score
		}
	}
	return guessKey, guessMsg, maxScore, nil
}


func RepeatXOR(data []byte, key []byte) []byte {
	keyLength := len(key)
	out := make([]byte, len(data))
	for idx, val := range(data) {
		out[idx] = key[idx % keyLength] ^ val
	}
	return out
}


func PKCS7Padding(dat []byte, blockSize int) []byte {
	datSize := len(dat)
	paddingReqd := ((2 * blockSize) - (datSize % (2 * blockSize))) % 16
	newDat := make([]byte, datSize + paddingReqd)
	copy(newDat[:datSize], dat)
	for i := 0; i < paddingReqd; i++ {
		newDat[datSize + i] = byte(paddingReqd)
	}
	return newDat
}

func Unpad(dat []byte) []byte {
	datSize := len(dat)
	lastByte := int(dat[datSize-1])
	if (0 < lastByte) && (lastByte < 16) {
		valid := false
		for idx := 0; idx < lastByte; idx++ {
			iByte := int(dat[datSize - idx - 1])
			if iByte != lastByte {
				break
			}
			valid = true
		}
		if valid {
			return dat[: datSize - lastByte]
		}
	}
	return dat
}

func DecryptECB(cipher, key []byte) []byte {
	res := make([]byte, len(cipher))
	bs := aes.BlockSize
	inp := make([]byte, bs)
	out := make([]byte, bs)
	c, _ := aes.NewCipher(key)
	blockCount := 1
	size := len(cipher)
	for (blockCount * bs <= size) {
		copy(inp, cipher[(blockCount - 1) * bs: (blockCount * bs)])
		c.Decrypt(out, inp)
		copy(res[(blockCount - 1) * bs: (blockCount * bs)], out)
		blockCount += 1
	}
	return res
}

func EncryptECB(inDat, key []byte) []byte {
	dat := PKCS7Padding(inDat, aes.BlockSize/2)
	res := make([]byte, len(dat))
	bs := aes.BlockSize
	inp := make([]byte, bs)
	out := make([]byte, bs)
	c, _ := aes.NewCipher(key)
	blockCount := 1
	size := len(dat)
	for (blockCount * bs <= size) {
		copy(inp, dat[(blockCount - 1) * bs: (blockCount * bs)])
		c.Encrypt(out, inp)
		copy(res[(blockCount - 1) * bs: (blockCount * bs)], out)
		blockCount += 1
	}
	return res
}


func FixedXOR(b1, b2 []byte) []byte {
	b3 := make([]byte, len(b1))
	for i := range(b1) {
		b3[i] = b1[i] ^ b2[i]
	}
	return b3
}


func EncryptCBC(inDat, key, iv []byte) ([]byte, error) {
	dat := PKCS7Padding(inDat, aes.BlockSize/2)
	//fmt.Println("after padding", len(dat))
	if len(iv) != aes.BlockSize {
		return []byte {}, errors.New("Size of IV needs to be same as block size")
	}
	datSize := len(dat)
	bs := aes.BlockSize
	// paddingReqd := (2 * bs) - (datSize % (2 * bs))
	newDat := make([]byte, datSize)
	prevBlock := make([]byte, bs)
	curBlock := make([]byte, bs)
	size := len(dat)
	copy(prevBlock, iv)
	blockCount := 1
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return []byte {}, err
	}
	for blockCount * bs <= size {
		dataBlock := dat[(blockCount - 1) * bs : blockCount * bs]
		block := FixedXOR(prevBlock, dataBlock)
		cipher.Encrypt(curBlock, block)
		copy(newDat[(blockCount - 1) * bs : blockCount * bs], curBlock)
		copy(prevBlock, curBlock)
		blockCount += 1
	}
	return newDat, nil
}

func DecryptCBC(dat, key, iv []byte) ([]byte, error) {
	if len(iv) != aes.BlockSize {
		return []byte {}, errors.New("Size of IV needs to be same as block size")
	}
	datSize := len(dat)
	bs := aes.BlockSize
	newDat := make([]byte, datSize)
	prevEBlock := make([]byte, bs)
	curDBlock := make([]byte, bs)
	copy(prevEBlock, iv)
	blockCount := 1
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return []byte {}, err
	}
	for blockCount * bs <= datSize {
		dataBlock := dat[(blockCount - 1) * bs : blockCount * bs]
		cipher.Decrypt(curDBlock, dataBlock)
		block := FixedXOR(prevEBlock, curDBlock)
		copy(newDat[(blockCount - 1) * bs : blockCount * bs], block)
		copy(prevEBlock, dataBlock)
		blockCount += 1
	}
	return Unpad(newDat), nil
}


func GenerateRandomKey(keyLength int) ([]byte, error){
	b := make([]byte, keyLength)
	_, err := rand.Read(b)
	if err != nil {
		return []byte {}, err
	}
	return b, nil
}


func padInput(input []byte) ([]byte, error) {
	size := len(input)
	nilByte := []byte {}
	preR, err1 := rand.Int(rand.Reader, big.NewInt(6))
	if err1 != nil {
		return nilByte, err1
	}
	pre := int(preR.Int64()) + 5
	postR, err2 := rand.Int(rand.Reader, big.NewInt(6))
	if err2 != nil {
		return nilByte, err2
	}
	post := int(postR.Int64()) + 5
	prePad, err3 := GenerateRandomKey(pre)
	if err3 != nil {
		return nilByte, err3
	}
	postPad, err4 := GenerateRandomKey(post)
	if err4 != nil {
		return nilByte, err4
	}
	plainText := make([]byte, pre + post + size)
	copy(plainText[:pre], prePad)
	copy(plainText[pre: pre+size], input)
	copy(plainText[pre+size: ], postPad)
	return plainText, nil
}	

type Oracle struct {}

func (e Oracle) EncryptionOracle(input []byte) ([]byte, error) {
	nilByte := []byte {}
	key, keyErr := GenerateRandomKey(16)
	if keyErr != nil {
		return nilByte, keyErr
	}
	// pad input with 5-10 bytes on each side
	plainText, padErr := padInput(input)
	if padErr != nil {
		return nilByte, padErr
	}
	
	flip, errFlip := rand.Int(rand.Reader, big.NewInt(2))
	if padErr != nil {
		return nilByte, errFlip
	}
	if flip.Int64() == 0 {
		fmt.Println("using ECB")
		result := EncryptECB(plainText, key)
		return result, nil
	} else {
		iv, ivErr := GenerateRandomKey(16)
		if ivErr != nil {
			return nilByte, ivErr
		}
		fmt.Println("using CBC")
		return EncryptCBC(plainText, key, iv)
	}
}


type BlackBox interface {
	EncryptionOracle(input []byte) ([]byte, error)
}


func DetectionOracle(box BlackBox) (string, error) {
	testInput := make([]byte, 64)
	for i := range(testInput) {
		testInput[i] = byte(12)
	}
	cipher, err := box.EncryptionOracle(testInput)
	if err != nil {
		return "", err
	}

	size := len(cipher)
	counter := make(map[string]int)
	bs := aes.BlockSize
	bc := 1
	for bc*bs <= size {
		key := string(cipher[(bc-1)*bs: bc*bs])
		counter[key] += 1
		bc += 1
	}
	maxCount := 0
	for _, v := range(counter) {
		if v > maxCount {
			maxCount = v
		}
	}
	if maxCount >= 3 {
		return "ECB", nil
	} else {
		return "CBC", nil
	}
}
