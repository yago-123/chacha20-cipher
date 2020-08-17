package chacha

import (
	"encoding/binary"
	"log"
)

const (
	NUMBER_ROUNDS = 20

	CHACHA_BLOCK_LEN = 16

	CHACHA_CONST_LEN   = 4
	CHACHA_KEY_LEN     = 8
	CHACHA_COUNTER_LEN = 2
	CHACHA_NONCE_LEN   = 2

	MAX_UINT32 = 4294967295
)

type Block_t struct {
	chachaConst   [CHACHA_CONST_LEN]uint32
	chachaKey     [CHACHA_KEY_LEN]uint32
	chachaCounter [CHACHA_COUNTER_LEN]uint32
	chachaNonce   [CHACHA_NONCE_LEN]uint32
}

func XOR(u, v uint32) uint32 {
	return u ^ v
}

func rotation(x, n uint32) uint32 {
	return (((x) << (n)) | ((x) >> (32 - (n))))
}

func quarterround(a, b, c, d uint32, input []uint32) {
	input[a] += input[b]
	input[d] = XOR(d, a)
	input[d] = rotation(d, 16)

	input[c] += input[d]
	input[b] = XOR(b, c)
	input[b] = rotation(b, 12)

	input[a] += input[b]
	input[d] = XOR(d, a)
	input[d] = rotation(d, 8)

	input[c] += input[d]
	input[b] = XOR(b, c)
	input[b] = rotation(b, 7)
}

func chacha20_block(input []uint32) {
	tmp := [CHACHA_BLOCK_LEN]uint32{}

	for i := 0; i < CHACHA_BLOCK_LEN; i++ {
		tmp[i] = input[i]
	}

	for i := 0; i < NUMBER_ROUNDS/2; i++ {
		/* Column */
		quarterround(0, 4, 8, 12, input)
		quarterround(1, 5, 9, 13, input)
		quarterround(2, 6, 10, 14, input)
		quarterround(3, 7, 11, 15, input)

		/* Diagonal */
		quarterround(0, 5, 10, 15, input)
		quarterround(1, 6, 11, 12, input)
		quarterround(2, 7, 8, 13, input)
		quarterround(3, 4, 9, 14, input)
	}

	for i := 0; i < CHACHA_BLOCK_LEN; i++ {
		input[i] += tmp[i]
	}
}

func incrementCounter(block_t *Block_t) {
	for i := 0; i < CHACHA_COUNTER_LEN; i++ {
		if block_t.chachaCounter[i] < MAX_UINT32 {
			block_t.chachaCounter[i]++
			return
		} else {
			if (i + 1) == CHACHA_COUNTER_LEN {
				log.Fatal("Too much data")
			}
		}
	}
}

func buildStreamBlock(streamBlock []uint32, block_t Block_t) {
	i := 0

	for j := 0; j < CHACHA_CONST_LEN; j, i = j+1, i+1 {
		streamBlock[i] = block_t.chachaConst[j]
	}

	for j := 0; j < CHACHA_KEY_LEN; j, i = j+1, i+1 {
		streamBlock[i] = block_t.chachaKey[j]
	}

	for j := 0; j < CHACHA_COUNTER_LEN; j, i = j+1, i+1 {
		streamBlock[i] = block_t.chachaCounter[j]
	}

	for j := 0; j < CHACHA_NONCE_LEN; j, i = j+1, i+1 {
		streamBlock[i] = block_t.chachaNonce[j]
	}
}

func restoreData(data []byte) {
	for i := 0; i < len(data); i++ {
		data[i] = 0
	}
}

func InitBlock(block_t *Block_t, key, nonce []byte) {
	block_t.chachaConst = [4]uint32{
		1634760805,
		857760878,
		2036477234,
		1797285236,
	}

	for i := 0; i < len(key); i += 4 {
		bts := key[i : i+4]
		block_t.chachaKey[i/4] = binary.LittleEndian.Uint32(bts)
	}

	for i := 0; i < len(nonce); i += 4 {
		bts := nonce[i : i+4]
		block_t.chachaNonce[i/4] = binary.LittleEndian.Uint32(bts)
	}
}

func Chacha20_encrypt(plainText, cipherText []byte, streamBlock []uint32, block_t *Block_t) {
	bufPlain := make([]uint32, 16)
	bufCipher := make([]uint32, 16)

	i := len(plainText) / 64
	for j := 0; j < i; j++ {
		fromBytesToUint(plainText[j*64:(j+1)*64], bufPlain)
		buildStreamBlock(streamBlock, *block_t)

		chacha20_block(streamBlock)

		for k := 0; k < 16; k++ {
			bufCipher[k] = XOR(bufPlain[k], streamBlock[k])
		}

		incrementCounter(block_t)
		fromUintToBytes(bufCipher, cipherText[j*64:(j+1)*64])
	}

	k := len(plainText) % 64
	if k != 0 {
		bufPlainBytes := make([]byte, 64)

		for j := 0; j < k; j++ {
			bufPlainBytes[j] = plainText[i*64+j]
		}

		Chacha20_encrypt(bufPlainBytes, cipherText[i*64:(i+1)*64], streamBlock, block_t)
	}

}

func fromBytesToUint(plainText []byte, bufPlain []uint32) {
	for i := 1; i-1 < cap(bufPlain); i++ {
		bufPlain[i-1] = binary.LittleEndian.Uint32(plainText[(i-1)*4 : 4*i])
	}
}

func fromUintToBytes(bufPlain []uint32, plainText []byte) {
	for i := 1; i-1 < cap(bufPlain); i++ {
		binary.LittleEndian.PutUint32(plainText[(i-1)*4:4*i], bufPlain[i-1])
	}
}
