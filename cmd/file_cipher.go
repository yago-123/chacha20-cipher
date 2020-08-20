package main

import (
	chacha "github.com/yfernandezgou/chacha20-cipher/pkg"

	"fmt"
	"io"
	"log"
	"os"
	"time"
)

const READ_SIZE = 12800

func main() {
	key := make([]byte, 32)
	nonce := make([]byte, 8)

	if len(os.Args) == 2 {
		fmt.Println("Insert key (32 bytes): ")
		fmt.Scanln(&key)

		fmt.Println("Inset nonce (8 bytes): ")
		fmt.Scanln(&nonce)

		cipherFile(os.Args[1], key, nonce)
	} else {
		log.Fatal("not enough arguments")
	}
}

func cipherFile(fileName string, key, nonce []byte) {
	inputFile, err := os.Open(fileName)
	if err != nil {
		log.Fatal(err)
	}
	defer inputFile.Close()

	outputFile, err := os.Create(fileName + ".chacha")
	if err != nil {
		log.Fatal(err)
	}
	defer outputFile.Close()

	plainText := make([]byte, READ_SIZE)
	cipherText := make([]byte, READ_SIZE)
	streamBlock := make([]uint32, 16)

	block_t := chacha.Block_t{}
	chacha.InitBlock(&block_t, key, nonce)

	start := time.Now()
	for {
		n, err := inputFile.Read(plainText)

		if n > 0 {
			chacha.Chacha20_encrypt(plainText, cipherText, streamBlock, &block_t)
			outputFile.Write(cipherText[0:n])
		}

		if err == io.EOF {
			break
		}

		if err != nil {
			log.Fatal("read %d bytes: %v", n, err)
		}

	}
	end := time.Now()

	fileStat, err := inputFile.Stat()
	if err != nil {
		log.Fatal(err)
	} else {
		fileLength := float64(fileStat.Size()) / (1024.0 * 1024.0)
		totalTime := float64(end.Sub(start)) / float64(time.Second)

		fmt.Printf("Time taken %0.2f seconds, file length %0.2f MB\n", totalTime, fileLength)
		fmt.Printf("Average time %0.2f MB/s \n", fileLength/totalTime)
	}
}
