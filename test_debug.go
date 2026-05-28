package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"os"
)

func main() {
	// 读取之前的映射表文件
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run test_debug.go <path-to-encrypted-map>")
		return
	}
	mapPath := os.Args[1]
	if _, err := os.Stat(mapPath); os.IsNotExist(err) {
		fmt.Printf("File not found: %s\n", mapPath)
		return
	}

	data, err := os.ReadFile(mapPath)
	if err != nil {
		fmt.Printf("Read failed: %v\n", err)
		return
	}

	fmt.Printf("Encrypted data size: %d bytes\n", len(data))

	// 打印加密数据的前几个字节
	if len(data) > 64 {
		fmt.Printf("First 64 bytes: %x\n", data[:64])
	}

	// 检查是否至少有一个块大小
	if len(data) < aes.BlockSize {
		fmt.Println("Too small")
		return
	}

	fmt.Printf("IV: %x\n", data[:aes.BlockSize])
	fmt.Printf("Ciphertext size: %d bytes\n", len(data)-aes.BlockSize)
}
