package main

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"time"
)

const (
	numFiles     = 100
	testDir       = "test_data"
)

func main() {
	// 创建测试目录
	if err := os.MkdirAll(testDir, 0755); err != nil {
		fmt.Printf("❌ 创建测试目录失败: %v\n", err)
		os.Exit(1)
	}

	rand.Seed(time.Now().UnixNano())

	// 创建不同类型的子目录
	subDirs := []string{"docs", "images", "data", "code", "logs"}
	for _, dir := range subDirs {
		subDirPath := filepath.Join(testDir, dir)
		if err := os.MkdirAll(subDirPath, 0755); err != nil {
			fmt.Printf("⚠️  创建子目录 %s 失败: %v\n", dir, err)
			continue
		}
	}

	fmt.Printf("✅ 开始生成 %d 个测试文件...\n\n", numFiles)

	// 生成100个测试文件
	for i := 0; i < numFiles; i++ {
		// 随机选择目录
		dirIndex := rand.Intn(len(subDirs) + 1) // +1 为了根目录也有文件
		var filePath string
		if dirIndex < len(subDirs) {
			filePath = filepath.Join(testDir, subDirs[dirIndex])
		} else {
			filePath = testDir
		}

		// 随机选择文件类型
		fileTypes := []string{".txt", ".md", ".json", ".csv", ".bin", ".log"}
		fileName := fmt.Sprintf("test_file_%03d%s", i, fileTypes[rand.Intn(len(fileTypes))])
		fullPath := filepath.Join(filePath, fileName)

		// 生成随机内容
		contentSize := rand.Intn(4096) + 1024 // 1KB-5KB
		content := generateRandomContent(contentSize)

		// 写入文件
		if err := os.WriteFile(fullPath, content, 0644); err != nil {
			fmt.Printf("⚠️  创建文件 %s 失败: %v\n", fullPath, err)
			continue
		}

		if (i+1)%20 == 0 {
			fmt.Printf("✅ 已生成 %d/%d 个文件\n", i+1, numFiles)
		}
	}

	fmt.Printf("\n✅ 测试文件生成完成！共 %d 个文件在 %s 目录\n", numFiles, testDir)
}

func generateRandomContent(size int) []byte {
	charset := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?\n\t\r"
	result := make([]byte, size)
	for i := 0; i < size; i++ {
		result[i] = charset[rand.Intn(len(charset))]
	}
	return result
}
