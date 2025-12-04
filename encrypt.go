package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/crypto/blowfish"
	"golang.org/x/crypto/pbkdf2"
	"gopkg.in/yaml.v2"
)

// 配置文件名称（只支持YAML）
const (
	CONFIG_FILENAME_YAML = "encrypt_config.yaml"
)

// 加密类型常量
const (
	EncryptTypeAES     = "aes"
	EncryptTypeBlowfish = "blowfish"
	EncryptTypeXOR     = "xor"
	// 密钥派生参数
	KeyDerivationIterations = 100000 // PBKDF2迭代次数
	AESKeySize              = 32     // AES-256密钥大小
	BlowfishKeySize         = 56     // Blowfish最大密钥大小
	XORKeySize              = 32     // XOR密钥大小
	SaltSize                = 16     // 盐值大小
)

// deriveKey 使用PBKDF2从密码派生密钥
func deriveKey(password string, salt []byte, keySize int) []byte {
	return pbkdf2.Key([]byte(password), salt, KeyDerivationIterations, keySize, sha256.New)
}

// 动态配置结构体（支持JSON和YAML）
type DynamicConfig struct {
	Password            string   `json:"password" yaml:"password"`
	EncryptType         string   `json:"encrypt_type" yaml:"encrypt_type"`
	TargetPaths         []string `json:"target_paths" yaml:"target_paths"`
	ObfuscateSuffix     string   `json:"obfuscate_suffix" yaml:"obfuscate_suffix"`
	ObfuscateNameLength int      `json:"obfuscate_name_length" yaml:"obfuscate_name_length"`
	MapFilename         string   `json:"map_filename" yaml:"map_filename"`
	LockFilename        string   `json:"lock_filename" yaml:"lock_filename"`
	MapStoragePath      string   `json:"map_storage_path" yaml:"map_storage_path"`
	Salt                string   `json:"salt,omitempty" yaml:"salt,omitempty"` // 可选的盐值字段
}

// 文件映射结构（保留原逻辑）
type FileMapItem struct {
	Path       string `json:"path"`
	Md5        string `json:"md5"`
	TargetDir  string `json:"target_dir"`
}

type DirMapItem struct {
	OriginalPath string `json:"original_path"`
	TargetDir    string `json:"target_dir"`
}

// 全局统计变量（保留原逻辑）
type StatData struct {
	TotalScanned        int
	TotalDuplicateDel   int
	TotalFilesEncrypted int
	TotalDirsObfuscated int
}



// 操作模式常量
const (
	ModeEncrypt = "encrypt"
	ModeDecrypt = "decrypt"
)

func main() {
	// 不再设置Go缓存环境变量，避免产生不必要的空目录
	// 只有在真正需要时才设置这些环境变量

	// 解析命令行参数
	help := flag.Bool("help", false, "显示帮助信息")
	h := flag.Bool("h", false, "显示帮助信息")
	encryptMode := flag.Bool("encrypt", false, "加密模式")
	decryptMode := flag.Bool("decrypt", false, "解密模式")
	flag.Parse()

	// 检查是否需要显示帮助信息
	if *help || *h {
		ShowHelp()
	}

	// 检查命令行参数
	if !*encryptMode && !*decryptMode {
		fmt.Println("❌ 请指定操作模式：-encrypt 或 -decrypt")
		os.Exit(1)
	}

	// 获取程序所在目录（读取同目录配置文件）
	exePath, err := os.Executable()
	if err != nil {
		fmt.Printf("❌ 获取程序路径失败：%v\n", err)
		os.Exit(1)
	}
	exeDir := filepath.Dir(exePath)
	
	// 只使用YAML配置文件
	configPath := filepath.Join(exeDir, CONFIG_FILENAME_YAML)
	
	// 读取动态配置文件
	config, err := loadDynamicConfig(configPath)
	if err != nil {
		fmt.Printf("❌ 读取配置文件失败：%v\n", err)
		os.Exit(1)
	}
	
	// 根据命令行参数确定操作模式
	mode := ModeEncrypt
	if *encryptMode {
		mode = ModeEncrypt
		fmt.Println("🔒 启动加密模式")
	} else if *decryptMode {
		mode = ModeDecrypt
		fmt.Println("🔓 启动解密模式")
	}
	
	// 校验配置合法性
	if err := validateConfig(config); err != nil {
		fmt.Printf("❌ 配置非法：%v\n", err)
		os.Exit(1)
	}

	// 过滤有效路径（保留原逻辑）
	var validPaths []string
	for _, path := range config.TargetPaths {
		if strings.TrimSpace(path) != "" {
			validPaths = append(validPaths, path)
		}
	}
	if len(validPaths) == 0 {
		fmt.Println("❌ 配置中无有效目标路径")
		os.Exit(1)
	}

	// 生成对应算法密钥（保留原逻辑）
	key, err := generateEncryptKey(config.Password, config.EncryptType, config.Salt)
	if err != nil {
		fmt.Printf("❌ 生成加密密钥失败：%v\n", err)
		os.Exit(1)
	}

	// 初始化统计数据（保留原逻辑）
	stat := &StatData{}

	// 初始化全局映射表
	globalFileMap := make(map[string]*FileMapItem)
	globalDirMap := make(map[string]*DirMapItem)

	// 如果是解密模式，需要加载映射表
	// 如果是加密模式，也需要加载映射表以进行去重
	if mode == ModeDecrypt {
		fmt.Printf("🔐 解密模式：正在加载映射表...\n")
		// 更新密钥为从映射表中提取的密钥
		key = loadGlobalMap(key, config, &globalFileMap, &globalDirMap)
		fmt.Printf("📄 加载文件映射: %d 项\n", len(globalFileMap))
		fmt.Printf("📁 加载目录映射: %d 项\n", len(globalDirMap))
	} else if mode == ModeEncrypt {
		fmt.Printf("🔐 加密模式：正在加载映射表...\n")
		// 更新密钥为从映射表中提取的密钥
		key = loadGlobalMap(key, config, &globalFileMap, &globalDirMap)
		fmt.Printf("📄 加载文件映射: %d 项\n", len(globalFileMap))
		fmt.Printf("📁 加载目录映射: %d 项\n", len(globalDirMap))
	}

	// 根据操作模式执行不同操作
	if mode == ModeEncrypt {
		// 统计待处理项总数（保留原逻辑）
		var totalFilesAll, totalDirsAll int
		for _, path := range validPaths {
			if isDir(path) {
				fCount, dCount := countActualItems(path, config)
				totalFilesAll += fCount
				totalDirsAll += dCount
			}
		}
		stat.TotalScanned = totalFilesAll + totalDirsAll

		// 处理每个目标目录（保留原逻辑）
		for _, path := range validPaths {
			processTargetDir(path, key, config, globalFileMap, globalDirMap, stat)
		}

		// 保存全局映射表（保留原逻辑）
		saveGlobalMap(key, config, globalFileMap, globalDirMap)

		// 输出统计信息（修改为更详细的格式）
		fmt.Printf("==================== 加密完成 ====================\n")
		fmt.Printf("已加密文件：%d\n", stat.TotalFilesEncrypted)
		fmt.Printf("已混淆目录：%d\n", stat.TotalDirsObfuscated)
		fmt.Printf("已删除重复文件：%d\n", stat.TotalDuplicateDel)
		fmt.Printf("================================================\n")
	} else {
		// 解密模式
		// 加载映射表（如果前面没有加载）
		if len(globalFileMap) == 0 && len(globalDirMap) == 0 {
			fmt.Printf("🔐 解密模式：正在加载映射表...\n")
			// 更新密钥为从映射表中提取的密钥
			key = loadGlobalMap(key, config, &globalFileMap, &globalDirMap)
			fmt.Printf("📄 加载文件映射: %d 项\n", len(globalFileMap))
			fmt.Printf("📁 加载目录映射: %d 项\n", len(globalDirMap))
		}
		
		for _, path := range validPaths {
			decryptTargetDir(path, key, config, globalFileMap, globalDirMap, stat)
		}

		// 解密完成后，删除映射表文件
		mapPath := filepath.Join(config.MapStoragePath, config.MapFilename)
		if isFile(mapPath) {
			if err := os.Remove(mapPath); err != nil {
				fmt.Printf("⚠️  删除映射表文件失败: %v\n", err)
			} else {
				fmt.Printf("✅ 映射表文件已删除: %s\n", mapPath)
			}
		} else {
			fmt.Printf("ℹ️  映射表文件不存在: %s\n", mapPath)
		}

		// 输出解密统计信息
		fmt.Printf("==================== 解密完成 ====================\n")
		fmt.Printf("已解密文件：%d\n", stat.TotalFilesEncrypted) // 复用统计字段
		fmt.Printf("已恢复目录：%d\n", stat.TotalDirsObfuscated)  // 复用统计字段
		fmt.Printf("================================================\n")
	}
}

// loadDynamicConfig 加载动态配置（只支持YAML）
func loadDynamicConfig(configPath string) (*DynamicConfig, error) {
	log.Printf("使用YAML配置文件: %s\n", configPath)

	if !isFile(configPath) {
		// 生成YAML格式的配置文件
		defaultConfig := &DynamicConfig{
			Password:            "请修改为你的加密密码",
			EncryptType:         EncryptTypeAES,
			TargetPaths:         []string{},
			ObfuscateSuffix:     ".dat",
			ObfuscateNameLength: 12,
			MapFilename:         ".app_encrypt",
			LockFilename:        ".encrypt.lock",
			MapStoragePath:      filepath.Join(filepath.Dir(configPath), "tmp"),
		}
		
		// 创建默认配置目录
		configDir := filepath.Dir(configPath)
		if err := os.MkdirAll(configDir, 0755); err != nil {
			return nil, fmt.Errorf("创建配置目录失败: %v", err)
		}
		
		// 写入默认配置文件
		file, err := os.Create(configPath)
		if err != nil {
			return nil, fmt.Errorf("创建配置文件失败: %v", err)
		}
		defer file.Close()
		
		encoder := yaml.NewEncoder(file)
		defer encoder.Close()
		if err := encoder.Encode(defaultConfig); err != nil {
			return nil, fmt.Errorf("写入YAML配置失败: %v", err)
		}
		
		fmt.Printf("ℹ️  配置文件不存在，已创建默认配置文件: %s\n", configPath)
		fmt.Printf("⚠️  请编辑配置文件并修改密码等参数后重新运行程序\n")
		os.Exit(0)
	}

	// 读取配置文件
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败: %v", err)
	}

	// 解析配置文件（只支持YAML）
	config := &DynamicConfig{}
	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("解析YAML配置失败: %v", err)
	}

	return config, nil
}

// validateConfig 校验配置合法性（保留原逻辑）
func validateConfig(config *DynamicConfig) error {
	if strings.TrimSpace(config.Password) == "" {
		return fmt.Errorf("密码不能为空")
	}
	if len(config.Password) < 8 {
		fmt.Printf("⚠️  密码长度建议至少8位，当前长度: %d\n", len(config.Password))
	}
	
	// 校验加密算法
	switch config.EncryptType {


	case EncryptTypeAES, EncryptTypeBlowfish, EncryptTypeXOR:
		// 合法值
	default:
		return fmt.Errorf("不支持的加密算法: %s", config.EncryptType)
	}
	
	// 校验目标路径
	if len(config.TargetPaths) == 0 {
		return fmt.Errorf("目标路径列表不能为空")
	}
	
	// 校验映射文件名
	if strings.TrimSpace(config.MapFilename) == "" {
		return fmt.Errorf("映射文件名不能为空")
	}
	
	// 校验锁文件名
	if strings.TrimSpace(config.LockFilename) == "" {
		return fmt.Errorf("锁文件名不能为空")
	}
	
	// 校验映射文件存储路径
	if strings.TrimSpace(config.MapStoragePath) == "" {
		return fmt.Errorf("映射文件存储路径不能为空")
	}
	
	// 校验混淆文件名后缀
	if strings.TrimSpace(config.ObfuscateSuffix) == "" {
		config.ObfuscateSuffix = ".dat" // 默认值
	}
	
	// 校验混淆文件名长度
	if config.ObfuscateNameLength <= 0 {
		config.ObfuscateNameLength = 12 // 默认值
	}
	
	return nil
}

// generateEncryptKey 生成加密密钥（保留原逻辑）
func generateEncryptKey(password, encryptType, saltStr string) ([]byte, error) {
	var keySize int
	switch encryptType {
	case EncryptTypeAES:
		keySize = AESKeySize
	case EncryptTypeBlowfish:
		keySize = BlowfishKeySize
	case EncryptTypeXOR:
		keySize = XORKeySize
	default:


		return nil, fmt.Errorf("不支持的加密算法: %s", encryptType)
	}

	// 处理盐值
	var salt []byte
	var err error
	
	if saltStr != "" {
		// 如果配置文件中指定了盐值，使用该盐值
		salt, err = base64.StdEncoding.DecodeString(saltStr)
		if err != nil {
			return nil, fmt.Errorf("解码盐值失败: %v", err)
		}
		if len(salt) != SaltSize {
			return nil, fmt.Errorf("盐值长度错误，期望%d字节，实际%d字节", SaltSize, len(salt))
		}
		fmt.Println("🔑 使用配置文件中指定的盐值")
	} else {
		// 如果配置文件中没有指定盐值，生成固定的默认盐值
		salt = make([]byte, SaltSize)
		for i := range salt {
			salt[i] = byte(i) // 使用简单的固定模式
		}
		fmt.Println("🔑 使用默认固定盐值")
	}
	
	// 使用PBKDF2派生密钥
	key := deriveKey(password, salt, keySize)
	
	// 将盐值附加到密钥前面（用于解密时提取）
	fullKey := make([]byte, SaltSize+len(key))
	copy(fullKey[:SaltSize], salt)
	copy(fullKey[SaltSize:], key)
	
	return fullKey, nil
}

// countActualItems 统计实际待处理项（保留原逻辑）
func countActualItems(path string, config *DynamicConfig) (files, dirs int) {
	_ = filepath.Walk(path, func(root string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			// 跳过隐藏目录和特殊目录
			dirName := info.Name()
			if strings.HasPrefix(dirName, ".") || dirName == config.MapFilename || dirName == config.LockFilename {
				return filepath.SkipDir
			}
			dirs++
			return nil
		}
		
		// 跳过特殊文件
		filename := info.Name()
		if filename == config.MapFilename || filename == config.LockFilename {
			return nil
		}
		
		files++
		return nil
	})
	return files, dirs
}

// processTargetDir 处理单个目录（修改为新的加密逻辑）
func processTargetDir(targetDir string, key []byte, config *DynamicConfig, fileMap map[string]*FileMapItem, dirMap map[string]*DirMapItem, stat *StatData) {
	fmt.Printf("🔍 processTargetDir: 目标目录: %s\n", targetDir)
	fmt.Printf("📊 processTargetDir: 传入的文件映射数量: %d\n", len(fileMap))
	fmt.Printf("📊 processTargetDir: 传入的目录映射数量: %d\n", len(dirMap))
	
	// 预处理与安全校验
	if !isDir(targetDir) {
		fmt.Printf("⚠️  目录不存在，跳过：%s\n", targetDir)
		return
	}

	// 检查目录是否为空
	isEmpty, err := isDirEmpty(targetDir, config)
	if err != nil {
		fmt.Printf("⚠️  检查目录是否为空失败：%s, 错误: %v\n", targetDir, err)
		return
	}
	if isEmpty {
		fmt.Printf("⚠️  目录为空，跳过：%s\n", targetDir)
		return
	}

	// 创建运行锁
	lockPath := filepath.Join(targetDir, config.LockFilename)
	if isFile(lockPath) {
		fmt.Printf("❌ 发现运行锁 %s，请确认无其他进程后手动删除。\n", config.LockFilename)
		return
	}

	err = createLockFile(lockPath)
	if err != nil {
		fmt.Printf("❌ 创建运行锁失败：%v\n", err)
		return
	}

	// 使用 defer 确保运行锁会被清理
	defer func() {
		if isFile(lockPath) {
			_ = os.Remove(lockPath)
		}
	}()

	// 先混淆目录（从子目录到父目录），再加密文件
	obfuscateDirsBottomUp(targetDir, config, dirMap, stat)
	encryptFiles(targetDir, key, config, fileMap, stat)
}

// createLockFile 创建运行锁（保留原逻辑）
func createLockFile(lockPath string) error {
	f, err := os.Create(lockPath)
	if err != nil {
		return err
	}
	defer f.Close()

	pid := os.Getpid()
	now := time.Now().Format("2006-01-02 15:04:05")
	content := fmt.Sprintf("PID: %d\nTime: %s\n", pid, now)
	_, err = f.WriteString(content)
	if err != nil {
		return err
	}
	return nil
}

// obfuscateDirsBottomUp 递归混淆目录（修改为从子目录到父目录的顺序）
func obfuscateDirsBottomUp(currentDir string, config *DynamicConfig, dirMap map[string]*DirMapItem, stat *StatData) {
	// 先递归处理所有子目录（深度优先）
	entries, err := os.ReadDir(currentDir)
	if err != nil {
		fmt.Printf("⚠️  读取目录失败: %s, 错误: %v\n", currentDir, err)
		return
	}

	// 先处理子目录
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		dirName := entry.Name()
		// 跳过隐藏目录和特殊目录
		if strings.HasPrefix(dirName, ".") || dirName == config.MapFilename || dirName == config.LockFilename {
			continue
		}
		dirPath := filepath.Join(currentDir, dirName)
		// 递归处理子目录
		obfuscateDirsBottomUp(dirPath, config, dirMap, stat)
	}

	// 处理当前目录中的文件夹（包括目标目录本身）
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		dirName := entry.Name()
		// 跳过隐藏目录和特殊目录
		if strings.HasPrefix(dirName, ".") || dirName == config.MapFilename || dirName == config.LockFilename {
			continue
		}

		// 为每个原始目录生成唯一隐藏名
		var obfDirName string
		for {
			obfDirName = generateObfuscatedName(true, config) // 生成目录名（无后缀）
			if _, exists := dirMap[obfDirName]; !exists {
				break
			}
		}

		// 保存相对于目标目录的路径
		var originalRelPath string
		matchedTargetPath := ""
		for _, targetPath := range config.TargetPaths {
			if strings.HasPrefix(currentDir, targetPath) {
				matchedTargetPath = targetPath
				relDir, err := filepath.Rel(targetPath, currentDir)
				if err == nil {
					if relDir == "." {
						originalRelPath = dirName
					} else {
						originalRelPath = filepath.Join(relDir, dirName)
					}
					break
				}
			}
		}
		
		// 如果没有匹配的目标路径，使用简单的目录名
		if originalRelPath == "" {
			originalRelPath = dirName
			matchedTargetPath = currentDir
		}

		// 记录映射关系
		dirMap[obfDirName] = &DirMapItem{
			OriginalPath: originalRelPath,
			TargetDir:    matchedTargetPath,
		}

		oldPath := filepath.Join(currentDir, dirName)
		newPath := filepath.Join(currentDir, obfDirName)
		err = os.Rename(oldPath, newPath)
		if err != nil {
			fmt.Printf("⚠️  混淆目录失败: %s -> %s, 错误: %v\n", oldPath, newPath, err)
			continue
		}
		_ = os.Chmod(newPath, 0755)
		stat.TotalDirsObfuscated++
		fmt.Printf("✅ 混淆目录: %s -> %s\n", dirName, obfDirName)
	}
}

// collectDirFiles 收集目录文件（修改为同级目录去重优化）
func collectDirFiles(targetDir string, config *DynamicConfig, fileMap map[string]*FileMapItem) ([]string, map[string]map[string]struct{}) {
	var currentFiles []string
	// 按目录存储已加密文件的MD5（同级目录去重）
	encryptedMd5 := make(map[string]map[string]struct{})
	
	// 初始化根目录的MD5集合
	encryptedMd5[targetDir] = make(map[string]struct{})
	
	// 收集全局映射表中所有已加密文件的MD5，按目录分组
	// 只有映射表中存在的文件才被认为是已加密文件
	for _, item := range fileMap {
		if item.Md5 != "" && item.TargetDir != "" {
			if _, exists := encryptedMd5[item.TargetDir]; !exists {
				encryptedMd5[item.TargetDir] = make(map[string]struct{})
			}
			encryptedMd5[item.TargetDir][item.Md5] = struct{}{}
		}
	}

	fmt.Printf("🔍 collectDirFiles: 检查目标目录: %s\n", targetDir)
	fmt.Printf("📊 collectDirFiles: 映射表中已加密目录数量: %d\n", len(encryptedMd5))

	// 遍历整个目标目录树，收集所有未加密文件
	_ = filepath.Walk(targetDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			fmt.Printf("⚠️  访问路径失败: %s, 错误: %v\n", path, err)
			return nil
		}
		
		// 跳过目录
		if info.IsDir() {
			// 为每个目录初始化MD5集合
			if _, exists := encryptedMd5[path]; !exists {
				encryptedMd5[path] = make(map[string]struct{})
			}
			return nil
		}

		filename := info.Name()
		// 跳过特殊文件
		if filename == config.MapFilename || filename == config.LockFilename {
			return nil
		}

		// 获取文件所在目录
		dir := filepath.Dir(path)
		
		// 确保目录的MD5集合已初始化
		if _, exists := encryptedMd5[dir]; !exists {
			encryptedMd5[dir] = make(map[string]struct{})
		}

		// 检查是否是加密文件
		if isFileEncrypted(path, config) {
			fmt.Printf("🔍 collectDirFiles: 发现加密文件: %s\n", path)
			// 如果是加密文件，检查映射表中是否有对应的MD5
			encryptedFilename := filepath.Base(path)
			if item, exists := fileMap[encryptedFilename]; exists && item.Md5 != "" {
				fmt.Printf("🔍 collectDirFiles: 加密文件 %s 的MD5: %s\n", path, item.Md5)
				// 只有映射表中存在的文件才被认为是已加密文件
				encryptedMd5[dir][item.Md5] = struct{}{}
			}
		} else {
			fmt.Printf("🔍 collectDirFiles: 发现未加密文件: %s\n", path)
			currentFiles = append(currentFiles, path) // 存储完整路径
		}
		return nil
	})

	fmt.Printf("📊 collectDirFiles: 返回待处理文件数量: %d\n", len(currentFiles))
	return currentFiles, encryptedMd5
}

// encryptFiles 加密文件（修改为同级目录去重优化）
func encryptFiles(targetDir string, key []byte, config *DynamicConfig, fileMap map[string]*FileMapItem, stat *StatData) {
	// 首先收集整个目录树中的文件
	allFiles, encryptedMd5Set := collectDirFiles(targetDir, config, fileMap)

	// 创建一个映射，方便快速查找文件是否需要处理
	filesToProcess := make(map[string]bool)
	for _, file := range allFiles {
		filesToProcess[file] = true
	}

	_ = filepath.Walk(targetDir, func(root string, info os.FileInfo, err error) error {
		if err != nil {
			fmt.Printf("⚠️  访问路径失败: %s, 错误: %v\n", root, err)
			return nil
		}
		if info.IsDir() {
			return nil
		}

		filename := info.Name()
		if filename == config.MapFilename || filename == config.LockFilename {
			return nil
		}
		
		// 获取文件的真实路径（处理符号链接）
		realPath, err := filepath.EvalSymlinks(root)
		if err != nil {
			fmt.Printf("⚠️  无法解析符号链接: %s, 错误: %v\n", root, err)
			return nil
		}
		
		// 构建正确的文件路径
		filePath := root

		// 检查当前文件是否在需要处理的文件列表中
		if !filesToProcess[filePath] {
			return nil
		}

		// 计算文件MD5（使用真实路径）
		fileMd5, err := calculateMd5(realPath)
		if err != nil {
			fmt.Printf("⚠️  计算文件MD5失败: %s (真实路径: %s), 错误: %v\n", filePath, realPath, err)
			return nil
		}

		// 获取文件所在目录
		dir := filepath.Dir(filePath)
		
		// 同级目录去重优化：仅在同级目录内判断重复
		foundDuplicate := false
		
		// 先获取相对路径
		originalRelPath, err := filepath.Rel(targetDir, filePath)
		if err != nil {
			fmt.Printf("⚠️  获取相对路径失败: %s, 错误: %v\n", filePath, err)
			return nil
		}
		
		// 只检查当前目录中是否已存在相同MD5的文件
		if md5Map, exists := encryptedMd5Set[dir]; exists {
			if _, md5Exists := md5Map[fileMd5]; md5Exists {
				fmt.Printf("⚠️  同级目录中已存在相同MD5的文件，删除当前文件: %s\n", filePath)
				fmt.Printf("🔍 详细信息 - 当前文件MD5: %s, 目录: %s\n", fileMd5, dir)
				if err := os.Remove(filePath); err != nil {
					fmt.Printf("⚠️  删除重复文件失败: %s, 错误: %v\n", filePath, err)
				} else {
					stat.TotalDuplicateDel++
					fmt.Printf("✅ 删除重复文件: %s\n", filePath)
				}
				foundDuplicate = true
			}
		}
		
		// 如果找到重复文件，跳过加密
		if foundDuplicate {
			return nil
		}

		var obfFileName string
		for i := 0; i < 100; i++ { // 添加重试限制，避免无限循环
			obfFileName = generateObfuscatedName(false, config)
			if _, exists := fileMap[obfFileName]; !exists {
				break
			}
		}

		fileMap[obfFileName] = &FileMapItem{
			Path:       originalRelPath,
			Md5:        fileMd5,
			TargetDir:  targetDir,
		}

		obfFilePath := filepath.Join(dir, obfFileName)
		// 加密时使用真实路径
		err = encryptFileByType(realPath, obfFilePath, key, config.EncryptType)
		if err != nil {
			fmt.Printf("⚠️  加密文件失败: %s (真实路径: %s), 错误: %v\n", filePath, realPath, err)
			delete(fileMap, obfFileName)
			return nil
		}

		if err := os.Chmod(obfFilePath, 0644); err != nil {
			fmt.Printf("⚠️  修改加密文件权限失败: %s, 错误: %v\n", obfFilePath, err)
		}

		if err := os.Remove(filePath); err != nil {
			fmt.Printf("❌ 删除原文件失败: %s, 错误: %v\n", filePath, err)
			// 不增加统计，因为操作未完成
			return nil
		}

		stat.TotalFilesEncrypted++
		// 将当前文件的MD5添加到对应目录的集合中，以便后续去重
		if _, exists := encryptedMd5Set[dir]; !exists {
			encryptedMd5Set[dir] = make(map[string]struct{})
		}
		encryptedMd5Set[dir][fileMd5] = struct{}{}
		fmt.Printf("✅ 加密文件: %s -> %s\n", filename, obfFileName)
		return nil
	})
}

// decryptFileByType 多算法解密函数（支持AES、Blowfish和XOR解密，使用流式处理）
func decryptFileByType(inputPath, outputPath string, key []byte, encryptType string, password string) error {
	// 打开输入文件
	inFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("打开输入文件失败: %v", err)
	}
	defer inFile.Close()

	// 创建临时输出文件，确保原子性操作
	tempOutputPath := outputPath + ".tmp"
	outFile, err := os.OpenFile(tempOutputPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600) // 使用更严格的初始权限
	if err != nil {
		return fmt.Errorf("创建临时输出文件失败: %v", err)
	}
	defer func() {
		outFile.Close()
		// 如果函数返回错误，删除临时文件
		if err != nil {
			os.Remove(tempOutputPath)
		}
	}()

	switch encryptType {
	case EncryptTypeAES:
		err = decryptFileAES(inFile, outFile, key, encryptType)
	case EncryptTypeBlowfish:
		err = decryptFileBlowfish(inFile, outFile, key, encryptType)
	case EncryptTypeXOR:
		err = decryptFileXOR(inFile, outFile, key, encryptType)
	default:




		err = fmt.Errorf("不支持的加密算法: %s", encryptType)
	}





	// 如果解密成功，重命名临时文件为目标文件
	if err == nil {
		// 确保输出文件已关闭
		outFile.Close()
		// 重命名临时文件为目标文件（原子操作）
		if err := os.Rename(tempOutputPath, outputPath); err != nil {
			return fmt.Errorf("重命名临时文件失败: %v", err)
		}
		// 设置最终权限
		if err := os.Chmod(outputPath, 0644); err != nil {
			// 权限设置失败不影响文件解密结果，仅记录警告
			fmt.Printf("⚠️  设置文件权限失败: %v\n", err)
		}
	}

	return err


}

// decryptFileAES 使用AES-CBC模式流式解密文件
func decryptFileAES(inFile *os.File, outFile *os.File, keyWithSalt []byte, encryptType string) error {
	// 从keyWithSalt中提取实际的解密密钥（去掉盐值部分）
	actualKey := keyWithSalt
	if len(keyWithSalt) > SaltSize {
		actualKey = keyWithSalt[SaltSize:]
	}
	
	// 确保密钥长度符合AES要求
	if len(actualKey) > AESKeySize {
		actualKey = actualKey[:AESKeySize]
	}

	// 读取IV
	iv := make([]byte, aes.BlockSize)
	n, err := inFile.Read(iv)
	if err != nil {
		return fmt.Errorf("读取IV失败: %v", err)
	}
	if n < aes.BlockSize {
		return fmt.Errorf("IV长度不足")
	}

	// 创建AES解密器
	block, err := aes.NewCipher(actualKey)
	if err != nil {
		return fmt.Errorf("创建AES解密器失败: %v", err)
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	// 使用缓冲区进行流式处理
	bufSize := 4096 * aes.BlockSize // 确保缓冲区大小是块大小的倍数
	cipherBuf := make([]byte, bufSize)
	plainBuf := make([]byte, bufSize)

	// 读取并解密数据
	for {
		n, err := inFile.Read(cipherBuf)
		if n > 0 {
			// 确保数据长度是块大小的倍数
			if n%aes.BlockSize != 0 {
				return fmt.Errorf("密文长度不是块大小的倍数: %d", n)
			}

			// 解密数据
			mode.CryptBlocks(plainBuf, cipherBuf[:n])

			// 检查是否是最后一个块
			isLastBlock := (err == io.EOF) || (n < bufSize)
			
			if isLastBlock {
				fmt.Printf("📄 解密最后一块，大小: %d, EOF: %v\n", n, err == io.EOF)
				// 验证并移除填充
				if n < aes.BlockSize {
					return fmt.Errorf("最后一个密文块长度不足")
				}

				// 获取填充长度
				padLen := int(plainBuf[n-1])
				fmt.Printf("📄 填充长度: %d\n", padLen)
				if padLen <= 0 || padLen > aes.BlockSize {
					return fmt.Errorf("无效的填充长度: %d", padLen)
				}

				// 验证填充数据
				validPadding := true
				for i := 1; i <= padLen; i++ {
					if plainBuf[n-i] != byte(padLen) {
						validPadding = false
						break
					}
				}

				if !validPadding {
					return fmt.Errorf("无效的填充数据")
				}

				// 写入去除填充后的数据
				if _, err := outFile.Write(plainBuf[:n-padLen]); err != nil {
					return fmt.Errorf("写入解密数据失败: %v", err)
				}
			} else {
				// 不是最后一个块，直接写入全部解密数据
				if _, err := outFile.Write(plainBuf[:n]); err != nil {
					return fmt.Errorf("写入解密数据失败: %v", err)
				}
			}
		}

		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("读取文件失败: %v", err)
		}
	}

	return nil
}

// decryptFileBlowfish 使用Blowfish-CBC模式流式解密文件
func decryptFileBlowfish(inFile *os.File, outFile *os.File, keyWithSalt []byte, encryptType string) error {
	// 从keyWithSalt中提取实际的解密密钥（去掉盐值部分）
	actualKey := keyWithSalt
	if len(keyWithSalt) > SaltSize {
		actualKey = keyWithSalt[SaltSize:]
	}
	
	// 确保密钥长度符合Blowfish要求
	if len(actualKey) > BlowfishKeySize {
		actualKey = actualKey[:BlowfishKeySize]
	}

	// 读取IV
	iv := make([]byte, blowfish.BlockSize)
	n, err := inFile.Read(iv)
	if err != nil {
		return fmt.Errorf("读取IV失败: %v", err)
	}
	if n < blowfish.BlockSize {
		return fmt.Errorf("IV长度不足")
	}

	// 创建Blowfish解密器
	block, err := blowfish.NewCipher(actualKey)
	if err != nil {
		return fmt.Errorf("创建Blowfish解密器失败: %v", err)
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	// 使用缓冲区进行流式处理
	bufSize := 4096 * blowfish.BlockSize // 确保缓冲区大小是块大小的倍数
	cipherBuf := make([]byte, bufSize)
	plainBuf := make([]byte, bufSize)

	// 读取并解密数据
	for {
		n, err := inFile.Read(cipherBuf)
		if n > 0 {
			// 确保数据长度是块大小的倍数
			if n%blowfish.BlockSize != 0 {
				return fmt.Errorf("密文长度不是块大小的倍数: %d", n)
			}

			// 解密数据
			mode.CryptBlocks(plainBuf, cipherBuf[:n])

			// 检查是否是最后一个块
			isLastBlock := (err == io.EOF) || (n < bufSize)
			
			if isLastBlock {
				fmt.Printf("📄 解密最后一块，大小: %d, EOF: %v\n", n, err == io.EOF)
				// 验证并移除填充
				if n < blowfish.BlockSize {
					return fmt.Errorf("最后一个密文块长度不足")
				}

				// 获取填充长度
				padLen := int(plainBuf[n-1])
				fmt.Printf("📄 填充长度: %d\n", padLen)
				if padLen <= 0 || padLen > blowfish.BlockSize {
					return fmt.Errorf("无效的填充长度: %d", padLen)
				}

				// 验证填充数据
				validPadding := true
				for i := 1; i <= padLen; i++ {
					if plainBuf[n-i] != byte(padLen) {
						validPadding = false
						break
					}
				}

				if !validPadding {
					return fmt.Errorf("无效的填充数据")
				}

				// 写入去除填充后的数据
				if _, err := outFile.Write(plainBuf[:n-padLen]); err != nil {
					return fmt.Errorf("写入解密数据失败: %v", err)
				}
			} else {
				// 不是最后一个块，直接写入全部解密数据
				if _, err := outFile.Write(plainBuf[:n]); err != nil {
					return fmt.Errorf("写入解密数据失败: %v", err)
				}
			}
		}

		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("读取文件失败: %v", err)
		}
	}

	return nil
}

// decryptFileXOR 使用XOR流式解密文件
func decryptFileXOR(inFile *os.File, outFile *os.File, keyWithSalt []byte, encryptType string) error {
	// 从keyWithSalt中提取实际的解密密钥（去掉盐值部分）
	actualKey := keyWithSalt
	if len(keyWithSalt) > SaltSize {
		actualKey = keyWithSalt[SaltSize:]
	}
	
	// 确保密钥长度符合要求
	if len(actualKey) != XORKeySize {
		return fmt.Errorf("XOR密钥长度错误，需要%d字节，实际为%d字节", XORKeySize, len(actualKey))
	}

	// 使用缓冲区进行流式处理
	buf := make([]byte, 4096)
	keyLen := len(actualKey)

	for {
		n, err := inFile.Read(buf)
		if n > 0 {
			// 对每个字节进行XOR操作
			for i := 0; i < n; i++ {
				buf[i] ^= actualKey[i%keyLen]
			}
			// 写入解密数据
			if _, err := outFile.Write(buf[:n]); err != nil {
				return fmt.Errorf("写入解密数据失败: %v", err)
			}
		}

		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("读取文件失败: %v", err)
		}
	}

	return nil
}

// encryptFileByType 多算法加密（完整保留Blowfish逻辑，使用流式处理大文件）
func encryptFileByType(inputPath, outputPath string, key []byte, encryptType string) error {
	// 打开输入文件
	inFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("打开输入文件失败: %v", err)
	}
	defer inFile.Close()

	// 获取文件信息
	info, err := inFile.Stat()
	if err != nil {
		return fmt.Errorf("获取文件信息失败: %v", err)
	}

	// 创建临时输出文件，确保原子性操作
	tempOutputPath := outputPath + ".tmp"
	outFile, err := os.OpenFile(tempOutputPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600) // 使用更严格的初始权限
	if err != nil {
		return fmt.Errorf("创建临时输出文件失败: %v", err)
	}
	defer func() {
		outFile.Close()
		// 如果函数返回错误，删除临时文件
		if err != nil {
			os.Remove(tempOutputPath)
		}
	}()

	switch encryptType {
	case EncryptTypeAES:
		err = encryptFileAES(inFile, outFile, key, info.Size())
	case EncryptTypeBlowfish:
		err = encryptFileBlowfish(inFile, outFile, key, info.Size())
	case EncryptTypeXOR:
		err = encryptFileXOR(inFile, outFile, key)
	default:
		err = fmt.Errorf("不支持的加密算法：%s", encryptType)
	}

	// 如果加密成功，重命名临时文件为目标文件
	if err == nil {
		// 确保输出文件已关闭
		outFile.Close()
		// 重命名临时文件为目标文件（原子操作）
		if err := os.Rename(tempOutputPath, outputPath); err != nil {
			return fmt.Errorf("重命名临时文件失败: %v", err)
		}
		// 设置最终权限
		if err := os.Chmod(outputPath, 0644); err != nil {
			// 权限设置失败不影响文件加密结果，仅记录警告
			fmt.Printf("⚠️  设置文件权限失败: %v\n", err)
		}
	}

	return err
}

// encryptFileAES 使用AES-CBC模式流式加密文件
func encryptFileAES(inFile *os.File, outFile *os.File, keyWithSalt []byte, fileSize int64) error {
	// 从keyWithSalt中提取实际的加密密钥（去掉盐值部分）
	actualKey := keyWithSalt
	if len(keyWithSalt) > SaltSize {
		actualKey = keyWithSalt[SaltSize:]
	}
	
	// 确保密钥长度符合AES-256要求
	if len(actualKey) != AESKeySize {
		return fmt.Errorf("AES密钥长度错误，需要%d字节，实际为%d字节", AESKeySize, len(actualKey))
	}

	// 生成随机IV
	iv := make([]byte, aes.BlockSize)
	if _, err := crand.Read(iv); err != nil {
		return fmt.Errorf("生成IV失败: %v", err)
	}

	// 先写入IV到输出文件
	if _, err := outFile.Write(iv); err != nil {
		return fmt.Errorf("写入IV失败: %v", err)
	}

	// 创建AES加密器
	block, err := aes.NewCipher(actualKey)
	if err != nil {
		return fmt.Errorf("创建AES加密器失败: %v", err)
	}

	mode := cipher.NewCBCEncrypter(block, iv)

	// 计算需要的填充长度
	padLen := aes.BlockSize - (int(fileSize) % aes.BlockSize)
	fmt.Printf("📄 文件大小: %d, 填充长度: %d\n", fileSize, padLen)

	// 使用缓冲区进行流式处理
	bufSize := 4096 * aes.BlockSize // 确保缓冲区大小是块大小的倍数
	buf := make([]byte, bufSize)
	var totalRead int64 = 0

	for {
		n, err := inFile.Read(buf)
		if n > 0 {
			totalRead += int64(n)
			
			// 处理当前读取的数据块
			blockBuf := buf[:n]
			
			// 如果是最后一个块，添加填充
			if totalRead >= fileSize {
				fmt.Printf("📄 最后一块: 已读取 %d, 文件大小 %d\n", totalRead, fileSize)
				// 扩展缓冲区以容纳填充
				paddedSize := n + padLen
				if paddedSize > len(buf) {
					blockBuf = make([]byte, paddedSize)
					copy(blockBuf, buf[:n])
				} else {
					blockBuf = buf[:paddedSize]
				}
				// 添加PKCS#7填充
				for i := n; i < paddedSize; i++ {
					blockBuf[i] = byte(padLen)
				}
				fmt.Printf("📄 填充后大小: %d\n", paddedSize)
				// 加密填充后的块
				encryptedBuf := make([]byte, paddedSize)
				mode.CryptBlocks(encryptedBuf, blockBuf)
				// 写入加密数据
				if _, err := outFile.Write(encryptedBuf); err != nil {
					return fmt.Errorf("写入加密数据失败: %v", err)
				}
			} else {
				// 确保数据长度是块大小的倍数
				if n%aes.BlockSize != 0 {
					// 这种情况理论上不应该发生，因为我们使用了足够大的缓冲区
					// 但为了安全起见，我们还是处理一下
					return fmt.Errorf("读取的数据长度不是块大小的倍数")
				}
				// 加密数据
				encryptedBuf := make([]byte, n)
				mode.CryptBlocks(encryptedBuf, blockBuf)
				// 写入加密数据
				if _, err := outFile.Write(encryptedBuf); err != nil {
					return fmt.Errorf("写入加密数据失败: %v", err)
				}
			}
		}

		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("读取文件失败: %v", err)
		}
	}

	return nil
}

// encryptFileBlowfish 使用Blowfish-CBC模式流式加密文件
func encryptFileBlowfish(inFile *os.File, outFile *os.File, keyWithSalt []byte, fileSize int64) error {
	// 从keyWithSalt中提取实际的加密密钥（去掉盐值部分）
	actualKey := keyWithSalt
	if len(keyWithSalt) > SaltSize {
		actualKey = keyWithSalt[SaltSize:]
	}
	
	// 确保密钥长度符合Blowfish要求
	if len(actualKey) > BlowfishKeySize {
		actualKey = actualKey[:BlowfishKeySize]
	}

	// 生成随机IV
	iv := make([]byte, blowfish.BlockSize)
	if _, err := crand.Read(iv); err != nil {
		return fmt.Errorf("生成IV失败: %v", err)
	}

	// 先写入IV到输出文件
	if _, err := outFile.Write(iv); err != nil {
		return fmt.Errorf("写入IV失败: %v", err)
	}

	// 创建Blowfish加密器
	block, err := blowfish.NewCipher(actualKey)
	if err != nil {
		return fmt.Errorf("创建Blowfish加密器失败: %v", err)
	}

	mode := cipher.NewCBCEncrypter(block, iv)

	// 计算需要的填充长度
	padLen := blowfish.BlockSize - (int(fileSize) % blowfish.BlockSize)
	fmt.Printf("📄 文件大小: %d, 填充长度: %d\n", fileSize, padLen)

	// 使用缓冲区进行流式处理
	bufSize := 4096 * blowfish.BlockSize // 确保缓冲区大小是块大小的倍数
	buf := make([]byte, bufSize)
	var totalRead int64 = 0

	for {
		n, err := inFile.Read(buf)
		if n > 0 {
			totalRead += int64(n)
			
			// 处理当前读取的数据块
			blockBuf := buf[:n]
			
			// 如果是最后一个块，添加填充
			if totalRead >= fileSize {
				fmt.Printf("📄 最后一块: 已读取 %d, 文件大小 %d\n", totalRead, fileSize)
				// 扩展缓冲区以容纳填充
				paddedSize := n + padLen
				if paddedSize > len(buf) {
					blockBuf = make([]byte, paddedSize)
					copy(blockBuf, buf[:n])
				} else {
					blockBuf = buf[:paddedSize]
				}
				// 添加PKCS#7填充
				for i := n; i < paddedSize; i++ {
					blockBuf[i] = byte(padLen)
				}
				fmt.Printf("📄 填充后大小: %d\n", paddedSize)
				// 加密填充后的块
				encryptedBuf := make([]byte, paddedSize)
				mode.CryptBlocks(encryptedBuf, blockBuf)
				// 写入加密数据
				if _, err := outFile.Write(encryptedBuf); err != nil {
					return fmt.Errorf("写入加密数据失败: %v", err)
				}
			} else {
				// 确保数据长度是块大小的倍数
				if n%blowfish.BlockSize != 0 {
					// 这种情况理论上不应该发生，因为我们使用了足够大的缓冲区
					// 但为了安全起见，我们还是处理一下
					return fmt.Errorf("读取的数据长度不是块大小的倍数")
				}
				// 加密数据
				encryptedBuf := make([]byte, n)
				mode.CryptBlocks(encryptedBuf, blockBuf)
				// 写入加密数据
				if _, err := outFile.Write(encryptedBuf); err != nil {
					return fmt.Errorf("写入加密数据失败: %v", err)
				}
			}
		}

		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("读取文件失败: %v", err)
		}
	}

	return nil
}

// encryptFileXOR 使用XOR流式加密文件
func encryptFileXOR(inFile *os.File, outFile *os.File, keyWithSalt []byte) error {
	// 从keyWithSalt中提取实际的加密密钥（去掉盐值部分）
	actualKey := keyWithSalt
	if len(keyWithSalt) > SaltSize {
		actualKey = keyWithSalt[SaltSize:]
	}
	
	// 确保密钥长度符合要求
	if len(actualKey) != XORKeySize {
		return fmt.Errorf("XOR密钥长度错误，需要%d字节，实际为%d字节", XORKeySize, len(actualKey))
	}

	// 使用缓冲区进行流式处理
	buf := make([]byte, 4096)
	keyLen := len(actualKey)

	for {
		n, err := inFile.Read(buf)
		if n > 0 {
			// 对每个字节进行XOR操作
			for i := 0; i < n; i++ {
				buf[i] ^= actualKey[i%keyLen]
			}
			// 写入加密数据
			if _, err := outFile.Write(buf[:n]); err != nil {
				return fmt.Errorf("写入加密数据失败: %v", err)
			}
		}

		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("读取文件失败: %v", err)
		}
	}

	return nil
}

// decryptTargetDir 解密目标目录（修改为符合新解密逻辑）
func decryptTargetDir(targetDir string, key []byte, config *DynamicConfig, fileMap map[string]*FileMapItem, dirMap map[string]*DirMapItem, stat *StatData) {
	// 解密预处理与安全校验
	if !isDir(targetDir) {
		fmt.Printf("⚠️  目录不存在，跳过：%s\n", targetDir)
		return
	}

	lockPath := filepath.Join(targetDir, config.LockFilename)
	if isFile(lockPath) {
		fmt.Printf("❌ 发现运行锁 %s，请确认无其他进程后手动删除。\n", config.LockFilename)
		return
	}

	err := createLockFile(lockPath)
	if err != nil {
		fmt.Printf("❌ 创建运行锁失败：%v\n", err)
		return
	}

	defer func() {
		if isFile(lockPath) {
			_ = os.Remove(lockPath)
		}
	}()

	// 先解密文件（优先执行），再恢复目录结构
	decryptFiles(targetDir, key, config, fileMap, stat)
	recoverDirs(targetDir, config, dirMap, stat)
}

// recoverDirs 恢复目录结构（修改为符合新解密逻辑）
func recoverDirs(targetDir string, config *DynamicConfig, dirMap map[string]*DirMapItem, stat *StatData) {
	// 采用「先子目录后父目录」的递归顺序，确保多层级目录正确恢复
	
	// 首先递归处理所有子目录（深度优先）
	entries, err := os.ReadDir(targetDir)
	if err != nil {
		fmt.Printf("⚠️  读取目录失败: %s, 错误: %v\n", targetDir, err)
		return
	}
	
	// 先递归处理子目录
	for _, entry := range entries {
		if entry.IsDir() {
			dirName := entry.Name()
			// 跳过特殊文件和目录
			if dirName == config.MapFilename || dirName == config.LockFilename {
				continue
			}
			// 安全地拼接子目录路径
			dirPath, err := safeJoin(targetDir, dirName)
			if err != nil {
				fmt.Printf("⚠️  安全拼接子目录路径失败: %s, 错误: %v\n", dirName, err)
				continue
			}
			recoverDirs(dirPath, config, dirMap, stat)
		}
	}
	
	// 处理完所有子目录后，再处理当前目录
	for _, entry := range entries {
		// 只处理目录，跳过文件
		if !entry.IsDir() {
			continue
		}
		dirName := entry.Name()
		// 跳过特殊文件和目录
		if dirName == config.MapFilename || dirName == config.LockFilename {
			continue
		}
		
		// 遍历目录下的混淆目录（.开头+12位随机字符），匹配目录映射表
		if strings.HasPrefix(dirName, ".") {
			fmt.Printf("🔍 检查混淆目录: %s (在 %s 中)\n", dirName, targetDir)
			// 查找目录映射信息
			if dirItem, exists := dirMap[dirName]; exists {
				// 安全地拼接原路径和目标路径
				oldPath, err := safeJoin(targetDir, dirName)
				if err != nil {
					fmt.Printf("⚠️  安全拼接原路径失败: %s, 错误: %v\n", dirName, err)
					continue
				}
				
				// 从映射表中获取原始路径信息
				fmt.Printf("🔍 映射信息 - 混淆目录: %s, 原始路径: %s, 目标目录: %s\n", dirName, dirItem.OriginalPath, dirItem.TargetDir)
				
				// 正确构建原始完整目录路径
				// 需要根据映射表中的信息正确构建路径
				var newPath string
				if filepath.IsAbs(dirItem.TargetDir) {
					// 如果TargetDir是绝对路径
					newPath = filepath.Join(dirItem.TargetDir, dirItem.OriginalPath)
				} else {
					// 如果TargetDir是相对路径，需要根据当前targetDir构建
					newPath = filepath.Join(targetDir, dirItem.OriginalPath)
				}
				
				fmt.Printf("🔍 路径信息 - 旧路径: %s, 新路径: %s\n", oldPath, newPath)
				
				// 确保父目录存在，但避免创建不必要的目录
				parentDir := filepath.Dir(newPath)
				// 只有当父目录不等于当前处理目录时才创建
				if parentDir != targetDir && parentDir != "." {
					if err := os.MkdirAll(parentDir, 0755); err != nil {
						fmt.Printf("⚠️  创建父目录失败: %s, 错误: %v\n", parentDir, err)
						continue
					}
				}
				
				// 检查目标路径是否已存在
				if isDir(newPath) {
					fmt.Printf("⚠️  目标目录已存在，将删除: %s\n", newPath)
					if err := os.RemoveAll(newPath); err != nil {
						fmt.Printf("⚠️  删除已存在的目录失败: %s, 错误: %v\n", newPath, err)
						continue
					}
				}
				
				// 重命名混淆目录为原始名称
				if err := os.Rename(oldPath, newPath); err != nil {
					fmt.Printf("⚠️  恢复目录失败: %s -> %s, 错误: %v\n", oldPath, newPath, err)
					continue
				}
				
				// 设置权限为0o755
				if err := os.Chmod(newPath, 0755); err != nil {
					fmt.Printf("⚠️  设置目录权限失败: %s, 错误: %v\n", newPath, err)
				}
				
				stat.TotalDirsObfuscated++
				fmt.Printf("✅ 恢复目录: %s -> %s\n", dirName, newPath)
			} else {
				fmt.Printf("⚠️  未找到混淆目录 %s 的映射信息\n", dirName)
			}
		}
	}
}


// decryptFiles 解密文件（修改为符合新解密逻辑）
func decryptFiles(targetDir string, key []byte, config *DynamicConfig, fileMap map[string]*FileMapItem, stat *StatData) {
	// 递归遍历目标目录下所有文件，筛选加密文件（.开头+.dat后缀）
	_ = filepath.Walk(targetDir, func(root string, info os.FileInfo, err error) error {
		if err != nil {
			fmt.Printf("⚠️  访问路径失败: %s, 错误: %v\n", root, err)
			return nil
		}
		// 跳过目录
		if info.IsDir() {
			return nil
		}
		
		// 获取文件的完整路径
		fullPath := root
		// 获取文件名
		filename := info.Name()
		
		// 跳过锁文件和映射文件
		if filename == config.MapFilename || filename == config.LockFilename {
			return nil
		}
		
		// 检查是否是加密文件（.开头+.dat后缀）
		if isFileEncrypted(fullPath, config) && strings.HasPrefix(filename, ".") {
			fmt.Printf("🔍 发现加密文件: %s\n", fullPath)
			// 查找文件映射信息
			if fileItem, exists := fileMap[filename]; exists {
				encryptedPath := fullPath
				// 从映射表中获取文件原始相对路径，拼接得到完整原始路径
				originalPath := filepath.Join(targetDir, fileItem.Path)
				
				// 自动创建原始父目录（避免目录不存在报错）
				parentDir := filepath.Dir(originalPath)
				if err := os.MkdirAll(parentDir, 0755); err != nil {
					fmt.Printf("⚠️  创建父目录失败: %s, 错误: %v\n", parentDir, err)
					return nil
				}
				
				// 采用AES-CBC解密：读取加密文件中的IV和密文，解密后去除补位，写入原始路径文件
				if err := decryptFileByType(encryptedPath, originalPath, key, config.EncryptType, config.Password); err != nil {
					fmt.Printf("❌ 解密文件失败: %s -> %s, 错误: %v\n", encryptedPath, originalPath, err)
					return nil
				}
				
				// 设置原始文件权限为0o644
				if err := os.Chmod(originalPath, 0644); err != nil {
					fmt.Printf("⚠️  设置原始文件权限失败: %s, 错误: %v\n", originalPath, err)
				}
				
				// 删除加密文件，统计解密成功数量
				if err := os.Remove(encryptedPath); err != nil {
					fmt.Printf("⚠️  删除加密文件失败: %s, 错误: %v\n", encryptedPath, err)
				} else {
					stat.TotalFilesEncrypted++
					fmt.Printf("✅ 解密文件: %s -> %s\n", filename, fileItem.Path)
				}
			} else {
				fmt.Printf("⚠️  找不到文件映射信息: %s\n", filename)
			}
		} else {
			fmt.Printf("🔍 非加密文件（跳过）: %s\n", fullPath)
		}
		return nil
	})
}

// calculateMd5 计算文件MD5（修改以更好地处理符号链接）
func calculateMd5(filePath string) (string, error) {
	// 获取文件的真实路径
	realPath, err := filepath.EvalSymlinks(filePath)
	if err != nil {
		return "", fmt.Errorf("无法解析符号链接 %s: %v", filePath, err)
	}
	
	file, err := os.Open(realPath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := md5.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

// isFileEncrypted 判断文件是否已加密（修改以更好地处理符号链接）
func isFileEncrypted(filePath string, config *DynamicConfig) bool {
	// 简单判断：文件名以混淆后缀结尾
	return strings.HasSuffix(filePath, config.ObfuscateSuffix)
}

// isDirEmpty 检查目录是否为空（排除特殊文件）
func isDirEmpty(dirPath string, config *DynamicConfig) (bool, error) {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return false, err
	}
	
	// 检查是否有非特殊文件
	for _, entry := range entries {
		name := entry.Name()
		// 跳过特殊文件
		if name == config.MapFilename || name == config.LockFilename {
			continue
		}
		// 跳过隐藏文件/目录
		if strings.HasPrefix(name, ".") {
			continue
		}
		// 如果有非特殊文件，则目录不为空
		return false, nil
	}
	// 如果所有文件都是特殊文件或没有文件，则目录为空
	return true, nil
}

// generateObfuscatedName 生成混淆名称（保留原逻辑)


func generateObfuscatedName(isDir bool, config *DynamicConfig) string {
	nameLen := config.ObfuscateNameLength
	if nameLen <= 0 {
		nameLen = 12
	}
	
	// 生成随机名称
	name := make([]byte, nameLen)
	charset := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	for i := range name {
		// 使用math/rand生成随机索引
		index := rand.Intn(len(charset))
		name[i] = charset[index]
	}
	
	// 添加混淆后缀
	if !isDir {
		return "." + string(name) + config.ObfuscateSuffix
	}
	return "." + string(name)
}

// loadGlobalMap 加载全局映射表（保留原逻辑）
func loadGlobalMap(key []byte, config *DynamicConfig, fileMap *map[string]*FileMapItem, dirMap *map[string]*DirMapItem) []byte {
	mapPath := filepath.Join(config.MapStoragePath, config.MapFilename)
	if !isFile(mapPath) {
		fmt.Printf("⚠️  映射表文件不存在: %s\n", mapPath)
		return key
	}

	// 读取映射表文件
	encryptedData, err := os.ReadFile(mapPath)
	if err != nil {
		fmt.Printf("❌ 读取映射表文件失败: %v\n", err)
		return key
	}
	fmt.Printf("📂 尝试加载映射表文件: %s\n", mapPath)
	fmt.Printf("📄 读取映射表文件成功，大小: %d 字节\n", len(encryptedData))

	// 解密映射表数据
	decryptedData, err := decryptMapData(encryptedData, key)
	if err != nil {
		fmt.Printf("❌ 解密映射表数据失败: %v\n", err)
		return key
	}
	fmt.Printf("🔓 解密映射表数据成功，大小: %d 字节\n", len(decryptedData))

	// 解析JSON数据
	var mapData struct {
		Files map[string]*FileMapItem `json:"files"`
		Dirs  map[string]*DirMapItem  `json:"dirs"`
		Salt  string                  `json:"salt,omitempty"`
	}
	
	if err := json.Unmarshal(decryptedData, &mapData); err != nil {
		fmt.Printf("❌ 解析映射表JSON失败: %v\n", err)
		return key
	}
	fmt.Printf("📋 解析映射表JSON成功，条目数: %d\n", len(mapData.Files)+len(mapData.Dirs))

	// 如果映射表中有盐值，重新生成密钥
	if mapData.Salt != "" {
		fmt.Printf("🔑 提取到盐值: %s\n", mapData.Salt)
		newKey, err := generateEncryptKey(config.Password, config.EncryptType, mapData.Salt)
		if err != nil {
			fmt.Printf("❌ 使用映射表中的盐值重新生成密钥失败: %v\n", err)
		} else {
			fmt.Printf("🔄 新密钥已生成，长度: %d 字节\n", len(newKey))
			key = newKey
		}
	}

	// 更新映射表
	fmt.Printf("📊 loadGlobalMap: 更新前文件映射数量: %d\n", len(*fileMap))
	fmt.Printf("📊 loadGlobalMap: 更新前目录映射数量: %d\n", len(*dirMap))
	*fileMap = mapData.Files
	*dirMap = mapData.Dirs
	fmt.Printf("📊 loadGlobalMap: 更新后文件映射数量: %d\n", len(*fileMap))
	fmt.Printf("📊 loadGlobalMap: 更新后目录映射数量: %d\n", len(*dirMap))
	
	// 打印加载的映射信息（限制数量以避免过多输出）
	fileCount := 0
	for k, v := range *fileMap {
		if fileCount < 20 { // 只显示前20个
			fmt.Printf("📄 加载文件映射: %s -> %s (MD5: %s)\n", k, v.Path, v.Md5)
		} else if fileCount == 20 {
			fmt.Printf("📄 ... (还有 %d 个文件映射)\n", len(*fileMap)-20)
			break
		}
		fileCount++
	}
	
	dirCount := 0
	for k, v := range *dirMap {
		if dirCount < 10 { // 只显示前10个
			fmt.Printf("📁 加载目录映射: %s -> %s\n", k, v.OriginalPath)
		} else if dirCount == 10 {
			fmt.Printf("📁 ... (还有 %d 个目录映射)\n", len(*dirMap)-10)
			break
		}
		dirCount++
	}
	
	fmt.Printf("📄 加载文件映射: %d 项\n", len(*fileMap))
	fmt.Printf("📁 加载目录映射: %d 项\n", len(*dirMap))

	return key
}

// saveGlobalMap 保存全局映射表（保留原逻辑）
func saveGlobalMap(key []byte, config *DynamicConfig, fileMap map[string]*FileMapItem, dirMap map[string]*DirMapItem) {
	// 创建映射表存储目录
	if err := os.MkdirAll(config.MapStoragePath, 0755); err != nil {
		fmt.Printf("❌ 创建映射表存储目录失败: %v\n", err)
		return
	}

	// 准备映射表数据
	mapData := struct {
		Files map[string]*FileMapItem `json:"files"`
		Dirs  map[string]*DirMapItem  `json:"dirs"`
		Salt  string                  `json:"salt,omitempty"`
	}{
		Files: fileMap,
		Dirs:  dirMap,
	}

	// 如果密钥包含盐值，将其保存到映射表中
	if len(key) > SaltSize {
		salt := key[:SaltSize]
		mapData.Salt = base64.StdEncoding.EncodeToString(salt)
		fmt.Printf("🔐 保存盐值到映射表: %s\n", mapData.Salt)
	}

	// 序列化为JSON
	jsonData, err := json.Marshal(mapData)
	if err != nil {
		fmt.Printf("❌ 序列化映射表失败: %v\n", err)
		return
	}
	
	fmt.Printf("🔐 序列化映射表数据大小: %d 字节\n", len(jsonData))

	// 加密映射表数据
	encryptedData, err := encryptMapData(jsonData, key)
	if err != nil {
		fmt.Printf("❌ 加密映射表数据失败: %v\n", err)
		return
	}

	// 写入映射表文件
	mapPath := filepath.Join(config.MapStoragePath, config.MapFilename)
	if err := os.WriteFile(mapPath, encryptedData, 0600); err != nil {
		fmt.Printf("❌ 保存映射表文件失败: %v\n", err)
		return
	}

	fmt.Printf("✅ 映射表保存成功: %s\n", mapPath)
}

// encryptMapData 加密映射表（保留原逻辑）
func encryptMapData(data []byte, key []byte) ([]byte, error) {
	// 计算需要的填充长度
	padLen := aes.BlockSize - (len(data) % aes.BlockSize)
	if padLen == 0 {
		padLen = aes.BlockSize // 如果已经是块大小的倍数，仍需要添加一个完整的填充块
	}
	
	// 添加PKCS#7填充
	padBytes := bytesRepeat(byte(padLen), padLen)
	data = append(data, padBytes...)

	// 从key中提取实际的AES密钥（去掉盐值部分）
	actualKey := key
	if len(key) > SaltSize {
		actualKey = key[SaltSize:]
	}
	
	// 确保密钥长度符合AES要求（使用前32字节）
	if len(actualKey) > AESKeySize {
		actualKey = actualKey[:AESKeySize]
	}

	iv := make([]byte, aes.BlockSize)
	_, err := crand.Read(iv)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(actualKey)
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(data))
	mode.CryptBlocks(ciphertext, data)
	return append(iv, ciphertext...), nil
}

// decryptMapData 解密映射表（保留原逻辑）
func decryptMapData(encryptedData []byte, key []byte) ([]byte, error) {
	if len(encryptedData) < aes.BlockSize {
		return nil, fmt.Errorf("映射表数据长度非法")
	}

	// 从key中提取实际的AES密钥（去掉盐值部分）
	actualKey := key
	if len(key) > SaltSize {
		actualKey = key[SaltSize:]
	}
	
	// 确保密钥长度符合AES要求（使用前32字节）
	if len(actualKey) > AESKeySize {
		actualKey = actualKey[:AESKeySize]
	}

	iv := encryptedData[:aes.BlockSize]
	ciphertext := encryptedData[aes.BlockSize:]

	block, err := aes.NewCipher(actualKey)
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	// 检查并移除PKCS#7填充
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("解密后的数据为空")
	}
	
	padLen := int(plaintext[len(plaintext)-1])
	if padLen < 1 || padLen > aes.BlockSize || padLen > len(plaintext) {
		return nil, fmt.Errorf("映射表数据填充非法")
	}
	
	// 验证填充数据
	for i := len(plaintext) - padLen; i < len(plaintext); i++ {
		if plaintext[i] != byte(padLen) {
			return nil, fmt.Errorf("映射表数据填充非法")
		}
	}
	
	return plaintext[:len(plaintext)-padLen], nil
}

// 辅助工具函数（保留原逻辑）
func isFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func isDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func bytesRepeat(b byte, count int) []byte {
	bytes := make([]byte, count)
	for i := range bytes {
		bytes[i] = b
	}
	return bytes
}

// 规范化路径（跨平台支持）
func normalizePath(path string) string {
	// 确保路径使用系统特定的分隔符并清理多余部分
	cleanedPath := filepath.Clean(path)
	// 对于Windows系统，确保路径大小写一致性
	if runtime.GOOS == "windows" {
		// Windows不区分大小写，但保持原始大小写可能有帮助
		// 这里不进行大小写转换，但可以根据需要调整
	}
	return cleanedPath
}

// 安全地拼接路径，避免路径遍历攻击
func safeJoin(basePath, subPath string) (string, error) {
	// 确保基础路径是绝对路径，如果不是则转换为绝对路径
	if !filepath.IsAbs(basePath) {
		absBasePath, err := filepath.Abs(basePath)
		if err != nil {
			return "", fmt.Errorf("无法获取基础路径的绝对路径: %s, 错误: %v", basePath, err)
		}
		basePath = absBasePath
	}
	
	// 拼接路径
	joined := filepath.Join(basePath, subPath)
	
	// 验证拼接后的路径是否仍在基础路径内
	rel, err := filepath.Rel(basePath, joined)
	if err != nil || strings.HasPrefix(rel, "..") {
		return "", fmt.Errorf("路径拼接不安全，可能导致路径遍历: %s + %s", basePath, subPath)
	}
	
	return joined, nil
}















