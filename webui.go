package main

import (
	"embed"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/blowfish"
	"gopkg.in/yaml.v2"
)

//go:embed webui/index.html
//go:embed webui/static/css/*
//go:embed webui/static/js/*
var webuiFiles embed.FS

// ProgressData represents the progress information
type ProgressData struct {
	CurrentProcessed int    `json:"current_processed"`
	TotalToProcess  int    `json:"total_to_process"`
	OperationType   string `json:"operation_type"`
	IsRunning       bool   `json:"is_running"`
}

// WebServer represents the web UI server
type WebServer struct {
	server *http.Server
	port   string
	mu     sync.Mutex
}

// Global server instance
var globalServer *WebServer

// Global progress tracking
var (
	currentProgress ProgressData
	progressMutex  sync.RWMutex
)

// Global operation context for cancellation
var (
	operationCtx    context.Context
	operationCancel context.CancelFunc
	operationMutex  sync.Mutex
)

// Log channel management
var (
	logChannels = make(map[chan string]bool)
	logMutex    = sync.RWMutex{}
)

// NewWebServer creates a new web server instance
func NewWebServer(port string) *WebServer {
	return &WebServer{
		port: port,
	}
}

// Start starts the web server
func (ws *WebServer) Start() error {
	// Define routes
	http.HandleFunc("/", ws.serveIndex)
	http.HandleFunc("/api/config", ws.handleConfig)
	http.HandleFunc("/api/files", ws.handleFiles)
	http.HandleFunc("/api/preview", ws.handlePreview)
	http.HandleFunc("/api/decrypt-preview", ws.handleDecryptPreview)
	http.HandleFunc("/api/start", ws.handleStart)
	http.HandleFunc("/api/stop", ws.handleStop)
	http.HandleFunc("/api/status", ws.handleStatus)
	http.HandleFunc("/api/logs", ws.handleLogs)
	http.HandleFunc("/api/progress", ws.handleProgress)

	// Serve static files
	// Serve static files from embedded filesystem
	staticFS, err := fs.Sub(webuiFiles, "webui/static")
	if err != nil {
		fmt.Printf("警告: 无法创建静态文件子系统: %v\n", err)
		// Fallback to directory-based serving
		http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("webui/static"))))
	} else {
		http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))
	}
	// Create server
	ws.server = &http.Server{
		Addr: ":" + ws.port,
	}

	fmt.Printf("🚀 WebUI服务器启动，监听端口 %s\n", ws.port)
	fmt.Printf("🌐 访问地址: http://localhost:%s\n", ws.port)

	// Start server
	return ws.server.ListenAndServe()
}

// Stop stops the web server
func (ws *WebServer) Stop() error {
	ws.mu.Lock()
	defer ws.mu.Unlock()

	if ws.server != nil {
		fmt.Println("🛑 正在停止WebUI服务器...")
		// Create a context with timeout for graceful shutdown
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// Attempt graceful shutdown
		if err := ws.server.Shutdown(ctx); err != nil {
			fmt.Printf("❌ WebUI服务器优雅关闭失败: %v\n", err)
			// Force close
			if err := ws.server.Close(); err != nil {
				return fmt.Errorf("强制关闭服务器失败: %v", err)
			}
		} else {
			fmt.Println("✅ WebUI服务器已优雅关闭")
		}
		ws.server = nil
	}
	return nil
}

// IsRunning checks if the server is running
func (ws *WebServer) IsRunning() bool {
	ws.mu.Lock()
	defer ws.mu.Unlock()
	return ws.server != nil
}

// serveIndex serves the main HTML page
func (ws *WebServer) serveIndex(w http.ResponseWriter, r *http.Request) {
	// If requesting the root path, serve index.html
	if r.URL.Path == "/" || r.URL.Path == "" {
		// Try to serve index.html from embedded filesystem first
		indexData, err := webuiFiles.ReadFile("webui/index.html")
		if err == nil {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write(indexData)
			return
		}
		
		// If webui/index.html exists, serve it
		indexPath := filepath.Join("webui", "index.html")
		if _, err := os.Stat(indexPath); err == nil {
			http.ServeFile(w, r, indexPath)
			return
		}
		
		// Fallback to simple UI
		html := `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>文件加密工具 - Web管理界面</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background-color: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #333; text-align: center; }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        button { background-color: #007bff; color: white; border: none; padding: 10px 20px; cursor: pointer; border-radius: 4px; }
        button:hover { background-color: #0056b3; }
        input, select, textarea { width: 100%; padding: 8px; margin: 5px 0; box-sizing: border-box; }
        label { font-weight: bold; }
        .status { padding: 10px; margin: 10px 0; border-radius: 4px; }
        .success { background-color: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .error { background-color: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        .file-list { max-height: 300px; overflow-y: auto; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 文件加密工具 - Web管理界面</h1>
        
        <div class="section">
            <h2>应用查看</h2>
            <button onclick="checkStatus()">检查应用状态</button>
            <div id="statusResult"></div>
        </div>
        
        <div class="section">
            <h2>配置管理</h2>
            <button onclick="loadConfig()">加载配置</button>
            <button onclick="saveConfig()">保存配置</button>
            <div id="configForm"></div>
        </div>
        
        <div class="section">
            <h2>文件操作</h2>
            <button onclick="listFiles()">查看加密文件</button>
            <button onclick="startEncrypt()">开始加密</button>
            <button onclick="startDecrypt()">开始解密</button>
            <div id="filesList" class="file-list"></div>
        </div>
    </div>

    <script>
        function checkStatus() {
            fetch('/api/status')
                .then(response => response.json())
                .then(data => {
                    const resultDiv = document.getElementById('statusResult');
                    resultDiv.innerHTML = '<div class="status success">应用状态: 运行中</div>';
                })
                .catch(error => {
                    const resultDiv = document.getElementById('statusResult');
                    resultDiv.innerHTML = '<div class="status error">应用状态: 未运行</div>';
                });
        }

        function loadConfig() {
            fetch('/api/config')
                .then(response => response.json())
                .then(data => {
                    // Display config form
                    const formHtml = '
                        <label>密码:</label>\n
                        <input type="password" id="password" value="'+(data.password || '')+'">\n
                        \n
                        <label>加密算法:</label>\n
                        <select id="encryptType">\n
                            <option value="aes" '+(data.encrypt_type === 'aes' ? 'selected' : '')+'>AES</option>\n
                            <option value="blowfish" '+(data.encrypt_type === 'blowfish' ? 'selected' : '')+'>Blowfish</option>\n
                            <option value="xor" '+(data.encrypt_type === 'xor' ? 'selected' : '')+'>XOR</option>\n
                        </select>\n
                        \n
                        <label>目标路径 (每行一个):</label>\n
                        <textarea id="targetPaths" rows="4">'+(data.target_paths ? data.target_paths.join('\n') : '')+'</textarea>\n
                    ';
                    document.getElementById('configForm').innerHTML = formHtml;
                })
                .catch(error => {
                    alert('加载配置失败: ' + error);
                });
        }

        function saveConfig() {
            const config = {
                password: document.getElementById('password').value,
                encrypt_type: document.getElementById('encryptType').value,
                target_paths: document.getElementById('targetPaths').value.split('\n').filter(p => p.trim() !== '')
            };

            fetch('/api/config', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(config)
            })
            .then(response => response.json())
            .then(data => {
                alert('配置保存成功');
            })
            .catch(error => {
                alert('保存配置失败: ' + error);
            });
        }

        function listFiles() {
            fetch('/api/files')
                .then(response => response.json())
                .then(data => {
                    let html = '<h3>加密文件列表:</h3><ul>';
                    data.files.forEach(file => {
                        html += '<li>'+file.original_path+' -> '+file.encrypted_path+' ('+file.size+' bytes)</li>';
                    });
                    html += '</ul>';
                    document.getElementById('filesList').innerHTML = html;
                })
                .catch(error => {
                    alert('获取文件列表失败: ' + error);
                });
        }

        function startEncrypt() {
            if (confirm('确定要开始加密吗？')) {
                fetch('/api/start?mode=encrypt', { method: 'POST' })
                    .then(response => response.json())
                    .then(data => {
                        alert('加密任务已启动');
                    })
                    .catch(error => {
                        alert('启动加密失败: ' + error);
                    });
            }
        }

        function startDecrypt() {
            if (confirm('确定要开始解密吗？这将还原所有加密文件。')) {
                fetch('/api/start?mode=decrypt', { method: 'POST' })
                    .then(response => response.json())
                    .then(data => {
                        alert('解密任务已启动');
                    })
                    .catch(error => {
                        alert('启动解密失败: ' + error);
                    });
            }
        }
    </script>
</body>
</html>`
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, html)
		return
	}
	
	// Handle static files
	// Try embedded filesystem first
	if strings.HasPrefix(r.URL.Path, "/static/") {
		filePath := filepath.Join("webui", r.URL.Path[1:]) // Remove leading slash
		data, err := webuiFiles.ReadFile(filePath)
		if err == nil {
			// Set appropriate content type
			contentType := "application/octet-stream"
			ext := filepath.Ext(filePath)
			switch ext {
			case ".css":
				contentType = "text/css"
			case ".js":
				contentType = "application/javascript"
			case ".html":
				contentType = "text/html"
			case ".png", ".jpg", ".jpeg", ".gif", ".ico":
				contentType = "image/" + strings.TrimPrefix(ext, ".")
			}
			w.Header().Set("Content-Type", contentType)
			w.Write(data)
			return
		}
	}
	
	// Try to serve static files from disk
	if strings.HasPrefix(r.URL.Path, "/static/") {
		staticPath := filepath.Join("webui", r.URL.Path[1:]) // Remove leading slash
		if _, err := os.Stat(staticPath); err == nil {
			http.ServeFile(w, r, staticPath)
			return
		}
	}
	
	// If we get here, the file was not found
	http.NotFound(w, r)
}

// handleConfig handles configuration API requests
func (ws *WebServer) handleConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case "GET":
		// Get current config
		config, err := loadCurrentConfig()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		
		json.NewEncoder(w).Encode(config)
		
	case "POST":
		// Save config
		var config DynamicConfig
		if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		
		if err := saveConfig(&config); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "success"})
		
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleFiles handles file listing API requests
func (ws *WebServer) handleFiles(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	// Get encrypted files list
	files, err := getEncryptedFiles()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	
	response := map[string]interface{}{
		"files": files,
	}
	
	json.NewEncoder(w).Encode(response)
}

// handlePreview handles file preview API requests
func (ws *WebServer) handlePreview(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Get file path from query parameters
	filePath := r.URL.Query().Get("path")
	if filePath == "" {
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Missing file path",
		})
		return
	}

	// Check if file exists
	if isFile(filePath) {
		// Prepare basic response with file path info
		response := map[string]interface{}{
			"path":         filePath,
			"is_encrypted": true, // 标记为加密文件
			"preview_info": "这是一个加密文件，要查看内容需要先解密", // 提示信息
			"size":         int64(0),
			"modified":     "未知",
			"content_type": "加密文件",
		}	
		
		// Get file stats
		stat, err := os.Stat(filePath)
		if err == nil {
			response["size"] = stat.Size()
			response["modified"] = stat.ModTime().Format("2006-01-02 15:04:05")
			
			// Try to read first few bytes to determine file type
			file, err := os.Open(filePath)
			if err == nil {
				defer file.Close()
				
				// Read first 512 bytes for MIME type detection
				buffer := make([]byte, 512)
				_, err = file.Read(buffer)
				if err == nil || err == io.EOF {
					// Detect content type
					contentType := http.DetectContentType(buffer)
					response["content_type"] = contentType
					response["is_image"] = strings.HasPrefix(contentType, "image/")
					response["is_text"] = strings.HasPrefix(contentType, "text/") || contentType == "application/json"
				}
			}
		}
		
		json.NewEncoder(w).Encode(response)
	} else {
		// File doesn't exist, return error
		json.NewEncoder(w).Encode(map[string]string{
			"error": "文件不存在: " + filePath,
		})
	}
}

// handleDecryptPreview handles decrypted file preview API requests
func (ws *WebServer) handleDecryptPreview(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Get file path from query parameters
	filePath := r.URL.Query().Get("path")
	if filePath == "" {
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Missing file path",
		})
		return
	}

	// Load current config to get target directory and password
	config, err := loadCurrentConfig()
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Failed to load config: " + err.Error(),
		})
		return
	}

	// Load mapping table to find the actual encrypted file path
	globalFileMap := make(map[string]*FileMapItem)
	globalDirMap := make(map[string]*DirMapItem)
	
	// Generate key from config
	var key []byte
	key, err = generateEncryptKey(config.Password, config.EncryptType, config.Salt)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Failed to generate key: " + err.Error(),
		})
		return
	}
	
	// Load the mapping table using the proper decryption method
	key = loadGlobalMap(key, config, &globalFileMap, &globalDirMap)
	
	// Find the encrypted file path from the mapping table
	var actualFilePath string
	found := false

	// Look for the file in the mapping table
	// globalFileMap 的 key 是加密后的文件名，item.Path 是原始相对路径
	for encryptedName, item := range globalFileMap {
		// Check if the encrypted file name matches the requested path
		if encryptedName == filePath || filepath.Base(encryptedName) == filePath {
			actualFilePath = filepath.Join(item.TargetDir, encryptedName)
			found = true
			break
		}
		// Also check if the original path matches
		if item.Path == filePath || filepath.Base(item.Path) == filePath {
			actualFilePath = filepath.Join(item.TargetDir, encryptedName)
			found = true
			break
		}
	}
	
	// If not found in mapping table, try to construct path from target directories
	if !found {
		// Try each target directory
		for _, targetPath := range config.TargetPaths {
			candidatePath := filepath.Join(targetPath, filePath)
			if isFile(candidatePath) {
				actualFilePath = candidatePath
				found = true
				break
			}
		}
	}

	// If still not found, return error
	if !found {
		json.NewEncoder(w).Encode(map[string]string{
			"error": "File not found in mapping table or target directories: " + filePath,
		})
		return
	}	
	// Check if file exists
	if !isFile(actualFilePath) {
		json.NewEncoder(w).Encode(map[string]string{
			"error": "File not found: " + actualFilePath,
		})
		return
	}	
	// Decrypt file content
	decryptedContent, err := decryptFileContent(actualFilePath, key, config.EncryptType)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Failed to decrypt file: " + err.Error(),
		})
		return
	}

	// Get file stats
	stat, err := os.Stat(actualFilePath)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Failed to get file stats: " + err.Error(),
		})
		return
	}

	// Detect content type from decrypted content
	contentType := http.DetectContentType(decryptedContent)

	// Prepare response
	response := map[string]interface{}{
		"path":           actualFilePath,
		"size":           len(decryptedContent),
		"original_size":  stat.Size(),
		"modified":       stat.ModTime().Format("2006-01-02 15:04:05"),
		"content_type":   contentType,
		"is_image":       strings.HasPrefix(contentType, "image/"),
		"is_text":        strings.HasPrefix(contentType, "text/") || contentType == "application/json",
		"content":        base64.StdEncoding.EncodeToString(decryptedContent),
		"is_decrypted":   true,
		"preview_info":   "文件已成功解密预览",
	}

	json.NewEncoder(w).Encode(response)
}

// handleStart handles start encryption/decryption API requests
func (ws *WebServer) handleStart(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	mode := r.URL.Query().Get("mode")
	if mode != "encrypt" && mode != "decrypt" {
		http.Error(w, "Invalid mode. Use 'encrypt' or 'decrypt'", http.StatusBadRequest)
		return
	}

	// Cancel any existing operation
	operationMutex.Lock()
	if operationCancel != nil {
		operationCancel()
	}
	// Create a new context for the operation
	operationCtx, operationCancel = context.WithCancel(context.Background())
	operationMutex.Unlock()

	// Start the operation in a goroutine with context
	go func(ctx context.Context) {
		select {
		case <-ctx.Done():
			return
		default:
			if mode == "encrypt" {
				startEncryption()
			} else {
				startDecryption()
			}
		}
	}(operationCtx)

	response := map[string]string{
		"status": "started",
		"mode":   mode,
	}

	json.NewEncoder(w).Encode(response)
}

// handleStop handles stop API requests
func (ws *WebServer) handleStop(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Cancel any running operation
	operationMutex.Lock()
	if operationCancel != nil {
		operationCancel()
		broadcastLog(`{"message": "操作已取消", "level": "warn", "type": "cancelled"}`)
	}
	operationMutex.Unlock()

	// Stop the server
	if err := ws.Stop(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]string{
		"status": "stopped",
	}

	json.NewEncoder(w).Encode(response)
}

// handleLogs handles log streaming API requests
func (ws *WebServer) handleLogs(w http.ResponseWriter, r *http.Request) {
	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// Create a channel for log messages
	logChan := make(chan string, 100)

	// Register the channel
	registerLogChannel(logChan)
	defer unregisterLogChannel(logChan)

	// Send initial message
	fmt.Fprintf(w, "data: %s\n\n", `{"message": "Connected to log stream"}`)
	w.(http.Flusher).Flush()

	// Listen for log messages
	for {
		select {
		case logMsg := <-logChan:
			fmt.Fprintf(w, "data: %s\n\n", logMsg)
			w.(http.Flusher).Flush()
		case <-r.Context().Done():
			return
		}
	}
}

// registerLogChannel registers a log channel
func registerLogChannel(ch chan string) {
	logMutex.Lock()
	defer logMutex.Unlock()
	logChannels[ch] = true
}

// unregisterLogChannel unregisters a log channel
func unregisterLogChannel(ch chan string) {
	logMutex.Lock()
	defer logMutex.Unlock()
	delete(logChannels, ch)
}

// broadcastLog broadcasts a log message to all channels
func broadcastLog(message string) {
	logMutex.RLock()
	defer logMutex.RUnlock()
	
	for ch := range logChannels {
		select {
		case ch <- message:
		default:
			// Channel is full, skip
		}
	}
}

// handleStatus handles status check API requests
func (ws *WebServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	status := "stopped"
	if ws.IsRunning() {
		status = "running"
	}

	response := map[string]string{
		"status": status,
	}
	
	json.NewEncoder(w).Encode(response)
}

// loadCurrentConfig loads the current configuration
func loadCurrentConfig() (*DynamicConfig, error) {
	exePath, err := os.Executable()
	if err != nil {
		return nil, err
	}
	exeDir := filepath.Dir(exePath)
	configPath := filepath.Join(exeDir, CONFIG_FILENAME_YAML)

	// Check if config file exists
	if !isFile(configPath) {
		// Return default config if file doesn't exist
		defaultConfig := &DynamicConfig{
			Password:            "",
			EncryptType:         EncryptTypeAES,
			TargetPaths:         []string{},
			ObfuscateSuffix:     ".dat",
			ObfuscateNameLength: 12,
			MapFilename:         ".app_encrypt",
			LockFilename:        ".encrypt.lock",
			MapStoragePath:      filepath.Join(exeDir, "tmp"),
			Salt:                "",
		}
		return defaultConfig, nil
	}

	// Load existing config
	return loadDynamicConfig(configPath)
}

// saveConfig saves the configuration
func saveConfig(config *DynamicConfig) error {
	exePath, err := os.Executable()
	if err != nil {
		return err
	}
	exeDir := filepath.Dir(exePath)
	configPath := filepath.Join(exeDir, CONFIG_FILENAME_YAML)

	// Ensure config directory exists
	configDir := filepath.Dir(configPath)
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("创建配置目录失败: %v", err)
	}

	file, err := os.Create(configPath)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := yaml.NewEncoder(file)
	defer encoder.Close()

	return encoder.Encode(config)
}

// loadGlobalMapWithSalt 加载全局映射表并返回盐值
func loadGlobalMapWithSalt(key []byte, config *DynamicConfig, fileMap *map[string]*FileMapItem, dirMap *map[string]*DirMapItem, salt *string) []byte {
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

	// 设置盐值
	*salt = mapData.Salt
	fmt.Printf("🔑 提取到盐值: %s\n", mapData.Salt)

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

// getEncryptedFiles gets a list of encrypted files, organized by target paths
func getEncryptedFiles() ([]map[string]interface{}, error) {
	// Load config to get target paths and map storage path
	config, err := loadCurrentConfig()
	if err != nil {
		fmt.Printf("[DEBUG] 加载配置失败: %v\n", err)
		return nil, err
	}

	var files []map[string]interface{}
	var salt string // 用于存储盐值

	fmt.Printf("[DEBUG] MapStoragePath: %s, MapFilename: %s\n", config.MapStoragePath, config.MapFilename)

	// Check map storage path for encrypted files
	if config.MapStoragePath != "" {
		// Read mapping file to get encrypted file list
		mapPath := filepath.Join(config.MapStoragePath, config.MapFilename)
		fmt.Printf("[DEBUG] 映射文件路径: %s\n", mapPath)
		fmt.Printf("[DEBUG] 映射文件是否存在: %v\n", isFile(mapPath))
		
		if isFile(mapPath) {
			// Initialize maps
			globalFileMap := make(map[string]*FileMapItem)
			globalDirMap := make(map[string]*DirMapItem)
			
			// 先尝试读取独立的盐值文件
			saltPath := filepath.Join(config.MapStoragePath, config.MapFilename+".salt")
			if isFile(saltPath) {
				saltBytes, err := os.ReadFile(saltPath)
				if err == nil {
					config.Salt = strings.TrimSpace(string(saltBytes))
					fmt.Printf("[DEBUG] 从独立文件读取到盐值: %s\n", config.Salt)
				}
			}
			
			// Generate a dummy key for loading (we only need to read the file list, not decrypt files)
			key, err := generateEncryptKey(config.Password, config.EncryptType, config.Salt)
			if err != nil {
				fmt.Printf("[DEBUG] 生成密钥失败: %v\n", err)
				return nil, err
			}
			
			// Load the mapping file using the proper decryption method and extract salt
			key = loadGlobalMapWithSalt(key, config, &globalFileMap, &globalDirMap, &salt)
			fmt.Printf("[DEBUG] 成功加载映射文件，文件数量: %d\n", len(globalFileMap))
			
			// Group files by target directory
			targetFiles := make(map[string][]map[string]interface{})
			
			// Extract file information
			for encryptedName, item := range globalFileMap {
				// 构建正确的加密文件完整路径
				encryptedFilePath := filepath.Join(item.TargetDir, encryptedName)
				
				fileInfo := map[string]interface{}{
					"original_path":  item.Path,
					"encrypted_path": encryptedName,
					"target_dir":     item.TargetDir,
					"md5":            item.Md5,
					"salt":           salt,         // 添加盐值信息
					"password":       config.Password, // 添加加密密码信息
					"encrypt_type":   config.EncryptType, // 添加加密类型
				}
				
				// Get file stats if the encrypted file exists
				if isFile(encryptedFilePath) {
					if stat, err := os.Stat(encryptedFilePath); err == nil {
						fileInfo["size"] = stat.Size()
						fileInfo["modified"] = stat.ModTime().Format("2006-01-02 15:04:05")
					}
				}
				
				// Group by target directory
				targetDir := item.TargetDir
				if targetDir == "" {
					targetDir = "unknown"
				}
				
				if _, exists := targetFiles[targetDir]; !exists {
					targetFiles[targetDir] = []map[string]interface{}{}
				}
				targetFiles[targetDir] = append(targetFiles[targetDir], fileInfo)
			}
			
			// Flatten the grouped files into a single list
			for _, fileGroup := range targetFiles {
				files = append(files, fileGroup...)
			}
			
			fmt.Printf("[DEBUG] 分组后的文件数量: %d\n", len(files))
		} else {
			fmt.Printf("[DEBUG] 映射文件不存在\n")
		}
	} else {
		fmt.Printf("[DEBUG] MapStoragePath为空\n")
	}

	fmt.Printf("[DEBUG] 返回文件数量: %d\n", len(files))
	return files, nil
}
// startEncryption starts the encryption process
func startEncryption() {
	// 广播日志消息
	broadcastLog(`{"message": "开始加密操作", "level": "info"}`)

	// 设置进度为运行状态
	progressMutex.Lock()
	currentProgress.IsRunning = true
	currentProgress.OperationType = "encrypt"
	currentProgress.CurrentProcessed = 0
	currentProgress.TotalToProcess = 0
	progressMutex.Unlock()

	// 获取当前配置
	config, err := loadCurrentConfig()
	if err != nil {
		broadcastLog(fmt.Sprintf(`{"message": "加载配置失败: %s", "level": "error"}`, err.Error()))
		// 重置进度状态
		progressMutex.Lock()
		currentProgress.IsRunning = false
		progressMutex.Unlock()
		return
	}

	// 验证配置
	if err := validateConfig(config); err != nil {
		broadcastLog(fmt.Sprintf(`{"message": "配置验证失败: %s", "level": "error"}`, err.Error()))
		// 重置进度状态
		progressMutex.Lock()
		currentProgress.IsRunning = false
		progressMutex.Unlock()
		return
	}

	// 过滤有效路径
	var validPaths []string
	for _, path := range config.TargetPaths {
		if strings.TrimSpace(path) != "" {
			validPaths = append(validPaths, path)
		}
	}

	if len(validPaths) == 0 {
		broadcastLog(`{"message": "配置中无有效目标路径", "level": "error"}`)
		// 重置进度状态
		progressMutex.Lock()
		currentProgress.IsRunning = false
		progressMutex.Unlock()
		return
	}

	// 生成密钥
	key, err := generateEncryptKey(config.Password, config.EncryptType, config.Salt)
	if err != nil {
		broadcastLog(fmt.Sprintf(`{"message": "生成加密密钥失败: %s", "level": "error"}`, err.Error()))
		// 重置进度状态
		progressMutex.Lock()
		currentProgress.IsRunning = false
		progressMutex.Unlock()
		return
	}

	// 初始化统计数据
	stat := &StatData{}

	// 初始化映射表
	globalFileMap := make(map[string]*FileMapItem)
	globalDirMap := make(map[string]*DirMapItem)

	// 加载现有映射表
	broadcastLog(`{"message": "正在加载映射表...", "level": "info"}`)
	key = loadGlobalMap(key, config, &globalFileMap, &globalDirMap)
	broadcastLog(fmt.Sprintf(`{"message": "加载文件映射: %d 项", "level": "info"}`, len(globalFileMap)))
	broadcastLog(fmt.Sprintf(`{"message": "加载目录映射: %d 项", "level": "info"}`, len(globalDirMap)))

	// 统计待处理项总数
	var totalFilesAll, totalDirsAll int
	for _, path := range validPaths {
		if isDir(path) {
			fCount, dCount := countActualItems(path, config)
			totalFilesAll += fCount
			totalDirsAll += dCount
		}
	}
	stat.TotalScanned = totalFilesAll + totalDirsAll

	// 更新总处理数量
	progressMutex.Lock()
	currentProgress.TotalToProcess = stat.TotalScanned
	progressMutex.Unlock()

	broadcastLog(fmt.Sprintf(`{"message": "总计待处理项: %d", "level": "info"}`, stat.TotalScanned))

	// 处理每个目标目录
	for _, path := range validPaths {
		broadcastLog(fmt.Sprintf(`{"message": "开始处理目录: %s", "level": "info"}`, path))
		processTargetDir(path, key, config, globalFileMap, globalDirMap, stat)
		// 更新进度
		progressMutex.Lock()
		currentProgress.CurrentProcessed = stat.TotalFilesEncrypted + stat.TotalDirsObfuscated + stat.TotalDuplicateDel
		progressMutex.Unlock()
	}

	// 保存全局映射表
	saveGlobalMap(key, config, globalFileMap, globalDirMap)

	// 输出统计信息
	broadcastLog(`{"message": "==================== 加密完成 ===================", "level": "info"}`)
	broadcastLog(fmt.Sprintf(`{"message": "已加密文件：%d", "level": "info"}`, stat.TotalFilesEncrypted))
	broadcastLog(fmt.Sprintf(`{"message": "已混淆目录：%d", "level": "info"}`, stat.TotalDirsObfuscated))
	broadcastLog(fmt.Sprintf(`{"message": "已删除重复文件：%d", "level": "info"}`, stat.TotalDuplicateDel))
	broadcastLog(`{"message": "===============================================", "level": "info"}`)
	// 发送操作完成信号
	broadcastLog(`{"message": "操作完成", "level": "success", "type": "complete"}`)

	// 重置进度状态
	progressMutex.Lock()
	currentProgress.IsRunning = false
	progressMutex.Unlock()
}

// decryptFileContent decrypts the content of a file
func decryptFileContent(filePath string, key []byte, encryptType string) ([]byte, error) {
	// Read encrypted file
	encryptedData, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("读取文件失败: %v", err)
	}

	// Decrypt based on encryption type
	switch encryptType {
	case EncryptTypeAES:
		return decryptAES(encryptedData, key)
	case EncryptTypeBlowfish:
		return decryptBlowfish(encryptedData, key)
	case EncryptTypeXOR:
		return decryptXOR(encryptedData, key)
	default:
		return nil, fmt.Errorf("不支持的加密类型: %s", encryptType)
	}
}

// decryptAES decrypts data using AES
func decryptAES(encryptedData, key []byte) ([]byte, error) {
	if len(encryptedData) < aes.BlockSize {
		return nil, fmt.Errorf("加密数据长度不足")
	}

	// Extract IV
	iv := encryptedData[:aes.BlockSize]
	ciphertext := encryptedData[aes.BlockSize:]

	// Extract actual key (remove salt if present)
	actualKey := key
	if len(key) > SaltSize {
		actualKey = key[SaltSize:] // Skip the salt part
	}

	// Ensure key size is correct for AES
	if len(actualKey) > AESKeySize {
		actualKey = actualKey[:AESKeySize] // Trim to 32 bytes for AES-226
	}

	// Create cipher
	block, err := aes.NewCipher(actualKey)
	if err != nil {
		return nil, err
	}

	// Decrypt
	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	// Remove PKCS#7 padding
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("解密后的数据为空")
	}
	
	// Calculate padding length
	padLen := int(plaintext[len(plaintext)-1])
	if padLen > len(plaintext) || padLen > aes.BlockSize {
		return nil, fmt.Errorf("无效的填充长度")
	}
	
	// Validate padding
	for i := len(plaintext) - padLen; i < len(plaintext); i++ {
		if plaintext[i] != byte(padLen) {
			return nil, fmt.Errorf("无效的填充数据")
		}
	}
	
	return plaintext[:len(plaintext)-padLen], nil
}

// decryptBlowfish decrypts data using Blowfish
func decryptBlowfish(encryptedData, key []byte) ([]byte, error) {
	if len(encryptedData) < blowfish.BlockSize {
		return nil, fmt.Errorf("加密数据长度不足")
	}

	// Extract IV
	iv := encryptedData[:blowfish.BlockSize]
	ciphertext := encryptedData[blowfish.BlockSize:]

	// Extract actual key (remove salt if present)
	actualKey := key
	if len(key) > SaltSize {
		actualKey = key[SaltSize:]
	}

	// Ensure key size is correct for Blowfish
	if len(actualKey) > BlowfishKeySize {
		actualKey = actualKey[:BlowfishKeySize]
	}

	// Create cipher
	block, err := blowfish.NewCipher(actualKey)
	if err != nil {
		return nil, err
	}

	// Decrypt
	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	// Remove PKCS#7 padding
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("解密后的数据为空")
	}

	// Calculate padding length
	padLen := int(plaintext[len(plaintext)-1])
	if padLen > len(plaintext) || padLen > blowfish.BlockSize {
		return nil, fmt.Errorf("无效的填充长度")
	}

	// Validate padding
	for i := len(plaintext) - padLen; i < len(plaintext); i++ {
		if plaintext[i] != byte(padLen) {
			return nil, fmt.Errorf("无效的填充数据")
		}
	}

	return plaintext[:len(plaintext)-padLen], nil
}

// decryptXOR decrypts data using XOR
func decryptXOR(encryptedData, key []byte) ([]byte, error) {
	if len(encryptedData) == 0 {
		return nil, fmt.Errorf("加密数据为空")
	}

	// Extract actual key (remove salt if present)
	actualKey := key
	if len(key) > SaltSize {
		actualKey = key[SaltSize:]
	}

	// Ensure key size is correct for XOR
	if len(actualKey) != XORKeySize {
		return nil, fmt.Errorf("XOR密钥长度错误，需要%d字节，实际为%d字节", XORKeySize, len(actualKey))
	}

	// Decrypt by XORing with the same key
	plaintext := make([]byte, len(encryptedData))
	keyLen := len(actualKey)
	for i := range encryptedData {
		plaintext[i] = encryptedData[i] ^ actualKey[i%keyLen]
	}

	return plaintext, nil
}

// handleProgress handles progress tracking API requests
func (ws *WebServer) handleProgress(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	progressMutex.RLock()
	defer progressMutex.RUnlock()

	json.NewEncoder(w).Encode(currentProgress)
}

// startDecryption starts the decryption process
func startDecryption() {
	// 广播日志消息
	broadcastLog(`{"message": "开始解密操作", "level": "info"}`)

	// 设置进度为运行状态
	progressMutex.Lock()
	currentProgress.IsRunning = true
	currentProgress.OperationType = "decrypt"
	currentProgress.CurrentProcessed = 0
	currentProgress.TotalToProcess = 0
	progressMutex.Unlock()

	// 获取当前配置
	config, err := loadCurrentConfig()
	if err != nil {
		broadcastLog(fmt.Sprintf(`{"message": "加载配置失败: %s", "level": "error"}`, err.Error()))
		// 重置进度状态
		progressMutex.Lock()
		currentProgress.IsRunning = false
		progressMutex.Unlock()
		return
	}

	// 验证配置
	if err := validateConfig(config); err != nil {
		broadcastLog(fmt.Sprintf(`{"message": "配置验证失败: %s", "level": "error"}`, err.Error()))
		// 重置进度状态
		progressMutex.Lock()
		currentProgress.IsRunning = false
		progressMutex.Unlock()
		return
	}

	// 过滤有效路径
	var validPaths []string
	for _, path := range config.TargetPaths {
		if strings.TrimSpace(path) != "" {
			validPaths = append(validPaths, path)
		}
	}

	if len(validPaths) == 0 {
		broadcastLog(`{"message": "配置中无有效目标路径", "level": "error"}`)
		// 重置进度状态
		progressMutex.Lock()
		currentProgress.IsRunning = false
		progressMutex.Unlock()
		return
	}

	// 生成密钥
	key, err := generateEncryptKey(config.Password, config.EncryptType, config.Salt)
	if err != nil {
		broadcastLog(fmt.Sprintf(`{"message": "生成解密密钥失败: %s", "level": "error"}`, err.Error()))
		// 重置进度状态
		progressMutex.Lock()
		currentProgress.IsRunning = false
		progressMutex.Unlock()
		return
	}

	// 初始化统计数据
	stat := &StatData{}

	// 初始化映射表
	globalFileMap := make(map[string]*FileMapItem)
	globalDirMap := make(map[string]*DirMapItem)

	// 加载映射表
	broadcastLog(`{"message": "正在加载映射表...", "level": "info"}`)
	key = loadGlobalMap(key, config, &globalFileMap, &globalDirMap)
	broadcastLog(fmt.Sprintf(`{"message": "加载文件映射: %d 项", "level": "info"}`, len(globalFileMap)))
	broadcastLog(fmt.Sprintf(`{"message": "加载目录映射: %d 项", "level": "info"}`, len(globalDirMap)))

	// 处理解密
	for _, path := range validPaths {
		broadcastLog(fmt.Sprintf(`{"message": "开始解密目录: %s", "level": "info"}`, path))
		decryptTargetDir(path, key, config, globalFileMap, globalDirMap, stat)
		// 更新进度
		progressMutex.Lock()
		currentProgress.CurrentProcessed = stat.TotalFilesEncrypted + stat.TotalDirsObfuscated
		progressMutex.Unlock()
	}

	// 解密完成后，删除映射表文件
	mapPath := filepath.Join(config.MapStoragePath, config.MapFilename)
	if isFile(mapPath) {
		if err := os.Remove(mapPath); err != nil {
			broadcastLog(fmt.Sprintf(`{"message": "删除映射表文件失败: %s", "level": "warn"}`, err.Error()))
		} else {
			broadcastLog(fmt.Sprintf(`{"message": "映射表文件已删除: %s", "level": "info"}`, mapPath))
		}
	} else {
		broadcastLog(fmt.Sprintf(`{"message": "映射表文件不存在: %s", "level": "info"}`, mapPath))
	}

	// 输出解密统计信息
	broadcastLog(`{"message": "==================== 解密完成 ===================", "level": "info"}`)
	broadcastLog(fmt.Sprintf(`{"message": "已解密文件：%d", "level": "info"}`, stat.TotalFilesEncrypted))
	broadcastLog(fmt.Sprintf(`{"message": "已恢复目录：%d", "level": "info"}`, stat.TotalDirsObfuscated))
	broadcastLog(`{"message": "===============================================", "level": "info"}`)
	// 发送操作完成信号
	broadcastLog(`{"message": "操作完成", "level": "success", "type": "complete"}`)

	// 重置进度状态
	progressMutex.Lock()
	currentProgress.IsRunning = false
	progressMutex.Unlock()
}


