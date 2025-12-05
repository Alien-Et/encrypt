# 文件加密工具 WebUI

这是一个现代化、响应式的Web管理界面，用于控制文件加密工具。该工具支持多种加密算法，具有直观的用户界面和强大的功能。

## 功能特性

- 🎨 精美现代化界面设计
- 📱 完全响应式，适配手机、平板和电脑
- 🔒 实时进度跟踪
- ⚙️ 配置管理
- 📁 文件映射表查看
- ▶️ 加密/解密操作控制
- 📜 实时日志查看
- 🔄 映射表实时更新显示，无需手动刷新
- 🚫 移除加解密操作的二次确认弹窗，提升操作效率

## 界面预览

![WebUI界面](webui/static/images/screenshot.png)

## 使用方法

### 命令行参数

```
-encrypt    启动加密模式
-decrypt    启动解密模式
-webui      启动WebUI管理界面
-help, -h   显示帮助信息
```

### 启动WebUI服务

1. 启动WebUI服务：
   ```bash
   ./encrypt -webui
   ```

2. 在浏览器中访问：http://localhost:9394

### 命令行模式

```bash
# 加密模式
./encrypt -encrypt

# 解密模式
./encrypt -decrypt
```

## 功能说明

### 仪表板
- 显示应用当前运行状态
- 显示正在进行的操作模式（加密/解密）
- 实时进度条显示处理进度
- 实时日志查看和下载

### 配置管理
- 设置加密密码
- 选择加密算法（AES/Blowfish/XOR）
- 配置目标路径（支持多个路径）
- 设置混淆文件名后缀
- 配置映射文件存储路径

### 映射表
- 查看已加密文件列表
- 显示原始路径、加密路径、MD5校验值等信息
- 实时更新显示，无需手动刷新

### 操作控制
- 启动加密操作
- 启动解密操作
- 停止当前操作

## 技术实现

- 前端：HTML5 + CSS3 + JavaScript + Font Awesome图标库
- 响应式设计：Flexbox + Grid
- 后端：Go语言
- 通信：RESTful API + Server-Sent Events
- 加密算法：AES/Blowfish/XOR
- 密钥派生：PBKDF2 with SHA-256

## 浏览器兼容性

- Chrome 60+
- Firefox 55+
- Safari 12+
- Edge 79+

## 构建和部署

### 自动构建
项目包含自动化的构建脚本，支持跨平台编译：

```bash
# 构建所有平台的二进制文件
./build.sh

# 构建特定平台
./build.sh linux amd64 encrypt-linux-amd64
```

支持的平台：
- Linux (amd64)
- Windows (amd64)
- macOS (amd64, arm64)
- Android (arm64)

### 配置文件
工具使用YAML格式的配置文件 `encrypt_config.yaml`：

```yaml
password: your_password_here
encrypt_type: aes
target_paths:
  - /path/to/target1
  - /path/to/target2
obfuscate_suffix: .dat
obfuscate_name_length: 12
map_filename: .app_encrypt
lock_filename: .encrypt.lock
map_storage_path: /path/to/map/storage
```

## 注意事项

- 请确保配置文件中的密码足够复杂以保证安全性
- 加密/解密操作可能需要较长时间，请耐心等待
- 操作过程中请勿关闭浏览器或刷新页面
- 映射表会自动保存，用于解密时恢复原始文件名
- 支持断点续传，可以在中断后继续操作