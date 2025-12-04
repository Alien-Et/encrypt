#!/bin/bash

# 加密工具打包脚本
# 输出全平台的64位二进制文件

# 确保在正确的目录下执行
cd "$(dirname "$0")"

# 如果提供了参数，则只构建指定平台
if [ $# -eq 3 ]; then
    GOOS=$1
    GOARCH=$2
    OUTPUT=$3
    
    echo "正在构建 $GOOS $GOARCH 版本到 $OUTPUT..."
    export CGO_ENABLED=0
    export GO111MODULE=on
    export GOOS="$GOOS"
    export GOARCH="$GOARCH"
    
    # 针对不同平台设置特定参数
    if [ "$GOOS" == "windows" ]; then
        go build -o "dist/$OUTPUT" -ldflags "-s -w" encrypt.go help.go webui.go
    else
        go build -o "dist/$OUTPUT" -ldflags "-s -w" encrypt.go help.go webui.go
    fi
    
    if [ $? -eq 0 ]; then
        echo "✓ $GOOS $GOARCH 版本构建成功: dist/$OUTPUT"
    else
        echo "✗ $GOOS $GOARCH 版本构建失败"
        exit 1
    fi
    
    exit 0
fi

echo "开始打包加密工具二进制文件..."

# 创建输出目录
mkdir -p dist

# 设置通用环境变量
export CGO_ENABLED=0
export GO111MODULE=on

# 定义平台数组
platforms=(
    "linux:amd64:encrypt-linux-amd64"
    "windows:amd64:encrypt-windows-amd64.exe"
    "darwin:amd64:encrypt-mac-amd64"
    "darwin:arm64:encrypt-mac-arm64"
    "android:arm64:encrypt-android-arm64"
)

# 遍历平台数组进行构建
for platform in "${platforms[@]}"; do
    # 分割平台信息
    IFS=':' read -r goos goarch output <<< "$platform"
    
    echo "正在构建 $goos $goarch 版本..."
    export GOOS="$goos"
    export GOARCH="$goarch"
    
    # 针对不同平台设置特定参数
    if [ "$goos" == "windows" ]; then
        go build -o "dist/$output" -ldflags "-s -w" encrypt.go help.go webui.go
    else
        go build -o "dist/$output" -ldflags "-s -w" encrypt.go help.go webui.go
    fi
    
    if [ $? -eq 0 ]; then
        echo "✓ $goos $goarch 版本构建成功: dist/$output"
    else
        echo "✗ $goos $goarch 版本构建失败"
        exit 1
    fi
done

echo "打包完成!"
echo "输出文件:"
echo "  - dist/encrypt-linux-amd64 (Linux 64位二进制文件)"
echo "  - dist/encrypt-windows-amd64.exe (Windows 64位二进制文件)"
echo "  - dist/encrypt-mac-amd64 (Mac Intel 64位二进制文件)"
echo "  - dist/encrypt-mac-arm64 (Mac ARM 64位二进制文件)"
echo "  - dist/encrypt-android-arm64 (Android 64位二进制文件)"