#!/bin/bash

# 版本管理脚本
# 用于显示和管理加密工具的版本信息

# 当前版本号
VERSION="v1.0.0"

# 显示版本信息
show_version() {
    echo "文件加密/解密工具 $VERSION"
    echo "构建时间: $(date)"
}

# 显示详细版本信息
show_detailed_version() {
    echo "=========================================="
    echo "文件加密/解密工具版本信息"
    echo "=========================================="
    echo "版本号: $VERSION"
    echo "构建时间: $(date)"
    echo "Go版本: $(go version 2>/dev/null || echo '未知')"
    echo "操作系统: $(uname -s)"
    echo "架构: $(uname -m)"
    echo "=========================================="
}

# 更新源代码中的版本号
update_version_in_code() {
    local new_version=$1
    if [ -z "$new_version" ]; then
        echo "请提供新的版本号，例如: ./version.sh update v1.0.1"
        return 1
    fi
    
    echo "正在更新版本号为: $new_version"
    
    # 更新 encrypt.go 文件中的版本号
    if [ -f "encrypt.go" ]; then
        sed -i "s/Version = \"v[0-9]*\.[0-9]*\.[0-9]*\"/Version = \"$new_version\"/" encrypt.go
        echo "已更新 encrypt.go 中的版本号"
    else
        echo "错误: 找不到 encrypt.go 文件"
        return 1
    fi
    
    # 更新 CHANGELOG.md 文件中的版本号（如果存在 Unreleased 部分）
    if [ -f "CHANGELOG.md" ]; then
        sed -i "s/## \[Unreleased\]/## [$(echo $new_version | sed 's/v//')]/" CHANGELOG.md
        echo "已更新 CHANGELOG.md 中的版本号"
    fi
    
    echo "版本号更新完成"
}

# 创建新的版本标签
create_git_tag() {
    local tag_version=$1
    if [ -z "$tag_version" ]; then
        echo "当前版本: $VERSION"
        echo "要创建新标签，请提供版本号，例如: ./version.sh tag v1.0.1"
        return 0
    fi
    
    echo "正在创建 Git 标签: $tag_version"
    git tag $tag_version
    echo "Git 标签 $tag_version 创建完成"
    echo "请使用 'git push origin $tag_version' 推送标签到远程仓库"
}

# 主函数
main() {
    case "$1" in
        "show"|"--show"|"-s")
            show_version
            ;;
        "detail"|"--detail"|"-d")
            show_detailed_version
            ;;
        "update"|"--update"|"-u")
            update_version_in_code $2
            ;;
        "tag"|"--tag"|"-t")
            create_git_tag $2
            ;;
        *)
            echo "版本管理脚本"
            echo "用法:"
            echo "  ./version.sh show     (-s)  : 显示当前版本"
            echo "  ./version.sh detail   (-d)  : 显示详细版本信息"
            echo "  ./version.sh update   (-u)  : 更新源代码中的版本号"
            echo "  ./version.sh tag      (-t)  : 创建 Git 标签"
            echo ""
            echo "当前版本: $VERSION"
            ;;
    esac
}

# 执行主函数
main "$@"