#!/bin/bash
# 简单但可靠的测试脚本

set -x

# 初始化报告
REPORT="simple_test_report.md"
> $REPORT
echo "# 加密解密完整测试报告" >> $REPORT
echo "" >> $REPORT
echo "测试时间: $(date)" >> $REPORT
echo "" >> $REPORT

test_one_scenario() {
    local algo=$1
    local dir=$2
    local desc=$3
    
    echo "=== 测试 $algo - $desc ==="
    echo "" >> $REPORT
    echo "## $algo - $desc" >> $REPORT
    
    # 备份目录
    cp -r $dir ${dir}_original
    
    # 记录原始状态
    echo "原始文件数: $(find $dir -name "*.txt" | wc -l)" >> $REPORT
    
    # 生成配置
    cat > encrypt_config.yaml << EOF
password: testpassword123!@#
encrypt_type: $algo
target_paths:
  - $(pwd)/$dir
obfuscate_suffix: .dat
obfuscate_name_length: 12
map_filename: .app_encrypt
lock_filename: .encrypt.lock
map_storage_path: $(pwd)/tmp
EOF
    
    # 清理
    rm -rf tmp
    mkdir -p tmp
    
    # 加密
    echo "- 加密中..."
    if ./encrypt -encrypt > enc.log 2>&1; then
        echo "✅ 加密成功" >> $REPORT
        enc_files=$(find $dir -name "*.dat" | wc -l)
        echo "加密文件数: $enc_files" >> $REPORT
    else
        echo "❌ 加密失败" >> $REPORT
        cat enc.log >> $REPORT
        rm -rf $dir
        mv ${dir}_original $dir
        return 1
    fi
    
    # 解密
    echo "- 解密中..."
    if ./encrypt -decrypt > dec.log 2>&1; then
        echo "✅ 解密成功" >> $REPORT
    else
        echo "❌ 解密失败" >> $REPORT
        cat dec.log >> $REPORT
        rm -rf $dir
        mv ${dir}_original $dir
        return 1
    fi
    
    # 验证
    echo "- 验证中..."
    original_count=$(find ${dir}_original -name "*.txt" | wc -l)
    new_count=$(find $dir -name "*.txt" | wc -l)
    
    if [ "$original_count" == "$new_count" ]; then
        echo "✅ 文件数量匹配 ($original_count)" >> $REPORT
        
        # 简单验证内容
        local ok=1
        for f in $(find ${dir}_original -name "*.txt"); do
            rel=${f#${dir}_original/}
            new_f="$dir/$rel"
            if [ -f "$new_f" ]; then
                if ! diff -q "$f" "$new_f" > /dev/null; then
                    echo "❌ 文件内容不匹配: $rel" >> $REPORT
                    ok=0
                fi
            else
                echo "❌ 文件缺失: $rel" >> $REPORT
                ok=0
            fi
        done
        
        if [ $ok -eq 1 ]; then
            echo "✅ 所有文件验证通过" >> $REPORT
        fi
    else
        echo "❌ 文件数量不匹配 (原始:$original_count, 现在:$new_count)" >> $REPORT
    fi
    
    # 清理
    rm -rf $dir
    mv ${dir}_original $dir
    
    echo ""
    return 0
}

test_incremental() {
    local algo=$1
    local dir=$2
    
    echo "=== 测试 $algo - 增量加密解密 ==="
    echo "" >> $REPORT
    echo "## $algo - 增量加密解密" >> $REPORT
    
    # 备份
    cp -r $dir ${dir}_original
    
    # 初始加密
    cat > encrypt_config.yaml << EOF
password: testpassword123!@#
encrypt_type: $algo
target_paths:
  - $(pwd)/$dir
obfuscate_suffix: .dat
obfuscate_name_length: 12
map_filename: .app_encrypt
lock_filename: .encrypt.lock
map_storage_path: $(pwd)/tmp
EOF
    
    rm -rf tmp
    mkdir -p tmp
    
    ./encrypt -encrypt > /dev/null 2>&1
    
    # 添加新文件
    echo "新增文件内容" > $dir/new_test_file.txt
    echo "📝 新增文件: new_test_file.txt" >> $REPORT
    
    # 再次加密
    ./encrypt -encrypt > /dev/null 2>&1
    
    # 解密
    ./encrypt -decrypt > /dev/null 2>&1
    
    # 验证
    if [ -f "$dir/new_test_file.txt" ]; then
        content=$(cat $dir/new_test_file.txt)
        if [ "$content" == "新增文件内容" ]; then
            echo "✅ 增量测试通过" >> $REPORT
        else
            echo "❌ 增量文件内容不对" >> $REPORT
        fi
    else
        echo "❌ 增量文件缺失" >> $REPORT
    fi
    
    # 恢复
    rm -rf $dir
    mv ${dir}_original $dir
}

echo "开始测试..."
echo ""

# 测试AES
test_one_scenario aes aes_single "单目录加密"
test_one_scenario aes aes_multi "多目录加密"
test_incremental aes aes_incremental
test_one_scenario aes aes_nested "嵌套目录加密"

# 测试Blowfish
test_one_scenario blowfish bf_single "单目录加密"
test_one_scenario blowfish bf_multi "多目录加密"
test_incremental blowfish bf_incremental
test_one_scenario blowfish bf_nested "嵌套目录加密"

# 测试XOR
test_one_scenario xor xor_single "单目录加密"
test_one_scenario xor xor_multi "多目录加密"
test_incremental xor xor_incremental
test_one_scenario xor xor_nested "嵌套目录加密"

echo ""
echo "测试完成！报告: $REPORT"
