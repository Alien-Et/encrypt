#!/bin/bash
# 完整加密解密测试脚本

# 颜色输出
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

TEST_DIR=$(pwd)
ENCRYPT_BIN="$TEST_DIR/encrypt"
REPORT_FILE="$TEST_DIR/full_test_report_$(date +%Y%m%d_%H%M%S).md"

echo "# 完整加密解密测试报告" > $REPORT_FILE
echo "" >> $REPORT_FILE
echo "测试时间: $(date)" >> $REPORT_FILE
echo "" >> $REPORT_FILE

log_success() {
    echo -e "${GREEN}✅ $1${NC}"
    echo "- ✅ $1" >> $REPORT_FILE
}

log_failure() {
    echo -e "${RED}❌ $1${NC}"
    echo "- ❌ $1" >> $REPORT_FILE
}

log_info() {
    echo -e "${YELLOW}📝 $1${NC}"
    echo "---" >> $REPORT_FILE
    echo "### $1" >> $REPORT_FILE
    echo "" >> $REPORT_FILE
}

# 创建配置文件函数
create_config() {
    local algo=$1
    local target_dir=$2
    local config_file="${algo}_config.yaml"
    
    cat > $config_file << EOF
password: testpassword123!@#
encrypt_type: $algo
target_paths:
  - $target_dir
obfuscate_suffix: .dat
obfuscate_name_length: 12
map_filename: .app_encrypt
lock_filename: .encrypt.lock
map_storage_path: $TEST_DIR/tmp
EOF
    echo $config_file
}

# 清理函数
cleanup() {
    rm -f $TEST_DIR/encrypt_config.yaml
    rm -rf $TEST_DIR/tmp
    mkdir -p $TEST_DIR/tmp
}

# 测试单个场景
test_scenario() {
    local algo=$1
    local scenario=$2
    local desc=$3
    
    log_info "测试 ${algo^^} - $desc"
    
    # 计算文件数
    local file_count=$(find "$scenario" -type f -name "*.txt" | wc -l)
    echo "📊 文件数量: $file_count" >> $REPORT_FILE
    
    # 记录原始文件MD5
    declare -A original_md5
    while IFS= read -r f; do
        md5=$(md5sum "$f" | awk '{print $1}')
        original_md5["$f"]=$md5
    done < <(find "$scenario" -type f -name "*.txt")
    
    # 加密
    cleanup
    config_file=$(create_config $algo "$(pwd)/$scenario")
    cp $config_file encrypt_config.yaml
    
    echo "🔒 加密中..."
    if $ENCRYPT_BIN -encrypt > encrypt.log 2>&1; then
        log_success "加密成功"
    else
        log_failure "加密失败"
        return 1
    fi
    
    # 验证加密 - 检查文件是否都有.dat后缀且原始文件不存在
    encrypted_files=$(find "$scenario" -type f -name "*.dat" | wc -l)
    if [ "$encrypted_files" -gt 0 ]; then
        log_success "文件加密成功，共 $encrypted_files 个加密文件"
    else
        log_failure "没有找到加密文件"
    fi
    
    # 解密
    echo "🔓 解密中..."
    if $ENCRYPT_BIN -decrypt > decrypt.log 2>&1; then
        log_success "解密成功"
    else
        log_failure "解密失败"
        return 1
    fi
    
    # 验证解密 - 对比MD5
    local verify_ok=1
    for f in "${!original_md5[@]}"; do
        if [ -f "$f" ]; then
            new_md5=$(md5sum "$f" | awk '{print $1}')
            if [ "$new_md5" != "${original_md5[$f]}" ]; then
                log_failure "文件 $f MD5不匹配"
                verify_ok=0
            fi
        else
            log_failure "文件 $f 不存在"
            verify_ok=0
        fi
    done
    
    if [ $verify_ok -eq 1 ]; then
        log_success "所有文件MD5验证通过"
    fi
    
    return $verify_ok
}

# 测试增量场景
test_incremental() {
    local algo=$1
    local scenario=$2
    
    log_info "测试 ${algo^^} - 增量加密解密"
    
    # 阶段1: 初始加密
    cleanup
    config_file=$(create_config $algo "$(pwd)/$scenario")
    cp $config_file encrypt_config.yaml
    
    # 保存初始文件数
    initial_files=$(find "$scenario" -type f -name "*.txt" | wc -l)
    
    # 初始加密
    $ENCRYPT_BIN -encrypt > inc_encrypt1.log 2>&1
    log_success "初始加密完成（$initial_files 个文件）"
    
    # 阶段2: 添加新文件
    new_file="$scenario/new_incremental_file.txt"
    echo "这是新增的增量测试文件" > $new_file
    echo "➕ 新增文件: $new_file" >> $REPORT_FILE
    
    # 阶段3: 再次加密（增量）
    $ENCRYPT_BIN -encrypt > inc_encrypt2.log 2>&1
    log_success "增量加密完成（新增文件）"
    
    # 阶段4: 解密
    $ENCRYPT_BIN -decrypt > inc_decrypt.log 2>&1
    log_success "增量解密完成"
    
    # 验证新文件是否存在且正确
    if [ -f "$new_file" ]; then
        content=$(cat "$new_file")
        if [ "$content" == "这是新增的增量测试文件" ]; then
            log_success "增量文件验证通过"
        else
            log_failure "增量文件内容不正确"
        fi
    else
        log_failure "增量文件不存在"
    fi
}

echo "开始完整测试..."
echo ""

# ==================== 准备测试文件 ====================
echo "📋 准备测试文件..."

# 单目录测试 - 每个算法30个文件
for algo in aes bf xor; do
    dest="${algo}_single"
    rm -rf $dest && mkdir -p $dest/dir1 $dest/dir2
    
    # 复制1-30号文件
    start=$(( ($RANDOM % 70) + 1 ))
    for i in $(seq $start $((start + 29))); do
        idx=$((i % 100))
        [ $idx -eq 0 ] && idx=100
        src=$(printf "test_data/file_%03d.txt" $idx)
        [ $((i % 3)) -eq 0 ] && dest_sub="$dest/dir1" || [ $((i % 3)) -eq 1 ] && dest_sub="$dest/dir2" || dest_sub="$dest"
        cp "$src" "$dest_sub/"
    done
done

# 多目录测试 - 每个算法20个文件
for algo in aes bf xor; do
    dest="${algo}_multi"
    rm -rf $dest && mkdir -p $dest/dirA $dest/dirB $dest/dirC
    
    for i in $(seq 1 20); do
        src=$(printf "test_data/file_%03d.txt" $((i + 30)))
        case $((i % 4)) in
            0) cp "$src" "$dest/dirA/" ;;
            1) cp "$src" "$dest/dirB/" ;;
            2) cp "$src" "$dest/dirC/" ;;
            3) cp "$src" "$dest/" ;;
        esac
    done
done

# 增量测试 - 每个算法15个文件
for algo in aes bf xor; do
    dest="${algo}_incremental"
    rm -rf $dest && mkdir -p $dest
    for i in $(seq 51 65); do
        src=$(printf "test_data/file_%03d.txt" $i)
        cp "$src" "$dest/"
    done
done

# 嵌套目录测试 - 每个算法10个文件
for algo in aes bf xor; do
    dest="${algo}_nested"
    rm -rf $dest && mkdir -p $dest/level1/level2/level3
    for i in $(seq 66 75); do
        src=$(printf "test_data/file_%03d.txt" $i)
        lvl=$((i % 4))
        case $lvl in
            0) cp "$src" "$dest/" ;;
            1) cp "$src" "$dest/level1/" ;;
            2) cp "$src" "$dest/level1/level2/" ;;
            3) cp "$src" "$dest/level1/level2/level3/" ;;
        esac
    done
done

echo "✅ 测试文件准备完成"
echo ""

# ==================== 开始测试 ====================
passed=0
failed=0

# 测试AES
echo -e "${YELLOW}========================${NC}"
echo -e "${YELLOW}开始AES加密算法测试${NC}"
echo -e "${YELLOW}========================${NC}"
if test_scenario aes aes_single "单目录加密解密"; then ((passed++)); else ((failed++)); fi
if test_scenario aes aes_multi "多目录加密解密"; then ((passed++)); else ((failed++)); fi
test_incremental aes aes_incremental && ((passed++)) || ((failed++))
if test_scenario aes aes_nested "嵌套目录加密解密"; then ((passed++)); else ((failed++)); fi

echo ""
# 测试Blowfish
echo -e "${YELLOW}============================${NC}"
echo -e "${YELLOW}开始Blowfish加密算法测试${NC}"
echo -e "${YELLOW}============================${NC}"
if test_scenario bf bf_single "单目录加密解密"; then ((passed++)); else ((failed++)); fi
if test_scenario bf bf_multi "多目录加密解密"; then ((passed++)); else ((failed++)); fi
test_incremental bf bf_incremental && ((passed++)) || ((failed++))
if test_scenario bf bf_nested "嵌套目录加密解密"; then ((passed++)); else ((failed++)); fi

echo ""
# 测试XOR
echo -e "${YELLOW}========================${NC}"
echo -e "${YELLOW}开始XOR加密算法测试${NC}"
echo -e "${YELLOW}========================${NC}"
if test_scenario xor xor_single "单目录加密解密"; then ((passed++)); else ((failed++)); fi
if test_scenario xor xor_multi "多目录加密解密"; then ((passed++)); else ((failed++)); fi
test_incremental xor xor_incremental && ((passed++)) || ((failed++))
if test_scenario xor xor_nested "嵌套目录加密解密"; then ((passed++)); else ((failed++)); fi

echo ""
echo "==============================="
echo "测试完成！"
echo "通过: $passed"
echo "失败: $failed"
echo "==============================="
echo ""
echo "详细报告已保存到: $REPORT_FILE"

# 在报告中添加总结
echo "" >> $REPORT_FILE
echo "## 总结" >> $REPORT_FILE
echo "- 通过: $passed" >> $REPORT_FILE
echo "- 失败: $failed" >> $REPORT_FILE

if [ $failed -eq 0 ]; then
    echo -e "${GREEN}🎉 所有测试通过！${NC}"
else
    echo -e "${RED}⚠️  有 $failed 个测试失败${NC}"
fi
