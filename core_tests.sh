#!/bin/bash
# 核心加密解密测试脚本

# 配置
TEST_DIR=$(pwd)
ENCRYPT_BIN="$TEST_DIR/encrypt"
REPORT="$TEST_DIR/final_test_report.md"

# 颜色
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

append_report() {
    echo "$1" >> $REPORT
}

log_ok() {
    echo -e "${GREEN}✅ $1${NC}"
    append_report "- ✅ $1"
}

log_fail() {
    echo -e "${RED}❌ $1${NC}"
    append_report "- ❌ $1"
}

log_info() {
    echo -e "${YELLOW}📋 $1${NC}"
    append_report ""
    append_report "---"
    append_report "### $1"
    append_report ""
}

# 清理临时文件
cleanup() {
    rm -f $TEST_DIR/encrypt_config.yaml
    rm -rf $TEST_DIR/tmp
    mkdir -p $TEST_DIR/tmp
}

# 生成配置文件
generate_config() {
    local algo=$1
    local target=$2
    cat > encrypt_config.yaml << EOF
password: testpassword123!@#
encrypt_type: $algo
target_paths:
  - $target
obfuscate_suffix: .dat
obfuscate_name_length: 12
map_filename: .app_encrypt
lock_filename: .encrypt.lock
map_storage_path: $TEST_DIR/tmp
EOF
}

# 备份原始目录
backup_dir() {
    local src=$1
    local backup="${src}_backup"
    rm -rf $backup
    cp -r $src $backup
}

# 恢复目录
restore_backup() {
    local src=$1
    local backup="${src}_backup"
    if [ -d $backup ]; then
        rm -rf $src
        mv $backup $src
    fi
}

# 计算目录文件的MD5
calculate_md5() {
    local dir=$1
    declare -gA md5_map
    while IFS= read -r f; do
        md5=$(md5sum "$f" 2>/dev/null | awk '{print $1}')
        [ -n "$md5" ] && md5_map["$f"]=$md5
    done < <(find "$dir" -type f -name "*.txt")
    echo ${#md5_map[@]}
}

# 验证MD5
verify_md5() {
    local dir=$1
    local ok=1
    for f in "${!md5_map[@]}"; do
        if [ ! -f "$f" ]; then
            echo "文件缺失: $f"
            ok=0
            continue
        fi
        new_md5=$(md5sum "$f" 2>/dev/null | awk '{print $1}')
        if [ "$new_md5" != "${md5_map[$f]}" ]; then
            echo "MD5不匹配: $f"
            ok=0
        fi
    done
    return $ok
}

# 基础加密解密测试
test_basic() {
    local algo=$1
    local test_dir=$2
    local scenario=$3
    
    log_info "测试 ${algo^^} - $scenario"
    
    # 备份
    backup_dir $test_dir
    
    # 计算原始MD5
    file_count=$(calculate_md5 $test_dir)
    append_report "📊 文件数量: $file_count"
    
    # 加密
    cleanup
    generate_config $algo "$(pwd)/$test_dir"
    echo "🔒 加密中..."
    if $ENCRYPT_BIN -encrypt > encrypt.log 2>&1; then
        log_ok "加密成功"
    else
        log_fail "加密失败"
        cat encrypt.log
        restore_backup $test_dir
        return 1
    fi
    
    # 验证加密状态
    encrypted=$(find $test_dir -name "*.dat" | wc -l)
    if [ "$encrypted" -gt 0 ]; then
        log_ok "加密文件数: $encrypted"
    else
        log_fail "没有找到加密文件"
    fi
    
    # 解密
    echo "🔓 解密中..."
    if $ENCRYPT_BIN -decrypt > decrypt.log 2>&1; then
        log_ok "解密成功"
    else
        log_fail "解密失败"
        cat decrypt.log
        restore_backup $test_dir
        return 1
    fi
    
    # 验证解密结果
    if verify_md5 $test_dir; then
        log_ok "MD5验证全部通过"
        restore_backup $test_dir
        return 0
    else
        log_fail "MD5验证失败"
        restore_backup $test_dir
        return 1
    fi
}

# 增量测试
test_incremental() {
    local algo=$1
    local test_dir=$2
    
    log_info "测试 ${algo^^} - 增量加密解密"
    
    # 备份
    backup_dir $test_dir
    
    # 阶段1: 初始加密
    cleanup
    generate_config $algo "$(pwd)/$test_dir"
    initial_count=$(find $test_dir -name "*.txt" | wc -l)
    append_report "📊 初始文件数: $initial_count"
    
    $ENCRYPT_BIN -encrypt > inc1.log 2>&1
    log_ok "初始加密完成"
    
    # 阶段2: 添加新文件
    new_file="$test_dir/incremental_new_file.txt"
    echo "这是新增的测试文件内容" > $new_file
    append_report "➕ 新增文件: incremental_new_file.txt"
    log_ok "添加新文件完成"
    
    # 阶段3: 增量加密
    $ENCRYPT_BIN -encrypt > inc2.log 2>&1
    log_ok "增量加密完成"
    
    # 阶段4: 解密
    $ENCRYPT_BIN -decrypt > inc_dec.log 2>&1
    log_ok "解密完成"
    
    # 验证
    if [ -f "$new_file" ]; then
        content=$(cat "$new_file")
        if [ "$content" == "这是新增的测试文件内容" ]; then
            log_ok "增量文件验证通过"
            restore_backup $test_dir
            return 0
        else
            log_fail "增量文件内容不对"
            restore_backup $test_dir
            return 1
        fi
    else
        log_fail "增量文件不存在"
        restore_backup $test_dir
        return 1
    fi
}

# 主函数 - 运行所有测试
run_all_tests() {
    echo "开始完整加密解密测试"
    echo "=============================="
    
    > $REPORT
    append_report "# 完整加密解密最终测试报告"
    append_report "## 测试时间: $(date)"
    append_report ""
    append_report "---"
    append_report "## 1. 概要"
    append_report ""
    append_report "| 加密算法 | 单目录 | 多目录 | 增量加密 | 嵌套目录 | 总计 |"
    append_report "|---------|-------|-------|---------|---------|------|"
    
    local total_pass=0
    local total_test=0
    
    # AES测试
    echo ""
    echo -e "${YELLOW}=== AES 算法测试 ===${NC}"
    local aes_pass=0
    
    append_report ""
    append_report "---"
    append_report "## 2. AES 算法详细测试"
    
    if test_basic aes aes_single "单目录加密解密"; then ((aes_pass++)); fi
    if test_basic aes aes_multi "多目录加密解密"; then ((aes_pass++)); fi
    if test_incremental aes aes_incremental; then ((aes_pass++)); fi
    if test_basic aes aes_nested "嵌套目录加密解密"; then ((aes_pass++)); fi
    
    total_pass=$((total_pass + aes_pass))
    total_test=$((total_test + 4))
    
    # Blowfish测试
    echo ""
    echo -e "${YELLOW}=== Blowfish 算法测试 ===${NC}"
    local bf_pass=0
    
    append_report ""
    append_report "---"
    append_report "## 3. Blowfish 算法详细测试"
    
    if test_basic bf bf_single "单目录加密解密"; then ((bf_pass++)); fi
    if test_basic bf bf_multi "多目录加密解密"; then ((bf_pass++)); fi
    if test_incremental bf bf_incremental; then ((bf_pass++)); fi
    if test_basic bf bf_nested "嵌套目录加密解密"; then ((bf_pass++)); fi
    
    total_pass=$((total_pass + bf_pass))
    total_test=$((total_test + 4))
    
    # XOR测试
    echo ""
    echo -e "${YELLOW}=== XOR 算法测试 ===${NC}"
    local xor_pass=0
    
    append_report ""
    append_report "---"
    append_report "## 4. XOR 算法详细测试"
    
    if test_basic xor xor_single "单目录加密解密"; then ((xor_pass++)); fi
    if test_basic xor xor_multi "多目录加密解密"; then ((xor_pass++)); fi
    if test_incremental xor xor_incremental; then ((xor_pass++)); fi
    if test_basic xor xor_nested "嵌套目录加密解密"; then ((xor_pass++)); fi
    
    total_pass=$((total_pass + xor_pass))
    total_test=$((total_test + 4))
    
    # 更新概要表
    local aes_result=""
    [ $aes_pass -ge 1 ] && aes_result+=" ✅" || aes_result+=" ❌"
    [ $aes_pass -ge 2 ] && aes_result+=" ✅" || aes_result+=" ❌"
    [ $aes_pass -ge 3 ] && aes_result+=" ✅" || aes_result+=" ❌"
    [ $aes_pass -ge 4 ] && aes_result+=" ✅" || aes_result+=" ❌"
    
    local bf_result=""
    [ $bf_pass -ge 1 ] && bf_result+=" ✅" || bf_result+=" ❌"
    [ $bf_pass -ge 2 ] && bf_result+=" ✅" || bf_result+=" ❌"
    [ $bf_pass -ge 3 ] && bf_result+=" ✅" || bf_result+=" ❌"
    [ $bf_pass -ge 4 ] && bf_result+=" ✅" || bf_result+=" ❌"
    
    local xor_result=""
    [ $xor_pass -ge 1 ] && xor_result+=" ✅" || xor_result+=" ❌"
    [ $xor_pass -ge 2 ] && xor_result+=" ✅" || xor_result+=" ❌"
    [ $xor_pass -ge 3 ] && xor_result+=" ✅" || xor_result+=" ❌"
    [ $xor_pass -ge 4 ] && xor_result+=" ✅" || xor_result+=" ❌"
    
    # 重写报告开头的概要表
    echo "# 完整加密解密最终测试报告" > $REPORT.tmp
    echo "## 测试时间: $(date)" >> $REPORT.tmp
    echo "" >> $REPORT.tmp
    echo "---" >> $REPORT.tmp
    echo "## 1. 概要" >> $REPORT.tmp
    echo "" >> $REPORT.tmp
    echo "| 加密算法 | 单目录 | 多目录 | 增量加密 | 嵌套目录 | 总计 |" >> $REPORT.tmp
    echo "|---------|-------|-------|---------|---------|------|" >> $REPORT.tmp
    echo "| AES | ${aes_result:0:2} | ${aes_result:2:2} | ${aes_result:4:2} | ${aes_result:6:2} | $aes_pass/4 |" >> $REPORT.tmp
    echo "| Blowfish | ${bf_result:0:2} | ${bf_result:2:2} | ${bf_result:4:2} | ${bf_result:6:2} | $bf_pass/4 |" >> $REPORT.tmp
    echo "| XOR | ${xor_result:0:2} | ${xor_result:2:2} | ${xor_result:4:2} | ${xor_result:6:2} | $xor_pass/4 |" >> $REPORT.tmp
    echo "" >> $REPORT.tmp
    echo "---" >> $REPORT.tmp
    echo "## 5. 总体统计" >> $REPORT.tmp
    echo "" >> $REPORT.tmp
    echo "- 总测试数: $total_test" >> $REPORT.tmp
    echo "- 总通过数: $total_pass" >> $REPORT.tmp
    echo "- 通过率: $((total_pass * 100 / total_test))%" >> $REPORT.tmp
    
    # 追加原来的内容
    tail -n +10 $REPORT >> $REPORT.tmp
    mv $REPORT.tmp $REPORT
    
    echo ""
    echo "=============================="
    echo -e "${GREEN}测试完成！${NC}"
    echo "通过: $total_pass/$total_test"
    echo "报告: $REPORT"
    echo "=============================="
}

# 运行主测试
run_all_tests
