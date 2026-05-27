#!/bin/bash
# 测试准备脚本

# 清理旧的测试目录
rm -rf aes_* bf_* xor_*

# 准备函数
prepare_test_dirs() {
    local algo=$1
    
    echo "准备 $algo 测试目录..."
    
    # 单目录测试
    mkdir -p ${algo}_single/dir1 ${algo}_single/dir2
    for i in {1..10}; do cp test_data/file_$(printf "%03d" $i).txt ${algo}_single/ 2>/dev/null || true; done
    for i in {11..20}; do cp test_data/file_$(printf "%03d" $i).txt ${algo}_single/dir1/ 2>/dev/null || true; done
    for i in {21..30}; do cp test_data/file_$(printf "%03d" $i).txt ${algo}_single/dir2/ 2>/dev/null || true; done
    
    # 多目录测试
    mkdir -p ${algo}_multi/dirA ${algo}_multi/dirB ${algo}_multi/dirC
    for i in {31..40}; do cp test_data/file_$(printf "%03d" $i).txt ${algo}_multi/ 2>/dev/null || true; done
    for i in {41..50}; do cp test_data/file_$(printf "%03d" $i).txt ${algo}_multi/dirA/ 2>/dev/null || true; done
    for i in {51..60}; do cp test_data/file_$(printf "%03d" $i).txt ${algo}_multi/dirB/ 2>/dev/null || true; done
    for i in {61..70}; do cp test_data/file_$(printf "%03d" $i).txt ${algo}_multi/dirC/ 2>/dev/null || true; done
    
    # 增量测试
    mkdir -p ${algo}_incremental
    for i in {71..80}; do cp test_data/file_$(printf "%03d" $i).txt ${algo}_incremental/ 2>/dev/null || true; done
    
    # 嵌套目录测试
    mkdir -p ${algo}_nested/level1/level2/level3
    for i in {81..85}; do cp test_data/file_$(printf "%03d" $i).txt ${algo}_nested/ 2>/dev/null || true; done
    for i in {86..90}; do cp test_data/file_$(printf "%03d" $i).txt ${algo}_nested/level1/ 2>/dev/null || true; done
    for i in {91..95}; do cp test_data/file_$(printf "%03d" $i).txt ${algo}_nested/level1/level2/ 2>/dev/null || true; done
    for i in {96..100}; do cp test_data/file_$(printf "%03d" $i).txt ${algo}_nested/level1/level2/level3/ 2>/dev/null || true; done
    
    echo "✅ $algo 测试目录准备完成"
}

# 为三个算法准备
prepare_test_dirs aes
prepare_test_dirs bf
prepare_test_dirs xor

echo ""
echo "✅ 所有测试目录准备完成！"
echo ""
echo "单目录测试文件数:"
for d in aes_single bf_single xor_single; do echo "  $d: $(find $d -name "*.txt" | wc -l)"; done
echo ""
echo "多目录测试文件数:"
for d in aes_multi bf_multi xor_multi; do echo "  $d: $(find $d -name "*.txt" | wc -l)"; done
echo ""
echo "增量测试文件数:"
for d in aes_incremental bf_incremental xor_incremental; do echo "  $d: $(find $d -name "*.txt" | wc -l)"; done
echo ""
echo "嵌套目录测试文件数:"
for d in aes_nested bf_nested xor_nested; do echo "  $d: $(find $d -name "*.txt" | wc -l)"; done
