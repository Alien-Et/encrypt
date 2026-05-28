#!/bin/bash

# 创建测试文件
echo "测试文件1 - 单目录测试" > single_test/docs/file1.txt
echo "测试文件2 - 图片" > single_test/images/pic1.png
echo "测试文件3 - 日志" > single_test/logs.txt

echo "多目录文件1" > multi_test/folder1/test1.txt
echo "多目录文件2" > multi_test/folder2/test2.txt
echo "多目录文件3" > multi_test/folder3/test3.txt

echo "嵌套文件1" > multi_test/folder1/subdir/nested1.txt
echo "嵌套文件2" > multi_test/folder2/subdir/nested2.txt

echo "测试文件创建完成"
ls -la single_test/
ls -la single_test/docs/
ls -la single_test/images/
