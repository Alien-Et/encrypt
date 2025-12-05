// 全局变量
let logStream = null;
let currentOperation = null;
let progressInterval = null;

// DOM加载完成后初始化
document.addEventListener('DOMContentLoaded', function() {
    // 初始化标签页切换
    initTabs();
    
    // 初始化事件监听器
    initEventListeners();
    
    // 初始化移动端导航
    initMobileNav();
    
    // 初始化密码查看功能
    initPasswordToggle();
    
    // 检查应用状态
    checkAppStatus();
    
    // 加载配置
    loadConfig();
    
    // 加载文件列表
    loadFileList();
    
    // 开始日志流
    startLogStream();
});

// 初始化标签页切换
function initTabs() {
    const tabLinks = document.querySelectorAll('.nav-link[data-tab]');
    const tabContents = document.querySelectorAll('.tab-content');
    
    tabLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            
            const tabId = this.getAttribute('data-tab');
            
            // 更新活动标签
            tabLinks.forEach(l => l.classList.remove('active'));
            this.classList.add('active');
            
            // 显示对应内容
            tabContents.forEach(content => {
                content.classList.remove('active');
                if (content.id === tabId) {
                    content.classList.add('active');
                }
            });
            
            // 关闭移动端菜单
            const navMenu = document.querySelector('.nav-menu');
            navMenu.classList.remove('active');
        });
    });
}

// 初始化移动端导航
function initMobileNav() {
    const navToggle = document.querySelector('.nav-toggle');
    const navMenu = document.querySelector('.nav-menu');
    
    if (navToggle && navMenu) {
        navToggle.addEventListener('click', function() {
            navMenu.classList.toggle('active');
        });
    }
}

// 初始化事件监听器
function initEventListeners() {
    // 配置表单提交
    const configForm = document.getElementById('config-form');
    if (configForm) {
        configForm.addEventListener('submit', saveConfig);
    }
    
    // 加载配置按钮
    const loadConfigBtn = document.getElementById('load-config');
    if (loadConfigBtn) {
        loadConfigBtn.addEventListener('click', loadConfig);
    }
    
    // 刷新文件列表按钮
    const refreshFilesBtn = document.getElementById('refresh-files');
    if (refreshFilesBtn) {
        refreshFilesBtn.addEventListener('click', loadFileList);
    }
    
    // 开始加密按钮
    const startEncryptBtn = document.getElementById('start-encrypt');
    if (startEncryptBtn) {
        startEncryptBtn.addEventListener('click', startEncryption);
    }
    
    // 开始解密按钮
    const startDecryptBtn = document.getElementById('start-decrypt');
    if (startDecryptBtn) {
        startDecryptBtn.addEventListener('click', startDecryption);
    }
    
    // 停止操作按钮
    const stopOperationBtn = document.getElementById('stop-operation');
    if (stopOperationBtn) {
        stopOperationBtn.addEventListener('click', stopOperation);
    }
    
    // 清空日志按钮
    const clearLogsBtn = document.getElementById('clear-logs');
    if (clearLogsBtn) {
        clearLogsBtn.addEventListener('click', clearLogs);
    }
}

// 初始化密码查看功能
function initPasswordToggle() {
    const toggleButton = document.getElementById('toggle-password');
    const passwordInput = document.getElementById('password');
    
    if (toggleButton && passwordInput) {
        toggleButton.addEventListener('click', function() {
            const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
            passwordInput.setAttribute('type', type);
            
            // 更新眼睛图标
            const eyeIcon = this.querySelector('.eye-icon i');
            if (eyeIcon) {
                if (type === 'password') {
                    eyeIcon.className = 'fas fa-eye';
                } else {
                    eyeIcon.className = 'fas fa-eye-slash';
                }
            }
        });
    }
}

// 检查应用状态
async function checkAppStatus() {
    try {
        const response = await fetch('/api/status');
        const data = await response.json();
        
        const statusElement = document.getElementById('app-status');
        if (statusElement) {
            statusElement.textContent = data.status === 'running' ? '运行中' : '已停止';
            statusElement.className = 'status-value ' + (data.status === 'running' ? 'running' : 'stopped');
        }
    } catch (error) {
        console.error('检查应用状态失败:', error);
    }
}

// 加载配置
async function loadConfig() {
    try {
        showLoading(true);
        
        const response = await fetch('/api/config');
        const config = await response.json();
        
        // 填充表单字段
        document.getElementById('password').value = config.password || '';
        document.getElementById('encrypt-type').value = config.encrypt_type || 'aes';
        document.getElementById('target-paths').value = (config.target_paths || []).join('\n');
        document.getElementById('obfuscate-suffix').value = config.obfuscate_suffix || '.dat';
        document.getElementById('map-storage-path').value = config.map_storage_path || '';
        
        // 更新状态显示
        updateStatusInfo(config);
        
        showMessage('配置加载成功', 'success');
    } catch (error) {
        showMessage('加载配置失败: ' + error.message, 'error');
    } finally {
        showLoading(false);
    }
}

// 保存配置
async function saveConfig(event) {
    event.preventDefault();
    
    try {
        showLoading(true);
        
        const formData = new FormData(document.getElementById('config-form'));
        const config = {
            password: formData.get('password'),
            encrypt_type: formData.get('encrypt_type'),
            target_paths: formData.get('target_paths').split('\n').filter(p => p.trim() !== ''),
            obfuscate_suffix: formData.get('obfuscate_suffix'),
            obfuscate_name_length: 12, // 默认值
            map_filename: '.app_encrypt', // 默认值
            lock_filename: '.encrypt.lock', // 默认值
            map_storage_path: formData.get('map_storage_path'),
            salt: '' // 默认值
        };
        
        const response = await fetch('/api/config', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(config)
        });
        
        if (response.ok) {
            showMessage('配置保存成功', 'success');
            updateStatusInfo(config);
        } else {
            throw new Error('保存配置失败');
        }
    } catch (error) {
        showMessage('保存配置失败: ' + error.message, 'error');
    } finally {
        showLoading(false);
    }
}

// 更新状态信息显示
function updateStatusInfo(config) {
    const algorithmElement = document.getElementById('encrypt-algorithm');
    const pathsElement = document.getElementById('target-paths-count');
    
    if (algorithmElement) {
        const algorithmNames = {
            'aes': 'AES',
            'blowfish': 'Blowfish',
            'xor': 'XOR'
        };
        algorithmElement.textContent = algorithmNames[config.encrypt_type] || '-';
    }
    
    if (pathsElement) {
        pathsElement.textContent = (config.target_paths || []).length;
    }
}

// 加载文件列表
async function loadFileList() {
    try {
        showLoading(true);
        
        const response = await fetch('/api/files');
        const data = await response.json();
        
        const fileListBody = document.querySelector('#file-list tbody');
        if (fileListBody) {
            fileListBody.innerHTML = '';
            
            if (data.files && data.files.length > 0) {
                // Group files by target directory
                const groupedFiles = {};
                data.files.forEach(file => {
                    const targetDir = file.target_dir || 'unknown';
                    if (!groupedFiles[targetDir]) {
                        groupedFiles[targetDir] = [];
                    }
                    groupedFiles[targetDir].push(file);
                });
                
                // Display files grouped by target directory
                Object.keys(groupedFiles).forEach(targetDir => {
                    // Add group header
                    const groupHeader = document.createElement('tr');
                    groupHeader.className = 'file-group-header';
                    groupHeader.innerHTML = `<td colspan="4"><strong>📁 目标路径: ${escapeHtml(targetDir)}</strong></td>`;
                    fileListBody.appendChild(groupHeader);
                    
                    // Add files in this group
                    groupedFiles[targetDir].forEach(file => {
                        const row = document.createElement('tr');
                        row.innerHTML = `
                            <td style="padding-left: 20px;">${escapeHtml(file.original_path || '-')}</td>
                            <td>${escapeHtml(file.encrypted_path || '-')}</td>
                            <td>${formatFileSize(file.size || 0)}</td>
                            <td>${file.modified || '-'}</td>
                        `;
                        fileListBody.appendChild(row);
                    });
                });
            } else {
                const row = document.createElement('tr');
                row.innerHTML = '<td colspan="4" style="text-align: center;">暂无加密文件</td>';
                fileListBody.appendChild(row);
            }
        }
        
        showMessage('文件列表刷新成功', 'success');
    } catch (error) {
        showMessage('加载文件列表失败: ' + error.message, 'error');
    } finally {
        showLoading(false);
    }
}

// 开始加密
async function startEncryption() {
    if (!confirm('确定要开始加密吗？')) {
        return;
    }
    
    try {
        showLoading(true);
        updateOperationButtons(true);
        
        // 重置进度条
        updateProgress(0, '准备开始加密...');
        
        const response = await fetch('/api/start?mode=encrypt', {
            method: 'POST'
        });
        
        if (response.ok) {
            showMessage('加密任务已启动', 'success');
            currentOperation = 'encrypt';
            startProgressTracking();
        } else {
            throw new Error('启动加密失败');
        }
    } catch (error) {
        showMessage('启动加密失败: ' + error.message, 'error');
        updateOperationButtons(false);
    } finally {
        showLoading(false);
    }
}

// 开始解密
async function startDecryption() {
    if (!confirm('确定要开始解密吗？这将还原所有加密文件。')) {
        return;
    }
    
    try {
        showLoading(true);
        updateOperationButtons(true);
        
        // 重置进度条
        updateProgress(0, '准备开始解密...');
        
        const response = await fetch('/api/start?mode=decrypt', {
            method: 'POST'
        });
        
        if (response.ok) {
            showMessage('解密任务已启动', 'success');
            currentOperation = 'decrypt';
            startProgressTracking();
        } else {
            throw new Error('启动解密失败');
        }
    } catch (error) {
        showMessage('启动解密失败: ' + error.message, 'error');
        updateOperationButtons(false);
    } finally {
        showLoading(false);
    }
}

// 停止操作
async function stopOperation() {
    try {
        showLoading(true);
        
        const response = await fetch('/api/stop', {
            method: 'POST'
        });
        
        if (response.ok) {
            showMessage('操作已停止', 'success');
            currentOperation = null;
            stopProgressTracking();
            updateOperationButtons(false);
            updateProgress(0, '操作已停止');
        } else {
            throw new Error('停止操作失败');
        }
    } catch (error) {
        showMessage('停止操作失败: ' + error.message, 'error');
    } finally {
        showLoading(false);
    }
}

// 更新操作按钮状态
function updateOperationButtons(running) {
    const startEncryptBtn = document.getElementById('start-encrypt');
    const startDecryptBtn = document.getElementById('start-decrypt');
    const stopOperationBtn = document.getElementById('stop-operation');
    
    if (startEncryptBtn) startEncryptBtn.disabled = running;
    if (startDecryptBtn) startDecryptBtn.disabled = running;
    if (stopOperationBtn) stopOperationBtn.disabled = !running;
}

// 开始进度跟踪
function startProgressTracking() {
    if (progressInterval) {
        clearInterval(progressInterval);
    }
    
    progressInterval = setInterval(async () => {
        if (currentOperation === null) {
            clearInterval(progressInterval);
            return;
        }
        
        try {
            // 从服务器获取实际进度
            const response = await fetch('/api/progress');
            if (response.ok) {
                const progressData = await response.json();
                
                // 检查操作是否仍在运行
                if (!progressData.is_running) {
                    // 操作已完成
                    clearInterval(progressInterval);
                    updateOperationButtons(false);
                    updateProgress(100, '操作完成');
                    showMessage(`${currentOperation === 'encrypt' ? '加密' : '解密'}完成`, 'success');
                    currentOperation = null;
                    return;
                }
                
                // 计算进度百分比
                let percent = 0;
                if (progressData.total_to_process > 0) {
                    percent = (progressData.current_processed / progressData.total_to_process) * 100;
                }
                
                // 确保进度不超过100%
                if (percent > 100) percent = 100;
                
                updateProgress(percent, `${currentOperation === 'encrypt' ? '加密' : '解密'}进行中... (${progressData.current_processed}/${progressData.total_to_process})`);
            }
        } catch (error) {
            console.error('获取进度信息失败:', error);
            // 如果获取进度失败，继续使用之前的逻辑
            updateProgress(0, '获取进度信息失败');
        }
    }, 1000);
}

// 停止进度跟踪
function stopProgressTracking() {
    if (progressInterval) {
        clearInterval(progressInterval);
        progressInterval = null;
    }
}

// 更新进度条
function updateProgress(percent, text) {
    const progressFill = document.getElementById('progress-fill');
    const progressText = document.getElementById('progress-text');
    const progressPercent = document.getElementById('progress-percent');
    
    if (progressFill) {
        // 使用动画效果使进度条变化更平滑
        progressFill.style.transition = 'width 0.3s ease';
        progressFill.style.width = percent + '%';
    }
    if (progressText) progressText.textContent = text;
    if (progressPercent) progressPercent.textContent = Math.round(percent) + '%';
}

// 开始日志流
function startLogStream() {
    if (logStream) {
        logStream.close();
    }
    
    logStream = new EventSource('/api/logs');
    
    logStream.onmessage = function(event) {
        try {
            const data = JSON.parse(event.data);
            addLogMessage(data.message || event.data, data.level || 'info');
        } catch (e) {
            addLogMessage(event.data, 'info');
        }
    };
    
    logStream.onerror = function(event) {
        console.error('日志流连接错误:', event);
    };
}

// 添加日志消息
function addLogMessage(message, level) {
    const logContent = document.getElementById('log-content');
    const autoScroll = document.getElementById('auto-scroll');
    
    if (logContent) {
        const timestamp = new Date().toLocaleTimeString();
        const logEntry = `[${timestamp}] ${message}\n`;
        
        logContent.textContent += logEntry;
        
        // 自动滚动到底部
        if (autoScroll && autoScroll.checked) {
            logContent.scrollTop = logContent.scrollHeight;
        }
    }
}

// 清空日志
function clearLogs() {
    const logContent = document.getElementById('log-content');
    if (logContent) {
        logContent.textContent = '';
    }
}

// 显示消息提示
function showMessage(message, type) {
    // 移除现有的消息
    const existingMessage = document.querySelector('.message');
    if (existingMessage) {
        existingMessage.remove();
    }
    
    // 创建新消息
    const messageDiv = document.createElement('div');
    messageDiv.className = `message ${type}`;
    messageDiv.textContent = message;
    
    document.body.appendChild(messageDiv);
    
    // 3秒后自动移除
    setTimeout(() => {
        if (messageDiv.parentNode) {
            messageDiv.parentNode.removeChild(messageDiv);
        }
    }, 3000);
}

// 显示加载状态
function showLoading(show) {
    // 这里可以实现全局加载状态显示
    // 暂时留空
}

// 格式化文件大小
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// 转义HTML
function escapeHtml(text) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    
    return text.replace(/[&<>"']/g, function(m) { return map[m]; });
}