
let currentOperation = null;
let progressInterval = null;
let logStream = null;
let currentFiles = [];

document.addEventListener('DOMContentLoaded', function() {
    initTabs();
    initEventListeners();
    checkAppStatus();
    loadConfig();
    loadFileList();
    startLogStream();
});

function initTabs() {
    const tabButtons = document.querySelectorAll('.nav-item[data-tab]');
    const tabContents = document.querySelectorAll('.tab-content');
    
    tabButtons.forEach(button => {
        button.addEventListener('click', function() {
            const tabId = this.getAttribute('data-tab');
            
            tabButtons.forEach(btn => btn.classList.remove('active'));
            this.classList.add('active');
            
            tabContents.forEach(content => {
                content.classList.remove('active');
                if (content.id === tabId) {
                    content.classList.add('active');
                    if (tabId === 'files') {
                        loadFileList();
                    }
                }
            });
        });
    });
}

function initEventListeners() {
    const configForm = document.getElementById('config-form');
    if (configForm) {
        configForm.addEventListener('submit', saveConfig);
    }
    
    const loadConfigBtn = document.getElementById('load-config');
    if (loadConfigBtn) {
        loadConfigBtn.addEventListener('click', loadConfig);
    }
    
    const togglePasswordBtn = document.getElementById('toggle-password');
    if (togglePasswordBtn) {
        togglePasswordBtn.addEventListener('click', togglePasswordVisibility);
    }
    
    const refreshFilesBtn = document.getElementById('refresh-files');
    if (refreshFilesBtn) {
        refreshFilesBtn.addEventListener('click', loadFileList);
    }
    
    const startEncryptBtn = document.getElementById('start-encrypt');
    if (startEncryptBtn) {
        startEncryptBtn.addEventListener('click', startEncryption);
    }
    
    const startDecryptBtn = document.getElementById('start-decrypt');
    if (startDecryptBtn) {
        startDecryptBtn.addEventListener('click', startDecryption);
    }
    
    const stopOperationBtn = document.getElementById('stop-operation');
    if (stopOperationBtn) {
        stopOperationBtn.addEventListener('click', stopOperation);
    }
    
    const clearLogsBtn = document.getElementById('clear-logs');
    if (clearLogsBtn) {
        clearLogsBtn.addEventListener('click', clearLogs);
    }
    
    const searchInput = document.getElementById('search-files');
    if (searchInput) {
        searchInput.addEventListener('input', filterFiles);
    }
}

function togglePasswordVisibility() {
    const passwordInput = document.getElementById('password');
    const icon = this.querySelector('i');
    
    if (passwordInput.type === 'password') {
        passwordInput.type = 'text';
        icon.className = 'fas fa-eye-slash';
    } else {
        passwordInput.type = 'password';
        icon.className = 'fas fa-eye';
    }
}

async function checkAppStatus() {
    try {
        const response = await fetch('/api/status');
        const data = await response.json();
        const statusElement = document.getElementById('header-status');
        if (statusElement) {
            statusElement.textContent = data.status === 'running' ? '运行中' : '准备就绪';
        }
    } catch (error) {
        console.error('检查状态失败:', error);
    }
}

async function loadConfig() {
    try {
        const response = await fetch('/api/config');
        const config = await response.json();
        
        const passwordInput = document.getElementById('password');
        if (passwordInput) passwordInput.value = config.password || '';
        
        const encryptType = document.getElementById('encrypt-type');
        if (encryptType) encryptType.value = config.encrypt_type || 'aes';
        
        const targetPaths = document.getElementById('target-paths');
        if (targetPaths) targetPaths.value = (config.target_paths || []).join('\n');
        
        const obfuscateSuffix = document.getElementById('obfuscate-suffix');
        if (obfuscateSuffix) obfuscateSuffix.value = config.obfuscate_suffix || '.dat';
        
        const mapStoragePath = document.getElementById('map-storage-path');
        if (mapStoragePath) mapStoragePath.value = config.map_storage_path || '';
        
        updateStatusInfo(config);
    } catch (error) {
        console.error('加载配置失败:', error);
    }
}

async function saveConfig(e) {
    e.preventDefault();
    
    try {
        const formData = new FormData(document.getElementById('config-form'));
        const config = {
            password: formData.get('password'),
            encrypt_type: formData.get('encrypt_type'),
            target_paths: formData.get('target_paths').split('\n').filter(p => p.trim() !== ''),
            obfuscate_suffix: formData.get('obfuscate_suffix'),
            obfuscate_name_length: 12,
            map_filename: '.app_encrypt',
            lock_filename: '.encrypt.lock',
            map_storage_path: formData.get('map_storage_path'),
            salt: ''
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
    }
}

function updateStatusInfo(config) {
    const algoElement = document.getElementById('current-algo');
    const algoNames = {
        'aes': 'AES-256',
        'blowfish': 'Blowfish',
        'xor': 'XOR'
    };
    if (algoElement) algoElement.textContent = algoNames[config.encrypt_type] || 'AES-256';
    
    const pathsElement = document.getElementById('paths-count');
    if (pathsElement) pathsElement.textContent = (config.target_paths || []).length;
}

async function loadFileList() {
    try {
        const response = await fetch('/api/files');
        const data = await response.json();
        currentFiles = data.files || [];
        
        renderFileList(currentFiles);
        
        const encryptedCount = document.getElementById('encrypted-count');
        if (encryptedCount) encryptedCount.textContent = currentFiles.length;
        
        const totalFiles = document.getElementById('total-files');
        if (totalFiles) totalFiles.textContent = currentFiles.length;
    } catch (error) {
        console.error('加载文件列表失败:', error);
    }
}

function renderFileList(files) {
    const fileListBody = document.querySelector('#file-list');
    if (!fileListBody) return;
    
    if (!files || files.length === 0) {
        fileListBody.innerHTML = `
            <tr class="empty-row">
                <td colspan="8">
                    <div class="empty-state">
                        <i class="fas fa-folder-open"></i>
                        <p>暂无加密文件</p>
                    </div>
                </td>
            </tr>
        `;
        return;
    }
    
    fileListBody.innerHTML = files.map(file => {
        const originalPath = escapeHtml(file.original_path || '-');
        const encryptedPath = escapeHtml(file.encrypted_path || '-');
        const md5 = file.md5 ? file.md5.substring(0, 16) + '...' : '-';
        const salt = file.salt ? escapeHtml(file.salt) : '-';
        const password = file.password ? escapeHtml(file.password) : '-';
        const encryptType = file.encrypt_type ? escapeHtml(file.encrypt_type.toUpperCase()) : '-';
        const size = file.size ? formatFileSize(file.size) : '-';
        const targetDir = escapeHtml(file.target_dir || '-');
        
        return `
            <tr>
                <td><i class="fas fa-file"></i> ${originalPath}</td>
                <td><i class="fas fa-lock"></i> ${encryptedPath}</td>
                <td><i class="fas fa-fingerprint"></i> ${md5}</td>
                <td><i class="fas fa-key"></i> ${salt}</td>
                <td><i class="fas fa-unlock"></i> ${password}</td>
                <td><i class="fas fa-shield-alt"></i> ${encryptType}</td>
                <td>${size}</td>
                <td><i class="fas fa-folder"></i> ${targetDir}</td>
            </tr>
        `;
    }).join('');
}

function filterFiles(e) {
    const searchTerm = e.target.value.toLowerCase();
    const filteredFiles = currentFiles.filter(file => {
        return (file.original_path && file.original_path.toLowerCase().includes(searchTerm)) ||
               (file.encrypted_path && file.encrypted_path.toLowerCase().includes(searchTerm)) ||
               (file.salt && file.salt.toLowerCase().includes(searchTerm)) ||
               (file.password && file.password.toLowerCase().includes(searchTerm)) ||
               (file.encrypt_type && file.encrypt_type.toLowerCase().includes(searchTerm)) ||
               (file.target_dir && file.target_dir.toLowerCase().includes(searchTerm));
    });
    renderFileList(filteredFiles);
}

async function startEncryption() {
    try {
        updateOperationButtons(true);
        
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
    }
}

async function startDecryption() {
    try {
        updateOperationButtons(true);
        
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
    }
}

async function stopOperation() {
    try {
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
    }
}

function updateOperationButtons(running) {
    const startEncryptBtn = document.getElementById('start-encrypt');
    const startDecryptBtn = document.getElementById('start-decrypt');
    const stopOperationBtn = document.getElementById('stop-operation');
    const operationStatus = document.getElementById('operation-status');
    
    if (startEncryptBtn) startEncryptBtn.disabled = running;
    if (startDecryptBtn) startDecryptBtn.disabled = running;
    if (stopOperationBtn) stopOperationBtn.disabled = !running;
    
    if (operationStatus) {
        if (running) {
            operationStatus.innerHTML = '<i class="fas fa-circle"></i> 运行中';
        } else {
            operationStatus.innerHTML = '<i class="fas fa-circle"></i> 待命';
        }
    }
}

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
            const response = await fetch('/api/progress');
            if (response.ok) {
                const progressData = await response.json();
                
                if (!progressData.is_running) {
                    clearInterval(progressInterval);
                    updateOperationButtons(false);
                    updateProgress(100, '操作完成');
                    showMessage(`${currentOperation === 'encrypt' ? '加密' : '解密'}完成`, 'success');
                    currentOperation = null;
                    loadFileList();
                    return;
                }
                
                const currentProcessed = progressData.current_processed;
                const totalToProcess = progressData.total_to_process;
                
                let percent = 0;
                if (totalToProcess > 0) {
                    percent = (currentProcessed / totalToProcess) * 100;
                }
                
                if (percent > 100) percent = 100;
                
                updateProgress(
                    percent,
                    `${currentOperation === 'encrypt' ? '加密' : '解密'}进行中`,
                    `${currentProcessed}/${totalToProcess}`
                );
            }
        } catch (error) {
            console.error('获取进度信息失败:', error);
        }
    }, 1000);
}

function stopProgressTracking() {
    if (progressInterval) {
        clearInterval(progressInterval);
        progressInterval = null;
    }
}

function updateProgress(percent, text, countText) {
    const progressFill = document.getElementById('progress-fill');
    const progressText = document.getElementById('progress-text');
    const progressPercent = document.getElementById('progress-percent');
    
    if (progressFill) {
        progressFill.style.width = percent + '%';
    }
    if (progressText) {
        progressText.textContent = text;
    }
    if (progressPercent) {
        progressPercent.textContent = countText || '';
    }
}

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

function addLogMessage(message, level) {
    const logContent = document.getElementById('log-content');
    const autoScroll = document.getElementById('auto-scroll');
    
    if (!logContent) return;
    
    const timestamp = new Date().toLocaleTimeString();
    const logEntry = document.createElement('div');
    logEntry.className = 'log-line';
    logEntry.innerHTML = `<span class="timestamp">[${timestamp}]</span> ${escapeHtml(message)}`;
    
    logContent.appendChild(logEntry);
    
    if (autoScroll && autoScroll.checked) {
        logContent.scrollTop = logContent.scrollHeight;
    }
}

function clearLogs() {
    const logContent = document.getElementById('log-content');
    if (logContent) {
        logContent.innerHTML = '';
    }
}

function showMessage(message, type) {
    const existingMessage = document.querySelector('.message');
    if (existingMessage) {
        existingMessage.remove();
    }
    
    const messageDiv = document.createElement('div');
    messageDiv.className = `message ${type}`;
    messageDiv.textContent = message;
    
    const style = document.createElement('style');
    style.textContent = `
        .message {
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 15px 25px;
            border-radius: 12px;
            color: white;
            font-weight: 600;
            z-index: 10000;
            animation: slideIn 0.3s ease;
            box-shadow: 0 8px 32px rgba(0,0,0,0.3);
        }
        .message.success {
            background: linear-gradient(135deg, #22c55e, #16a34a);
        }
        .message.error {
            background: linear-gradient(135deg, #ef4444, #dc2626);
        }
        @keyframes slideIn {
            from {
                transform: translateX(100%);
                opacity: 0;
            }
            to {
                transform: translateX(0);
                opacity: 1;
            }
        }
    `;
    
    if (!document.querySelector('style[message]')) {
        style.setAttribute('message', 'true');
        document.head.appendChild(style);
    }
    
    document.body.appendChild(messageDiv);
    
    setTimeout(() => {
        if (messageDiv.parentNode) {
            messageDiv.remove();
        }
    }, 3000);
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

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
