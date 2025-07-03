// Global variables
let currentPath = window.DEFAULT_PATH || '/mnt/home';
let currentRemotePath = '/';
let currentSyncSource = '';
let currentSyncJobId = '';
let configs = [];

// Initialize app
document.addEventListener('DOMContentLoaded', function() {
    loadConfigs();
    loadFiles();
    loadSyncJobs();
    
    // Set up form submission
    document.getElementById('config-form').addEventListener('submit', saveConfig);
    
    // Auto-refresh sync jobs
    setInterval(loadSyncJobs, 2000);
});

// Tab switching
function switchTab(tabName) {
    // Hide all tabs
    document.querySelectorAll('.tab-content').forEach(tab => {
        tab.classList.remove('active');
    });
    document.querySelectorAll('.tab').forEach(tab => {
        tab.classList.remove('active');
    });
    
    // Show selected tab
    document.getElementById(tabName + '-tab').classList.add('active');
    event.target.classList.add('active');
    
    // Refresh content based on tab
    switch(tabName) {
        case 'config':
            loadConfigs();
            break;
        case 'files':
            loadFiles();
            break;
        case 'sync':
            loadSyncJobs();
            break;
    }
}

// Configuration functions
async function saveConfig(event) {
    event.preventDefault();
    
    const config = {
        name: document.getElementById('config-name').value,
        config_type: document.getElementById('config-type').value,
        url: document.getElementById('config-url').value || null,
        username: document.getElementById('config-username').value || null,
        password: document.getElementById('config-password').value || null
    };
    
    try {
        const response = await fetch('/api/configs', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(config)
        });
        
        const result = await response.json();
        
        if (result.success) {
            showAlert('config-alert', 'Configuration saved successfully!', 'success');
            document.getElementById('config-form').reset();
            loadConfigs();
        } else {
            showAlert('config-alert', 'Error: ' + result.error, 'error');
        }
    } catch (error) {
        showAlert('config-alert', 'Error saving configuration: ' + error.message, 'error');
    }
}

async function loadConfigs() {
    try {
        const response = await fetch('/api/configs');
        const result = await response.json();
        
        if (result.success) {
            configs = result.data;
            displayConfigs();
            updateRemoteSelect();
        } else {
            showAlert('config-alert', 'Error loading configurations: ' + result.error, 'error');
        }
    } catch (error) {
        showAlert('config-alert', 'Error loading configurations: ' + error.message, 'error');
    }
}

function displayConfigs() {
    const configList = document.getElementById('config-list');
    
    if (configs.length === 0) {
        configList.innerHTML = '<p>No configurations found.</p>';
        return;
    }
    
    configList.innerHTML = configs.map(config => `
        <div class="config-item">
            <div>
                <div class="config-name">${config.name}</div>
                <div class="config-type">${config.config_type}</div>
            </div>
            <button class="delete-btn" onclick="deleteConfig('${config.name}')">Delete</button>
        </div>
    `).join('');
}

async function deleteConfig(name) {
    if (!confirm('Are you sure you want to delete this configuration?')) {
        return;
    }
    
    try {
        const response = await fetch(`/api/configs/${name}`, {
            method: 'DELETE'
        });
        
        const result = await response.json();
        
        if (result.success) {
            showAlert('config-alert', 'Configuration deleted successfully!', 'success');
            loadConfigs();
        } else {
            showAlert('config-alert', 'Error deleting configuration: ' + result.error, 'error');
        }
    } catch (error) {
        showAlert('config-alert', 'Error deleting configuration: ' + error.message, 'error');
    }
}

// File browser functions
async function loadFiles(path = currentPath) {
    currentPath = path;
    
    try {
        const response = await fetch(`/api/files/local?path=${encodeURIComponent(path)}`);
        const result = await response.json();
        
        if (result.success) {
            displayFiles(result.data);
            updateBreadcrumb(path);
        } else {
            showAlert('files-alert', 'Error loading files: ' + result.error, 'error');
        }
    } catch (error) {
        showAlert('files-alert', 'Error loading files: ' + error.message, 'error');
    }
}

function displayFiles(files) {
    const fileList = document.getElementById('file-list');
    
    if (files.length === 0) {
        fileList.innerHTML = '<p>No files found.</p>';
        return;
    }
    
    fileList.innerHTML = files.map(file => `
        <div class="file-item" ${file.is_dir ? `onclick="loadFiles('${file.path}')"` : ''}>
            <div class="file-icon">${file.is_dir ? '📁' : '📄'}</div>
            <div class="file-name">${file.name}</div>
            <div class="file-actions">
                <button class="sync-btn" onclick="openSyncModal('${file.path}')">Sync</button>
            </div>
        </div>
    `).join('');
}

function updateBreadcrumb(path) {
    const breadcrumb = document.getElementById('breadcrumb');
    const parts = path.split('/').filter(part => part);
    
    let breadcrumbHTML = '<a onclick="loadFiles(\'/\')">Root</a>';
    let currentPath = '';
    
    parts.forEach(part => {
        currentPath += '/' + part;
        breadcrumbHTML += ` / <a onclick="loadFiles('${currentPath}')">${part}</a>`;
    });
    
    breadcrumb.innerHTML = breadcrumbHTML;
}

// Sync functions
function openSyncModal(sourcePath) {
    currentSyncSource = sourcePath;
    document.getElementById('sync-source').value = sourcePath;
    document.getElementById('sync-modal').style.display = 'block';
    updateRemoteSelect();
    
    // Suggest chunk size based on file/folder
    suggestChunkSize(sourcePath);
}

function suggestChunkSize(sourcePath) {
    // This is a simple heuristic - in a real implementation,
    // you might want to check actual file sizes
    const fileName = sourcePath.split('/').pop().toLowerCase();
    const chunkSizeSelect = document.getElementById('chunk-size');
    
    if (fileName.includes('video') || fileName.includes('.mp4') || fileName.includes('.avi') || fileName.includes('.mkv')) {
        chunkSizeSelect.value = '32M';
        showAlert('sync-alert', 'Video-Datei erkannt: 32MB Chunks empfohlen', 'success');
    } else if (fileName.includes('iso') || fileName.includes('.zip') || fileName.includes('.tar')) {
        chunkSizeSelect.value = '64M';
        showAlert('sync-alert', 'Große Archiv-Datei erkannt: 64MB Chunks empfohlen', 'success');
    } else {
        chunkSizeSelect.value = '8M';
    }
}

function closeSyncModal() {
    document.getElementById('sync-modal').style.display = 'none';
    currentSyncSource = '';
    currentRemotePath = '/';
}

function updateRemoteSelect() {
    const remoteSelect = document.getElementById('sync-remote');
    remoteSelect.innerHTML = '<option value="">Select remote...</option>';
    
    configs.forEach(config => {
        const option = document.createElement('option');
        option.value = config.name;
        option.textContent = config.name;
        remoteSelect.appendChild(option);
    });
}

async function loadRemoteFiles(remotePath = '/') {
    const remoteName = document.getElementById('sync-remote').value;
    if (!remoteName) {
        return;
    }
    
    currentRemotePath = remotePath;
    
    try {
        const response = await fetch(`/api/files/remote?remote=${remoteName}&path=${encodeURIComponent(remotePath)}`);
        const result = await response.json();
        
        if (result.success) {
            displayRemoteFiles(result.data);
            updateRemoteBreadcrumb(remotePath);
        } else {
            showAlert('sync-alert', 'Error loading remote files: ' + result.error, 'error');
        }
    } catch (error) {
        showAlert('sync-alert', 'Error loading remote files: ' + error.message, 'error');
    }
}

function displayRemoteFiles(files) {
    const remoteFileList = document.getElementById('remote-file-list');
    
    if (files.length === 0) {
        remoteFileList.innerHTML = '<p>No files found.</p>';
        return;
    }
    
    remoteFileList.innerHTML = files.map(file => `
        <div class="file-item" ${file.is_dir ? `onclick="loadRemoteFiles('${file.path}')"` : ''}>
            <div class="file-icon">${file.is_dir ? '📁' : '📄'}</div>
            <div class="file-name">${file.name}</div>
        </div>
    `).join('');
}

function updateRemoteBreadcrumb(path) {
    const remoteBreadcrumb = document.getElementById('remote-breadcrumb');
    const parts = path.split('/').filter(part => part);
    
    let breadcrumbHTML = '<a onclick="loadRemoteFiles(\'/\')">Root</a>';
    let currentPath = '';
    
    parts.forEach(part => {
        currentPath += '/' + part;
        breadcrumbHTML += ` / <a onclick="loadRemoteFiles('${currentPath}')">${part}</a>`;
    });
    
    remoteBreadcrumb.innerHTML = breadcrumbHTML;
}

async function startSync() {
    const remoteName = document.getElementById('sync-remote').value;
    
    if (!remoteName) {
        showAlert('sync-alert', 'Please select a remote', 'error');
        return;
    }
    
    const useChunking = document.getElementById('use-chunking').checked;
    const chunkSize = document.getElementById('chunk-size').value;
    
    const syncRequest = {
        source_path: currentSyncSource,
        remote_name: remoteName,
        remote_path: currentRemotePath,
        use_chunking: useChunking,
        chunk_size: useChunking ? chunkSize : null
    };
    
    try {
        const response = await fetch('/api/sync', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(syncRequest)
        });
        
        const result = await response.json();
        
        if (result.success) {
            currentSyncJobId = result.data;
            closeSyncModal();
            openProgressModal();
            monitorProgress();
        } else {
            showAlert('sync-alert', 'Error starting sync: ' + result.error, 'error');
        }
    } catch (error) {
        showAlert('sync-alert', 'Error starting sync: ' + error.message, 'error');
    }
}

function openProgressModal() {
    document.getElementById('progress-modal').style.display = 'block';
}

function closeProgressModal() {
    document.getElementById('progress-modal').style.display = 'none';
    currentSyncJobId = '';
}

async function monitorProgress() {
    if (!currentSyncJobId) return;
    
    try {
        const response = await fetch(`/api/sync/${currentSyncJobId}`);
        const result = await response.json();
        
        if (result.success) {
            const progress = result.data;
            updateProgressDisplay(progress);
            
            if (progress.status === 'Running' || progress.status === 'Starting') {
                setTimeout(monitorProgress, 1000);
            }
        }
    } catch (error) {
        console.error('Error monitoring progress:', error);
    }
}

function updateProgressDisplay(progress) {
    document.getElementById('progress-fill').style.width = progress.progress + '%';
    document.getElementById('progress-info').textContent = `Status: ${progress.status}`;
    document.getElementById('progress-details').innerHTML = `
        <p>Progress: ${progress.progress.toFixed(1)}%</p>
        <p>Transferred: ${formatBytes(progress.transferred)}</p>
        <p>Total: ${formatBytes(progress.total)}</p>
    `;
}

async function loadSyncJobs() {
    try {
        const response = await fetch('/api/sync');
        const result = await response.json();
        
        if (result.success) {
            displaySyncJobs(result.data);
        }
    } catch (error) {
        console.error('Error loading sync jobs:', error);
    }
}

function displaySyncJobs(jobs) {
    const syncJobsDiv = document.getElementById('sync-jobs');
    
    if (jobs.length === 0) {
        syncJobsDiv.innerHTML = '<p>No sync jobs found.</p>';
        return;
    }
    
    syncJobsDiv.innerHTML = jobs.map(job => `
        <div class="config-item">
            <div>
                <div class="config-name">Job ID: ${job.id}</div>
                <div class="config-type">Status: ${job.status} (${job.progress.toFixed(1)}%)</div>
            </div>
            <div class="progress-bar" style="width: 200px;">
                <div class="progress-fill" style="width: ${job.progress}%"></div>
            </div>
        </div>
    `).join('');
}

// Utility functions
function showAlert(containerId, message, type) {
    const container = document.getElementById(containerId);
    container.innerHTML = `<div class="alert alert-${type}">${message}</div>`;
    
    // Auto-hide after 5 seconds
    setTimeout(() => {
        container.innerHTML = '';
    }, 5000);
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

async function persistConfigs() {
    try {
        const response = await fetch('/api/configs/persist', {
            method: 'POST'
        });
        
        const result = await response.json();
        
        if (result.success) {
            showAlert('config-alert', 'Configurations saved to file successfully!', 'success');
        } else {
            showAlert('config-alert', 'Error saving configurations: ' + result.error, 'error');
        }
    } catch (error) {
        showAlert('config-alert', 'Error saving configurations: ' + error.message, 'error');
    }
}