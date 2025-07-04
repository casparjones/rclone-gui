// Global variables
let currentPath = window.DEFAULT_PATH || '/mnt/home';
let currentRemotePath = '/';
let selectedRemotePath = '/';  // Der aktuell ausgewählte Ordner für den Upload
let currentSyncSource = '';
let currentSyncJobId = '';
let configs = [];

// Initialize app
document.addEventListener('DOMContentLoaded', function() {
    // Load initial data
    loadConfigs().then(() => {
        // Check if we have configs and set default tab accordingly
        setDefaultTab();
    });
    loadFiles();
    loadSyncJobs();
    
    // Set up form submission
    document.getElementById('config-form').addEventListener('submit', saveConfig);
    
    // Auto-refresh sync jobs
    setInterval(loadSyncJobs, 2000);
});

function setDefaultTab() {
    // If no configs exist, show config tab, otherwise show file browser
    if (configs.length === 0) {
        // Hide file browser tab and show config tab
        document.getElementById('files-tab').classList.remove('block');
        document.getElementById('config-tab').classList.add('block');
        
        // Update tab buttons
        document.getElementById('files-tab-btn').classList.remove('tab-active');
        document.getElementById('config-tab-btn').classList.add('tab-active');
        
        showToast('No remote configurations found. Please add a remote first.', 'info');
    }
    // File browser is already default (has 'block' class in HTML)
}

// Tab switching for DaisyUI
function switchTab(tabName) {
    // Hide all tab contents (remove block class)
    document.querySelectorAll('.tab-content').forEach(tab => {
        tab.classList.remove('block');
    });
    
    // Remove active class from all tabs
    document.querySelectorAll('.tab').forEach(tab => {
        tab.classList.remove('tab-active');
    });
    
    // Show selected tab content (add block class to override display: none)
    document.getElementById(tabName + '-tab').classList.add('block');
    
    // Add active class to clicked tab
    event.target.classList.add('tab-active');
    
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
            return configs; // Return for promise handling
        } else {
            showAlert('config-alert', 'Error loading configurations: ' + result.error, 'error');
            return [];
        }
    } catch (error) {
        showAlert('config-alert', 'Error loading configurations: ' + error.message, 'error');
        return [];
    }
}

function displayConfigs() {
    const configList = document.getElementById('config-list');
    
    if (configs.length === 0) {
        configList.innerHTML = '<div class="text-center text-base-content/60 py-8">No configurations found.</div>';
        return;
    }
    
    configList.innerHTML = configs.map(config => `
        <div class="card bg-base-200 shadow-sm">
            <div class="card-body py-3 px-4">
                <div class="flex items-center justify-between">
                    <div>
                        <div class="font-semibold text-lg">${config.name}</div>
                        <div class="text-sm text-base-content/70">${config.config_type}</div>
                    </div>
                    <button class="btn btn-error btn-sm" onclick="deleteConfig('${config.name}')">
                        <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                        </svg>
                        Delete
                    </button>
                </div>
            </div>
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
        fileList.innerHTML = '<div class="text-center text-base-content/60 py-8">No files found.</div>';
        return;
    }
    
    fileList.innerHTML = files.map(file => {
        const sizeInfo = file.size ? formatBytes(file.size) : '';
        const fileTypeInfo = file.is_dir ? 'Folder' : (sizeInfo ? `File · ${sizeInfo}` : 'File');
        
        return `
        <div class="card bg-base-100 shadow-sm file-item-hover cursor-pointer" ${file.is_dir ? `onclick="loadFiles('${file.path}')"` : ''}>
            <div class="card-body py-3 px-4">
                <div class="flex items-center justify-between">
                    <div class="flex items-center space-x-3">
                        <div class="text-2xl">${file.is_dir ? '📁' : '📄'}</div>
                        <div>
                            <div class="font-medium">${file.name}</div>
                            <div class="text-sm text-base-content/70">${fileTypeInfo}</div>
                        </div>
                    </div>
                    <div class="flex items-center space-x-2">
                        <button class="btn btn-primary btn-sm" onclick="event.stopPropagation(); openSyncModal('${file.path}')">
                            <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
                            </svg>
                            Sync
                        </button>
                    </div>
                </div>
            </div>
        </div>
        `;
    }).join('');
}

function updateBreadcrumb(path) {
    const breadcrumb = document.getElementById('breadcrumb');
    const parts = path.split('/').filter(part => part);
    
    let breadcrumbHTML = '<li><a onclick="loadFiles(\'/\')" class="cursor-pointer hover:text-primary">🏠 Root</a></li>';
    let currentPath = '';
    
    parts.forEach(part => {
        currentPath += '/' + part;
        breadcrumbHTML += `<li><a onclick="loadFiles('${currentPath}')" class="cursor-pointer hover:text-primary">${part}</a></li>`;
    });
    
    breadcrumb.innerHTML = breadcrumbHTML;
}

// Sync functions
function openSyncModal(sourcePath) {
    currentSyncSource = sourcePath;
    document.getElementById('sync-source').value = sourcePath;
    document.getElementById('sync-modal').showModal();
    updateRemoteSelect();
    
    // Suggest chunk size based on file/folder
    suggestChunkSize(sourcePath);
}

function suggestChunkSize(sourcePath) {
    // This is a simple heuristic - in a real implementation,
    // you might want to check actual file sizes
    const fileName = sourcePath.split('/').pop().toLowerCase();
    const performanceSelect = document.getElementById('chunk-size');
    
    if (fileName.includes('video') || fileName.includes('.mp4') || fileName.includes('.avi') || fileName.includes('.mkv')) {
        performanceSelect.value = '32M';
        showAlert('sync-alert', 'Video-Datei erkannt: Aggressives Multi-Threading empfohlen', 'success');
    } else if (fileName.includes('iso') || fileName.includes('.zip') || fileName.includes('.tar')) {
        performanceSelect.value = '64M';
        showAlert('sync-alert', 'Große Archiv-Datei erkannt: Maximum Performance empfohlen', 'success');
    } else {
        performanceSelect.value = '16M';
    }
}

function closeSyncModal() {
    document.getElementById('sync-modal').close();
    currentSyncSource = '';
    currentRemotePath = '/';
    selectedRemotePath = '/';
    document.getElementById('selected-remote-path').textContent = '/';
    
    // Alle Auswahlen entfernen - jetzt mit card Selektoren
    document.querySelectorAll('#remote-file-list .card').forEach(item => {
        item.classList.remove('bg-primary/20', 'border-primary');
        item.classList.add('bg-base-200');
    });
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
    
    // Wenn wir in einen neuen Ordner navigieren, setze ihn auch als ausgewählt
    selectedRemotePath = remotePath;
    document.getElementById('selected-remote-path').textContent = remotePath;
    
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
    
    // Filter nur Ordner
    const folders = files.filter(file => file.is_dir);
    
    let html = '';
    
    // Parent-Ordner (..) hinzufügen, wenn nicht im Root
    if (currentRemotePath !== '/') {
        const parentPath = getParentPath(currentRemotePath);
        html += `
            <div class="card bg-warning/10 border border-warning/20 cursor-pointer hover:bg-warning/20 transition-colors" 
                 onclick="selectRemoteFolder('${parentPath}')" 
                 ondblclick="loadRemoteFiles('${parentPath}')">
                <div class="card-body py-2 px-3">
                    <div class="flex items-center space-x-3">
                        <div class="text-xl">⬆️</div>
                        <div class="font-medium">.. (zurück zu ${parentPath === '/' ? 'Root' : parentPath.split('/').pop()})</div>
                    </div>
                </div>
            </div>
        `;
    }
    
    // Ordner hinzufügen
    html += folders.map(folder => `
        <div class="card bg-base-200 cursor-pointer hover:bg-base-300 transition-colors" 
             onclick="selectRemoteFolder('${folder.path}')" 
             ondblclick="loadRemoteFiles('${folder.path}')">
            <div class="card-body py-2 px-3">
                <div class="flex items-center space-x-3">
                    <div class="text-xl">📁</div>
                    <div class="font-medium">${folder.name}</div>
                </div>
            </div>
        </div>
    `).join('');
    
    if (folders.length === 0 && currentRemotePath === '/') {
        html = '<div class="text-center text-base-content/60 py-4">Keine Ordner gefunden.</div>';
    }
    
    remoteFileList.innerHTML = html;
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

function selectRemoteFolder(folderPath) {
    // Vorherige Auswahl entfernen - jetzt mit card Selektoren
    document.querySelectorAll('#remote-file-list .card').forEach(item => {
        item.classList.remove('bg-primary/20', 'border-primary');
        item.classList.add('bg-base-200');
    });
    
    // Aktuelle Auswahl markieren
    const clickedCard = event.target.closest('.card');
    if (clickedCard) {
        clickedCard.classList.remove('bg-base-200', 'bg-warning/10');
        clickedCard.classList.add('bg-primary/20', 'border-primary');
    }
    
    // Ausgewählten Pfad aktualisieren
    selectedRemotePath = folderPath;
    document.getElementById('selected-remote-path').textContent = folderPath;
}

function getParentPath(path) {
    if (path === '/' || path === '') {
        return '/';
    }
    
    // Entferne trailing slash falls vorhanden
    path = path.replace(/\/$/, '');
    
    // Finde das letzte '/' und schneide alles danach ab
    const lastSlash = path.lastIndexOf('/');
    if (lastSlash <= 0) {
        return '/';
    }
    
    return path.substring(0, lastSlash);
}

async function startSync() {
    const remoteName = document.getElementById('sync-remote').value;
    
    if (!remoteName) {
        showAlert('sync-alert', 'Please select a remote', 'error');
        return;
    }
    
    const useMultiThreading = document.getElementById('use-chunking').checked;
    const performanceLevel = document.getElementById('chunk-size').value;
    
    const syncRequest = {
        source_path: currentSyncSource,
        remote_name: remoteName,
        remote_path: selectedRemotePath,  // Verwende den ausgewählten Pfad
        use_chunking: useMultiThreading,
        chunk_size: useMultiThreading ? performanceLevel : null
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
    document.getElementById('progress-modal').showModal();
}

function closeProgressModal() {
    document.getElementById('progress-modal').close();
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
        syncJobsDiv.innerHTML = '<div class="text-center text-base-content/60 py-8">No sync jobs found.</div>';
        return;
    }
    
    syncJobsDiv.innerHTML = jobs.map(job => {
        const statusColor = job.status === 'Completed' ? 'badge-success' : 
                           job.status === 'Failed' ? 'badge-error' : 
                           job.status === 'Running' ? 'badge-warning' : 'badge-info';
        
        return `
            <div class="card bg-base-100 shadow-sm">
                <div class="card-body py-4 px-5">
                    <div class="flex items-center justify-between mb-3">
                        <div>
                            <div class="font-semibold text-lg">Job ID: ${job.id.substring(0, 8)}...</div>
                            <div class="flex items-center space-x-2 mt-1">
                                <span class="badge ${statusColor}">${job.status}</span>
                                <span class="text-sm text-base-content/70">${job.progress.toFixed(1)}%</span>
                            </div>
                        </div>
                        <div class="text-right">
                            <div class="text-sm text-base-content/70">Progress</div>
                            <div class="text-lg font-bold">${job.progress.toFixed(1)}%</div>
                        </div>
                    </div>
                    
                    <div class="w-full bg-base-300 rounded-full h-3">
                        <div class="bg-primary h-3 rounded-full progress-animate" style="width: ${job.progress}%"></div>
                    </div>
                    
                    <div class="flex justify-between text-sm text-base-content/70 mt-2">
                        <span>Transferred: ${formatBytes(job.transferred)}</span>
                        <span>Total: ${formatBytes(job.total)}</span>
                    </div>
                </div>
            </div>
        `;
    }).join('');
}

// Utility functions
function showAlert(containerId, message, type) {
    // Show as toast notification instead of inline alert
    showToast(message, type);
}

function showToast(message, type) {
    const container = document.getElementById('toast-container');
    const toastId = 'toast-' + Date.now();
    
    const alertClass = type === 'error' ? 'alert-error' : type === 'success' ? 'alert-success' : 'alert-info';
    const icon = type === 'error' ? '❌' : type === 'success' ? '✅' : 'ℹ️';
    
    const toast = document.createElement('div');
    toast.id = toastId;
    toast.className = `alert ${alertClass} shadow-lg mb-2`;
    toast.innerHTML = `
        <span>${icon} ${message}</span>
        <button onclick="removeToast('${toastId}')" class="btn btn-ghost btn-xs">✕</button>
    `;
    
    container.appendChild(toast);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        removeToast(toastId);
    }, 5000);
}

function removeToast(toastId) {
    const toast = document.getElementById(toastId);
    if (toast) {
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(-100%)';
        setTimeout(() => {
            if (toast.parentNode) {
                toast.parentNode.removeChild(toast);
            }
        }, 300);
    }
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    if (bytes === null || bytes === undefined) return '';
    
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    // Special formatting: 1 decimal for GB and TB, no decimals for smaller units
    if (i >= 3) { // GB or TB
        return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
    } else if (i >= 2) { // MB
        return Math.round(bytes / Math.pow(k, i)) + ' ' + sizes[i];
    } else {
        return parseFloat((bytes / Math.pow(k, i)).toFixed(0)) + ' ' + sizes[i];
    }
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