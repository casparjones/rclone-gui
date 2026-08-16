// The remote folder pane inside the sync modal: remote picker, folder listing,
// breadcrumb and the localStorage cache that makes reopening the modal instant.

import { state, STORAGE_KEYS } from '../state.js';
import { fetchRemoteFiles } from '../api.js';
import { showAlert } from '../util/dom.js';
import { getParentPath } from '../util/format.js';

export function updateRemoteSelect() {
    const remoteSelect = document.getElementById('sync-remote');
    remoteSelect.innerHTML = '<option value="">Select remote...</option>';

    state.configs.forEach(config => {
        const option = document.createElement('option');
        option.value = config.name;
        option.textContent = config.name;
        remoteSelect.appendChild(option);
    });

    // Auto-select logic
    if (state.configs.length === 1) {
        // Only one remote - auto-select it
        remoteSelect.value = state.configs[0].name;
        saveLastSelectedRemote(state.configs[0].name);
        loadRemoteFiles('/'); // Load root folder immediately
    } else if (state.configs.length > 1) {
        // Multiple remotes - try to restore last selected
        const lastRemote = getLastSelectedRemote();
        if (lastRemote && state.configs.some(config => config.name === lastRemote)) {
            remoteSelect.value = lastRemote;
            loadRemoteFiles('/'); // Load root folder for restored remote
        }
    }
}

function saveLastSelectedRemote(remoteName) {
    localStorage.setItem(STORAGE_KEYS.lastRemote, remoteName);
}

export function getLastSelectedRemote() {
    return localStorage.getItem(STORAGE_KEYS.lastRemote);
}

export function clearLastSelectedRemote() {
    localStorage.removeItem(STORAGE_KEYS.lastRemote);
}

export function onRemoteSelectChange() {
    const remoteName = document.getElementById('sync-remote').value;
    if (remoteName) {
        saveLastSelectedRemote(remoteName);
        loadRemoteFiles('/'); // Reset to root when changing remote
    }
}

// Cache management for remote folders ----------------------------------------

function getCacheKey(remoteName, remotePath) {
    return `${STORAGE_KEYS.remoteCachePrefix}${remoteName}-${remotePath}`;
}

function saveRemoteFolderCache(remoteName, remotePath, folders) {
    const cacheKey = getCacheKey(remoteName, remotePath);
    const cacheData = {
        folders: folders,
        timestamp: Date.now(),
        remoteName: remoteName,
        remotePath: remotePath
    };
    localStorage.setItem(cacheKey, JSON.stringify(cacheData));
}

function getRemoteFolderCache(remoteName, remotePath) {
    const cacheKey = getCacheKey(remoteName, remotePath);
    const cached = localStorage.getItem(cacheKey);

    if (!cached) return null;

    try {
        const cacheData = JSON.parse(cached);
        const cacheAge = Date.now() - cacheData.timestamp;

        // Cache is valid for 5 minutes (300000 ms)
        if (cacheAge < 300000) {
            return cacheData.folders;
        }

        // Remove expired cache
        localStorage.removeItem(cacheKey);
        return null;
    } catch (e) {
        // Invalid cache data, remove it
        localStorage.removeItem(cacheKey);
        return null;
    }
}

export function clearRemoteCache(remoteName = null) {
    const keys = Object.keys(localStorage);
    keys.forEach(key => {
        if (key.startsWith(STORAGE_KEYS.remoteCachePrefix)) {
            if (!remoteName || key.startsWith(`${STORAGE_KEYS.remoteCachePrefix}${remoteName}-`)) {
                localStorage.removeItem(key);
            }
        }
    });
}

// Listing --------------------------------------------------------------------

export async function loadRemoteFiles(remotePath = '/') {
    const remoteName = document.getElementById('sync-remote').value;
    if (!remoteName) {
        return;
    }

    state.currentRemotePath = remotePath;

    // Wenn wir in einen neuen Ordner navigieren, setze ihn auch als ausgewählt
    state.selectedRemotePath = remotePath;
    document.getElementById('selected-remote-path').textContent = remotePath;

    // Check cache first
    const cachedFolders = getRemoteFolderCache(remoteName, remotePath);

    if (cachedFolders) {
        // Show cached data immediately
        displayRemoteFiles(cachedFolders);
        updateRemoteBreadcrumb(remotePath);

        // Still fetch fresh data in background to update cache
        loadRemoteFilesInBackground(remoteName, remotePath);
    } else {
        // No cache - show loading spinner and fetch data
        showRemoteLoadingSpinner();
        await loadRemoteFilesFromServer(remoteName, remotePath);
    }
}

async function loadRemoteFilesFromServer(remoteName, remotePath) {
    try {
        const result = await fetchRemoteFiles(remoteName, remotePath);

        if (result.ok) {
            // Filter only directories for our use case
            const folders = result.data.filter(file => file.is_dir);

            // Save to cache
            saveRemoteFolderCache(remoteName, remotePath, folders);

            // Display the folders
            displayRemoteFiles(folders);
            updateRemoteBreadcrumb(remotePath);
        } else {
            showAlert('sync-alert', 'Error loading remote files: ' + result.error, 'error');
            hideRemoteLoadingSpinner();
        }
    } catch (error) {
        showAlert('sync-alert', 'Error loading remote files: ' + error.message, 'error');
        hideRemoteLoadingSpinner();
    }
}

async function loadRemoteFilesInBackground(remoteName, remotePath) {
    try {
        const result = await fetchRemoteFiles(remoteName, remotePath);

        if (result.ok) {
            const folders = result.data.filter(file => file.is_dir);

            // Update cache with fresh data
            saveRemoteFolderCache(remoteName, remotePath, folders);

            // Update display if user is still on the same path
            if (state.currentRemotePath === remotePath && document.getElementById('sync-remote').value === remoteName) {
                displayRemoteFiles(folders);
            }
        }
    } catch (error) {
        // Silent fail for background updates
        console.warn('Background folder refresh failed:', error);
    }
}

function showRemoteLoadingSpinner() {
    const remoteFileList = document.getElementById('remote-file-list');
    remoteFileList.innerHTML = `
        <div class="flex items-center justify-center py-8">
            <span class="loading loading-spinner loading-md mr-2"></span>
            <span class="text-base-content/70">Loading folders...</span>
        </div>
    `;
}

function hideRemoteLoadingSpinner() {
    // This is called implicitly when displayRemoteFiles() updates the innerHTML
}

// Eine Ordner-Karte. Name und Pfad kommen vom Remote und sind damit fremd
// kontrolliert: der Name geht per textContent hinein, der Pfad landet in einer
// Closure statt in einem onclick-Attribut. Ein Ordner `<img src=x onerror=…>`
// oder `'); alert(1); //` kann so strukturell nichts auslösen.
function remoteFolderCard(cardClass, label, path) {
    const card = document.createElement('div');
    card.className = cardClass;

    const body = document.createElement('div');
    body.className = 'card-body py-2 px-3';

    const row = document.createElement('div');
    row.className = 'flex items-center space-x-3';

    const icon = document.createElement('div');
    icon.className = 'text-xl';
    icon.textContent = cardClass.includes('bg-warning') ? '⬆️' : '📁';

    const name = document.createElement('div');
    name.className = 'font-medium';
    name.textContent = label;

    row.appendChild(icon);
    row.appendChild(name);
    body.appendChild(row);
    card.appendChild(body);

    card.addEventListener('click', () => selectRemoteFolder(path, card));
    card.addEventListener('dblclick', () => loadRemoteFiles(path));

    return card;
}

function displayRemoteFiles(files) {
    const remoteFileList = document.getElementById('remote-file-list');

    // Filter nur Ordner (falls noch nicht gefiltert)
    const folders = Array.isArray(files) ? files.filter(file => file.is_dir || !Object.prototype.hasOwnProperty.call(file, 'is_dir')) : files;

    if (folders.length === 0 && state.currentRemotePath === '/') {
        remoteFileList.innerHTML = '<div class="text-center text-base-content/60 py-4">Keine Ordner gefunden.</div>';
        return;
    }

    const cards = [];

    // Parent-Ordner (..) hinzufügen, wenn nicht im Root
    if (state.currentRemotePath !== '/') {
        const parentPath = getParentPath(state.currentRemotePath);
        const parentLabel = parentPath === '/' ? 'Root' : parentPath.split('/').pop();
        cards.push(remoteFolderCard(
            'card bg-warning/10 border border-warning/20 cursor-pointer hover:bg-warning/20 transition-colors',
            `.. (zurück zu ${parentLabel})`,
            parentPath
        ));
    }

    folders.forEach(folder => {
        cards.push(remoteFolderCard(
            'card bg-base-200 cursor-pointer hover:bg-base-300 transition-colors',
            folder.name,
            folder.path
        ));
    });

    remoteFileList.replaceChildren(...cards);
}

// Auch der Breadcrumb wird aus Elementen gebaut: die Pfadsegmente stammen vom
// Remote und dürfen weder als Markup noch in ein onclick-Attribut geraten.
function breadcrumbLink(label, path) {
    const link = document.createElement('a');
    link.textContent = label;
    link.addEventListener('click', () => loadRemoteFiles(path));
    return link;
}

function updateRemoteBreadcrumb(path) {
    const remoteBreadcrumb = document.getElementById('remote-breadcrumb');
    const parts = path.split('/').filter(part => part);

    const nodes = [breadcrumbLink('Root', '/')];
    let currentPath = '';

    parts.forEach(part => {
        currentPath += '/' + part;
        nodes.push(document.createTextNode(' / '));
        nodes.push(breadcrumbLink(part, currentPath));
    });

    remoteBreadcrumb.replaceChildren(...nodes);
}

// Die Karte wird jetzt direkt übergeben (Listener statt inline onclick). Der
// window.event-Zweig bleibt als Rückfallebene für Aufrufe aus dem Markup.
export function selectRemoteFolder(folderPath, cardElement) {
    // Vorherige Auswahl entfernen - jetzt mit card Selektoren
    document.querySelectorAll('#remote-file-list .card').forEach(item => {
        item.classList.remove('bg-primary/20', 'border-primary');
        item.classList.add('bg-base-200');
    });

    // Aktuelle Auswahl markieren
    const clickedCard = cardElement || (window.event && window.event.target.closest('.card'));
    if (clickedCard) {
        clickedCard.classList.remove('bg-base-200', 'bg-warning/10');
        clickedCard.classList.add('bg-primary/20', 'border-primary');
    }

    // Ausgewählten Pfad aktualisieren
    state.selectedRemotePath = folderPath;
    document.getElementById('selected-remote-path').textContent = folderPath;
}
