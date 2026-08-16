// Pure formatting helpers — no DOM, no state.

export function formatBytes(bytes) {
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

export function formatDuration(seconds) {
    if (seconds < 60) {
        return `${seconds}s`;
    } else if (seconds < 3600) {
        const minutes = Math.floor(seconds / 60);
        const remainingSeconds = seconds % 60;
        return remainingSeconds > 0 ? `${minutes}m ${remainingSeconds}s` : `${minutes}m`;
    } else {
        const hours = Math.floor(seconds / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        return minutes > 0 ? `${hours}h ${minutes}m` : `${hours}h`;
    }
}

// The server sends unix seconds as a string
export function formatTimestamp(value) {
    if (!value) {
        return '';
    }

    const seconds = Number(value);
    if (!Number.isFinite(seconds)) {
        return '';
    }

    const date = new Date(seconds * 1000);
    return date.toLocaleString();
}

export function basename(path) {
    const parts = String(path || '').split('/').filter(part => part.length > 0);
    return parts.length ? parts[parts.length - 1] : String(path || '');
}

export function getParentPath(path) {
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

export function fileIcon(entry) {
    if (entry.is_dir) {
        return '📁';
    }

    const extension = entry.name.includes('.') ? entry.name.split('.').pop().toLowerCase() : '';
    const icons = {
        jpg: '🖼️', jpeg: '🖼️', png: '🖼️', gif: '🖼️', webp: '🖼️', svg: '🖼️', bmp: '🖼️',
        mp4: '🎬', mkv: '🎬', avi: '🎬', mov: '🎬', webm: '🎬',
        mp3: '🎵', flac: '🎵', wav: '🎵', ogg: '🎵', m4a: '🎵',
        pdf: '📕', doc: '📘', docx: '📘', odt: '📘',
        xls: '📗', xlsx: '📗', ods: '📗', csv: '📗',
        zip: '🗜️', tar: '🗜️', gz: '🗜️', bz2: '🗜️', xz: '🗜️', '7z': '🗜️', rar: '🗜️',
        txt: '📄', md: '📄', log: '📄',
        json: '⚙️', yml: '⚙️', yaml: '⚙️', toml: '⚙️', ini: '⚙️', conf: '⚙️',
        sh: '📜', rs: '📜', js: '📜', py: '📜', html: '📜', css: '📜'
    };

    return icons[extension] || '📄';
}
