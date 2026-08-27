// Pure formatting helpers — no DOM, no state.

// The one byte formatter for the whole UI — left browser, remote pane, job bar,
// selection bar, previews. It used to exist twice (a private copy in
// ui/remotepane.js), and the two disagreed: 1536 bytes read "2 KB" on the left
// and "1.5 KB" on the right, which looks like a calculation error, not like two
// formatters. That was ticket 67b61d0d.
//
// The rules, and why:
//   * unit "B", never "Bytes" — "1 Bytes" is wrong, and no plural is right for
//     every value.
//   * one decimal, trailing ".0" stripped — 1536 is "1.5 KB", not "2 KB"
//     (rounding away half a unit is what made the two panes disagree in value)
//     and 1024 is "1 KB", not "1.0 KB".
//   * unknown size — null, undefined, "", NaN, or a negative marker — returns
//     the empty string. It is *not* 0: object stores report -1 for a folder and
//     the local backend the inode size, and printing either as a number would
//     be a lie. Callers turn "" into an em dash.
export function formatBytes(bytes) {
    if (bytes === null || bytes === undefined || bytes === '') {
        return '';
    }

    const value = Number(bytes);
    if (!Number.isFinite(value) || value < 0) {
        return '';
    }

    // Whole bytes below the first unit boundary: "0 B", "1 B", "1023 B".
    if (value < 1024) {
        return Math.round(value) + ' B';
    }

    const units = ['KB', 'MB', 'GB', 'TB', 'PB'];
    let size = value / 1024;
    let unit = 0;
    while (size >= 1024 && unit < units.length - 1) {
        size /= 1024;
        unit++;
    }

    // parseFloat drops the trailing ".0", so exact multiples stay short.
    return parseFloat(size.toFixed(1)) + ' ' + units[unit];
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
