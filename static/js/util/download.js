// Downloads are plain navigations — the browser handles the streaming.
// Kept in its own module because both the file browser and the preview overlay
// use it and neither should have to import the other.

// Folders are packed into a ZIP, single files are streamed as they are
export function downloadEntry(path, isDir) {
    const encoded = encodeURIComponent(path);
    if (isDir) {
        window.location.href = `/api/download/zip?path=${encoded}`;
    } else {
        window.location.href = `/api/download/file?path=${encoded}`;
    }
}
