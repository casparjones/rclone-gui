// DOM helpers shared by every view module.

// Everything that reaches innerHTML and comes from outside the code goes
// through here. File and folder names are attacker controlled — a folder named
// `<img src=x onerror=alert(1)>` used to execute. Do not weaken this, and do
// not build markup from unescaped names anywhere.
export function escapeHtml(value) {
    return String(value == null ? '' : value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

// Inline alerts were replaced by toasts a while ago; the container id stays in
// the signature because the call sites name the section they belong to.
export function showAlert(containerId, message, type) {
    showToast(message, type);
}

export function clearAlert(containerId) {
    const container = document.getElementById(containerId);
    if (container) {
        container.innerHTML = '';
    }
}

export function showToast(message, type) {
    const container = document.getElementById('toast-container');
    const toastId = 'toast-' + Date.now();

    const alertClass = type === 'error' ? 'alert-error' : type === 'success' ? 'alert-success' : 'alert-info';
    const icon = type === 'error' ? '❌' : type === 'success' ? '✅' : 'ℹ️';

    const toast = document.createElement('div');
    toast.id = toastId;
    toast.className = `alert ${alertClass} shadow-lg mb-2`;

    // Messages regularly carry server data (paths, remote names, error texts).
    // They are built as text nodes, never as markup — call sites therefore pass
    // the raw message and must *not* run it through escapeHtml() first.
    const text = document.createElement('span');
    text.textContent = `${icon} ${message == null ? '' : message}`;

    const close = document.createElement('button');
    close.className = 'btn btn-ghost btn-xs';
    close.textContent = '✕';
    close.addEventListener('click', () => removeToast(toastId));

    toast.appendChild(text);
    toast.appendChild(close);

    container.appendChild(toast);

    // Auto-remove after 5 seconds
    setTimeout(() => {
        removeToast(toastId);
    }, 5000);
}

export function removeToast(toastId) {
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
