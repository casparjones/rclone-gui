// Saved sync tasks: the list in the panel, creating one from the sync modal
// and starting one.

import { state } from '../state.js';
import * as api from '../api.js';
import { clearAlert, showAlert, showToast } from '../util/dom.js';
import { openMenuPanel, showMenuSection } from './menu.js';
import { monitorProgress, openProgressModal } from './sync.js';

export async function loadTasks() {
    try {
        const result = await api.fetchTasks();

        if (result.ok) {
            state.tasks = result.data;
            displayTasks();
        } else {
            showToast('Error loading tasks: ' + result.error, 'error');
        }
    } catch (error) {
        showToast('Error loading tasks: ' + error.message, 'error');
    }
}

// Icons are constant markup and stay as strings; every value that comes from
// the server is written with textContent instead.
const PLAY_ICON = '<svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">'
    + '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.828 14.828a4 4 0 01-5.656 0M9 10h1m4 0h1m-6 4h1m4 0h1m-6 4h6M7 10V7a3 3 0 013-3h4a3 3 0 013 3v3M7 13v8a2 2 0 002 2h6a2 2 0 002-2v-8" />'
    + '</svg>';

const TRASH_ICON = '<svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">'
    + '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />'
    + '</svg>';

// Small builder so the task card never needs a template literal for data.
function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) {
        node.className = className;
    }
    if (text !== undefined) {
        node.textContent = text;
    }
    return node;
}

// One action button: static icon markup plus a text label as a text node.
function iconButton(className, icon, label, onClick) {
    const button = el('button', className);
    button.innerHTML = icon;
    button.appendChild(document.createTextNode(label));
    button.addEventListener('click', onClick);
    return button;
}

// The card is assembled from elements, not from a string. Task name and the
// three path fields are attacker controlled (a folder name is enough), so they
// only ever reach the DOM through textContent — escaping would be a convention
// that the next feature forgets again.
function taskCard(task) {
    const card = el('div', 'card bg-base-100 shadow-sm');
    const body = el('div', 'card-body py-4 px-5');
    const row = el('div', 'flex items-center justify-between');

    const info = el('div', 'flex-1');
    info.appendChild(el('div', 'font-semibold text-lg', task.name));

    const details = el('div', 'text-sm text-base-content/70 mt-1');
    details.appendChild(el('div', null, `📁 ${task.source_path}`));
    details.appendChild(el('div', null, `☁️ ${task.remote_name}:${task.remote_path}`));
    details.appendChild(el('div', null, `📅 Created: ${new Date(task.created_at).toLocaleDateString()}`));
    if (task.use_chunking) {
        const chunk = task.chunk_size ? ` (${task.chunk_size})` : '';
        details.appendChild(el('div', null, `⚡ Multi-threading enabled${chunk}`));
    }
    info.appendChild(details);

    const actions = el('div', 'flex items-center space-x-2');
    actions.appendChild(iconButton('btn btn-success btn-sm', PLAY_ICON, 'Start', () => startTaskFromList(task.name)));
    actions.appendChild(iconButton('btn btn-error btn-sm', TRASH_ICON, 'Delete', () => deleteTask(task.id)));

    row.appendChild(info);
    row.appendChild(actions);
    body.appendChild(row);
    card.appendChild(body);

    return card;
}

function displayTasks() {
    const tasksList = document.getElementById('tasks-list');

    if (state.tasks.length === 0) {
        tasksList.innerHTML = '<div class="text-center text-base-content/60 py-8">No tasks found. Create a task from the sync modal.</div>';
        return;
    }

    tasksList.replaceChildren(...state.tasks.map(taskCard));
}

export function openCreateTaskModal() {
    const remoteName = document.getElementById('sync-remote').value;

    if (!remoteName) {
        showAlert('sync-alert', 'Please select a remote first', 'error');
        return;
    }

    // Clear previous values
    document.getElementById('task-name').value = '';
    clearAlert('create-task-alert');

    // Close sync modal and open task modal
    document.getElementById('sync-modal').close();
    document.getElementById('create-task-modal').showModal();
}

export async function createTask() {
    const taskName = document.getElementById('task-name').value.trim();
    const remoteName = document.getElementById('sync-remote').value;

    // Validation
    if (!taskName) {
        showAlert('create-task-alert', 'Please enter a task name', 'error');
        return;
    }

    if (!remoteName) {
        showAlert('create-task-alert', 'No remote selected', 'error');
        return;
    }

    // Validate alphanumeric name
    if (!/^[a-zA-Z0-9_-]+$/.test(taskName)) {
        showAlert('create-task-alert', 'Task name can only contain letters, numbers, underscores, and hyphens', 'error');
        return;
    }

    const useChunking = document.getElementById('use-chunking').checked;
    const chunkSize = useChunking ? document.getElementById('chunk-size').value : null;

    const taskRequest = {
        name: taskName,
        source_path: state.currentSyncSource,
        remote_name: remoteName,
        remote_path: state.selectedRemotePath,
        chunk_size: chunkSize,
        use_chunking: useChunking
    };

    try {
        const result = await api.createTask(taskRequest);

        if (result.ok) {
            showToast(`Task '${taskName}' created successfully!`, 'success');
            document.getElementById('create-task-modal').close();
            loadTasks(); // Refresh tasks list

            // Open the tasks section in the menu panel to show the new task
            openMenuPanel('tasks');
        } else {
            showAlert('create-task-alert', 'Error creating task: ' + result.error, 'error');
        }
    } catch (error) {
        showAlert('create-task-alert', 'Error creating task: ' + error.message, 'error');
    }
}

export async function deleteTask(taskId) {
    if (!confirm('Are you sure you want to delete this task?')) {
        return;
    }

    try {
        const result = await api.deleteTask(taskId);

        if (result.ok) {
            showToast('Task deleted successfully', 'success');
            loadTasks(); // Refresh tasks list
        } else {
            showToast('Error deleting task: ' + result.error, 'error');
        }
    } catch (error) {
        showToast('Error deleting task: ' + error.message, 'error');
    }
}

export async function startTaskFromList(taskName) {
    try {
        const result = await api.startTask(taskName);

        if (result.ok) {
            state.currentSyncJobId = result.data;
            showToast(`Task '${taskName}' started successfully!`, 'success');

            // Show the sync jobs section in the menu panel to monitor progress
            showMenuSection('sync');

            // Open progress modal
            openProgressModal();
            monitorProgress();
        } else {
            showToast('Error starting task: ' + result.error, 'error');
        }
    } catch (error) {
        showToast('Error starting task: ' + error.message, 'error');
    }
}
