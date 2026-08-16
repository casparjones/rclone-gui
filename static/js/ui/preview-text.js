// Text renderer for the preview overlay.
//
// Registers `previewRenderers.text`. The frame (ui/preview.js) has already
// decided that this file is text — the decision comes from the server, the
// extension never decides. What the extension *may* do is pick a syntax
// highlighting profile; that is a display detail, nothing else.
//
// Two rules hold everywhere in here:
//
//   1. File content is attacker controlled. It goes into the DOM through
//      `textContent` only — never innerHTML, not even for the highlighted
//      tokens (those are <span> elements whose text is set with textContent).
//   2. The size limit belongs to the server. This module has no way to ask for
//      more than /api/preview/text hands out; it only reports what came back.

import { previewRenderers } from './preview.js';
import { fetchPreviewText } from '../api.js';
import { formatBytes } from '../util/format.js';

// Above this many characters the file is shown as plain text. Highlighting
// walks the whole content once; on a 2 MB log that is noticeable work for no
// gain — nobody reads a two-megabyte file by its colours.
const HIGHLIGHT_LIMIT = 256 * 1024;

// Guards late answers: every render takes a token, `release` and the next
// render invalidate it. Same idea as the request id guard in the frame.
let activeToken = 0;

previewRenderers.text = function (info, stage) {
    const token = ++activeToken;

    const wrap = document.createElement('div');
    wrap.className = 'pv-text';

    const note = document.createElement('div');
    note.className = 'pv-note';
    note.hidden = true;

    const pre = document.createElement('pre');
    pre.className = 'pv-code';
    const code = document.createElement('code');
    code.textContent = 'Loading …';
    pre.appendChild(code);

    wrap.appendChild(note);
    wrap.appendChild(pre);
    stage.appendChild(wrap);

    loadText(info, token, note, code);
    return true;
};

previewRenderers.text.release = function () {
    activeToken++;
};

async function loadText(info, token, note, code) {
    let result = null;
    try {
        result = await fetchPreviewText(info.path);
    } catch (error) {
        showMessage(token, code, 'Text could not be loaded: ' + error.message);
        return;
    }

    if (token !== activeToken || !code.isConnected) {
        return;
    }

    if (!result.ok || !result.data) {
        // Invalid UTF-8, binary content behind the sniffed head, unreadable
        // file: the server says what happened, and that is what is shown —
        // instead of a mangled page. Download stays available in the footer.
        showMessage(token, code, result.error || 'Text could not be loaded.');
        return;
    }

    const data = result.data;
    const notice = buildNotice(data);
    if (notice) {
        note.textContent = notice;
        note.hidden = false;
    }

    code.textContent = '';
    const content = typeof data.content === 'string' ? data.content : '';

    const language = languageFor(data.extension || info.extension);
    if (language && content.length <= HIGHLIGHT_LIMIT) {
        code.appendChild(highlight(content, language));
    } else {
        code.textContent = content;
    }
}

function showMessage(token, code, message) {
    if (token !== activeToken || !code.isConnected) {
        return;
    }
    code.textContent = message;
    code.classList.add('pv-error');
}

// The visible truncation hint, plus the note about replaced control characters.
function buildNotice(data) {
    const parts = [];

    if (data.truncated) {
        parts.push(
            `File is larger than the preview limit — showing the first ${formatBytes(data.bytes_read)} of ${formatBytes(data.size)}. Use Download for the whole file.`
        );
    }
    if (data.sanitized) {
        parts.push('Control characters were replaced so the display stays readable.');
    }
    if (data.encoding && data.encoding !== 'utf-8') {
        parts.push(`Decoded as ${data.encoding}.`);
    }

    return parts.join(' ');
}

// ---------------------------------------------------------------------------
// Syntax highlighting
// ---------------------------------------------------------------------------
//
// No new CDN reference is allowed (AGENTS.md §6) and no bundler exists, so a
// highlighting library is out. What is in reach without a dependency is a small
// tokenizer: comments, strings, numbers and keywords. That is the part that
// actually helps when skimming a config or a source file; anything finer
// (types, scopes) is not worth hand-writing per language and is left out.
//
// Anything not listed here — md, txt, log, csv, … — stays plain on purpose.

const C_LIKE_KEYWORDS = [
    'as', 'async', 'await', 'break', 'case', 'catch', 'class', 'const', 'continue', 'default',
    'do', 'else', 'enum', 'export', 'extends', 'extern', 'final', 'finally', 'fn', 'for', 'func',
    'function', 'go', 'if', 'impl', 'import', 'in', 'interface', 'let', 'match', 'mod', 'move',
    'mut', 'new', 'package', 'private', 'protected', 'public', 'pub', 'return', 'static',
    'struct', 'super', 'switch', 'this', 'throw', 'trait', 'try', 'type', 'typeof', 'use', 'var',
    'void', 'where', 'while', 'yield'
];

const SHELL_KEYWORDS = [
    'case', 'do', 'done', 'elif', 'else', 'esac', 'export', 'fi', 'for', 'function', 'if', 'in',
    'local', 'return', 'then', 'until', 'while'
];

const PYTHON_KEYWORDS = [
    'and', 'as', 'assert', 'async', 'await', 'break', 'class', 'continue', 'def', 'del', 'elif',
    'else', 'except', 'finally', 'for', 'from', 'global', 'if', 'import', 'in', 'is', 'lambda',
    'nonlocal', 'not', 'or', 'pass', 'raise', 'return', 'try', 'while', 'with', 'yield'
];

const LITERALS = ['true', 'false', 'null', 'nil', 'none', 'undefined', 'yes', 'no', 'on', 'off'];

const LANGUAGES = {
    json: { strings: ['"'], keywords: [] },
    yaml: { line: ['#'], strings: ['"', "'"], keywords: [] },
    conf: { line: ['#', ';'], strings: ['"', "'"], keywords: [] },
    shell: { line: ['#'], strings: ['"', "'"], keywords: SHELL_KEYWORDS },
    python: { line: ['#'], strings: ['"', "'"], keywords: PYTHON_KEYWORDS },
    clike: { line: ['//'], block: true, strings: ['"', "'", '`'], keywords: C_LIKE_KEYWORDS },
    css: { block: true, strings: ['"', "'"], keywords: [] }
};

const EXTENSION_LANGUAGE = {
    json: 'json', jsonc: 'json', map: 'json',
    yaml: 'yaml', yml: 'yaml',
    conf: 'conf', cfg: 'conf', ini: 'conf', toml: 'conf', properties: 'conf', env: 'conf',
    sh: 'shell', bash: 'shell', zsh: 'shell', ksh: 'shell',
    py: 'python', rb: 'python', pl: 'python',
    js: 'clike', mjs: 'clike', cjs: 'clike', jsx: 'clike', ts: 'clike', tsx: 'clike',
    c: 'clike', h: 'clike', cpp: 'clike', cc: 'clike', hpp: 'clike', cs: 'clike',
    go: 'clike', rs: 'clike', java: 'clike', kt: 'clike', swift: 'clike', php: 'clike',
    css: 'css', scss: 'css', less: 'css'
};

function languageFor(extension) {
    const key = String(extension || '').toLowerCase();
    const name = EXTENSION_LANGUAGE[key];
    return name ? LANGUAGES[name] : null;
}

function escapeRegExp(value) {
    return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// One scanner per language, built once and cached on the config object.
function scannerFor(language) {
    if (language.scanner) {
        language.scanner.lastIndex = 0;
        return language.scanner;
    }

    const parts = [];
    const kinds = [];

    if (language.line && language.line.length) {
        // Inner groups must stay non-capturing: the match index below maps one
        // capture group per alternative, in order.
        parts.push('(?:' + language.line.map(p => escapeRegExp(p)).join('|') + ')[^\\n]*');
        kinds.push('comment');
    }
    if (language.block) {
        // Unterminated block comments run to the end — that happens in a
        // truncated file and must not throw the rest of the scan off.
        parts.push('/\\*[\\s\\S]*?(?:\\*/|$)');
        kinds.push('comment');
    }
    for (const quote of language.strings || []) {
        const q = escapeRegExp(quote);
        // Backticks may span lines, the other quotes may not — an unclosed
        // quote then eats one line at most instead of the whole file.
        const body = quote === '`' ? `(?:\\\\.|[^\\\\${q}])*` : `(?:\\\\.|[^\\\\${q}\\n])*`;
        parts.push(`${q}${body}(?:${q}|$)`);
        kinds.push('string');
    }
    parts.push('\\b(?:0[xXbBoO][0-9a-fA-F_]+|\\d[\\d_]*(?:\\.\\d[\\d_]*)?(?:[eE][+-]?\\d+)?)\\b');
    kinds.push('number');
    parts.push('[A-Za-z_$][A-Za-z0-9_$]*');
    kinds.push('word');

    language.kinds = kinds;
    language.scanner = new RegExp(parts.map(p => `(${p})`).join('|'), 'g');
    return language.scanner;
}

// Returns a DocumentFragment of text nodes and <span> tokens. Every piece of
// file content is written with textContent, so nothing in here can inject
// markup no matter what the file contains.
function highlight(content, language) {
    const fragment = document.createDocumentFragment();
    const scanner = scannerFor(language);
    const keywords = new Set(language.keywords || []);
    let last = 0;
    let match;

    while ((match = scanner.exec(content)) !== null) {
        // Zero-length matches would loop forever; the alternatives above can
        // only match at least one character, but the guard is free.
        if (match[0].length === 0) {
            scanner.lastIndex++;
            continue;
        }

        let kind = null;
        for (let i = 0; i < language.kinds.length; i++) {
            if (match[i + 1] !== undefined) {
                kind = language.kinds[i];
                break;
            }
        }

        if (kind === 'word') {
            const lower = match[0].toLowerCase();
            if (keywords.has(match[0])) {
                kind = 'keyword';
            } else if (LITERALS.includes(lower)) {
                kind = 'literal';
            } else {
                kind = null;
            }
        }

        if (kind === null) {
            continue;
        }

        if (match.index > last) {
            fragment.appendChild(document.createTextNode(content.slice(last, match.index)));
        }
        const span = document.createElement('span');
        span.className = 'pv-tok-' + kind;
        span.textContent = match[0];
        fragment.appendChild(span);
        last = match.index + match[0].length;
    }

    if (last < content.length) {
        fragment.appendChild(document.createTextNode(content.slice(last)));
    }

    return fragment;
}
