'use strict';

const PW_API_BASE        = '/plugins/passwork';
const PW_REVEAL_TIMEOUT  = (window.PW_SECRET_REVEAL_TIMEOUT || 30) * 1000;
const PW_REQUEST_TIMEOUT = (window.PW_REQUEST_TIMEOUT || 5) * 1000;

// ---------------------------------------------------------------------------
// Bootstrap Modal helper — NetBox-compatible (ESM and global bootstrap)
// ---------------------------------------------------------------------------

function pwModal(id) {
    const el = document.getElementById(id);
    if (!el) return null;
    // NetBox may export bootstrap via window or via import
    if (window.bootstrap && window.bootstrap.Modal) {
        return window.bootstrap.Modal.getOrCreate
            ? window.bootstrap.Modal.getOrCreate(el)
            : (window.bootstrap.Modal.getInstance(el) || new window.bootstrap.Modal(el));
    }
    // Fallback: look for bootstrap in a script type=module tag
    const bsModal = el._bsModal;
    if (bsModal) return bsModal;
    // Last resort: via jQuery if available
    if (window.$ && $.fn && $.fn.modal) {
        return { show: () => $(el).modal('show'), hide: () => $(el).modal('hide') };
    }
    return null;
}

function pwShowModal(id) {
    const m = pwModal(id);
    if (m) { m.show(); return; }
    // Fallback: show manually via Bootstrap CSS classes
    const el = document.getElementById(id);
    if (!el) return;
    el.style.display = 'block';
    el.classList.add('show');
    document.body.classList.add('modal-open');
    // Backdrop
    let bd = document.getElementById('pw-modal-backdrop');
    if (!bd) {
        bd = document.createElement('div');
        bd.id = 'pw-modal-backdrop';
        bd.className = 'modal-backdrop fade show';
        document.body.appendChild(bd);
    }
}

function pwHideModal(id) {
    const m = pwModal(id);
    if (m) { m.hide(); return; }
    const el = document.getElementById(id);
    if (!el) return;
    el.style.display = 'none';
    el.classList.remove('show');
    document.body.classList.remove('modal-open');
    const bd = document.getElementById('pw-modal-backdrop');
    if (bd) bd.remove();
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

function pwCsrfToken() {
    // NetBox passes CSRF via window.CSRF_TOKEN (base/base.html)
    if (window.CSRF_TOKEN) return window.CSRF_TOKEN;
    // Fallback: cookie
    const match = document.cookie.match(/(?:^|;)\s*csrftoken=([^;]+)/);
    return match ? decodeURIComponent(match[1]) : '';
}

async function pwFetch(url, options = {}) {
    const controller = new AbortController();
    const tid = setTimeout(() => controller.abort(), PW_REQUEST_TIMEOUT);
    try {
        const resp = await fetch(url, {
            ...options,
            signal: controller.signal,
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': pwCsrfToken(),
                ...(options.headers || {}),
            },
        });
        return resp;
    } finally {
        clearTimeout(tid);
    }
}

// ---------------------------------------------------------------------------
// Tab loading
// ---------------------------------------------------------------------------

// Header button mirrors the auth state: with no Passwork session the card
// shows "Authenticate" (opens the login modal) instead of "Bind secret".
function pwSetAuthButton(authenticated) {
    const bindBtn = document.getElementById('pw-bind-btn');
    const authBtn = document.getElementById('pw-auth-btn');
    if (!bindBtn || !authBtn) return;
    bindBtn.style.display = authenticated ? '' : 'none';
    authBtn.style.display = authenticated ? 'none' : '';
}

async function pwLoadSecretsTab() {
    const loading = document.getElementById('pw-loading');
    const empty   = document.getElementById('pw-empty');
    const table   = document.getElementById('pw-secrets-table');
    const tbody   = document.getElementById('pw-secrets-tbody');
    const authReq = document.getElementById('pw-auth-required');

    if (!loading) return;

    loading.style.display = '';
    empty.style.display   = 'none';
    table.style.display   = 'none';
    authReq.style.display = 'none';

    let resp;
    try {
        resp = await pwFetch(
            `${PW_API_BASE}/secrets/?object_type=${PW_OBJECT_TYPE}&object_id=${PW_OBJECT_ID}`
        );
    } catch {
        loading.style.display = 'none';
        empty.style.display = '';
        return;
    }

    loading.style.display = 'none';

    if (resp.status === 401) {
        authReq.style.display = '';
        table.style.display   = 'none';
        empty.style.display   = 'none';
        pwSetAuthButton(false);
        return;
    }
    if (!resp.ok) {
        // Non-401 error: the auth state is unknown — leave the button as is
        empty.style.display = '';
        return;
    }
    pwSetAuthButton(true);

    const items = await resp.json();

    if (!items.length) {
        empty.style.display = '';
        return;
    }

    const counter = document.getElementById('pw-secrets-count');
    if (counter) { counter.textContent = items.length; counter.style.display = ''; }

    // Check authentication before showing rows
    if (items.length > 0) {
        const checkResp = await pwFetch(
            `${PW_API_BASE}/secrets/${encodeURIComponent(items[0].pw_id)}/detail/` +
            `?object_type=${PW_OBJECT_TYPE}&object_id=${PW_OBJECT_ID}`
        );
        if (checkResp.status === 401) {
            authReq.style.display = '';
            table.style.display   = 'none';
            empty.style.display   = 'none';
            pwSetAuthButton(false);
            return;
        }
    }

    tbody.innerHTML = '';
    items.forEach(({ pw_id, binding_id }) => {
        tbody.appendChild(pwSkeletonRow(pw_id, binding_id));
    });
    table.style.display = '';

    await Promise.allSettled(items.map(({ pw_id }) => pwLoadSecretMeta(pw_id)));
}

function pwSkeletonRow(pwId, bindingId) {
    const tr = document.createElement('tr');
    tr.id = `pw-row-${CSS.escape(pwId)}`;
    tr.dataset.pwId = pwId;
    tr.dataset.bindingId = bindingId || '';

    const tdName = document.createElement('td');
    tdName.className = 'pw-name';
    tdName.innerHTML = '<span class="placeholder col-6"></span>';

    const tdLogin = document.createElement('td');
    tdLogin.className = 'pw-login';
    tdLogin.innerHTML = '<span class="placeholder col-4"></span>';

    const tdPwd = document.createElement('td');
    tdPwd.className = 'pw-password';
    tdPwd.innerHTML = '<span class="font-monospace text-muted">•••••••••</span>';

    const tdActions = document.createElement('td');
    tdActions.className = 'text-end';
    tdActions.style.whiteSpace = 'nowrap';

    const btnGroup = document.createElement('div');
    btnGroup.className = 'btn-group btn-group-sm';

    const btnReveal = document.createElement('button');
    btnReveal.className = 'btn btn-outline-secondary';
    btnReveal.title = 'Reveal';
    btnReveal.innerHTML = '<i class="mdi mdi-eye-outline"></i>';
    btnReveal.addEventListener('click', () => pwRevealSecret(pwId));

    const btnCopy = document.createElement('button');
    btnCopy.className = 'btn btn-outline-secondary';
    btnCopy.title = 'Copy password';
    btnCopy.innerHTML = '<i class="mdi mdi-content-copy"></i>';
    btnCopy.addEventListener('click', () => pwCopyField(pwId, 'password'));

    const btnDelete = document.createElement('button');
    btnDelete.className = 'btn btn-outline-danger';
    btnDelete.title = 'Unbind';
    btnDelete.innerHTML = '<i class="mdi mdi-link-variant-off"></i>';
    btnDelete.addEventListener('click', () => pwDeleteBinding(pwId));

    btnGroup.append(btnReveal, btnCopy, btnDelete);
    tdActions.appendChild(btnGroup);
    tr.append(tdName, tdLogin, tdPwd, tdActions);
    return tr;
}

async function pwLoadSecretMeta(pwId) {
    const url = `${PW_API_BASE}/secrets/${encodeURIComponent(pwId)}/detail/` +
        `?object_type=${PW_OBJECT_TYPE}&object_id=${PW_OBJECT_ID}`;
    try {
        const resp = await pwFetch(url);
        if (resp.status === 401) {
            pwMarkRowUnauthenticated(pwId);
            // Show the global authentication block
            const authReq = document.getElementById('pw-auth-required');
            if (authReq) authReq.style.display = '';
            pwSetAuthButton(false);
            return;
        }
        if (resp.status === 403) { pwMarkRowNoAccess(pwId); return; }
        if (!resp.ok)            { pwMarkRowUnavailable(pwId); return; }
        pwFillRow(pwId, await resp.json());
    } catch {
        pwMarkRowUnavailable(pwId);
    }
}

function pwFillRow(pwId, data) {
    const row = document.getElementById(`pw-row-${CSS.escape(pwId)}`);
    if (!row) return;
    row.querySelector('.pw-name').textContent  = data.name  || '—';
    row.querySelector('.pw-login').textContent = data.login || '—';
    // Store metadata
    row.dataset.pwName        = data.name         || '';
    row.dataset.pwLogin       = data.login        || '';
    row.dataset.pwDescription = data.description  || '';
    row.dataset.pwUrl         = data.passwork_url || '';
    // Add the detail row
    pwAddDetailRow(row, pwId, data);
}

function pwAddDetailRow(row, pwId, data) {
    // Remove the old detail row if present
    const existing = document.getElementById(`pw-detail-${CSS.escape(pwId)}`);
    if (existing) existing.remove();

    const detail = document.createElement('tr');
    detail.id = `pw-detail-${CSS.escape(pwId)}`;
    detail.style.display = 'none';

    const outerTd = document.createElement('td');
    outerTd.colSpan = 4;
    outerTd.className = 'p-0';

    const innerTable = document.createElement('table');
    innerTable.className = 'table table-sm mb-0';
    const tbody = document.createElement('tbody');

    // Helper: make a label <td>
    function labelTd(text, style = '') {
        const td = document.createElement('td');
        td.className = 'text-muted pe-3';
        if (style) td.style.cssText = style;
        td.textContent = text;
        return td;
    }

    // Helper: make a copy button (value kept in closure, never in attribute)
    function copyBtn(getValue) {
        const btn = document.createElement('button');
        btn.className = 'btn btn-sm btn-link p-0 ms-1';
        btn.title = 'Copy';
        btn.innerHTML = '<i class="mdi mdi-content-copy"></i>';
        btn.addEventListener('click', () => pwCopyValue(getValue()));
        return btn;
    }

    // Helper: safe <a> for URLs — only http/https allowed
    function safeLink(url) {
        const a = document.createElement('a');
        try {
            const parsed = new URL(url);
            if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
                a.href = url;
                a.target = '_blank';
                a.rel = 'noopener noreferrer';
            } else {
                a.removeAttribute('href');
            }
        } catch {
            a.removeAttribute('href');
        }
        a.textContent = url;
        return a;
    }

    // Helper: append a row to tbody
    function addRow(labelEl, valueEl) {
        const tr = document.createElement('tr');
        tr.appendChild(labelEl);
        const tdVal = document.createElement('td');
        if (Array.isArray(valueEl)) {
            valueEl.forEach(el => tdVal.appendChild(el));
        } else {
            tdVal.appendChild(valueEl);
        }
        tr.appendChild(tdVal);
        tbody.appendChild(tr);
    }

    // Login row
    if (data.login) {
        const span = document.createElement('span');
        span.className = 'font-monospace';
        span.textContent = data.login;
        const loginVal = data.login;
        addRow(
            labelTd('Login', 'white-space:nowrap;width:180px'),
            [span, copyBtn(() => loginVal)]
        );
    }

    // Password row (visible only when has data)
    if (data.password !== undefined && data.password !== null) {
        const pwSpan = document.createElement('span');
        pwSpan.className = 'font-monospace pw-cf-secret';
        pwSpan.dataset.field = 'password';
        pwSpan.dataset.pwId = pwId;
        pwSpan.textContent = '•••••••••';

        const revealBtn = document.createElement('button');
        revealBtn.className = 'btn btn-sm btn-link p-0 ms-1';
        revealBtn.title = 'Reveal';
        revealBtn.innerHTML = '<i class="mdi mdi-eye-outline"></i>';
        revealBtn.addEventListener('click', () => pwRevealCustomField(revealBtn, pwId, 'password'));

        const copyPwBtn = document.createElement('button');
        copyPwBtn.className = 'btn btn-sm btn-link p-0';
        copyPwBtn.title = 'Copy';
        copyPwBtn.innerHTML = '<i class="mdi mdi-content-copy"></i>';
        copyPwBtn.addEventListener('click', () => pwCopyCustomField(pwId, 'password'));

        addRow(labelTd('Password', 'white-space:nowrap'), [pwSpan, revealBtn, copyPwBtn]);
    }

    // Custom fields
    (data.custom_fields || []).forEach(f => {
        const fieldName = f.name;  // kept in closure — never embedded in HTML attributes
        if (f.is_secret) {
            const cfSpan = document.createElement('span');
            cfSpan.className = 'font-monospace pw-cf-secret';
            cfSpan.dataset.field = fieldName;
            cfSpan.dataset.pwId = pwId;
            cfSpan.textContent = '•••••••••';

            const labelEl = labelTd(fieldName, 'white-space:nowrap');
            if (f.type === 'totp') {
                const icon = document.createElement('i');
                icon.className = 'mdi mdi-shield-key-outline text-muted ms-1';
                icon.title = 'TOTP';
                labelEl.appendChild(icon);
            }

            const revealBtn = document.createElement('button');
            revealBtn.className = 'btn btn-sm btn-link p-0 ms-1';
            revealBtn.title = 'Reveal';
            revealBtn.innerHTML = '<i class="mdi mdi-eye-outline"></i>';
            revealBtn.addEventListener('click', () => pwRevealCustomField(revealBtn, pwId, fieldName));

            const cfCopyBtn = document.createElement('button');
            cfCopyBtn.className = 'btn btn-sm btn-link p-0';
            cfCopyBtn.title = 'Copy';
            cfCopyBtn.innerHTML = '<i class="mdi mdi-content-copy"></i>';
            cfCopyBtn.addEventListener('click', () => pwCopyCustomField(pwId, fieldName));

            addRow(labelEl, [cfSpan, revealBtn, cfCopyBtn]);
        } else {
            const fieldValue = f.value || '';
            const valSpan = document.createElement('span');
            valSpan.textContent = fieldValue || '—';
            addRow(
                labelTd(fieldName, 'white-space:nowrap'),
                [valSpan, copyBtn(() => fieldValue)]
            );
        }
    });

    // URL row
    if (data.passwork_url) {
        addRow(labelTd('URL'), [safeLink(data.passwork_url)]);
    }

    // Description row
    if (data.description) {
        const descSpan = document.createElement('span');
        descSpan.style.whiteSpace = 'pre-wrap';
        descSpan.textContent = data.description;
        addRow(labelTd('Description'), [descSpan]);
    }

    innerTable.appendChild(tbody);
    outerTd.appendChild(innerTable);
    detail.appendChild(outerTd);
    row.insertAdjacentElement('afterend', detail);

    // Click on the row — toggle details
    row.style.cursor = 'pointer';
    row.querySelector('.pw-name').onclick = (e) => {
        e.stopPropagation();
        const isVisible = detail.style.display !== 'none';
        detail.style.display = isVisible ? 'none' : '';
    };
}

function pwMarkRowStatus(pwId, text, cls) {
    const row = document.getElementById(`pw-row-${CSS.escape(pwId)}`);
    if (!row) return;
    const cell = row.querySelector('.pw-name');
    const span = document.createElement('span');
    span.className = `${cls} fst-italic`;
    span.textContent = text;
    cell.innerHTML = '';
    cell.appendChild(span);
}

function pwMarkRowUnavailable(pwId)     { pwMarkRowStatus(pwId, 'unavailable',       'text-muted'); }
function pwMarkRowNoAccess(pwId)        { pwMarkRowStatus(pwId, 'no access',          'text-warning'); }
function pwMarkRowUnauthenticated(pwId) { pwMarkRowStatus(pwId, 'not authenticated',  'text-danger'); }

// ---------------------------------------------------------------------------
// Reveal / Copy
// ---------------------------------------------------------------------------

let _pwRevealTimer = null;

async function pwRevealSecret(pwId) {
    const url = `${PW_API_BASE}/secrets/${encodeURIComponent(pwId)}/detail/` +
        `?object_type=${PW_OBJECT_TYPE}&object_id=${PW_OBJECT_ID}&reveal=true`;
    const resp = await pwFetch(url);
    if (resp.status === 401) { pwShowLoginModal(); return; }
    if (!resp.ok) return;
    const data = await resp.json();
    const row  = document.getElementById(`pw-row-${CSS.escape(pwId)}`);
    if (!row) return;
    const cell = row.querySelector('.pw-password');
    const pwd = data.password || '';

    // The Reveal button lives in .btn-group — find it by class, not onclick
    const revealBtn = row.querySelector('.btn-group button:first-child');

    function hidePwd() {
        cell.innerHTML = '<span class="font-monospace text-muted">•••••••••</span>';
        if (revealBtn) revealBtn.innerHTML = '<i class="mdi mdi-eye-outline"></i>';
    }

    // If already revealed — hide it
    if (cell.querySelector('.pw-revealed-value')) {
        clearTimeout(_pwRevealTimer);
        hidePwd();
        return;
    }

    // Create a span with textContent — never innerHTML with data
    cell.innerHTML = '';
    const pwSpan = document.createElement('span');
    pwSpan.className = 'font-monospace user-select-all pw-revealed-value';
    pwSpan.textContent = pwd;
    cell.appendChild(pwSpan);

    clearTimeout(_pwRevealTimer);
    _pwRevealTimer = setTimeout(hidePwd, PW_REVEAL_TIMEOUT);
    if (revealBtn) revealBtn.innerHTML = '<i class="mdi mdi-eye-off-outline"></i>';
}

async function pwCopyField(pwId, field) {
    const url = `${PW_API_BASE}/secrets/${encodeURIComponent(pwId)}/detail/` +
        `?object_type=${PW_OBJECT_TYPE}&object_id=${PW_OBJECT_ID}&reveal=true`;
    const resp = await pwFetch(url);
    if (resp.status === 401) { pwShowLoginModal(); return; }
    if (!resp.ok) return;
    const data = await resp.json();
    // clipboard API requires HTTPS — fallback for HTTP
    const value = data[field] || '';
    if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(value);
    } else {
        // Fallback: execCommand for HTTP
        const ta = document.createElement('textarea');
        ta.value = value;
        ta.style.position = 'fixed';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.focus();
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
    }
    await pwFetch(
        `${PW_API_BASE}/secrets/${encodeURIComponent(pwId)}/copy/` +
        `?object_type=${PW_OBJECT_TYPE}&object_id=${PW_OBJECT_ID}`,
        { method: 'POST', body: '{}' }
    );
    const row = document.getElementById(`pw-row-${CSS.escape(pwId)}`);
    if (row) {
        const btn = row.querySelector('[onclick*="pwCopyField"]');
        if (btn) {
            btn.innerHTML = '<i class="mdi mdi-check text-success"></i>';
            setTimeout(() => { btn.innerHTML = '<i class="mdi mdi-content-copy"></i>'; }, 1500);
        }
    }
}

// ---------------------------------------------------------------------------
// Login modal
// ---------------------------------------------------------------------------

function pwShowLoginModal() {
    // The login modal opens exactly when there is no Passwork session —
    // sync the header button (covers mid-use 401s in reveal/copy too).
    pwSetAuthButton(false);
    pwHideModal('pw-totp-modal');
    pwShowModal('pw-login-modal');
    // Focus the username field
    setTimeout(() => {
        const u = document.getElementById('pw-login-username');
        if (u) u.focus();
    }, 100);
}

function pwInitTotpDigits() {
    const digits = document.querySelectorAll('.pw-totp-digit');
    digits.forEach((input, idx) => {
        // Reset the value
        input.value = '';

        input.addEventListener('input', (e) => {
            // Keep digits only
            input.value = input.value.replace(/[^0-9]/g, '').slice(-1);
            if (input.value && idx < digits.length - 1) {
                digits[idx + 1].focus();
            }
            // If all filled in — auto-submit
            const code = Array.from(digits).map(d => d.value).join('');
            if (code.length === 6) {
                setTimeout(() => pwSubmitTotp(), 100);
            }
        });

        input.addEventListener('keydown', (e) => {
            if (e.key === 'Backspace' && !input.value && idx > 0) {
                digits[idx - 1].focus();
                digits[idx - 1].value = '';
            }
            if (e.key === 'Enter') {
                pwSubmitTotp();
            }
        });

        // Paste the whole code at once
        input.addEventListener('paste', (e) => {
            e.preventDefault();
            const pasted = (e.clipboardData || window.clipboardData)
                .getData('text').replace(/[^0-9]/g, '').slice(0, 6);
            digits.forEach((d, i) => { d.value = pasted[i] || ''; });
            if (pasted.length === 6) setTimeout(() => pwSubmitTotp(), 100);
            else if (pasted.length > 0) digits[Math.min(pasted.length, 5)].focus();
        });
    });
    // Focus the first field
    if (digits.length) digits[0].focus();
}

async function pwSubmitLogin() {
    const username = document.getElementById('pw-login-username').value.trim();
    const password = document.getElementById('pw-login-password').value;
    const errEl    = document.getElementById('pw-login-error');
    errEl.classList.add('d-none');

    if (!username || !password) {
        errEl.textContent = 'Username and password are required.';
        errEl.classList.remove('d-none');
        return;
    }

    const btn = document.getElementById('pw-login-submit');
    btn.disabled = true;
    try {
        const resp = await pwFetch(`${PW_API_BASE}/auth/login/`, {
            method: 'POST',
            body: JSON.stringify({ username, password }),
        });
        const data = await resp.json();
        if (!resp.ok) {
            errEl.textContent = data.code === 'invalid_credentials'
                ? 'Invalid username or password.'
                : 'Login failed. Please try again.';
            errEl.classList.remove('d-none');
            return;
        }
        pwHideModal('pw-login-modal');
        if (data.requires_totp) {
            setTimeout(() => {
                pwShowModal('pw-totp-modal');
                pwInitTotpDigits();
            }, 300);
        } else {
            pwLoadSecretsTab();
        }
    } finally {
        btn.disabled = false;
    }
}

async function pwSubmitTotp() {
    const digits = document.querySelectorAll('.pw-totp-digit');
    const code   = Array.from(digits).map(d => d.value).join('');
    const errEl  = document.getElementById('pw-totp-error');
    errEl.classList.add('d-none');

    if (!code || code.length !== 6) {
        errEl.textContent = 'Enter all 6 digits.';
        errEl.classList.remove('d-none');
        if (digits.length) digits[0].focus();
        return;
    }

    const btn = document.getElementById('pw-totp-submit');
    btn.disabled = true;
    try {
        const resp = await pwFetch(`${PW_API_BASE}/auth/totp/`, {
            method: 'POST',
            body: JSON.stringify({ code }),
        });
        if (!resp.ok) {
            errEl.textContent = 'Invalid code. Please try again.';
            errEl.classList.remove('d-none');
            return;
        }
        pwHideModal('pw-totp-modal');
        pwLoadSecretsTab();
    } finally {
        btn.disabled = false;
    }
}

// ---------------------------------------------------------------------------
// Picker
// ---------------------------------------------------------------------------

async function pwOpenPicker() {
    pwShowModal('pw-picker-modal');
    await pwLoadPickerFolders();
}

async function pwLoadPickerFolders() {
    const tree = document.getElementById('pw-picker-tree');
    tree.innerHTML = '<div class="text-center py-3"><div class="spinner-border spinner-border-sm"></div></div>';

    const resp = await pwFetch(`${PW_API_BASE}/picker/folders/`);
    if (resp.status === 401) {
        tree.innerHTML = '<div class="text-danger p-2">Authentication required. <a href="#" onclick="pwHideModal(\'pw-picker-modal\');pwShowLoginModal()">Log in</a></div>';
        return;
    }
    if (!resp.ok) { tree.innerHTML = '<div class="text-muted p-2">Failed to load folders.</div>'; return; }

    const folders = await resp.json();
    tree.innerHTML = '';
    (Array.isArray(folders) ? folders : []).forEach(folder => {
        const item = document.createElement('div');
        item.className = 'p-2 border-bottom cursor-pointer';
        item.style.cursor = 'pointer';
        item.textContent = folder.name || folder.id;
        item.onclick = () => pwLoadPickerContents(folder.id, null);
        tree.appendChild(item);
    });
    if (!tree.children.length) {
        tree.innerHTML = '<div class="text-muted p-2">No folders found.</div>';
    }
}

async function pwLoadPickerContents(vaultId, folderId) {
    const list = document.getElementById('pw-picker-list');
    list.innerHTML = '<div class="text-center py-2"><div class="spinner-border spinner-border-sm"></div></div>';
    let url = `${PW_API_BASE}/picker/folders/${encodeURIComponent(vaultId)}/items/`;
    if (folderId) url += `?folder_id=${encodeURIComponent(folderId)}`;
    const resp = await pwFetch(url);
    if (!resp.ok) { list.innerHTML = '<div class="text-muted p-2">Failed to load secrets.</div>'; return; }
    const data = await resp.json();
    pwRenderPickerContents(vaultId, data.folders || [], data.items || []);
}

function pwRenderPickerContents(vaultId, folders, secrets) {
    const list = document.getElementById('pw-picker-list');
    list.innerHTML = '';
    if (!folders.length && !secrets.length) {
        list.innerHTML = '<div class="text-muted p-2">Folder is empty.</div>';
        return;
    }
    folders.forEach(folder => {
        const item = document.createElement('div');
        item.className = 'p-2 border-bottom d-flex align-items-center';
        item.style.cursor = 'pointer';

        const icon = document.createElement('i');
        icon.className = 'mdi mdi-folder-outline me-2';

        const name = document.createElement('span');
        name.textContent = folder.name || folder.id;

        item.append(icon, name);
        item.onclick = () => pwLoadPickerContents(vaultId, folder.id);
        list.appendChild(item);
    });
    secrets.forEach(secret => list.appendChild(pwPickerSecretRow(secret)));
}

async function pwPickerSearch(query) {
    if (query.length < 2) return;
    const list = document.getElementById('pw-picker-list');
    list.innerHTML = '<div class="text-center py-2"><div class="spinner-border spinner-border-sm"></div></div>';
    const resp = await pwFetch(`${PW_API_BASE}/picker/search/?q=${encodeURIComponent(query)}`);
    if (!resp.ok) { list.innerHTML = '<div class="text-muted p-2">Search failed.</div>'; return; }
    const data = await resp.json();
    pwRenderPickerSecrets(Array.isArray(data) ? data : []);
}

function pwPickerSecretRow(secret) {
    const item = document.createElement('div');
    item.className = 'p-2 border-bottom d-flex justify-content-between align-items-center';

    const info = document.createElement('div');

    const nameDiv = document.createElement('div');
    nameDiv.className = 'fw-semibold';
    nameDiv.textContent = secret.name || secret.id;

    const loginSmall = document.createElement('small');
    loginSmall.className = 'text-muted';
    loginSmall.textContent = secret.login || '';

    info.append(nameDiv, loginSmall);

    const bindBtn = document.createElement('button');
    bindBtn.className = 'btn btn-sm btn-primary';
    bindBtn.innerHTML = '<i class="mdi mdi-link-variant"></i> Bind';
    bindBtn.addEventListener('click', () => pwCreateBinding(secret.id));

    item.append(info, bindBtn);
    return item;
}

function pwRenderPickerSecrets(secrets) {
    const list = document.getElementById('pw-picker-list');
    list.innerHTML = '';
    if (!secrets.length) { list.innerHTML = '<div class="text-muted p-2">No secrets found.</div>'; return; }
    secrets.forEach(secret => list.appendChild(pwPickerSecretRow(secret)));
}

// ---------------------------------------------------------------------------
// Binding create / delete
// ---------------------------------------------------------------------------

async function pwCreateBinding(pwId) {
    const resp = await pwFetch(`${PW_API_BASE}/bindings/`, {
        method: 'POST',
        body: JSON.stringify({
            object_type:      PW_OBJECT_TYPE,
            object_id:        parseInt(PW_OBJECT_ID),
            passwork_item_id: pwId,
        }),
    });
    if (resp.status === 409) { alert('This secret is already bound to this object.'); return; }
    if (!resp.ok)             { alert('Failed to create binding.'); return; }
    pwHideModal('pw-picker-modal');
    pwLoadSecretsTab();
}

async function pwCopyValue(value) {
    if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(value);
    } else {
        const ta = document.createElement('textarea');
        ta.value = value;
        ta.style.cssText = 'position:fixed;opacity:0';
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
    }
}

async function pwCopyCustomField(pwId, fieldName) {
    const url = `${PW_API_BASE}/secrets/${encodeURIComponent(pwId)}/detail/` +
        `?object_type=${PW_OBJECT_TYPE}&object_id=${PW_OBJECT_ID}&reveal=true`;
    const resp = await pwFetch(url);
    if (resp.status === 401) { pwShowLoginModal(); return; }
    if (!resp.ok) return;
    const data = await resp.json();
    let value = '';
    if (fieldName === 'password') {
        value = data.password || '';
    } else {
        const cf = (data.custom_fields || []).find(f => f.name === fieldName);
        value = cf ? cf.value || '' : '';
    }
    await pwCopyValue(value);
}

async function pwRevealCustomField(btn, pwId, fieldName) {
    const url = `${PW_API_BASE}/secrets/${encodeURIComponent(pwId)}/detail/` +
        `?object_type=${PW_OBJECT_TYPE}&object_id=${PW_OBJECT_ID}&reveal=true`;
    const resp = await pwFetch(url);
    if (resp.status === 401) { pwShowLoginModal(); return; }
    if (!resp.ok) return;
    const data = await resp.json();
    let value = '';
    if (fieldName === 'password') {
        value = data.password || '';
    } else {
        const cf = (data.custom_fields || []).find(f => f.name === fieldName);
        value = cf ? cf.value || '' : '';
    }
    const span = btn.previousElementSibling;
    if (span && span.classList.contains('pw-cf-secret')) {
        const isRevealed = span.textContent !== '•••••••••';
        if (isRevealed) {
            span.textContent = '•••••••••';
            btn.innerHTML = '<i class="mdi mdi-eye-outline"></i>';
        } else {
            span.textContent = value || '—';
            btn.innerHTML = '<i class="mdi mdi-eye-off-outline"></i>';
        }
    }
}

async function pwDeleteBinding(pwId) {
    if (!confirm('Remove this secret binding?')) return;
    // Get binding_id from the row's data attribute
    const row = document.getElementById(`pw-row-${CSS.escape(pwId)}`);
    const bindingId = row ? row.dataset.bindingId : null;
    if (!bindingId) {
        alert('Binding ID not found.');
        return;
    }
    const resp = await pwFetch(
        `${PW_API_BASE}/bindings/${bindingId}/`,
        { method: 'DELETE', body: '{}' }
    );
    if (!resp.ok) {
        alert('Failed to delete binding.');
        return;
    }
    // Remove the row from the table
    if (row) row.remove();
    // Update the counter
    const remaining = document.querySelectorAll('#pw-secrets-tbody tr').length;
    const counter = document.getElementById('pw-secrets-count');
    if (counter) counter.textContent = remaining;
    if (!remaining) {
        document.getElementById('pw-secrets-table').style.display = 'none';
        document.getElementById('pw-empty').style.display = '';
    }
}

// ---------------------------------------------------------------------------
// Auto-start
// ---------------------------------------------------------------------------
document.addEventListener('DOMContentLoaded', () => {
    pwLoadSecretsTab();
});
