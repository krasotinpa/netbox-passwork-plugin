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
// Picker — Explorer-style: a folder tree on the left, the selected node's
// direct children on the right, breadcrumbs, and a debounced global search.
// ---------------------------------------------------------------------------

const PW_SEARCH_MIN_CHARS = 3;
const PW_SEARCH_DEBOUNCE  = window.PW_SEARCH_DEBOUNCE !== undefined ? window.PW_SEARCH_DEBOUNCE : 300;

// All picker state lives for one modal opening (pwOpenPicker resets it): repeated
// clicks reuse the caches below, closing and reopening the modal fetches everything anew.
let pwPicker = null;

function pwPickerReset() {
    pwPicker = {
        vaults: [],            // [{id, name}]
        vaultState: {},        // vaultId → 'loading' | 'loaded' | 'denied' | 'error'
        foldersByVault: {},    // vaultId → [{id, name, parentFolderId}] (flat, one request per vault)
        open: new Set(),       // expanded tree nodes (vault ids and folder ids)
        current: null,         // {vaultId, folderId|null} — the selected node
        contents: {},          // `${vaultId}:${folderId||''}` → {folders, items}
        searchActive: false,
        searchSeq: 0,          // stale search responses (older seq) are never rendered
        searchTimer: null,
        highlightId: null,     // secret highlighted after "show in folder"
    };
}

async function pwOpenPicker() {
    pwPickerReset();
    const search = document.getElementById('pw-picker-search');
    if (search) search.value = '';
    const scope = document.getElementById('pw-picker-scope');
    if (scope) scope.checked = false;
    document.getElementById('pw-picker-path').textContent = '';
    document.getElementById('pw-picker-list').innerHTML =
        '<div class="text-center text-muted py-3">Select a vault or folder on the left, or search for secrets.</div>';
    pwShowModal('pw-picker-modal');
    await pwPickerLoadVaults();
}

function pwPickerMessage(container, text, retryFn) {
    container.innerHTML = '';
    const box = document.createElement('div');
    box.className = 'text-muted p-3';
    const span = document.createElement('span');
    span.textContent = text;
    box.appendChild(span);
    if (retryFn) {
        const btn = document.createElement('button');
        btn.className = 'btn btn-sm btn-outline-secondary ms-2';
        btn.textContent = 'Retry';
        btn.addEventListener('click', retryFn);
        box.appendChild(btn);
    }
    container.appendChild(box);
}

// pwFetch aborts on PW_REQUEST_TIMEOUT — surface that as a retryable message
// that also names the setting to raise for very large vaults.
const PW_TIMEOUT_MSG = 'Passwork did not answer in time (PW_REQUEST_TIMEOUT).';

function pwPickerSpinner(container) {
    container.innerHTML = '<div class="text-center py-3"><div class="spinner-border spinner-border-sm"></div></div>';
}

function pwPickerLoginPrompt(container) {
    // The only string-built HTML in the picker — static content, no data inside
    container.innerHTML = '<div class="text-danger p-2">Authentication required. ' +
        '<a href="#" onclick="pwHideModal(\'pw-picker-modal\');pwShowLoginModal()">Log in</a></div>';
}

async function pwPickerLoadVaults() {
    const tree = document.getElementById('pw-picker-tree');
    pwPickerSpinner(tree);

    let resp;
    try {
        resp = await pwFetch(`${PW_API_BASE}/picker/folders/`);
    } catch {
        pwPickerMessage(tree, PW_TIMEOUT_MSG, pwPickerLoadVaults);
        return;
    }
    if (resp.status === 401) { pwPickerLoginPrompt(tree); return; }
    if (!resp.ok) { pwPickerMessage(tree, 'Failed to load vaults.', pwPickerLoadVaults); return; }

    const vaults = await resp.json();
    pwPicker.vaults = Array.isArray(vaults) ? vaults : [];
    if (!pwPicker.vaults.length) {
        pwPickerMessage(tree, 'No vaults found.');
        return;
    }
    pwPickerRenderTree();
}

// Loads the vault's flat folder list once per modal opening; 403 marks the
// vault "no access" in the tree, other vaults keep working.
async function pwPickerEnsureVaultFolders(vaultId) {
    if (vaultId in pwPicker.foldersByVault) return true;
    if (pwPicker.vaultState[vaultId] === 'loading') return false;
    pwPicker.vaultState[vaultId] = 'loading';
    pwPickerRenderTree();

    let resp;
    try {
        resp = await pwFetch(`${PW_API_BASE}/picker/folders/${encodeURIComponent(vaultId)}/folders/`);
    } catch {
        pwPicker.vaultState[vaultId] = 'error';
        pwPickerRenderTree();
        return false;
    }
    if (resp.status === 401) {
        pwPickerLoginPrompt(document.getElementById('pw-picker-tree'));
        return false;
    }
    if (resp.status === 403) {
        pwPicker.vaultState[vaultId] = 'denied';
        pwPickerRenderTree();
        return false;
    }
    if (!resp.ok) {
        pwPicker.vaultState[vaultId] = 'error';
        pwPickerRenderTree();
        return false;
    }
    const folders = await resp.json();
    pwPicker.foldersByVault[vaultId] = (Array.isArray(folders) ? folders : []).filter(f => f && f.id);
    pwPicker.vaultState[vaultId] = 'loaded';
    pwPickerRenderTree();
    return true;
}

function pwPickerSortByName(list) {
    return list.slice().sort((a, b) => String(a.name || a.id).localeCompare(String(b.name || b.id)));
}

function pwPickerChildFolders(vaultId, parentId) {
    return pwPickerSortByName(
        (pwPicker.foldersByVault[vaultId] || []).filter(f => (f.parentFolderId || null) === parentId)
    );
}

function pwPickerTreeRow({ depth, icon, name, expandable, expanded, active, muted, onSelect, onToggle }) {
    const row = document.createElement('div');
    row.className = 'd-flex align-items-center px-2 py-1' + (active ? ' bg-primary-subtle fw-semibold' : '');
    row.style.paddingLeft = `${8 + depth * 16}px`;
    row.style.cursor = onSelect ? 'pointer' : 'default';

    const chevron = document.createElement('span');
    chevron.className = 'pw-tree-toggle me-1';
    chevron.style.width = '1.1em';
    chevron.style.display = 'inline-block';
    if (expandable) {
        chevron.innerHTML = `<i class="mdi mdi-chevron-${expanded ? 'down' : 'right'}"></i>`;
        chevron.style.cursor = 'pointer';
        chevron.addEventListener('click', (e) => { e.stopPropagation(); onToggle(); });
    }

    const iconEl = document.createElement('i');
    iconEl.className = `mdi ${icon} me-1`;

    const nameEl = document.createElement('span');
    nameEl.className = 'text-truncate' + (muted ? ' text-muted fst-italic' : '');
    nameEl.textContent = name;

    row.append(chevron, iconEl, nameEl);
    if (onSelect) row.addEventListener('click', onSelect);
    return row;
}

function pwPickerRenderTree() {
    const tree = document.getElementById('pw-picker-tree');
    tree.innerHTML = '';
    const cur = pwPicker.current;

    const renderFolder = (vaultId, folder, depth) => {
        const children = pwPickerChildFolders(vaultId, folder.id);
        const expanded = pwPicker.open.has(folder.id);
        tree.appendChild(pwPickerTreeRow({
            depth,
            icon: 'mdi-folder-outline',
            name: folder.name || folder.id,
            expandable: children.length > 0,
            expanded,
            active: !!cur && cur.vaultId === vaultId && cur.folderId === folder.id,
            onSelect: () => pwPickerSelect(vaultId, folder.id),
            onToggle: () => { pwPicker.open.has(folder.id) ? pwPicker.open.delete(folder.id) : pwPicker.open.add(folder.id); pwPickerRenderTree(); },
        }));
        if (expanded) children.forEach(f => renderFolder(vaultId, f, depth + 1));
    };

    pwPicker.vaults.forEach(vault => {
        const state = pwPicker.vaultState[vault.id];
        const denied = state === 'denied';
        const expanded = pwPicker.open.has(vault.id);
        tree.appendChild(pwPickerTreeRow({
            depth: 0,
            icon: denied ? 'mdi-lock-outline' : 'mdi-safe-square-outline',
            name: (vault.name || vault.id) + (denied ? ' — no access' : ''),
            expandable: !denied,
            expanded,
            active: !!cur && cur.vaultId === vault.id && cur.folderId === null,
            muted: denied,
            onSelect: denied ? null : () => pwPickerSelect(vault.id, null),
            onToggle: () => pwPickerToggleVault(vault.id),
        }));
        if (!expanded || denied) return;
        if (state === 'loading') {
            const busy = document.createElement('div');
            busy.className = 'text-muted small';
            busy.style.paddingLeft = '24px';
            busy.innerHTML = '<div class="spinner-border spinner-border-sm my-1"></div>';
            tree.appendChild(busy);
        } else if (state === 'error') {
            const err = document.createElement('div');
            err.className = 'text-muted small py-1';
            err.style.paddingLeft = '24px';
            const label = document.createElement('span');
            label.textContent = 'Failed to load folders. ';
            const retry = document.createElement('a');
            retry.href = '#';
            retry.textContent = 'Retry';
            retry.addEventListener('click', (e) => {
                e.preventDefault();
                delete pwPicker.vaultState[vault.id];
                pwPickerEnsureVaultFolders(vault.id);
            });
            err.append(label, retry);
            tree.appendChild(err);
        } else {
            pwPickerChildFolders(vault.id, null).forEach(f => renderFolder(vault.id, f, 1));
        }
    });
}

async function pwPickerToggleVault(vaultId) {
    if (pwPicker.open.has(vaultId)) {
        pwPicker.open.delete(vaultId);
        pwPickerRenderTree();
        return;
    }
    pwPicker.open.add(vaultId);
    await pwPickerEnsureVaultFolders(vaultId);
    pwPickerRenderTree();
}

// Breadcrumb chain for a node: [{id: null, name: <vault>}, ...folders down to the node]
function pwPickerPathChain(vaultId, folderId) {
    const vault = pwPicker.vaults.find(v => v.id === vaultId);
    const byId = {};
    (pwPicker.foldersByVault[vaultId] || []).forEach(f => { byId[f.id] = f; });
    const chain = [];
    let f = folderId ? byId[folderId] : null;
    while (f) {
        chain.unshift({ id: f.id, name: f.name || f.id });
        f = f.parentFolderId ? byId[f.parentFolderId] : null;
    }
    return [{ id: null, name: vault ? (vault.name || vault.id) : vaultId }, ...chain];
}

function pwPickerRenderPath() {
    const nav = document.getElementById('pw-picker-path');
    nav.innerHTML = '';
    if (pwPicker.searchActive) {
        nav.textContent = 'Search results';
        return;
    }
    if (!pwPicker.current) return;
    const { vaultId, folderId } = pwPicker.current;
    const chain = pwPickerPathChain(vaultId, folderId);
    chain.forEach((part, idx) => {
        if (idx) {
            const sep = document.createElement('span');
            sep.className = 'text-muted mx-1';
            sep.textContent = '/';
            nav.appendChild(sep);
        }
        if (idx === chain.length - 1) {
            const here = document.createElement('span');
            here.className = 'fw-semibold';
            here.textContent = part.name;
            nav.appendChild(here);
        } else {
            const link = document.createElement('a');
            link.href = '#';
            link.textContent = part.name;
            link.addEventListener('click', (e) => { e.preventDefault(); pwPickerSelect(vaultId, part.id); });
            nav.appendChild(link);
        }
    });
}

// Selecting a node exits search mode, expands the tree down to the node and
// shows the node's direct children on the right.
async function pwPickerSelect(vaultId, folderId, highlightId = null) {
    pwPicker.searchActive = false;
    pwPicker.searchSeq++;
    pwPicker.highlightId = highlightId;
    const search = document.getElementById('pw-picker-search');
    if (search && search.value) search.value = '';

    pwPicker.current = { vaultId, folderId: folderId || null };
    pwPicker.open.add(vaultId);
    await pwPickerEnsureVaultFolders(vaultId);
    pwPickerPathChain(vaultId, folderId).forEach(part => { if (part.id) pwPicker.open.add(part.id); });
    pwPickerRenderTree();
    pwPickerRenderPath();
    await pwPickerLoadContents(vaultId, folderId || null);
}

async function pwPickerLoadContents(vaultId, folderId) {
    const list = document.getElementById('pw-picker-list');
    const key = `${vaultId}:${folderId || ''}`;
    if (!(key in pwPicker.contents)) {
        pwPickerSpinner(list);
        let url = `${PW_API_BASE}/picker/folders/${encodeURIComponent(vaultId)}/items/`;
        if (folderId) url += `?folder_id=${encodeURIComponent(folderId)}`;
        let resp;
        try {
            resp = await pwFetch(url);
        } catch {
            pwPickerMessage(list, PW_TIMEOUT_MSG, () => pwPickerLoadContents(vaultId, folderId));
            return;
        }
        if (resp.status === 401) { pwPickerLoginPrompt(list); return; }
        if (!resp.ok) {
            pwPickerMessage(list, 'Failed to load contents.', () => pwPickerLoadContents(vaultId, folderId));
            return;
        }
        const data = await resp.json();
        pwPicker.contents[key] = { folders: data.folders || [], items: data.items || [] };
    }
    // Ignore a response that arrives after the user has already navigated elsewhere
    if (!pwPicker.current || pwPicker.current.vaultId !== vaultId || pwPicker.current.folderId !== (folderId || null)) return;
    pwPickerRenderContents(vaultId, pwPicker.contents[key]);
}

function pwPickerContentsTable(withPath) {
    const table = document.createElement('table');
    table.className = 'table table-sm table-hover mb-0';
    const head = document.createElement('thead');
    const tr = document.createElement('tr');
    ['Name', 'Login', ...(withPath ? ['Path'] : []), ''].forEach(text => {
        const th = document.createElement('th');
        th.textContent = text;
        tr.appendChild(th);
    });
    head.appendChild(tr);
    table.appendChild(head);
    const body = document.createElement('tbody');
    table.appendChild(body);
    return { table, body };
}

function pwPickerBindCell(secret) {
    const td = document.createElement('td');
    td.className = 'text-end';
    const btn = document.createElement('button');
    btn.className = 'btn btn-sm btn-primary py-0';
    btn.innerHTML = '<i class="mdi mdi-link-variant"></i> Bind';
    btn.addEventListener('click', (e) => { e.stopPropagation(); pwCreateBinding(secret.id); });
    td.appendChild(btn);
    return td;
}

function pwPickerSecretCells(secret, highlighted) {
    const tdName = document.createElement('td');
    const icon = document.createElement('i');
    icon.className = 'mdi mdi-key-outline me-1';
    const name = document.createElement('span');
    if (highlighted) name.className = 'fw-bold text-primary';
    name.textContent = secret.name || secret.id;
    tdName.append(icon, name);

    const tdLogin = document.createElement('td');
    tdLogin.className = 'text-muted';
    tdLogin.textContent = secret.login || '';
    return [tdName, tdLogin];
}

function pwPickerRenderContents(vaultId, data) {
    const list = document.getElementById('pw-picker-list');
    const folders = pwPickerSortByName(data.folders);
    const secrets = pwPickerSortByName(data.items);
    list.innerHTML = '';
    if (!folders.length && !secrets.length) {
        pwPickerMessage(list, 'Folder is empty.');
        return;
    }
    const { table, body } = pwPickerContentsTable(false);

    folders.forEach(folder => {
        const tr = document.createElement('tr');
        tr.style.cursor = 'pointer';
        const tdName = document.createElement('td');
        const icon = document.createElement('i');
        icon.className = 'mdi mdi-folder-outline me-1';
        const name = document.createElement('span');
        name.textContent = folder.name || folder.id;
        tdName.append(icon, name);
        const tdLogin = document.createElement('td');
        const tdBind = document.createElement('td');
        tr.append(tdName, tdLogin, tdBind);
        tr.addEventListener('click', () => pwPickerSelect(vaultId, folder.id));
        body.appendChild(tr);
    });

    secrets.forEach(secret => {
        const tr = document.createElement('tr');
        tr.append(...pwPickerSecretCells(secret, pwPicker.highlightId === secret.id), pwPickerBindCell(secret));
        body.appendChild(tr);
    });

    list.appendChild(table);
}

// --- Search: debounced, min 3 chars; an empty box returns to the current node ---

function pwPickerSearchInput(value) {
    const query = value.trim();
    clearTimeout(pwPicker.searchTimer);
    if (!query.length) {
        pwPicker.searchSeq++;
        pwPickerExitSearch();
        return;
    }
    if (query.length < PW_SEARCH_MIN_CHARS) return;
    pwPicker.searchTimer = setTimeout(() => pwPickerRunSearch(query), PW_SEARCH_DEBOUNCE);
}

function pwPickerExitSearch() {
    pwPicker.searchActive = false;
    pwPickerRenderPath();
    const list = document.getElementById('pw-picker-list');
    if (pwPicker.current) {
        pwPickerLoadContents(pwPicker.current.vaultId, pwPicker.current.folderId);
    } else {
        list.innerHTML =
            '<div class="text-center text-muted py-3">Select a vault or folder on the left, or search for secrets.</div>';
    }
}

function pwPickerScopeChanged() {
    const search = document.getElementById('pw-picker-search');
    const query = search ? search.value.trim() : '';
    if (pwPicker.searchActive && query.length >= PW_SEARCH_MIN_CHARS) pwPickerRunSearch(query);
}

async function pwPickerRunSearch(query) {
    const seq = ++pwPicker.searchSeq;
    pwPicker.searchActive = true;
    pwPicker.highlightId = null;
    pwPickerRenderPath();
    const list = document.getElementById('pw-picker-list');
    pwPickerSpinner(list);

    let url = `${PW_API_BASE}/picker/search/?q=${encodeURIComponent(query)}`;
    const scope = document.getElementById('pw-picker-scope');
    if (scope && scope.checked && pwPicker.current) {
        url += `&vault_id=${encodeURIComponent(pwPicker.current.vaultId)}`;
    }

    let resp;
    try {
        resp = await pwFetch(url);
    } catch {
        if (seq !== pwPicker.searchSeq) return;
        pwPickerMessage(list, PW_TIMEOUT_MSG, () => pwPickerRunSearch(query));
        return;
    }
    if (seq !== pwPicker.searchSeq) return;  // a newer search or navigation superseded this one
    if (resp.status === 401) { pwPickerLoginPrompt(list); return; }
    if (!resp.ok) {
        pwPickerMessage(list, 'Search failed.', () => pwPickerRunSearch(query));
        return;
    }
    const data = await resp.json();
    if (seq !== pwPicker.searchSeq) return;
    pwPickerRenderSearchResults(Array.isArray(data) ? data : []);
}

function pwPickerSearchResultPath(secret) {
    if (Array.isArray(secret.path)) {
        return secret.path.map(p => (p && p.name) || '').filter(Boolean).join(' / ');
    }
    const vault = pwPicker.vaults.find(v => v.id === secret.vaultId);
    return vault ? (vault.name || vault.id) : '';
}

function pwPickerRenderSearchResults(secrets) {
    const list = document.getElementById('pw-picker-list');
    list.innerHTML = '';
    if (!secrets.length) {
        pwPickerMessage(list, 'No secrets found.');
        return;
    }
    const { table, body } = pwPickerContentsTable(true);
    secrets.forEach(secret => {
        const tr = document.createElement('tr');
        const tdPath = document.createElement('td');
        tdPath.className = 'text-muted small';
        tdPath.textContent = pwPickerSearchResultPath(secret);
        const [tdName, tdLogin] = pwPickerSecretCells(secret, false);
        tr.append(tdName, tdLogin, tdPath, pwPickerBindCell(secret));
        // "Show in folder": jump to the secret's folder with the tree expanded
        if (secret.vaultId) {
            tr.style.cursor = 'pointer';
            tr.addEventListener('click', () => pwPickerShowInFolder(secret));
        }
        body.appendChild(tr);
    });
    list.appendChild(table);
}

async function pwPickerShowInFolder(secret) {
    await pwPickerSelect(secret.vaultId, secret.folderId || null, secret.id);
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
