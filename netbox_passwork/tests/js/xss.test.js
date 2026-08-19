/**
 * XSS security tests for passwork.js (C1 + C2 from code review).
 *
 * Strategy: execute passwork.js inside a jsdom window, call rendering
 * functions with XSS payloads, assert that no executable HTML nodes are
 * created in the DOM (i.e. values are treated as text, not markup).
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { JSDOM, VirtualConsole } from 'jsdom';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const JS_SRC = path.resolve(
    __dirname,
    '../../static/netbox_passwork/passwork.js'
);
const src = readFileSync(JS_SRC, 'utf8');

const XSS_IMG   = '<img src=x onerror="window.__xss=1">';
const XSS_SCRIPT = '<script>window.__xss=1<\/script>';
const XSS_QUOTE  = "'); window.__xss=1; ('";  // inline onclick injection

/**
 * Create a fresh jsdom window with passwork.js loaded.
 * Returns the window object so tests can call functions on it.
 */
function makeWindow(extraHtml = '') {
    const vc = new VirtualConsole();   // suppress console noise from passwork.js
    const dom = new JSDOM(
        `<!DOCTYPE html>
        <html><body>
            <div id="pw-secrets-table" style="display:none"></div>
            <div id="pw-secrets-tbody"></div>
            <div id="pw-secrets-count"></div>
            <div id="pw-loading"></div>
            <div id="pw-empty"></div>
            <div id="pw-auth-required"></div>
            <div id="pw-picker-list"></div>
            ${extraHtml}
        </body></html>`,
        {
            url: 'https://netbox.example.com/',
            runScripts: 'dangerously',
            pretendToBeVisual: true,
            virtualConsole: vc,
        }
    );
    const win = dom.window;

    // Globals passwork.js reads at startup
    win.PW_OBJECT_TYPE = 'dcim.device';
    win.PW_OBJECT_ID   = '1';
    win.__xss = 0;  // sentinel — XSS payload sets this to 1

    // CSS.escape polyfill (jsdom does not expose CSS global by default)
    if (!win.CSS) {
        win.CSS = {
            escape: (s) => String(s).replace(/([^\w-])/g, '\\$1'),
        };
    }

    // Stub fetch so DOMContentLoaded auto-loads don't throw unhandled rejections
    win.fetch = async () => ({ ok: false, status: 503, json: async () => ({}) });

    // Execute passwork.js in this window context
    const scriptEl = win.document.createElement('script');
    scriptEl.textContent = src;
    win.document.head.appendChild(scriptEl);
    return win;
}

/** Assert no XSS node was injected into the container element. */
function assertNoXssNode(container, label) {
    const imgs    = container.querySelectorAll('img');
    const scripts = container.querySelectorAll('script');
    assert.equal(
        imgs.length, 0,
        `${label}: XSS <img> node found in DOM — innerHTML not escaped`
    );
    assert.equal(
        scripts.length, 0,
        `${label}: XSS <script> node found in DOM — innerHTML not escaped`
    );
}

/** Assert the XSS sentinel was NOT triggered. */
function assertXssNotExecuted(win, label) {
    assert.equal(
        win.__xss, 0,
        `${label}: XSS payload executed (window.__xss === 1)`
    );
}

// ---------------------------------------------------------------------------
// pwAddDetailRow — C1: description, passwork_url, login, custom field name/value
// ---------------------------------------------------------------------------

describe('pwAddDetailRow — XSS in secret metadata', () => {

    test('description with XSS payload renders as text, not HTML', () => {
        const win = makeWindow(`<table><tbody id="pw-secrets-tbody"></tbody></table>`);
        const doc = win.document;

        // Create a skeleton row that pwAddDetailRow expects
        const tbody = doc.getElementById('pw-secrets-tbody');
        const row = doc.createElement('tr');
        row.id = 'pw-row-testid';
        row.innerHTML = `
            <td class="pw-name">name</td>
            <td class="pw-login">login</td>
            <td class="pw-password"></td>
            <td></td>`;
        tbody.appendChild(row);

        win.pwAddDetailRow(row, 'testid', {
            description: XSS_IMG,
            passwork_url: '',
            login: '',
            custom_fields: [],
        });

        const detail = doc.getElementById('pw-detail-testid');
        assert.ok(detail, 'detail row must be created');
        assertNoXssNode(detail, 'description');
        assertXssNotExecuted(win, 'description');

        // The text content should contain the raw string, not parse it as HTML
        assert.ok(
            detail.textContent.includes('<img'),
            'raw XSS text must appear as literal text content'
        );
    });

    test('passwork_url with XSS payload in href and text renders as text', () => {
        const win = makeWindow(`<table><tbody id="pw-secrets-tbody"></tbody></table>`);
        const doc = win.document;
        const tbody = doc.getElementById('pw-secrets-tbody');
        const row = doc.createElement('tr');
        row.id = 'pw-row-testid2';
        row.innerHTML = `<td class="pw-name">n</td><td class="pw-login">l</td><td class="pw-password"></td><td></td>`;
        tbody.appendChild(row);

        win.pwAddDetailRow(row, 'testid2', {
            passwork_url: `javascript:${XSS_SCRIPT}`,
            description: '',
            login: '',
            custom_fields: [],
        });

        const detail = doc.getElementById('pw-detail-testid2');
        assert.ok(detail, 'detail row must be created');
        // A javascript: href must not be rendered as a live link
        const links = detail.querySelectorAll('a[href^="javascript"]');
        assert.equal(links.length, 0, 'javascript: href must be rejected');
        assertXssNotExecuted(win, 'passwork_url');
    });

    test('login with XSS payload in copy button does not inject HTML', () => {
        const win = makeWindow(`<table><tbody id="pw-secrets-tbody"></tbody></table>`);
        const doc = win.document;
        const tbody = doc.getElementById('pw-secrets-tbody');
        const row = doc.createElement('tr');
        row.id = 'pw-row-testid3';
        row.innerHTML = `<td class="pw-name">n</td><td class="pw-login">l</td><td class="pw-password"></td><td></td>`;
        tbody.appendChild(row);

        win.pwAddDetailRow(row, 'testid3', {
            login: XSS_IMG,
            passwork_url: '',
            description: '',
            custom_fields: [],
        });

        const detail = doc.getElementById('pw-detail-testid3');
        assert.ok(detail);
        assertNoXssNode(detail, 'login');
        assertXssNotExecuted(win, 'login');
    });

    test('custom field name with XSS payload renders as text', () => {
        const win = makeWindow(`<table><tbody id="pw-secrets-tbody"></tbody></table>`);
        const doc = win.document;
        const tbody = doc.getElementById('pw-secrets-tbody');
        const row = doc.createElement('tr');
        row.id = 'pw-row-testid4';
        row.innerHTML = `<td class="pw-name">n</td><td class="pw-login">l</td><td class="pw-password"></td><td></td>`;
        tbody.appendChild(row);

        win.pwAddDetailRow(row, 'testid4', {
            login: '',
            passwork_url: '',
            description: '',
            custom_fields: [{ name: XSS_IMG, value: 'safe', is_secret: false, type: 'text' }],
        });

        const detail = doc.getElementById('pw-detail-testid4');
        assert.ok(detail);
        assertNoXssNode(detail, 'custom field name');
        assertXssNotExecuted(win, 'custom field name');
    });

    test('custom field value with XSS payload renders as text', () => {
        const win = makeWindow(`<table><tbody id="pw-secrets-tbody"></tbody></table>`);
        const doc = win.document;
        const tbody = doc.getElementById('pw-secrets-tbody');
        const row = doc.createElement('tr');
        row.id = 'pw-row-testid5';
        row.innerHTML = `<td class="pw-name">n</td><td class="pw-login">l</td><td class="pw-password"></td><td></td>`;
        tbody.appendChild(row);

        win.pwAddDetailRow(row, 'testid5', {
            login: '',
            passwork_url: '',
            description: '',
            custom_fields: [{ name: 'safe', value: XSS_IMG, is_secret: false, type: 'text' }],
        });

        const detail = doc.getElementById('pw-detail-testid5');
        assert.ok(detail);
        assertNoXssNode(detail, 'custom field value');
        assertXssNotExecuted(win, 'custom field value');
    });

    test('single-quote in custom field name does not appear in onclick attribute (C2 escapedName bug)', () => {
        const win = makeWindow(`<table><tbody id="pw-secrets-tbody"></tbody></table>`);
        const doc = win.document;
        const tbody = doc.getElementById('pw-secrets-tbody');
        const row = doc.createElement('tr');
        row.id = 'pw-row-testid6';
        row.innerHTML = `<td class="pw-name">n</td><td class="pw-login">l</td><td class="pw-password"></td><td></td>`;
        tbody.appendChild(row);

        // A single-quote in the field name breaks inline onclick: onclick="fn(this,'id','field'name')"
        // After the fix, buttons must NOT have inline onclick at all (use addEventListener instead).
        win.pwAddDetailRow(row, 'testid6', {
            login: '',
            passwork_url: '',
            description: '',
            custom_fields: [{ name: "field'name", value: '', is_secret: true, type: 'text' }],
        });

        const detail = doc.getElementById('pw-detail-testid6');
        assert.ok(detail, 'detail row must be created');

        const revealBtns = detail.querySelectorAll('button');
        assert.ok(revealBtns.length > 0, 'reveal/copy buttons must exist');

        // In the buggy version, buttons have inline onclick containing the unescaped quote.
        // In the fixed version, buttons must have NO onclick attribute (listeners attached via addEventListener).
        const btnsWithOnclick = Array.from(revealBtns).filter(b => b.hasAttribute('onclick'));
        assert.equal(
            btnsWithOnclick.length, 0,
            `buttons must not use inline onclick — found ${btnsWithOnclick.length} button(s) with onclick attribute containing unescaped field name`
        );
        assertXssNotExecuted(win, 'escapedName quote injection');
    });
});

// ---------------------------------------------------------------------------
// pwRevealSecret — C1: revealed password inserted via innerHTML (line 383)
// ---------------------------------------------------------------------------

describe('pwRevealSecret — XSS in revealed password', () => {

    test('revealed password with XSS payload renders as text, not HTML', async () => {
        // Use a table wrapper so jsdom parses <tr>/<td> in the right context.
        const win = makeWindow(`
            <table id="pw-secrets-table">
                <tbody id="pw-secrets-tbody-reveal"></tbody>
            </table>`);
        const doc = win.document;

        // Build skeleton row with createElement to avoid foster-parenting issues.
        const tbody = doc.getElementById('pw-secrets-tbody-reveal');
        const row = doc.createElement('tr');
        row.id = 'pw-row-xss-reveal';
        row.dataset.pwId = 'xss-reveal';

        const tdName = doc.createElement('td'); tdName.className = 'pw-name'; tdName.textContent = 'name';
        const tdLogin = doc.createElement('td'); tdLogin.className = 'pw-login'; tdLogin.textContent = 'login';
        const tdPwd = doc.createElement('td'); tdPwd.className = 'pw-password';
        tdPwd.innerHTML = '<span class="font-monospace text-muted">•••••••••</span>';
        const tdActions = doc.createElement('td');
        const btnGroup = doc.createElement('div'); btnGroup.className = 'btn-group btn-group-sm';
        const revealBtn = doc.createElement('button'); revealBtn.className = 'btn btn-outline-secondary';
        btnGroup.appendChild(revealBtn);
        tdActions.appendChild(btnGroup);
        row.append(tdName, tdLogin, tdPwd, tdActions);
        tbody.appendChild(row);

        // pwFetch calls the global `fetch`, so override win.fetch (not win.pwFetch)
        // to make the reveal endpoint return an XSS payload as the password.
        win.fetch = async () => ({
            ok: true,
            status: 200,
            json: async () => ({ password: XSS_IMG }),
        });

        await win.pwRevealSecret('xss-reveal');

        const cell = doc.querySelector('#pw-row-xss-reveal .pw-password');
        assert.ok(cell, 'pw-password cell must exist in DOM');
        assertNoXssNode(cell, 'revealed password cell');
        assertXssNotExecuted(win, 'pwRevealSecret');

        // The raw XSS string must appear as visible text
        assert.ok(
            cell.textContent.includes('<img'),
            'XSS payload must appear as literal text in revealed password'
        );
    });
});

// ---------------------------------------------------------------------------
// pwRenderPickerSecrets — C1: secret.name / secret.login via innerHTML (lines 625-626)
// ---------------------------------------------------------------------------

describe('pwRenderPickerSecrets — XSS in picker secret name/login', () => {

    test('secret name with XSS payload renders as text', () => {
        const win = makeWindow();
        win.pwRenderPickerSecrets([
            { id: 'abc', name: XSS_IMG, login: 'user' },
        ]);
        const list = win.document.getElementById('pw-picker-list');
        assertNoXssNode(list, 'picker secret name');
        assertXssNotExecuted(win, 'pwRenderPickerSecrets name');
    });

    test('secret login with XSS payload renders as text', () => {
        const win = makeWindow();
        win.pwRenderPickerSecrets([
            { id: 'abc', name: 'safe', login: XSS_IMG },
        ]);
        const list = win.document.getElementById('pw-picker-list');
        assertNoXssNode(list, 'picker secret login');
        assertXssNotExecuted(win, 'pwRenderPickerSecrets login');
    });
});
