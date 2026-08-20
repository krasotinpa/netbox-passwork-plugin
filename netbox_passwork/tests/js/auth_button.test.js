/**
 * Header button state on the secrets tab (issue #14).
 *
 * Without a Passwork session the header must show "Authenticate" (opens the
 * login modal directly) instead of "Bind secret" (opens the picker). The
 * state is driven by the same 401 signal that toggles #pw-auth-required.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { JSDOM, VirtualConsole } from 'jsdom';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const JS_SRC = path.resolve(
    __dirname,
    '../../static/netbox_passwork/passwork.js'
);
const src = readFileSync(JS_SRC, 'utf8');

/**
 * Fresh jsdom window with passwork.js loaded and the tab skeleton in place,
 * including both header buttons as secrets_tab.html renders them.
 */
function makeWindow() {
    const vc = new VirtualConsole();
    const dom = new JSDOM(
        `<!DOCTYPE html>
        <html><body>
            <button id="pw-bind-btn" onclick="pwOpenPicker(this)">Bind secret</button>
            <button id="pw-auth-btn" style="display:none" onclick="pwShowLoginModal()">Authenticate</button>
            <div id="pw-loading"></div>
            <div id="pw-empty" style="display:none"></div>
            <div id="pw-auth-required" style="display:none"></div>
            <table id="pw-secrets-table" style="display:none">
                <tbody id="pw-secrets-tbody"></tbody>
            </table>
        </body></html>`,
        {
            url: 'https://netbox.example.com/',
            runScripts: 'dangerously',
            pretendToBeVisual: true,
            virtualConsole: vc,
        }
    );
    const win = dom.window;
    win.PW_OBJECT_TYPE = 'dcim.device';
    win.PW_OBJECT_ID   = '1';
    if (!win.CSS) {
        win.CSS = { escape: (s) => String(s).replace(/([^\w-])/g, '\\$1') };
    }
    // Default fetch stub; tests override per scenario.
    win.fetch = async () => ({ ok: false, status: 503, json: async () => ({}) });

    const scriptEl = win.document.createElement('script');
    scriptEl.textContent = src;
    win.document.head.appendChild(scriptEl);
    return win;
}

function visible(win, id) {
    return win.document.getElementById(id).style.display !== 'none';
}

describe('header button vs Passwork auth state', () => {

    test('secrets list returns 401 — Authenticate shown, Bind secret hidden', async () => {
        const win = makeWindow();
        win.fetch = async () => ({ ok: false, status: 401, json: async () => ({}) });

        await win.pwLoadSecretsTab();

        assert.equal(visible(win, 'pw-bind-btn'), false, 'Bind secret must be hidden');
        assert.equal(visible(win, 'pw-auth-btn'), true, 'Authenticate must be shown');
        assert.equal(visible(win, 'pw-auth-required'), true, 'auth-required block must be shown');
    });

    test('detail check returns 401 — Authenticate shown, Bind secret hidden', async () => {
        const win = makeWindow();
        win.fetch = async (url) => {
            if (String(url).includes('/detail/')) {
                return { ok: false, status: 401, json: async () => ({}) };
            }
            return {
                ok: true, status: 200,
                json: async () => [{ pw_id: 'pw1', binding_id: 1 }],
            };
        };

        await win.pwLoadSecretsTab();

        assert.equal(visible(win, 'pw-bind-btn'), false, 'Bind secret must be hidden');
        assert.equal(visible(win, 'pw-auth-btn'), true, 'Authenticate must be shown');
    });

    test('successful reload switches back to Bind secret (post-login state)', async () => {
        const win = makeWindow();
        // Simulate the unauthenticated state left by a previous load
        win.document.getElementById('pw-bind-btn').style.display = 'none';
        win.document.getElementById('pw-auth-btn').style.display = '';
        win.fetch = async () => ({ ok: true, status: 200, json: async () => [] });

        await win.pwLoadSecretsTab();

        assert.equal(visible(win, 'pw-bind-btn'), true, 'Bind secret must be back');
        assert.equal(visible(win, 'pw-auth-btn'), false, 'Authenticate must be hidden');
    });

    test('non-401 server error leaves the button state unchanged', async () => {
        const win = makeWindow();
        // Unauthenticated state left by a previous load
        win.document.getElementById('pw-bind-btn').style.display = 'none';
        win.document.getElementById('pw-auth-btn').style.display = '';
        win.fetch = async () => ({ ok: false, status: 500, json: async () => ({}) });

        await win.pwLoadSecretsTab();

        assert.equal(visible(win, 'pw-bind-btn'), false, 'Bind secret must stay hidden on 500');
        assert.equal(visible(win, 'pw-auth-btn'), true, 'Authenticate must stay shown on 500');
    });

    test('401 during reveal — Authenticate shown via the login modal', async () => {
        const win = makeWindow();
        // Let the DOMContentLoaded auto-load settle, then force the
        // authenticated state: the session expires mid-use during reveal.
        await new Promise((resolve) => win.setTimeout(resolve, 0));
        win.document.getElementById('pw-bind-btn').style.display = '';
        win.document.getElementById('pw-auth-btn').style.display = 'none';
        win.fetch = async () => ({ ok: false, status: 401, json: async () => ({}) });

        await win.pwRevealSecret('pw1');

        assert.equal(visible(win, 'pw-bind-btn'), false, 'Bind secret must be hidden');
        assert.equal(visible(win, 'pw-auth-btn'), true, 'Authenticate must be shown');
    });

    test('late 401 while loading row metadata — Authenticate shown', async () => {
        const win = makeWindow();
        const doc = win.document;
        const row = doc.createElement('tr');
        row.id = 'pw-row-pw1';
        row.innerHTML = '<td class="pw-name"></td>';
        doc.getElementById('pw-secrets-tbody').appendChild(row);
        win.fetch = async () => ({ ok: false, status: 401, json: async () => ({}) });

        await win.pwLoadSecretMeta('pw1');

        assert.equal(visible(win, 'pw-bind-btn'), false, 'Bind secret must be hidden');
        assert.equal(visible(win, 'pw-auth-btn'), true, 'Authenticate must be shown');
    });
});
