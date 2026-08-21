/**
 * Picker folder-contents tests (issue #15).
 *
 * The regression: clicking a vault/folder used to send the folder ID as a
 * free-text search query (`/picker/search/?q=<id>`), so the right pane was
 * always empty. Now a click loads `/picker/folders/<vault>/items/` and the
 * right pane renders both subfolders and secrets.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { JSDOM, VirtualConsole } from 'jsdom';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const JS_SRC = path.resolve(__dirname, '../../static/netbox_passwork/passwork.js');
const src = readFileSync(JS_SRC, 'utf8');

const XSS_IMG = '<img src=x onerror="window.__xss=1">';

/**
 * jsdom window with passwork.js loaded and `fetch` recording every URL.
 * `routes` maps a URL substring to the JSON payload returned for it;
 * unmatched URLs resolve as HTTP 404.
 */
function makeWindow(routes = {}) {
    const vc = new VirtualConsole();
    const dom = new JSDOM(
        `<!DOCTYPE html>
        <html><body>
            <div id="pw-picker-tree"></div>
            <div id="pw-picker-list"></div>
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
    win.PW_OBJECT_ID = '1';
    win.__xss = 0;

    win.fetchCalls = [];
    win.fetch = async (url) => {
        win.fetchCalls.push(String(url));
        for (const [needle, payload] of Object.entries(routes)) {
            if (String(url).includes(needle)) {
                return { ok: true, status: 200, json: async () => payload };
            }
        }
        return { ok: false, status: 404, json: async () => ({}) };
    };

    const scriptEl = win.document.createElement('script');
    scriptEl.textContent = src;
    win.document.head.appendChild(scriptEl);
    return win;
}

/** Let click-handler async bodies (fetch → render) finish. */
const settle = () => new Promise((r) => setTimeout(r, 0));

const VAULT_ROUTES = {
    '/picker/folders/v1/items/': {
        folders: [{ id: 'f1', name: 'Network' }],
        items: [{ id: 'pw1', name: 'Router', login: 'admin' }],
    },
    '/picker/folders/': [{ id: 'v1', name: 'Vault1' }],
};

describe('picker folder contents', () => {

    test('vault click loads folder contents, not a text search by vault id', async () => {
        const win = makeWindow(VAULT_ROUTES);
        await win.pwLoadPickerFolders();

        win.document.getElementById('pw-picker-tree').children[0].click();
        await settle();

        assert.ok(
            win.fetchCalls.includes('/plugins/passwork/picker/folders/v1/items/'),
            `contents endpoint must be called, got: ${win.fetchCalls}`
        );
        assert.ok(
            !win.fetchCalls.some((u) => u.includes('/picker/search/')),
            'a vault click must not go through the text search'
        );

        const text = win.document.getElementById('pw-picker-list').textContent;
        assert.ok(text.includes('Network'), 'subfolder is rendered in the right pane');
        assert.ok(text.includes('Router'), 'secret is rendered in the right pane');
    });

    test('folder entry click drills down with folder_id', async () => {
        const win = makeWindow({
            // Routes match in insertion order: the drill-down URL also contains the
            // vault-contents prefix, so the more specific route goes first.
            'folder_id=f1': {
                folders: [],
                items: [{ id: 'pw2', name: 'Switch', login: 'admin' }],
            },
            ...VAULT_ROUTES,
        });
        await win.pwLoadPickerFolders();
        win.document.getElementById('pw-picker-tree').children[0].click();
        await settle();

        const list = win.document.getElementById('pw-picker-list');
        const folderRow = Array.from(list.children).find((el) => el.textContent.includes('Network'));
        assert.ok(folderRow, 'folder row must be rendered');
        folderRow.click();
        await settle();

        assert.ok(
            win.fetchCalls.includes('/plugins/passwork/picker/folders/v1/items/?folder_id=f1'),
            `drill-down must pass folder_id, got: ${win.fetchCalls}`
        );
        assert.ok(list.textContent.includes('Switch'), 'folder contents replace the pane');
    });

    test('empty contents show an empty-folder hint', async () => {
        const win = makeWindow({
            '/picker/folders/v1/items/': { folders: [], items: [] },
            '/picker/folders/': [{ id: 'v1', name: 'Vault1' }],
        });
        await win.pwLoadPickerFolders();
        win.document.getElementById('pw-picker-tree').children[0].click();
        await settle();

        assert.ok(
            win.document.getElementById('pw-picker-list').textContent.includes('empty'),
            'the pane must say the folder is empty instead of staying blank'
        );
    });

    test('folder name with XSS payload renders as text', async () => {
        const win = makeWindow({
            '/picker/folders/v1/items/': {
                folders: [{ id: 'f1', name: XSS_IMG }],
                items: [],
            },
            '/picker/folders/': [{ id: 'v1', name: 'Vault1' }],
        });
        await win.pwLoadPickerFolders();
        win.document.getElementById('pw-picker-tree').children[0].click();
        await settle();

        const list = win.document.getElementById('pw-picker-list');
        assert.equal(list.querySelectorAll('img').length, 0, 'folder name must not be parsed as HTML');
        assert.equal(win.__xss, 0, 'XSS payload must not execute');
        assert.ok(list.textContent.includes('<img'), 'payload appears as literal text');
    });

    test('text search still goes through /picker/search/', async () => {
        const win = makeWindow({
            '/picker/search/': [{ id: 'pw1', name: 'Router', login: 'admin' }],
        });
        await win.pwPickerSearch('rout');
        await settle();

        assert.ok(
            win.fetchCalls.includes('/plugins/passwork/picker/search/?q=rout'),
            `search must stay text-only, got: ${win.fetchCalls}`
        );
    });
});
