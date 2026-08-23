/**
 * Explorer-style picker tests (spec issue #26).
 *
 * The modal is a two-pane Explorer: a folder tree on the left (vaults are
 * roots, a vault's folders arrive as one flat list), the selected node's
 * direct children on the right with breadcrumbs, and a debounced global
 * search (min 3 chars) whose results carry the secret's path. All behavior
 * is tested through the fetch seam: which URLs were called and what ended
 * up in the DOM.
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
 * `routes` maps a URL substring to the payload returned for it; a payload of
 * `{ __status: N, body: ... }` answers with that HTTP status. Unmatched URLs
 * resolve as HTTP 404. Route order matters: the first matching substring wins.
 */
function makeWindow(routes = {}, { fetchImpl } = {}) {
    const vc = new VirtualConsole();
    const dom = new JSDOM(
        `<!DOCTYPE html>
        <html><body>
            <input id="pw-picker-search">
            <input id="pw-picker-scope" type="checkbox">
            <div id="pw-picker-tree"></div>
            <nav id="pw-picker-path"></nav>
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
    win.PW_SEARCH_DEBOUNCE = 0;  // keep the debounce out of the tests' way
    win.__xss = 0;

    win.fetchCalls = [];
    win.fetch = fetchImpl
        ? (url, options) => { win.fetchCalls.push(String(url)); return fetchImpl(String(url), options); }
        : async (url) => {
            win.fetchCalls.push(String(url));
            for (const [needle, payload] of Object.entries(routes)) {
                if (String(url).includes(needle)) {
                    if (payload && payload.__status) {
                        return { ok: false, status: payload.__status, json: async () => payload.body ?? {} };
                    }
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

/** Let chained async bodies (fetch → render → fetch → render) finish. */
async function settle(rounds = 4) {
    for (let i = 0; i < rounds; i++) await new Promise((r) => setTimeout(r, 0));
}

const FLAT_FOLDERS = [
    { id: 'f1', name: 'Network', parentFolderId: null },
    { id: 'f2', name: 'Nested', parentFolderId: 'f1' },
];

const ROUTES = {
    // Order matters: more specific URL substrings go first.
    'folder_id=f1': { folders: [{ id: 'f2', name: 'Nested' }], items: [{ id: 'pw2', name: 'Switch', login: 'admin' }] },
    '/picker/folders/v1/folders/': FLAT_FOLDERS,
    '/picker/folders/v1/items/': {
        folders: [{ id: 'f1', name: 'Network' }],
        items: [{ id: 'pw1', name: 'Router', login: 'admin' }],
    },
    '/picker/folders/': [{ id: 'v1', name: 'Vault1' }, { id: 'v2', name: 'Vault2' }],
};

/** Open the picker and select the first vault. */
async function openAndSelectVault(win) {
    await win.pwOpenPicker();
    await settle();
    const vaultRow = Array.from(win.document.getElementById('pw-picker-tree').children)
        .find((el) => el.textContent.includes('Vault1'));
    vaultRow.click();
    await settle();
}

describe('picker explorer: tree and contents', () => {

    test('opening the picker lists vaults as tree roots', async () => {
        const win = makeWindow(ROUTES);
        await win.pwOpenPicker();
        await settle();

        const tree = win.document.getElementById('pw-picker-tree');
        assert.ok(tree.textContent.includes('Vault1') && tree.textContent.includes('Vault2'));
        assert.ok(!win.fetchCalls.some((u) => u.includes('/picker/search/')), 'opening must not search');
    });

    test('vault click loads the flat folder list once and the root contents', async () => {
        const win = makeWindow(ROUTES);
        await openAndSelectVault(win);

        assert.ok(win.fetchCalls.includes('/plugins/passwork/picker/folders/v1/folders/'),
            `flat folder list must be fetched, got: ${win.fetchCalls}`);
        assert.ok(win.fetchCalls.includes('/plugins/passwork/picker/folders/v1/items/'),
            `root contents must be fetched, got: ${win.fetchCalls}`);
        assert.ok(!win.fetchCalls.some((u) => u.includes('/picker/search/')),
            'a vault click must not go through the text search');

        const list = win.document.getElementById('pw-picker-list');
        assert.ok(list.textContent.includes('Network'), 'subfolder is rendered in the right pane');
        assert.ok(list.textContent.includes('Router'), 'root secret is rendered in the right pane');
    });

    test('chevron expands a folder in the tree without changing the selection', async () => {
        const win = makeWindow(ROUTES);
        await openAndSelectVault(win);

        const tree = win.document.getElementById('pw-picker-tree');
        assert.ok(!tree.textContent.includes('Nested'), 'nested folder hidden until expanded');
        const folderRow = Array.from(tree.children).find((el) => el.textContent.includes('Network'));
        folderRow.querySelector('.pw-tree-toggle').click();
        await settle();

        assert.ok(win.document.getElementById('pw-picker-tree').textContent.includes('Nested'));
        assert.ok(!win.fetchCalls.includes('/plugins/passwork/picker/folders/v1/items/?folder_id=f1'),
            'expanding the tree must not load folder contents');
    });

    test('folder row click in the right pane opens it and highlights it in the tree', async () => {
        const win = makeWindow(ROUTES);
        await openAndSelectVault(win);

        const list = win.document.getElementById('pw-picker-list');
        const folderRow = Array.from(list.querySelectorAll('tbody tr'))
            .find((el) => el.textContent.includes('Network'));
        folderRow.click();
        await settle();

        assert.ok(win.fetchCalls.includes('/plugins/passwork/picker/folders/v1/items/?folder_id=f1'),
            `drill-down must pass folder_id, got: ${win.fetchCalls}`);
        assert.ok(win.document.getElementById('pw-picker-list').textContent.includes('Switch'));

        const treeFolderRow = Array.from(win.document.getElementById('pw-picker-tree').children)
            .find((el) => el.textContent.includes('Network'));
        assert.ok(treeFolderRow.className.includes('bg-primary-subtle'), 'the tree highlights the opened folder');
    });

    test('breadcrumbs show the path and navigate back up', async () => {
        const win = makeWindow(ROUTES);
        await openAndSelectVault(win);
        Array.from(win.document.querySelectorAll('#pw-picker-list tbody tr'))
            .find((el) => el.textContent.includes('Network')).click();
        await settle();

        const nav = win.document.getElementById('pw-picker-path');
        assert.ok(nav.textContent.includes('Vault1') && nav.textContent.includes('Network'));

        nav.querySelector('a').click();  // the vault link
        await settle();
        assert.ok(win.document.getElementById('pw-picker-list').textContent.includes('Router'),
            'clicking the vault crumb returns to the root contents');
    });

    test('repeated navigation reuses the per-opening cache', async () => {
        const win = makeWindow(ROUTES);
        await openAndSelectVault(win);
        Array.from(win.document.querySelectorAll('#pw-picker-list tbody tr'))
            .find((el) => el.textContent.includes('Network')).click();
        await settle();
        win.document.querySelector('#pw-picker-path a').click();  // back to the root
        await settle();

        const rootCalls = win.fetchCalls.filter((u) => u === '/plugins/passwork/picker/folders/v1/items/');
        assert.equal(rootCalls.length, 1, 'root contents are fetched once per modal opening');
    });

    test('empty contents show an empty-folder hint', async () => {
        const win = makeWindow({
            '/picker/folders/v1/folders/': [],
            '/picker/folders/v1/items/': { folders: [], items: [] },
            '/picker/folders/': [{ id: 'v1', name: 'Vault1' }],
        });
        await openAndSelectVault(win);

        assert.ok(win.document.getElementById('pw-picker-list').textContent.includes('empty'),
            'the pane must say the folder is empty instead of staying blank');
    });

    test('folder name with XSS payload renders as text', async () => {
        const win = makeWindow({
            '/picker/folders/v1/folders/': [{ id: 'f1', name: XSS_IMG, parentFolderId: null }],
            '/picker/folders/v1/items/': { folders: [{ id: 'f1', name: XSS_IMG }], items: [] },
            '/picker/folders/': [{ id: 'v1', name: 'Vault1' }],
        });
        await openAndSelectVault(win);

        assert.equal(win.document.querySelectorAll('img').length, 0, 'folder name must not be parsed as HTML');
        assert.equal(win.__xss, 0, 'XSS payload must not execute');
        assert.ok(win.document.getElementById('pw-picker-list').textContent.includes('<img'));
    });

    test('a vault denied with 403 is marked "no access", other vaults keep working', async () => {
        const win = makeWindow({
            '/picker/folders/v1/folders/': { __status: 403, body: { code: 'pw_access_denied' } },
            '/picker/folders/v1/items/': { __status: 403, body: { code: 'pw_access_denied' } },
            '/picker/folders/': [{ id: 'v1', name: 'Vault1' }, { id: 'v2', name: 'Vault2' }],
        });
        await openAndSelectVault(win);

        const tree = win.document.getElementById('pw-picker-tree');
        assert.ok(tree.textContent.includes('no access'), 'the denied vault stays visible with a mark');
        assert.ok(tree.textContent.includes('Vault2'), 'other vaults are still listed');
    });

    test('a timed-out request shows a retryable message naming the setting', async () => {
        const win = makeWindow({}, {
            fetchImpl: async (url) => {
                if (url.includes('/items/')) throw new win.DOMException('aborted', 'AbortError');
                if (url.includes('/folders/v1/folders/')) return { ok: true, status: 200, json: async () => [] };
                return { ok: true, status: 200, json: async () => [{ id: 'v1', name: 'Vault1' }] };
            },
        });
        await openAndSelectVault(win);

        const list = win.document.getElementById('pw-picker-list');
        assert.ok(list.textContent.includes('PW_REQUEST_TIMEOUT'), 'the message names the timeout setting');
        assert.ok(Array.from(list.querySelectorAll('button')).some((b) => b.textContent === 'Retry'));
    });
});

describe('picker explorer: search', () => {

    const SEARCH_ROUTES = {
        '/picker/search/': [
            { id: 'pw9', name: 'Core router', login: 'admin', vaultId: 'v1', folderId: 'f1',
              path: [{ name: 'Vault1' }, { name: 'Network' }] },
        ],
        ...ROUTES,
    };

    test('search fires from 3 characters and renders flat results with the path', async () => {
        const win = makeWindow(SEARCH_ROUTES);
        await win.pwOpenPicker();
        await settle();

        win.pwPickerSearchInput('ro');
        await settle();
        assert.ok(!win.fetchCalls.some((u) => u.includes('/picker/search/')), 'below 3 chars nothing is searched');

        win.pwPickerSearchInput('rout');
        await settle();
        assert.ok(win.fetchCalls.includes('/plugins/passwork/picker/search/?q=rout'),
            `search must hit the search endpoint, got: ${win.fetchCalls}`);

        const list = win.document.getElementById('pw-picker-list');
        assert.ok(list.textContent.includes('Core router'));
        assert.ok(list.textContent.includes('Vault1 / Network'), 'each result shows its path');
        assert.equal(win.document.getElementById('pw-picker-path').textContent, 'Search results');
    });

    test('clearing the search box returns to the node the user was on', async () => {
        const win = makeWindow(SEARCH_ROUTES);
        await openAndSelectVault(win);

        win.pwPickerSearchInput('rout');
        await settle();
        assert.ok(win.document.getElementById('pw-picker-list').textContent.includes('Core router'));

        win.pwPickerSearchInput('');
        await settle();
        const list = win.document.getElementById('pw-picker-list');
        assert.ok(list.textContent.includes('Router') && !list.textContent.includes('Core router'),
            'the pane shows the current node contents again');
        assert.ok(win.document.getElementById('pw-picker-path').textContent.includes('Vault1'));
    });

    test('the scope checkbox limits the search to the selected vault', async () => {
        const win = makeWindow(SEARCH_ROUTES);
        await openAndSelectVault(win);

        win.document.getElementById('pw-picker-scope').checked = true;
        win.pwPickerSearchInput('rout');
        await settle();

        assert.ok(win.fetchCalls.includes('/plugins/passwork/picker/search/?q=rout&vault_id=v1'),
            `scoped search must pass vault_id, got: ${win.fetchCalls}`);
    });

    test('a stale search response never overwrites a newer one', async () => {
        const pending = [];
        const win = makeWindow({}, {
            fetchImpl: (url) => {
                if (url.includes('/picker/search/')) {
                    return new Promise((resolve) => pending.push({ url, resolve }));
                }
                return Promise.resolve({ ok: true, status: 200, json: async () => [] });
            },
        });
        await win.pwOpenPicker();
        await settle();

        const first = win.pwPickerRunSearch('first');
        const second = win.pwPickerRunSearch('second');
        assert.equal(pending.length, 2);

        pending[1].resolve({ ok: true, status: 200, json: async () => [{ id: 's2', name: 'Fresh result' }] });
        await second;
        pending[0].resolve({ ok: true, status: 200, json: async () => [{ id: 's1', name: 'Stale result' }] });
        await first;
        await settle();

        const text = win.document.getElementById('pw-picker-list').textContent;
        assert.ok(text.includes('Fresh result') && !text.includes('Stale result'));
    });

    test('clicking a result shows the secret in its folder with the tree expanded', async () => {
        const win = makeWindow(SEARCH_ROUTES);
        await win.pwOpenPicker();
        await settle();

        win.pwPickerSearchInput('rout');
        await settle();
        Array.from(win.document.querySelectorAll('#pw-picker-list tbody tr'))
            .find((el) => el.textContent.includes('Core router')).click();
        await settle();

        assert.ok(win.fetchCalls.includes('/plugins/passwork/picker/folders/v1/items/?folder_id=f1'),
            `show-in-folder must open the secret's folder, got: ${win.fetchCalls}`);
        assert.ok(win.document.getElementById('pw-picker-tree').textContent.includes('Network'),
            'the tree is expanded down to the folder');
        assert.equal(win.document.getElementById('pw-picker-search').value, '', 'the search box is cleared');
    });

    test('the Bind button binds directly from the results', async () => {
        const win = makeWindow({ '/bindings/': { status: 'ok' }, ...SEARCH_ROUTES });
        await win.pwOpenPicker();
        await settle();

        win.pwPickerSearchInput('rout');
        await settle();
        Array.from(win.document.querySelectorAll('#pw-picker-list button'))
            .find((b) => b.textContent.includes('Bind')).click();
        await settle();

        assert.ok(win.fetchCalls.includes('/plugins/passwork/bindings/'), 'Bind must POST the binding');
        assert.ok(!win.fetchCalls.some((u) => u.includes('folder_id=f1')),
            'the Bind button must not navigate to the folder');
    });
});
