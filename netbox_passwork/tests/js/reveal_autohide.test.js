/**
 * Auto-hide of revealed detail-card fields (issue #30).
 *
 * The main list-row password re-masks itself after PW_REVEAL_TIMEOUT
 * (pwRevealSecret). Secret custom fields and the detail-card Password row go
 * through pwRevealCustomField — these tests pin down that it now behaves the
 * same way: a per-field auto-hide timer, manual hide cancels the timer and
 * sends no extra request.
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

const DOTS = '•••••••••';
const REVEAL_DELAY = 30 * 1000; // PW_REVEAL_TIMEOUT default (PW_SECRET_REVEAL_TIMEOUT unset)

function makeWindow() {
    const vc = new VirtualConsole();
    const dom = new JSDOM(
        `<!DOCTYPE html>
        <html><body>
            <div id="pw-secrets-table" style="display:none"></div>
            <div id="pw-loading"></div>
            <div id="pw-empty"></div>
            <div id="pw-auth-required"></div>
            <div id="pw-picker-list"></div>
            <table><tbody id="pw-secrets-tbody"></tbody></table>
        </body></html>`,
        {
            url: 'https://netbox.example.com/',
            runScripts: 'dangerously',
            pretendToBeVisual: true,
            virtualConsole: vc,
        }
    );
    const win = dom.window;
    win.PW_OBJECT_TYPE = 'device';
    win.PW_OBJECT_ID = '1';
    if (!win.CSS) {
        win.CSS = { escape: (s) => String(s).replace(/([^\w-])/g, '\\$1') };
    }
    win.fetch = async () => ({ ok: false, status: 503, json: async () => ({}) });

    const scriptEl = win.document.createElement('script');
    scriptEl.textContent = src;
    win.document.head.appendChild(scriptEl);
    return win;
}

/** Renders a detail card with a Password row and one secret custom field; returns {span, btn} per field. */
function setupDetail(win) {
    const doc = win.document;
    const tbody = doc.getElementById('pw-secrets-tbody');
    const row = doc.createElement('tr');
    row.id = 'pw-row-pw1';
    row.innerHTML = '<td class="pw-name">n</td><td class="pw-login">l</td><td class="pw-password"></td><td></td>';
    tbody.appendChild(row);

    win.pwAddDetailRow(row, 'pw1', {
        login: '',
        passwork_url: '',
        description: '',
        password: '',
        custom_fields: [{ name: 'Privacy', value: '', is_secret: true, type: 'text' }],
    });

    const detail = doc.getElementById('pw-detail-pw1');
    assert.ok(detail, 'detail row must be created');
    const fieldParts = (fieldName) => {
        const span = detail.querySelector(`span.pw-cf-secret[data-field="${fieldName}"]`);
        assert.ok(span, `secret span for "${fieldName}" must exist`);
        const btn = span.nextElementSibling;
        assert.ok(btn && btn.tagName === 'BUTTON', `reveal button for "${fieldName}" must follow the span`);
        return { span, btn };
    };
    return { privacy: fieldParts('Privacy'), password: fieldParts('password') };
}

/** Replaces the window's timer functions with capturing stubs. */
function captureTimers(win) {
    const scheduled = [];
    const cleared = [];
    let nextId = 100000;
    win.setTimeout = (cb, delay) => {
        const id = nextId++;
        scheduled.push({ id, cb, delay });
        return id;
    };
    win.clearTimeout = (id) => { cleared.push(id); };
    const revealTimers = () => scheduled.filter(t => t.delay === REVEAL_DELAY);
    return { scheduled, cleared, revealTimers };
}

/** Counting fetch stub answering the reveal endpoint. */
function stubRevealFetch(win) {
    const counter = { calls: 0 };
    win.fetch = async () => {
        counter.calls += 1;
        return {
            ok: true,
            status: 200,
            json: async () => ({
                password: 'PWVAL',
                custom_fields: [{ name: 'Privacy', value: 'CFVAL', is_secret: true, type: 'text' }],
            }),
        };
    };
    return counter;
}

describe('pwRevealCustomField — auto-hide (issue #30)', () => {

    test('a revealed secret custom field re-masks after PW_REVEAL_TIMEOUT', async () => {
        const win = makeWindow();
        const { privacy } = setupDetail(win);
        stubRevealFetch(win);
        const timers = captureTimers(win);

        await win.pwRevealCustomField(privacy.btn, 'pw1', 'Privacy');
        assert.equal(privacy.span.textContent, 'CFVAL', 'value must be revealed');

        const pending = timers.revealTimers();
        assert.equal(pending.length, 1, 'exactly one auto-hide timer must be scheduled');

        pending[0].cb();
        assert.equal(privacy.span.textContent, DOTS, 'value must re-mask when the timer fires');
        assert.ok(privacy.btn.innerHTML.includes('mdi-eye-outline'), 'icon must return to "reveal"');
    });

    test('the detail-card Password row auto-hides the same way', async () => {
        const win = makeWindow();
        const { password } = setupDetail(win);
        stubRevealFetch(win);
        const timers = captureTimers(win);

        await win.pwRevealCustomField(password.btn, 'pw1', 'password');
        assert.equal(password.span.textContent, 'PWVAL');

        const pending = timers.revealTimers();
        assert.equal(pending.length, 1);
        pending[0].cb();
        assert.equal(password.span.textContent, DOTS);
    });

    test('manual hide cancels the timer and sends no request', async () => {
        const win = makeWindow();
        const { privacy } = setupDetail(win);
        const counter = stubRevealFetch(win);
        const timers = captureTimers(win);

        await win.pwRevealCustomField(privacy.btn, 'pw1', 'Privacy');
        const timerId = timers.revealTimers()[0].id;
        const callsAfterReveal = counter.calls;

        await win.pwRevealCustomField(privacy.btn, 'pw1', 'Privacy'); // toggle off
        assert.equal(privacy.span.textContent, DOTS, 'manual hide must re-mask immediately');
        assert.ok(timers.cleared.includes(timerId), 'the auto-hide timer must be cancelled');
        assert.equal(counter.calls, callsAfterReveal, 'hiding must not fetch (no extra reveal audit entry)');
    });

    test('each field keeps its own timer — hiding one leaves the other revealed', async () => {
        const win = makeWindow();
        const { privacy, password } = setupDetail(win);
        stubRevealFetch(win);
        const timers = captureTimers(win);

        await win.pwRevealCustomField(privacy.btn, 'pw1', 'Privacy');
        await win.pwRevealCustomField(password.btn, 'pw1', 'password');
        const pending = timers.revealTimers();
        assert.equal(pending.length, 2, 'one timer per revealed field');

        pending[0].cb(); // fires for the field revealed first (Privacy)
        assert.equal(privacy.span.textContent, DOTS, 'first field re-masked');
        assert.equal(password.span.textContent, 'PWVAL', 'second field must stay revealed');
    });
});
