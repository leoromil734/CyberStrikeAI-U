const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { previewHtml, startPreview } = require('./knowledge-targets.preview.cjs');
const html = fs.readFileSync(path.join(__dirname, '../../templates/index.html'), 'utf8');
const experience = html.match(/<div id="page-experience-memory"[\s\S]*?(?=<!-- 知识检索历史页面 -->)/)[0];
const targets = html.match(/<div id="page-targets"[\s\S]*?(?=<!-- C2 监听器管理页面 -->)/)[0];

test('experience and targets keep every original DOM ID and original event binding', () => {
    const experienceIds = ['experience-status', 'experience-kind', 'experience-project', 'experience-query', 'experience-list', 'experience-pagination', 'experience-detail', 'experience-detail-json', 'experience-evidence', 'experience-editor', 'experience-review-status', 'experience-review-scope', 'experience-review-note', 'experience-outcome'];
    const targetIds = ['targets-search', 'targets-total', 'targets-table-body', 'targets-pagination'];
    for (const [source, ids] of [[experience, experienceIds], [targets, targetIds]]) {
        for (const id of ids) assert.equal([...source.matchAll(new RegExp(`id="${id}"`, 'g'))].length, 1, `${id} must exist exactly once`);
    }
    for (const action of ['refresh', 'newProposal', 'close', 'exportSkill', 'history', 'save', 'review', 'confirmOutcome']) assert.ok(experience.includes(`onclick="ExperienceMemory.${action}()`), `missing ${action}`);
    assert.equal((experience.match(/onchange="ExperienceMemory.refresh\(\)"/g) || []).length, 2);
    assert.ok(experience.includes("onkeydown=\"if(event.key==='Enter') ExperienceMemory.refresh()\""));
    assert.ok(targets.includes('onclick="refreshTargetsPage()"'));
});

test('static permission gates and page navigation permissions remain unchanged', () => {
    assert.equal((experience.match(/data-require-permission="experience:write"/g) || []).length, 2);
    assert.equal((experience.match(/data-require-permission="experience:review"/g) || []).length, 1);
    assert.equal((experience.match(/data-require-permission="experience:export"/g) || []).length, 1);
    assert.ok(html.includes('data-page="targets" data-require-permission-any="target:read"'));
    assert.ok(html.includes('data-page="experience-memory"'));
    for (const source of [experience, targets]) {
        for (const tag of source.matchAll(/<button\b[^>]*>/g)) assert.ok(tag[0].includes('type="button"'), `implicit submit button ${tag[0]}`);
    }
});

test('new page CSS is fully scoped and includes theme, keyboard, mobile and reduced-motion behavior', () => {
    for (const [filename, page] of [['experience.css', '#page-experience-memory'], ['targets.css', '#page-targets']]) {
        const css = fs.readFileSync(path.join(__dirname, '../css', filename), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '');
        for (const match of css.matchAll(/([^{}]+)\{/g)) {
            const selector = match[1].trim();
            if (selector.startsWith('@') || selector === 'to') continue;
            for (const part of selector.split(',')) assert.ok(part.includes(page), `unscoped selector in ${filename}: ${part}`);
        }
        assert.ok(css.includes('html[data-theme="dark"]'));
        assert.ok(css.includes('@media (max-width:'));
        assert.ok(css.includes('@media (prefers-reduced-motion: reduce)'));
        assert.ok(css.includes(':focus-visible'));
        assert.ok(css.includes('[hidden] { display: none !important; }'));
        assert.ok(html.includes(`/static/css/${filename}?v=`));
    }
});

test('isolated preview escapes HTML script boundaries and the bootstrap remains valid JavaScript', () => {
    const preview = previewHtml(new URL('http://fixture.invalid/?page=targets&read=1&lang=en-US&theme=dark'));
    const scripts = [...preview.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/g)];
    assert.equal(scripts.length, 3);
    assert.doesNotThrow(() => new vm.Script(scripts[0][1]));
    assert.ok(preview.includes('data-theme="dark"'));
    assert.ok(preview.includes('id="page-targets" class="page active"'));
    assert.ok(!preview.includes('id="page-experience-memory"'));
    assert.ok(scripts[0][1].includes('Mutation blocked by the read-only UI fixture'));
});

test('isolated preview serves only test assets and rejects backend paths and writes', async t => {
    const server = startPreview(0);
    await new Promise(resolve => server.once('listening', resolve));
    t.after(() => { server.closeAllConnections(); server.close(); });
    const base = `http://127.0.0.1:${server.address().port}`;
    const page = await fetch(base + '/?page=experience-memory');
    assert.equal(page.status, 200);
    assert.ok((await page.text()).includes('本地只读模拟数据'));
    assert.equal((await fetch(base + '/static/css/targets.css')).status, 200);
    assert.equal((await fetch(base + '/api/targets')).status, 404);
    assert.equal((await fetch(base + '/api/experiences', { method: 'POST', body: '{}' })).status, 405);
    assert.equal((await fetch(base + '/static/../templates/index.html')).status, 404);
});

test('all static page strings and translation interpolation placeholders are present in both languages', () => {
    const resources = ['zh-CN', 'en-US'].map(lang => JSON.parse(fs.readFileSync(path.join(__dirname, `../i18n/${lang}.json`), 'utf8')));
    for (const source of [experience, targets]) {
        for (const match of source.matchAll(/data-i18n="([^"]+)"/g)) {
            for (const language of resources) assert.ok(match[1].split('.').reduce((obj, key) => obj?.[key], language), `missing ${match[1]}`);
        }
    }
    for (const section of ['experience', 'targets']) {
        for (const [key, zhText] of Object.entries(resources[0][section])) {
            const names = text => [...text.matchAll(/\{\{(\w+)\}\}/g)].map(match => match[1]).sort();
            assert.deepEqual(names(zhText), names(resources[1][section][key]), `${section}.${key} interpolation mismatch`);
        }
    }
});
