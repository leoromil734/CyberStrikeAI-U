package handler

import (
	"os/exec"
	"strings"
	"testing"
)

// Run the actual sidebar and task rendering functions with a minimal local DOM.
// This verifies labels without starting an agent or contacting an external site.
func TestChatAIModelAndChannelFrontendLabels(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("frontend label checks require Node.js")
	}
	script := `
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const chat = fs.readFileSync('../../web/static/js/chat.js', 'utf8');
const monitor = fs.readFileSync('../../web/static/js/monitor.js', 'utf8');
const translations = JSON.parse(fs.readFileSync('../../web/static/i18n/zh-CN.json', 'utf8'));
const english = JSON.parse(fs.readFileSync('../../web/static/i18n/en-US.json', 'utf8'));
for (const key of ['aiModelLabel', 'aiModelUnknown', 'aiChannelUnknown']) {
    assert.ok(translations.chat[key]);
    assert.ok(english.chat[key]);
}
const allNodes = [];
class Element {
    constructor(tag) {
        this.tag = tag;
        this.children = [];
        this.dataset = {};
        this.style = {};
        this.className = '';
        this.textContent = '';
        this.classList = {add() {}};
        this.listeners = {};
        allNodes.push(this);
    }
    set innerHTML(html) { this.html = html; this.children = []; }
    get innerHTML() { return this.html || ''; }
    appendChild(child) { this.children.push(child); return child; }
    setAttribute(name, value) { this[name] = value; }
    addEventListener(name, handler) { this.listeners[name] = handler; }
    querySelector(selector) {
        return this.innerHTML.includes(selector.slice(1)) ? new Element('button') : null;
    }
}
const bar = new Element('div');
global.window = {t(key) { return key.split('.').reduce((obj, part) => obj && obj[part], translations) || key; }};
global.document = {
    createElement(tag) { return new Element(tag); },
    getElementById(id) { return id === 'active-tasks-bar' ? bar : null; },
    querySelectorAll(selector) { return allNodes.filter(node => node.className.split(' ').includes(selector.slice(1))); },
};
global.currentConversationId = null;
global.conversationGroupMappingCache = {};
global.groupsCache = [];
global.conversationExecutionTracker = {update() {}};
global.safeTruncateText = (text) => text;
global.formatConversationTimestamp = () => 'now';
global.getCurrentTimeLocale = () => 'zh-CN';
global.getTimeFormatOptions = () => ({});
global.escapeHtml = text => String(text).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
vm.runInThisContext('let chatAIChannels = {}; let chatAIChannelIdByNormalizedId = {}; let chatDefaultAIChannel = "";');
function loadFunction(source, name) {
    const start = source.indexOf('function ' + name + '(');
    assert.ok(start >= 0, 'missing actual renderer: ' + name);
    const next = /\n(?:async )?function /.exec(source.slice(start + 10));
    const end = next ? start + 10 + next.index : source.length;
    vm.runInThisContext(source.slice(start, end), {filename: name + '.js'});
}
for (const name of ['normalizeChatAIChannelId', 'resolveChatAIChannelId', 'populateChatAIChannelSelect', 'conversationAIChannelLabel', 'updateConversationAIChannelBadge', 'refreshConversationAILabels', 'appendConversationAIBadges', 'createConversationListItemWithMenu']) {
    loadFunction(chat, name);
}
for (const name of ['getActiveTaskDisplayName', 'renderActiveTasks', 'renderTaskItemIntoContainer']) loadFunction(monitor, name);
const findClass = (node, className) => node.className.split(' ').includes(className) ? node : node.children.map(child => findClass(child, className)).find(Boolean);
// Sidebar can load before channel configuration; initially show the recorded ID.
const first = createConversationListItemWithMenu({id:'one', title:'first', aiModel:'model-one', aiChannelId:'channel_a'}, false);
assert.equal(findClass(first, 'conversation-item-model-badge').textContent, 'model-one');
assert.equal(findClass(first, 'conversation-item-channel-badge').textContent, 'channel_a');
// Configuration arriving later refreshes existing labels without rebuilding the list.
populateChatAIChannelSelect({channels: {'channel-a': {name:'渠道甲', model:'new-config-model'}, 'channel-b': {name:'渠道乙', model:'other-model'}}, default_channel:'channel-b'});
assert.equal(findClass(first, 'conversation-item-channel-badge').textContent, '渠道甲');
assert.equal(findClass(first, 'conversation-item-model-badge').textContent, 'model-one');
assert.ok(findClass(first, 'conversation-item-channel-badge').title.includes('渠道甲'));
const second = createConversationListItemWithMenu({id:'two', aiModel:'model-one', aiChannelId:'channel-b'}, true);
assert.equal(findClass(second, 'conversation-item-channel-badge').textContent, '渠道乙');
assert.equal(conversationAIChannelLabel({aiChannelId:'deleted'}), 'deleted');
assert.equal(conversationAIChannelLabel({ai_channel_id:'channel_b'}), '渠道乙');
assert.equal(conversationAIChannelLabel({aiChannelId:''}), '');
const historical = createConversationListItemWithMenu({id:'old', aiModel:'historical-model'}, false);
assert.equal(findClass(historical, 'conversation-item-channel-badge').textContent, '渠道未记录');
const empty = createConversationListItemWithMenu({id:'empty'}, false);
assert.equal(findClass(empty, 'conversation-item-ai-metadata'), undefined);
const unsafeChannel = '<img src=x onerror=alert(1)>';
const unsafe = createConversationListItemWithMenu({id:'unsafe', aiModel:'model', aiChannelName:unsafeChannel}, false);
assert.equal(findClass(unsafe, 'conversation-item-channel-badge').textContent, unsafeChannel);
assert.equal(findClass(unsafe, 'conversation-item-channel-badge').innerHTML, '');
// All task items use their own recorded model in both flat and expanded layouts.
const tasks = [
    {conversationId:'one', title:'task one', aiModel:'actual-model-one', aiChannelName:'发现时渠道甲', status:'running'},
    {conversationId:'two', title:'task two', aiModel:'actual-model-two', aiChannelId:'channel-b', status:'running'},
    {conversationId:'three', title:'task three', aiModel:'<unsafe-model>', ai_channel_name:'<unsafe-channel>', status:'running'},
];
renderActiveTasks(tasks.slice(0, 2));
assert.equal(bar.children.length, 2);
assert.ok(bar.children[0].innerHTML.includes('actual-model-one'));
assert.ok(bar.children[1].innerHTML.includes('actual-model-two'));
assert.ok(!bar.children[0].innerHTML.includes('new-config-model'));
assert.ok(bar.children[0].innerHTML.includes('title="AI 模型: actual-model-one"'));
assert.ok(bar.children[0].innerHTML.includes('发现时渠道甲'));
assert.ok(bar.children[1].innerHTML.includes('渠道乙'));
assert.ok(bar.children[0].innerHTML.includes('active-task-channel'));
renderActiveTasks(tasks);
const expanded = findClass(bar, 'active-tasks-expanded-panel');
assert.equal(expanded.children.length, 3);
assert.ok(expanded.children[0].innerHTML.includes('actual-model-one'));
assert.ok(expanded.children[1].innerHTML.includes('actual-model-two'));
assert.ok(expanded.children[2].innerHTML.includes('&lt;unsafe-model&gt;'));
assert.ok(!expanded.children[2].innerHTML.includes('<unsafe-model>'));
assert.ok(expanded.children[2].innerHTML.includes('&lt;unsafe-channel&gt;'));
assert.ok(!expanded.children[2].innerHTML.includes('<unsafe-channel>'));
renderActiveTasks([{conversationId:'unrecorded', title:'new', status:'running'}]);
assert.ok(bar.children[0].innerHTML.includes('模型未记录'));
assert.ok(bar.children[0].innerHTML.includes('渠道未记录'));
console.log('chat model and channel label checks passed');
`
	cmd := exec.Command(node)
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("frontend label checks failed: %v\n%s", err, out)
	}
}
