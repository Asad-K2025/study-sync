import { apiDelete, apiGet, apiPost, apiPut, buildApiUrl, ensureHttpsOrRedirect } from './api.js';
import { closeModal, initModalOverlays, openModal } from './modal.js';
import { esc, setLoad, showToast } from './utils.js';
import { fetchAndVerifyPin } from './cert_pin.js';
import { deriveGroupKey, getOrCreateKeyPair, exportPublicKeyJwk, importPublicKeyJwk, generateGroupKey, wrapGroupKey, unwrapGroupKey, encryptMessage, decryptMessage, isEncrypted } from './crypto.js';

let ME = null;
let currentGroupId = null;
let calYear = new Date().getFullYear();
let calMon = new Date().getMonth();
let selectedGroupColor = '#4361ee';
let annEditingId = null;
let emojiOpen = false;
let previewAttId = null;
let previewFilename = '';

const state = {
  me: null,
  users: [],
  groups: [],
  information: [],
  calendar: { events: [], allocate_url: null },
  meetings: [],
  groupMembers: new Map(),
  messages: new Map(),
  announcements: new Map(),
  announcementsUnread: new Map(),
  groupKeys: new Map(),   // gid → CryptoKey (AES-GCM)
  myKeyPair: null,        // { privateKey, publicKey }
};

async function loadGroupKey(gid) {
  if (state.groupKeys.has(gid)) return;
  try {
    const groupKey = await deriveGroupKey(gid);
    state.groupKeys.set(gid, groupKey);
  } catch (e) {
    console.warn(`E2EE: failed to derive group key for group ${gid}:`, e);
  }
}

async function boot() {
  ensureHttpsOrRedirect();
  initModalOverlays();
  initThemeControls();
  try {
    setLoad(5);
    await fetchAndVerifyPin();

    setLoad(10);
    state.me = await apiGet('/api/auth/me');
    ME = state.me.id;

    setLoad(30);
    state.users = await apiGet('/api/users');

    setLoad(55);
    state.groups = await apiGet('/api/groups');

    setLoad(72);
    state.calendar = await apiGet('/api/calendar');

    setLoad(84);
    state.meetings = await apiGet('/api/meetings');

    setLoad(92);
    focusCalendarOnRelevantMonth();
    renderUserChip();
    document.getElementById('btnLogout')?.addEventListener('click', () => void logout());
    initChatTools();
    renderGroupList();
    renderCalendar();
    renderVotingList();
    loadSavedAllocateUrl();

    const groups = getMyGroups();
    if (groups.length) await selectGroup(groups[0].id);

    setLoad(100);
    setTimeout(() => {
      const ls = document.getElementById('loadScreen');
      if (!ls) return;
      ls.style.opacity = '0';
      setTimeout(() => (ls.style.display = 'none'), 400);
    }, 300);
  } catch (e) {
    console.error('Boot error:', e);
    const ls = document.getElementById('loadScreen');
    if (!ls) return;
    ls.innerHTML = `<div style="color:red;padding:20px;text-align:center;">
      <div style="font-size:32px;margin-bottom:12px">⚠️</div>
      <div style="font-size:16px;font-weight:600;">Failed to load</div>
      <div style="font-size:13px;margin-top:8px;color:#666">${esc(e?.message || 'Unknown error')}</div>
    </div>`;
  }
}

function getUser(id) {
  return state.users.find((u) => u.id === id) || null;
}

function getAllUsers() {
  return state.users;
}

function renderUserChip() {
  const me = state.me;
  if (!me) return;
  document.getElementById('myName').textContent = me.name;
  document.getElementById('myAvatar').textContent = me.name[0];
  document.getElementById('myAvatar').style.background = me.avatar_color;
  document.getElementById('calAvatar').textContent = me.name[0];
  document.getElementById('calAvatar').style.background = me.avatar_color;
  const menuName = document.getElementById('userMenuName');
  const menuUsername = document.getElementById('userMenuUsername');
  if (menuName) menuName.textContent = me.name;
  if (menuUsername) menuUsername.textContent = `@${me.username}`;
}

async function logout() {
  try {
    await apiPost('/api/auth/logout', {});
  } finally {
    location.href = '/login';
  }
}

function openSettingsModal() {
  syncThemeUi();
  openModal('modalSettings');
}

function openHelpModal() {
  openModal('modalHelp');
}

function openUserProfile() {
  if (!state.me) return;
  
  // Update profile information
  document.getElementById('profileAvatar').textContent = state.me.name[0];
  document.getElementById('profileAvatar').style.background = state.me.avatar_color;
  document.getElementById('profileName').textContent = state.me.name;
  document.getElementById('profileUsername').textContent = `@${state.me.username}`;
  
  // Calculate statistics
  const groups = getMyGroups();
  let totalMessages = 0;
  let totalMeetings = 0;
  
  groups.forEach(group => {
    const messages = state.messages.get(group.id) || [];
    totalMessages += messages.length;
  });
  
  totalMeetings = (state.meetings || []).length;
  
  // Update stats
  document.getElementById('groupCount').textContent = groups.length;
  document.getElementById('messageCount').textContent = totalMessages;
  document.getElementById('meetingCount').textContent = totalMeetings;
  
  // Update additional info (placeholder for now)
  document.getElementById('profileEmail').textContent = state.me.email || 'Not available';
  document.getElementById('profileJoinDate').textContent = state.me.created_at ? 
    new Date(state.me.created_at).toLocaleDateString('en-AU', { year: 'numeric', month: 'long', day: 'numeric' }) : 
    'Not available';
  
  openModal('modalUserProfile');
}

function setAnnBadge(count) {
  const badge = document.getElementById('annBadge');
  const btn = document.getElementById('annBtn');
  if (!badge || !btn) return;
  const n = Number.isFinite(+count) ? +count : 0;
  if (!currentGroupId || n <= 0) {
    badge.style.display = 'none';
    badge.textContent = '';
    btn.classList.remove('has-unread');
    return;
  }
  badge.textContent = n > 99 ? '99+' : String(n);
  badge.style.display = 'inline-flex';
  btn.classList.add('has-unread');
}

function resetAnnouncementComposer() {
  annEditingId = null;
  const ta = document.getElementById('annContent');
  if (ta) ta.value = '';
  syncAnnouncementComposerUi();
}

function syncAnnouncementComposerUi() {
  const title = document.getElementById('annComposeTitle');
  const btn = document.getElementById('annPublishBtn');
  const cancel = document.getElementById('annCancelEditBtn');
  if (!title || !btn || !cancel) return;
  if (annEditingId) {
    title.textContent = 'Edit announcement';
    btn.textContent = 'Save';
    cancel.style.display = '';
  } else {
    title.textContent = 'New announcement';
    btn.textContent = 'Publish';
    cancel.style.display = 'none';
  }
}

async function loadAnnouncements(gid, { render = false } = {}) {
  const payload = await apiGet(`/api/announcements?group_id=${gid}`);
  const list = Array.isArray(payload.announcements) ? payload.announcements : [];
  const unread = Number.isFinite(+payload.unread_count) ? +payload.unread_count : 0;
  state.announcements.set(gid, list);
  state.announcementsUnread.set(gid, unread);
  if (gid === currentGroupId) setAnnBadge(unread);
  if (render) renderAnnouncementsList(gid);
  return payload;
}

function fmtTime(ts) {
  if (!ts) return '';
  const s = String(ts).includes('T') ? String(ts) : String(ts).replace(' ', 'T');
  const d = new Date(s);
  if (Number.isNaN(d.getTime())) return '';
  return d.toLocaleString('en-AU', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function renderAnnouncementsList(gid) {
  const el = document.getElementById('annList');
  if (!el) return;
  const list = state.announcements.get(gid) || [];
  if (!list.length) {
    el.innerHTML = '<div class="ann-empty">No announcements yet.</div>';
    return;
  }

  el.innerHTML = list
    .map((a) => {
      const unread = !a.read_by_me && !a.can_edit;
      const avatar = (a.author_name || 'U')[0];
      const t = fmtTime(a.updated_at || a.created_at);
      const edited = a.updated_at ? ' · Edited' : '';
      return `<div class="ann-item ${unread ? 'unread' : ''}">
        <div class="ann-item-top">
          <div class="ann-item-meta">
            <div class="avatar" style="background:${a.author_color || 'var(--primary)'};width:28px;height:28px;font-size:11px">${esc(avatar)}</div>
            <div style="min-width:0;">
              <div class="ann-author">${esc(a.author_name || 'Unknown')}</div>
              <div class="ann-time">${esc(t)}${edited}</div>
            </div>
          </div>
          ${unread ? '<span class="ann-chip">UNREAD</span>' : ''}
        </div>
        <div class="ann-content">${esc(a.content || '')}</div>
        <div class="ann-actions">
          ${
            unread
              ? `<button class="ann-btn primary" type="button" onclick="markAnnouncementRead(${a.id})">Mark as read</button>`
              : ''
          }
          ${
            a.can_edit
              ? `<button class="ann-btn" type="button" onclick="startAnnouncementEdit(${a.id})">Edit</button>
                 <button class="ann-btn danger" type="button" onclick="deleteAnnouncement(${a.id})">Delete</button>`
              : ''
          }
        </div>
      </div>`;
    })
    .join('');
}

async function openAnnouncementsModal() {
  if (!currentGroupId) {
    showToast('Select a group first');
    return;
  }
  resetAnnouncementComposer();
  const listEl = document.getElementById('annList');
  if (listEl) listEl.innerHTML = '<div class="ann-empty">Loading…</div>';
  openModal('modalAnnouncements');
  try {
    await loadAnnouncements(currentGroupId, { render: true });
  } catch (e) {
    if (listEl) listEl.innerHTML = `<div class="ann-empty">${esc(e.message || 'Failed to load announcements')}</div>`;
  }
}

function cancelAnnouncementEdit() {
  annEditingId = null;
  syncAnnouncementComposerUi();
}

function startAnnouncementEdit(announcementId) {
  if (!currentGroupId) return;
  const list = state.announcements.get(currentGroupId) || [];
  const a = list.find((x) => +x.id === +announcementId);
  if (!a || !a.can_edit) return;
  annEditingId = +announcementId;
  const ta = document.getElementById('annContent');
  if (ta) ta.value = a.content || '';
  syncAnnouncementComposerUi();
  ta?.focus();
}

async function publishAnnouncement() {
  if (!currentGroupId) {
    showToast('Select a group first');
    return;
  }
  const ta = document.getElementById('annContent');
  const content = (ta?.value || '').trim();
  if (!content) {
    showToast('Write something first');
    return;
  }
  if (content.length > 4000) {
    showToast('Announcement is too long');
    return;
  }

  if (annEditingId) {
    await apiPut(`/api/announcements/${annEditingId}`, { content });
    showToast('✓ Announcement updated');
  } else {
    await apiPost('/api/announcements', { group_id: currentGroupId, content });
    showToast('✓ Announcement published');
  }

  resetAnnouncementComposer();
  await loadAnnouncements(currentGroupId, { render: true });
}

async function deleteAnnouncement(announcementId) {
  if (!currentGroupId) return;
  const ok = confirm('Delete this announcement?');
  if (!ok) return;
  await apiDelete(`/api/announcements/${announcementId}`);
  if (annEditingId && +annEditingId === +announcementId) resetAnnouncementComposer();
  await loadAnnouncements(currentGroupId, { render: true });
  showToast('✓ Announcement deleted');
}

async function markAnnouncementRead(announcementId) {
  if (!currentGroupId) return;
  await apiPost(`/api/announcements/${announcementId}/read`, {});
  await loadAnnouncements(currentGroupId, { render: true });
  showToast('✓ Marked as read');
}

async function markAllAnnouncementsRead() {
  if (!currentGroupId) return;
  await apiPost('/api/announcements/read_all', { group_id: currentGroupId });
  await loadAnnouncements(currentGroupId, { render: true });
  showToast('✓ All announcements marked as read');
}

function getThemePrefs() {
  const mode = (localStorage.getItem('studysync_mode') || document.documentElement.dataset.mode || 'light').toLowerCase();
  const theme = (localStorage.getItem('studysync_theme') || document.documentElement.dataset.theme || 'blue').toLowerCase();
  return {
    mode: mode === 'dark' ? 'dark' : 'light',
    theme: ['blue', 'violet', 'pink', 'teal', 'orange'].includes(theme) ? theme : 'blue',
  };
}

function resetTheme() {
  try {
    localStorage.removeItem('studysync_mode');
    localStorage.removeItem('studysync_theme');
  } catch {}
  applyThemePrefs({ mode: 'light', theme: 'blue' });
  syncThemeUi();
  showToast('✓ Theme reset');
}

function reloadApp() {
  location.reload();
}

function applyThemePrefs(prefs) {
  document.documentElement.dataset.mode = prefs.mode;
  document.documentElement.dataset.theme = prefs.theme;
  try {
    localStorage.setItem('studysync_mode', prefs.mode);
    localStorage.setItem('studysync_theme', prefs.theme);
  } catch {}
}

function initThemeControls() {
  syncThemeUi();

  const darkToggle = document.getElementById('stDarkToggle');
  if (darkToggle) {
    darkToggle.addEventListener('change', () => {
      const prefs = getThemePrefs();
      prefs.mode = darkToggle.checked ? 'dark' : 'light';
      applyThemePrefs(prefs);
      syncThemeUi();
    });
  }

  const grid = document.getElementById('themeGrid');
  if (grid) {
    grid.addEventListener('click', (e) => {
      const btn = e.target && e.target.closest ? e.target.closest('.theme-chip') : null;
      if (!btn) return;
      const theme = (btn.dataset.theme || '').toLowerCase();
      const prefs = getThemePrefs();
      prefs.theme = theme;
      applyThemePrefs(prefs);
      syncThemeUi();
    });
  }
}

function syncThemeUi() {
  const prefs = getThemePrefs();
  const darkToggle = document.getElementById('stDarkToggle');
  if (darkToggle) darkToggle.checked = prefs.mode === 'dark';
  document.querySelectorAll('.theme-chip').forEach((el) => {
    el.classList.toggle('sel', (el.dataset.theme || '').toLowerCase() === prefs.theme);
  });
}

function toggleUserMenu(e) {
  e.stopPropagation();
  const userChip = e.currentTarget;
  if (!userChip) return;
  userChip.classList.toggle('open');
  const menu = document.getElementById('userMenu');
  if (menu) menu.setAttribute('aria-hidden', userChip.classList.contains('open') ? 'false' : 'true');
}

function closeUserMenu() {
  const userChip = document.querySelector('.user-chip');
  if (!userChip) return;
  userChip.classList.remove('open');
  const menu = document.getElementById('userMenu');
  if (menu) menu.setAttribute('aria-hidden', 'true');
}

document.addEventListener('click', () => {
  closeUserMenu();
  closeEmojiPicker();
  closeAttachmentPreview();
  closeDropdown();
});

document.addEventListener('keydown', (e) => {
  if (e.key !== 'Escape') return;
  closeEmojiPicker();
  closeUserMenu();
  closeAttachmentPreview();
  closeDropdown();
});

function getMyGroups() {
  return state.groups;
}

async function getGroupMembers(gid) {
  if (state.groupMembers.has(gid)) return state.groupMembers.get(gid);
  const members = await apiGet(`/api/group_members?group_id=${gid}`);
  state.groupMembers.set(gid, members);
  return members;
}

function renderGroupList(filter = '') {
  const groups = getMyGroups();
  const el = document.getElementById('groupList');
  const filtered = filter ? groups.filter((g) => g.name.toLowerCase().includes(filter.toLowerCase())) : groups;
  el.innerHTML = filtered
    .map(
      (g) => `
    <div class="group-item ${g.id === currentGroupId ? 'active' : ''}" onclick="selectGroup(${g.id})">
      <div class="group-dot" style="background:${g.color}"></div>
      <span class="group-name-text">${esc(g.name)}</span>
      <div class="online-dot"></div>
    </div>`,
    )
    .join('');
}

function filterGroups(q) {
  renderGroupList(q);
}

async function selectGroup(gid) {
  closeAttachmentPreview();
  currentGroupId = gid;
  renderGroupList();
  const grp = state.groups.find((g) => g.id === gid);
  if (!grp) return;

  const scheduleView = document.getElementById('view-schedule');
  if (scheduleView && scheduleView.classList.contains('active')) {
    const nav = document.querySelectorAll('.sidebar-nav .nav-item')[0];
    if (nav) switchView('messages', nav);
  }

  document.getElementById('chatDot').style.background = grp.color;
  document.getElementById('chatName').textContent = grp.name;
  document.getElementById('syncBadgeBtn').textContent = `📅 Schedule ${grp.name} Sync`;

  const members = await getGroupMembers(gid);
  document.getElementById('chatMeta').textContent = `${members.length} members active now`;

  const av = document.getElementById('headerAvatars');
  av.innerHTML =
    members
      .slice(0, 3)
      .map(
        (m) =>
          `<div class="avatar" style="background:${m.avatar_color};width:26px;height:26px;font-size:10px;margin-left:-6px;border:2px solid #fff">${m.name[0]}</div>`,
      )
      .join('') +
    (members.length > 3
      ? `<div class="avatar" style="background:var(--text3);width:26px;height:26px;font-size:10px;margin-left:-6px;border:2px solid #fff">+${members.length - 3}</div>`
      : '');

  await loadGroupKey(gid);
  await renderChat(gid);
  void loadAnnouncements(gid).catch(() => {});
}

async function createGroup() {
  const name = document.getElementById('ngName').value.trim();
  if (!name) {
    showToast('Please enter a group name');
    return;
  }
  const description = document.getElementById('ngDescription').value.trim();

  const checked = Array.from(document.querySelectorAll('#ngMembers input:checked')).map((i) => +i.value);
  await apiPost('/api/groups', { name, color: selectedGroupColor, members: checked, description });
  state.groups = await apiGet('/api/groups');
  renderGroupList();
  closeModal('modalNewGroup');
  const newest = state.groups[state.groups.length - 1];
  if (newest) await selectGroup(newest.id);
  showToast(`✓ Group "${name}" created!`);
}

async function getMessages(gid) {
  if (state.messages.has(gid)) return state.messages.get(gid);
  const msgs = await apiGet(`/api/messages?group_id=${gid}`);
  state.messages.set(gid, msgs);
  return msgs;
}

async function renderChat(gid) {
  const msgs = await getMessages(gid);
  const body = document.getElementById('chatBody');
  const groupKey = state.groupKeys.get(gid) || null;
  const displayMsgs = await Promise.all(msgs.map(async (m) => {
    if (m._plaintext !== undefined) return { ...m, content: m._plaintext };
    if (groupKey && isEncrypted(m.content)) {
      try {
        return { ...m, content: await decryptMessage(groupKey, m.content) };
      } catch {
        return { ...m, content: '[encrypted — key mismatch]' };
      }
    }
    return m;
  }));

  if (!displayMsgs.length) {
    body.innerHTML =
      '<div style="display:flex;flex-direction:column;align-items:center;justify-content:center;height:100%;color:var(--text3);gap:10px;"><span style="font-size:38px">💬</span><span style="font-size:14px;font-weight:500">No messages yet. Say hello!</span></div>';
    return;
  }

  function fmtBytes(bytes) {
    const n = Number(bytes || 0);
    if (!Number.isFinite(n) || n <= 0) return '';
    const units = ['B', 'KB', 'MB', 'GB'];
    let v = n;
    let i = 0;
    while (v >= 1024 && i < units.length - 1) {
      v /= 1024;
      i += 1;
    }
    const s = i === 0 ? String(Math.round(v)) : v.toFixed(v >= 10 ? 1 : 2);
    return `${s} ${units[i]}`;
  }

  function fileUrl(attId, download = false) {
    const base = `/api/messages/files/${attId}`;
    return download ? `${base}?download=1` : base;
  }

  function renderAttachment(att) {
    const mime = String(att?.mime || '');
    const name = esc(att?.filename || 'file');
    const size = fmtBytes(att?.size);
    const previewBtn = `<button class="att-action" type="button" data-att-preview="1" data-att-id="${att.id}" data-mime="${esc(mime)}" data-filename="${name}">Preview</button>`;
    const downloadBtn = `<button class="att-action" type="button" data-att-download="1" data-att-id="${att.id}" data-filename="${name}">Download</button>`;
    const actions = `<div class="att-actions">${previewBtn}${downloadBtn}</div>`;

    if (mime.startsWith('image/')) {
      return `<div class="att-card">
        <img class="att-img" src="${fileUrl(att.id)}" alt="${name}" data-att-preview="1" data-att-id="${att.id}" data-mime="${esc(mime)}" data-filename="${name}" loading="lazy" />
        <div class="att-file" style="margin-top:10px;">
          <div class="att-file-ico">🖼️</div>
          <div class="att-file-meta">
            <div class="att-file-name">${name}</div>
            <div class="att-file-sub">${esc(size)}</div>
          </div>
          ${actions}
        </div>
      </div>`;
    }
    if (mime.startsWith('video/')) {
      return `<div class="att-card">
        <video class="att-media" controls src="${fileUrl(att.id)}"></video>
        <div class="att-file" style="margin-top:10px;">
          <div class="att-file-ico">🎬</div>
          <div class="att-file-meta">
            <div class="att-file-name">${name}</div>
            <div class="att-file-sub">${esc(size)}</div>
          </div>
          ${actions}
        </div>
      </div>`;
    }
    if (mime.startsWith('audio/')) {
      return `<div class="att-card">
        <audio class="att-media" controls src="${fileUrl(att.id)}"></audio>
        <div class="att-file" style="margin-top:10px;">
          <div class="att-file-ico">🎵</div>
          <div class="att-file-meta">
            <div class="att-file-name">${name}</div>
            <div class="att-file-sub">${esc(size)}</div>
          </div>
          ${actions}
        </div>
      </div>`;
    }
    if (mime === 'application/pdf') {
      return `<div class="att-card">
        <iframe class="att-frame" src="${fileUrl(att.id)}" title="${name}"></iframe>
        <div class="att-file" style="margin-top:10px;">
          <div class="att-file-ico">📄</div>
          <div class="att-file-meta">
            <div class="att-file-name">${name}</div>
            <div class="att-file-sub">${esc(size)}</div>
          </div>
          ${actions}
        </div>
      </div>`;
    }

    return `<div class="att-card">
      <div class="att-file">
        <div class="att-file-ico">📎</div>
        <div class="att-file-meta">
          <div class="att-file-name">${name}</div>
          <div class="att-file-sub">${esc(size)}${mime ? ` · ${esc(mime)}` : ''}</div>
        </div>
        ${actions}
      </div>
    </div>`;
  }

  let html = '';
  let lastDate = null;
  displayMsgs.forEach((m) => {
    const dt = new Date(m.created_at);
    const dStr = dt.toDateString();
    const todayStr = new Date().toDateString();
    if (dStr !== lastDate) {
      const label = dStr === todayStr ? 'TODAY' : dt.toLocaleDateString('en-AU', { weekday: 'long', day: 'numeric', month: 'long' }).toUpperCase();
      html += `<div class="day-divider">${label}</div>`;
      lastDate = dStr;
    }
    const mine = m.user_id === ME;
    const t = dt.toLocaleTimeString('en-AU', { hour: '2-digit', minute: '2-digit' });
    const atts = Array.isArray(m.attachments) ? m.attachments : [];
    const bubble = m.content
      ? `<div class="msg-bubble">${esc(m.content)}</div>`
      : '';
    const attHtml = atts.length ? `<div class="msg-attachments">${atts.map((a) => renderAttachment(a)).join('')}</div>` : '';
    html += `<div class="msg-row ${mine ? 'mine' : ''}">
      <div class="msg-avatar-wrap"><div class="avatar" style="background:${m.ucolor};width:32px;height:32px;font-size:12px">${m.uname[0]}</div></div>
      <div class="msg-content">
        ${!mine ? `<div class="msg-name">${esc(m.uname)}</div>` : ''}
        ${bubble}
        ${attHtml}
        <div class="msg-meta">${t}${mine ? '<span class="msg-tick">✓✓</span>' : ''}</div>
      </div>
    </div>`;
  });

  if (msgs.length <= 5 && gid === 1) {
    html += `<div class="astro-card">
      <div class="astro-bot-icon">🤖<span class="astro-spark">✦</span></div>
      <div class="astro-title">Astro Concierge</div>
      <div class="astro-desc">I found a gap in everyone's calendar for a 30-minute review session.</div>
      <div class="astro-btns">
        <button class="btn-astro-sched" onclick="openNewMeetingModal()">SCHEDULE SYNC</button>
        <button class="btn-astro-ignore" onclick="this.closest('.astro-card').remove()">IGNORE</button>
      </div>
    </div>`;
  }

  body.innerHTML = html;
  body.scrollTop = body.scrollHeight;
}

const e2ee_enabled = true;
async function sendMsg() {
  closeEmojiPicker();
  const inp = document.getElementById('msgInput');
  const txt = inp.value.trim();
  if (!txt || !currentGroupId) return;
  inp.value = '';

  let content = txt;
  const groupKey = state.groupKeys.get(currentGroupId);
  if (e2ee_enabled && groupKey) {
    try {
      content = await encryptMessage(groupKey, txt);
    } catch (e) {
      console.warn('E2EE encryption failed, sending plaintext:', e);
    }
  }

  const msg = await apiPost('/api/messages', { group_id: currentGroupId, content });
  msg._plaintext = txt; // cache so renderChat skips re-decrypting
  const list = (state.messages.get(currentGroupId) || []).slice();
  list.push(msg);
  state.messages.set(currentGroupId, list);
  await renderChat(currentGroupId);
}

function msgKeyDown(e) {
  if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault();
    void sendMsg();
  }
}

function initChatTools() {
  const pop = document.getElementById('emojiPopover');
  pop?.addEventListener('click', (e) => e.stopPropagation());

  const fileInput = document.getElementById('chatFileInput');
  if (fileInput && !fileInput.dataset.bound) {
    fileInput.dataset.bound = '1';
    fileInput.addEventListener('change', (e) => {
      const files = Array.from(e.target.files || []);
      e.target.value = '';
      if (!files.length) return;
      void uploadChatFiles(files);
    });
  }

  const body = document.getElementById('chatBody');
  if (body && !body.dataset.previewBound) {
    body.dataset.previewBound = '1';
    body.addEventListener('click', (e) => {
      const tPrev = e.target && e.target.closest ? e.target.closest('[data-att-preview="1"]') : null;
      if (tPrev) {
        e.preventDefault();
        e.stopPropagation();
        const attId = Number(tPrev.dataset.attId || 0);
        if (!attId) return;
        openAttachmentPreview(attId, tPrev.dataset.mime || '', tPrev.dataset.filename || '');
        return;
      }
      const tDl = e.target && e.target.closest ? e.target.closest('[data-att-download="1"]') : null;
      if (tDl) {
        e.preventDefault();
        e.stopPropagation();
        const attId = Number(tDl.dataset.attId || 0);
        if (!attId) return;
        void downloadAttachment(attId, tDl.dataset.filename || '');
      }
    });
  }
}

function closeAttachmentPreview() {
  previewAttId = null;
  previewFilename = '';
  const panel = document.getElementById('previewPanel');
  const bodyEl = document.getElementById('previewBody');
  if (bodyEl) bodyEl.innerHTML = '';
  if (!panel) return;
  panel.classList.remove('open');
  panel.setAttribute('aria-hidden', 'true');
}

function openAttachmentPreview(attId, mime = '', filename = '') {
  if (!attId) return;
  const titleEl = document.getElementById('previewTitle');
  const bodyEl = document.getElementById('previewBody');
  const panel = document.getElementById('previewPanel');
  const dlBtn = document.getElementById('previewDownloadBtn');
  if (!titleEl || !bodyEl || !panel || !dlBtn) return;

  const base = `/api/messages/files/${attId}`;
  titleEl.textContent = filename ? `Preview · ${filename}` : 'Preview';
  previewAttId = attId;
  previewFilename = filename || '';
  dlBtn.disabled = false;

  const m = String(mime || '').toLowerCase();
  if (m.startsWith('image/')) {
    bodyEl.innerHTML = `<img class="preview-media" src="${base}" alt="${esc(filename || 'Image')}" />`;
  } else if (m.startsWith('video/')) {
    bodyEl.innerHTML = `<video class="preview-media" controls src="${base}"></video>`;
  } else if (m.startsWith('audio/')) {
    bodyEl.innerHTML = `<audio class="preview-media" controls src="${base}" style="background:transparent;"></audio>`;
  } else if (m === 'application/pdf') {
    bodyEl.innerHTML = `<iframe class="preview-frame" sandbox="" src="${base}" title="${esc(filename || 'PDF')}"></iframe>`;
  } else if (m.startsWith('text/') || m === 'application/json') {
    bodyEl.innerHTML = `<iframe class="preview-frame" sandbox="" src="${base}" title="${esc(filename || 'Text')}"></iframe>`;
  } else {
    bodyEl.innerHTML = `<div class="preview-note">This file type cannot be previewed here. Use <span class="mono-inline">Download</span>.</div>`;
  }

  panel.classList.add('open');
  panel.setAttribute('aria-hidden', 'false');
}

async function downloadAttachment(attId, filename = '') {
  const url = buildApiUrl(`/api/messages/files/${attId}?download=1`);
  const resp = await fetch(url, { method: 'GET', credentials: 'include' });
  if (resp.status === 401) {
    if (!location.pathname.startsWith('/login')) location.href = '/login';
    return;
  }
  if (!resp.ok) throw new Error(`Download failed (${resp.status})`);
  const blob = await resp.blob();
  const objectUrl = URL.createObjectURL(blob);
  try {
    const a = document.createElement('a');
    a.href = objectUrl;
    a.download = filename ? String(filename) : 'download';
    document.body.appendChild(a);
    a.click();
    a.remove();
  } finally {
    setTimeout(() => URL.revokeObjectURL(objectUrl), 1500);
  }
}

function downloadCurrentPreview() {
  if (!previewAttId) return;
  void downloadAttachment(previewAttId, previewFilename).catch((e) => showToast(e.message || 'Download failed'));
}

function closeEmojiPicker() {
  emojiOpen = false;
  const pop = document.getElementById('emojiPopover');
  if (!pop) return;
  pop.style.display = 'none';
  pop.setAttribute('aria-hidden', 'true');
}

function toggleEmojiPicker(e) {
  e?.stopPropagation?.();
  if (emojiOpen) {
    closeEmojiPicker();
    return;
  }
  const btn = document.getElementById('emojiBtn');
  const pop = document.getElementById('emojiPopover');
  if (!btn || !pop) return;

  if (!pop.dataset.ready) {
    const EMOJIS = [
      '😀',
      '😁',
      '😂',
      '😊',
      '😍',
      '😘',
      '😎',
      '🤔',
      '😅',
      '😴',
      '😭',
      '😡',
      '👍',
      '👎',
      '👏',
      '🙏',
      '🔥',
      '🎉',
      '✨',
      '💯',
      '✅',
      '❌',
      '⚠️',
      '📌',
      '📎',
      '📅',
      '🕒',
      '🧠',
      '🚀',
      '❤️',
      '🫶',
      '😺',
      '👀',
      '🤝',
      '👋',
      '🌟',
      '💡',
      '📣',
      '🔔',
      '🎯',
    ];
    pop.innerHTML = `<div class="emoji-grid">${EMOJIS.map((x) => `<button class="emoji-btn" type="button" data-emoji="${esc(x)}">${esc(x)}</button>`).join('')}</div>`;
    pop.addEventListener('click', (ev) => {
      const b = ev.target && ev.target.closest ? ev.target.closest('.emoji-btn') : null;
      if (!b) return;
      insertEmoji(b.dataset.emoji || '');
    });
    pop.dataset.ready = '1';
  }

  const wrap = document.querySelector('.chat-input-wrap');
  const wrapRect = (wrap && wrap.getBoundingClientRect) ? wrap.getBoundingClientRect() : btn.getBoundingClientRect();
  const btnRect = btn.getBoundingClientRect();
  const pad = 10;
  pop.style.display = 'block';
  pop.style.visibility = 'hidden';
  const pr = pop.getBoundingClientRect();
  const pw = pr.width || 264;
  const ph = pr.height || 0;
  const x = Math.max(pad, Math.min(window.innerWidth - pw - pad, btnRect.left + btnRect.width / 2 - pw / 2));
  const y = wrapRect.top - ph - 12;
  pop.style.left = `${Math.round(x)}px`;
  pop.style.top = `${Math.max(pad, y)}px`;
  pop.style.visibility = 'visible';
  pop.setAttribute('aria-hidden', 'false');
  emojiOpen = true;
}

function insertEmoji(emoji) {
  if (!emoji) return;
  const inp = document.getElementById('msgInput');
  if (!inp) return;
  const start = Number.isFinite(inp.selectionStart) ? inp.selectionStart : inp.value.length;
  const end = Number.isFinite(inp.selectionEnd) ? inp.selectionEnd : inp.value.length;
  const before = inp.value.slice(0, start);
  const after = inp.value.slice(end);
  inp.value = `${before}${emoji}${after}`;
  const next = start + emoji.length;
  try {
    inp.setSelectionRange(next, next);
  } catch {}
  inp.focus();
  closeEmojiPicker();
}

function triggerFilePicker() {
  closeEmojiPicker();
  if (!currentGroupId) {
    showToast('Select a group first');
    return;
  }
  document.getElementById('chatFileInput')?.click();
}

async function requestJsonRaw(path, init) {
  ensureHttpsOrRedirect();
  const resp = await fetch(buildApiUrl(path), { ...init, credentials: 'include' });
  let payload = null;
  try {
    payload = await resp.json();
  } catch {
    payload = null;
  }
  if (resp.status === 401) {
    if (!location.pathname.startsWith('/login')) location.href = '/login';
  }
  if (!resp.ok) {
    const msg = payload && payload.error ? payload.error : `Request failed (${resp.status})`;
    throw new Error(msg);
  }
  return payload;
}

async function uploadChatFiles(files) {
  if (!currentGroupId) return;
  const inp = document.getElementById('msgInput');
  const content = (inp?.value || '').trim();
  if (inp) inp.value = '';

  const fd = new FormData();
  fd.set('group_id', String(currentGroupId));
  if (content) fd.set('content', content);
  for (const f of files) fd.append('files', f, f.name);

  try {
    showToast(`⤴ Uploading ${files.length} file${files.length !== 1 ? 's' : ''}…`);
    const msg = await requestJsonRaw('/api/messages/upload', { method: 'POST', body: fd });
    const list = (state.messages.get(currentGroupId) || []).slice();
    list.push(msg);
    state.messages.set(currentGroupId, list);
    await renderChat(currentGroupId);
    showToast('✓ Upload complete');
  } catch (e) {
    if (inp && content) inp.value = content;
    showToast(e.message || 'Upload failed');
  }
}

function getCalEvents() {
  return state.calendar.events || [];
}

function formatDateKey(date) {
  if (!(date instanceof Date) || Number.isNaN(date.getTime())) return '';
  const year = String(date.getFullYear());
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
}

function parseCalendarDate(value) {
  if (!value) return null;
  const normalized = String(value).includes('T') ? String(value) : String(value).replace(' ', 'T');
  const dt = new Date(normalized);
  return Number.isNaN(dt.getTime()) ? null : dt;
}

function focusCalendarOnRelevantMonth({ force = false } = {}) {
  const events = getCalEvents()
    .map((event) => ({ event, start: parseCalendarDate(event.start_dt) }))
    .filter((entry) => entry.start)
    .sort((a, b) => a.start.getTime() - b.start.getTime());

  if (!events.length) return null;

  const currentMonthHasEvents = events.some(
    ({ start }) => start.getFullYear() === calYear && start.getMonth() === calMon,
  );
  if (!force && currentMonthHasEvents) return null;

  const today = new Date();
  today.setHours(0, 0, 0, 0);

  const target = events.find(({ start }) => start.getTime() >= today.getTime())?.start || events[events.length - 1].start;
  if (!target) return null;

  calYear = target.getFullYear();
  calMon = target.getMonth();
  return target;
}

function renderCalendar() {
  const MONTHS = ['JAN', 'FEB', 'MAR', 'APR', 'MAY', 'JUN', 'JUL', 'AUG', 'SEP', 'OCT', 'NOV', 'DEC'];
  document.getElementById('calMonthLabel').textContent = `${MONTHS[calMon]} ${calYear}`;

  const events = getCalEvents();
  const today = new Date();
  const firstDay = new Date(calYear, calMon, 1);
  let startDow = firstDay.getDay();
  startDow = startDow === 0 ? 6 : startDow - 1;
  const daysInMonth = new Date(calYear, calMon + 1, 0).getDate();
  const prevMonDays = new Date(calYear, calMon, 0).getDate();
  const totalCells = Math.ceil((startDow + daysInMonth) / 7) * 7;

  const DAYS = ['MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT', 'SUN'];
  let html = `<div class="cal-days-hdr">${DAYS.map((d) => `<div class="cal-day-lbl">${d}</div>`).join('')}</div><div class="cal-weeks">`;

  for (let i = 0; i < totalCells; i++) {
    if (i % 7 === 0) html += '<div class="cal-week">';
    const offset = i - startDow + 1;
    let dispDay;
    let isThisMonth = false;
    let cellDate;
    if (offset < 1) {
      dispDay = prevMonDays + offset;
      cellDate = new Date(calYear, calMon - 1, dispDay);
    } else if (offset > daysInMonth) {
      dispDay = offset - daysInMonth;
      cellDate = new Date(calYear, calMon + 1, dispDay);
    } else {
      dispDay = offset;
      isThisMonth = true;
      cellDate = new Date(calYear, calMon, dispDay);
    }

    const isToday = cellDate.toDateString() === today.toDateString();
    const dateStr = formatDateKey(cellDate);
    const dayEvs = events.filter((e) => e.start_dt && e.start_dt.startsWith(dateStr));

    html += `<div class="cal-cell ${!isThisMonth ? 'other-month' : ''} ${isToday ? 'today' : ''}" onclick="openDailySchedule('${dateStr}', ${isThisMonth})">
      <div class="cal-date-num">${dispDay}</div>
      ${dayEvs
        .slice(0, 2)
        .map(
          (ev) =>
            `<div class="cal-event" style="background:${ev.source === 'allocate' ? 'var(--accent)' : 'var(--primary)'}" title="${esc(ev.title)}${
              ev.location ? ' @ ' + ev.location : ''
            }">${esc(ev.title)}</div>`,
        )
        .join('')}
      ${dayEvs.length > 2 ? `<div style="font-size:10px;color:var(--text3)">+${dayEvs.length - 2} more</div>` : ''}
    </div>`;
    if ((i + 1) % 7 === 0) html += '</div>';
  }
  html += '</div>';
  document.getElementById('calGrid').innerHTML = html;
}

function openDailySchedule(dateStr, isCurrentMonth) {
  if (!isCurrentMonth) return; // Don't open for other months
  
  const date = new Date(dateStr + 'T00:00:00');
  const formattedDate = date.toLocaleDateString('en-AU', {
    weekday: 'long',
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  });

  document.getElementById('dailyScheduleDate').textContent = formattedDate;

  const events = getCalEvents();
  const dayAllocateEvents = events.filter((e) => e.start_dt && e.start_dt.startsWith(dateStr));
  dayAllocateEvents.sort((a, b) => new Date(a.start_dt).getTime() - new Date(b.start_dt).getTime());

  // Meeting polls are stored by weekday+time, so we map the clicked date -> weekday.
  const weekday = date.toLocaleDateString('en-US', { weekday: 'long' }); // "Monday".."Sunday"
  const meetings = state.meetings || [];
  const dayMeetingSlots = [];
  for (const mtg of meetings) {
    const slots = mtg.slots || [];
    for (const s of slots) {
      if (s.day !== weekday) continue;
      const blocked = isSlotBlocked(s.day, s.time);
      dayMeetingSlots.push({ mtg, slot: s, blocked });
    }
  }

  // Sort meeting slots by time so the combined table reads top-to-bottom.
  dayMeetingSlots.sort((a, b) => {
    const [ha, ma] = String(a.slot.time || '0:0').split(':').map(Number);
    const [hb, mb] = String(b.slot.time || '0:0').split(':').map(Number);
    return (ha * 60 + ma) - (hb * 60 + mb);
  });

  const tbody = document.getElementById('dailyScheduleBody');
  const allRows = [];

  for (const event of dayAllocateEvents) {
    const startTime = new Date(event.start_dt);
    const endTime = new Date(event.end_dt || event.start_dt);
    const timeRange = `${startTime.toLocaleTimeString('en-AU', { hour: '2-digit', minute: '2-digit' })} - ${endTime.toLocaleTimeString('en-AU', { hour: '2-digit', minute: '2-digit' })}`;
    const sourceClass = event.source || 'meeting';
    allRows.push({
      ts: startTime.getTime(),
      html: `
        <tr>
          <td class="event-time">${timeRange}</td>
          <td>
            <div class="event-title">${esc(event.title)}</div>
            ${event.location ? `<div class="event-location">📍 ${esc(event.location)}</div>` : ''}
          </td>
          <td>${event.location ? esc(event.location) : '-'}</td>
          <td><span class="event-source ${sourceClass}">${esc(sourceClass)}</span></td>
        </tr>
      `,
    });
  }

  for (const item of dayMeetingSlots) {
    const s = item.slot;
    const mtg = item.mtg;
    const timeStart = s.time ? String(s.time) : '-';
    const voteCount = s.vote_count || 0;
    const myVote = s.my_vote;

    let statusText = 'No vote yet';
    if (!item.blocked) {
      statusText = myVote === 1 ? 'Available' : myVote === 0 ? 'Unavailable' : 'No vote yet';
    } else {
      statusText = 'Class conflict';
    }

    // Convert "HH:MM" -> timestamp for correct ordering with allocate events.
    const [h, m] = String(s.time || '0:0').split(':').map(Number);
    const ts = new Date(date.getFullYear(), date.getMonth(), date.getDate(), h || 0, m || 0).getTime();

    allRows.push({
      ts,
      html: `
        <tr>
          <td class="event-time">${esc(timeStart)}</td>
          <td>
            <div class="event-title">${esc(mtg.title)}</div>
            <div style="font-size:11px;color:var(--text3);margin-top:2px;">
              ${esc(voteCount)} vote${voteCount !== 1 ? 's' : ''} · ${esc(statusText)}
              ${item.blocked ? ' · 🚫 Blocked' : ''}
            </div>
          </td>
          <td>${mtg.gname ? esc(mtg.gname) : '-'}</td>
          <td><span class="event-source meeting">${item.blocked ? 'Poll (blocked)' : 'Poll'}</span></td>
        </tr>
      `,
    });
  }

  allRows.sort((a, b) => a.ts - b.ts);

  if (!allRows.length) {
    tbody.innerHTML = '<tr><td colspan="4" class="no-events">No events or poll slots scheduled for this day</td></tr>';
  } else {
    tbody.innerHTML = allRows.map((r) => r.html).join('');
  }

  openModal('modalDailySchedule');
}

async function openGroupInformationModal() {
  if (!currentGroupId) {
    showToast('Select a group first');
    return;
  }

  const grp = state.groups.find((g) => g.id === currentGroupId);
  const groupName = grp?.name || 'Unknown Group';

  // Set modal title
  document.getElementById('groupInfoTitle').textContent = `${groupName} — Info`;

  // Show loading state
  const bodyEl = document.getElementById('groupInfoBody');
  bodyEl.innerHTML = '<div style="text-align:center;color:var(--text3);padding:20px;">Loading…</div>';
  openModal('modalGroupInformation');

  try {
    const members = await getGroupMembers(currentGroupId);

    const description = grp?.description?.trim();
    const descHtml = description
      ? `<div style="font-size:14px;line-height:1.6;color:var(--text1);white-space:pre-wrap;">${esc(description)}</div>`
      : `<div style="font-size:13px;color:var(--text3);font-style:italic;">No description set.</div>`;

    let createdAtHtml = '';
    if (grp?.created_at) {
      const s = String(grp.created_at).includes('T') ? grp.created_at : grp.created_at.replace(' ', 'T');
      const d = new Date(s);
      if (!Number.isNaN(d.getTime())) {
        const formatted = d.toLocaleDateString('en-AU', { year: 'numeric', month: 'long', day: 'numeric' });
        createdAtHtml = `
          <div style="height:16px;"></div>
          <div style="font-size:10.5px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--text3);margin-bottom:8px;">Created</div>
          <div style="font-size:14px;color:var(--text1);">${esc(formatted)}</div>
        `;
      }
    }

    bodyEl.innerHTML = `
      <div style="display:flex;align-items:center;gap:12px;margin-bottom:16px;">
        <div style="width:40px;height:40px;border-radius:50%;background:${grp?.color || 'var(--primary)'};flex-shrink:0;"></div>
        <div>
          <div style="font-size:16px;font-weight:600;">${esc(groupName)}</div>
          <div style="font-size:12px;color:var(--text3);">${members.length} member${members.length !== 1 ? 's' : ''}</div>
        </div>
      </div>
      <div style="font-size:10.5px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--text3);margin-bottom:8px;">Description</div>
      ${descHtml}
      ${createdAtHtml}
    `;
  } catch (err) {
    bodyEl.innerHTML = `<div style="text-align:center;color:var(--pink);padding:20px;">Failed to load info: ${esc(err.message || 'Unknown error')}</div>`;
  }
}

function openGroupMembersModal() {
  if (!currentGroupId) {
    showToast('Select a group first');
    return;
  }
  
  const membersList = document.getElementById('membersList');
  membersList.innerHTML = '<div style="text-align:center;color:var(--text3);padding:20px;">Loading members...</div>';
  openModal('modalGroupMembers');
  
  // Load and display members
  getGroupMembers(currentGroupId).then(members => {
    const groupName = state.groups.find(g => g.id === currentGroupId)?.name || 'Unknown Group';
    document.querySelector('#modalGroupMembers .modal-title').textContent = `${groupName} - Members`;
    
    if (!members.length) {
      membersList.innerHTML = '<div style="text-align:center;color:var(--text3);padding:20px;">No members found</div>';
      return;
    }
    
    membersList.innerHTML = members.map(member => `
      <div class="member-item">
        <div class="member-avatar" style="background: ${member.avatar_color}">
          ${member.name[0]}
        </div>
        <div class="member-info">
          <div class="member-name">${esc(member.name)}</div>
          <div class="member-role">@${esc(member.username)}</div>
        </div>
        <div class="member-status" title="Online"></div>
      </div>
    `).join('');
  }).catch(err => {
    membersList.innerHTML = `<div style="text-align:center;color:var(--pink);padding:20px;">Failed to load members: ${esc(err.message || 'Unknown error')}</div>`;
  });
}

// Dropdown menu functionality
let currentDropdown = null;

function closeDropdown() {
  if (currentDropdown) {
    currentDropdown.remove();
    currentDropdown = null;
  }
}

function createDropdownMenu(items, x, y) {
  closeDropdown();
  
  const menu = document.createElement('div');
  menu.className = 'dropdown-menu';
  menu.style.left = `${x}px`;
  menu.style.top = `${y}px`;
  
  menu.innerHTML = items.map(item => {
    if (item === 'separator') {
      return '<div class="dropdown-separator"></div>';
    }
    return `<button class="dropdown-item ${item.danger ? 'danger' : ''}" onclick="${item.onclick}">${esc(item.label)}</button>`;
  }).join('');
  
  document.body.appendChild(menu);
  currentDropdown = menu;
  
  // Position menu within viewport
  const rect = menu.getBoundingClientRect();
  if (rect.right > window.innerWidth) {
    menu.style.left = `${x - (rect.right - window.innerWidth) - 10}px`;
  }
  if (rect.bottom > window.innerHeight) {
    menu.style.top = `${y - (rect.bottom - window.innerHeight) - 10}px`;
  }
}

function openChatDropdown(e) {
  e.preventDefault();
  e.stopPropagation();
  
  const rect = e.currentTarget.getBoundingClientRect();
  const items = [
    { label: 'View Members', onclick: 'openGroupMembersModal(); closeDropdown();' },
    { label: 'Group Info', onclick: 'openGroupInformationModal(); closeDropdown();' },
    'separator',
    { label: 'Leave Group', onclick: 'leaveCurrentGroup(); closeDropdown();', danger: true }
  ];
  
  createDropdownMenu(items, rect.right - 180, rect.bottom + 5);
}

async function leaveCurrentGroup() {
  if (!currentGroupId) {
    showToast('No group selected');
    return;
  }
  
  const group = state.groups.find(g => g.id === currentGroupId);
  const groupName = group ? group.name : 'this group';
  
  const confirmed = confirm(`Are you sure you want to leave "${groupName}"? You will no longer have access to messages and files in this group.`);
  if (!confirmed) return;
  
  try {
    await apiDelete(`/api/groups/${currentGroupId}/leave`);
    
    // Remove group from state
    state.groups = state.groups.filter(g => g.id !== currentGroupId);
    state.groupMembers.delete(currentGroupId);
    state.messages.delete(currentGroupId);
    state.announcements.delete(currentGroupId);
    state.announcementsUnread.delete(currentGroupId);
    
    // Clear current group
    currentGroupId = null;
    
    // Update UI
    renderGroupList();
    
    // Reset chat view
    document.getElementById('chatName').textContent = 'Select a group';
    document.getElementById('chatMeta').textContent = '';
    document.getElementById('chatDot').style.background = 'var(--primary)';
    document.getElementById('headerAvatars').innerHTML = '';
    document.getElementById('chatBody').innerHTML = `
      <div style="display:flex;flex-direction:column;align-items:center;justify-content:center;height:100%;color:var(--text3);gap:10px;">
        <span style="font-size:38px">💬</span>
        <span style="font-size:14px;font-weight:500;">Select a group to start chatting</span>
      </div>
    `;
    
    // Select next available group if any
    const remainingGroups = getMyGroups();
    if (remainingGroups.length > 0) {
      await selectGroup(remainingGroups[0].id);
    }
    
    showToast(`✓ You left "${groupName}"`);
  } catch (error) {
    showToast(`Failed to leave group: ${error.message || 'Unknown error'}`);
  }
}

function openScheduleDropdown(e) {
  e.preventDefault();
  e.stopPropagation();
  
  const rect = e.currentTarget.getBoundingClientRect();
  const items = [
    { label: 'Today\'s Schedule', onclick: 'showTodaySchedule(); closeDropdown();' },
    { label: 'Sync Calendar', onclick: 'showToast("Sync calendar coming soon"); closeDropdown();' },
    { label: 'Export Calendar', onclick: 'showToast("Export coming soon"); closeDropdown();' },
    'separator',
    { label: 'Calendar Settings', onclick: 'showToast("Settings coming soon"); closeDropdown();' }
  ];
  
  createDropdownMenu(items, rect.right - 180, rect.bottom + 5);
}

function showTodaySchedule() {
  const today = formatDateKey(new Date());
  openDailySchedule(today, true);
}

function calPrev() {
  calMon--;
  if (calMon < 0) {
    calMon = 11;
    calYear--;
  }
  renderCalendar();
}

function calNext() {
  calMon++;
  if (calMon > 11) {
    calMon = 0;
    calYear++;
  }
  renderCalendar();
}

async function syncAllocate() {
  const url = document.getElementById('allocateUrlInput').value.trim();
  if (!url) {
    showToast('Please enter your Allocate iCal URL or paste raw iCal text');
    return;
  }

  const statusEl = document.getElementById('allocStatus');
  statusEl.className = 'alloc-status';
  statusEl.textContent = '⟳ Syncing…';

  if (url.startsWith('BEGIN:VCALENDAR') || url.startsWith('BEGIN:VEVENT')) {
    await importIcalText(url);
    return;
  }

  try {
    const res = await apiPost('/api/sync_allocate', { url });
    statusEl.className = 'alloc-status alloc-ok';
    statusEl.textContent = `✓ Synced ${res.imported} class${res.imported !== 1 ? 'es' : ''}`;
    state.calendar = await apiGet('/api/calendar');
    state.meetings = await apiGet('/api/meetings');
    focusCalendarOnRelevantMonth({ force: true });
    renderCalendar();
    renderVotingList();
    showToast(`✓ Imported ${res.imported} calendar events`);
  } catch (e) {
    statusEl.className = 'alloc-status alloc-err';
    statusEl.textContent = `✗ ${e.message}`;
    showToast(e.message);
  }
}

async function syncFromPaste() {
  const val = document.getElementById('icalPaste').value.trim();
  if (!val) {
    showToast('Please paste an iCal link or text first');
    return;
  }

  const statusEl = document.getElementById('allocStatus');
  statusEl.className = 'alloc-status';
  statusEl.textContent = '⟳ Syncing…';

  try {
    if (val.startsWith('BEGIN:VCALENDAR') || val.startsWith('BEGIN:VEVENT')) {
      await importIcalText(val);
    } else {
      const res = await apiPost('/api/sync_allocate', { url: val });
      statusEl.className = 'alloc-status alloc-ok';
      statusEl.textContent = `✓ Synced ${res.imported} class${res.imported !== 1 ? 'es' : ''}`;
      state.calendar = await apiGet('/api/calendar');
      state.meetings = await apiGet('/api/meetings');
      focusCalendarOnRelevantMonth({ force: true });
      renderCalendar();
      renderVotingList();
      showToast(`✓ Imported ${res.imported} calendar events`);
    }
    document.getElementById('icalPaste').value = '';
  } catch (e) {
    statusEl.className = 'alloc-status alloc-err';
    statusEl.textContent = `✗ ${e.message}`;
    showToast(e.message);
  }
}

async function importIcalText(text) {
  const res = await apiPost('/api/sync_allocate', { ical_text: text });
  const statusEl = document.getElementById('allocStatus');
  statusEl.className = 'alloc-status alloc-ok';
  statusEl.textContent = `✓ Synced ${res.imported} class${res.imported !== 1 ? 'es' : ''}`;
  state.calendar = await apiGet('/api/calendar');
  state.meetings = await apiGet('/api/meetings');
  focusCalendarOnRelevantMonth({ force: true });
  renderCalendar();
  renderVotingList();
  showToast(`✓ Imported ${res.imported} calendar events`);
}

function loadSavedAllocateUrl() {
  if (state.calendar.allocate_url) {
    document.getElementById('allocateUrlInput').value = state.calendar.allocate_url;
    document.getElementById('allocStatus').className = 'alloc-status alloc-ok';
    document.getElementById('allocStatus').textContent = '✓ Allocate URL saved';
  }
}

function isSlotBlocked(day, time) {
  const dayMap = { Sunday: 0, Monday: 1, Tuesday: 2, Wednesday: 3, Thursday: 4, Friday: 5, Saturday: 6 };
  const wd = dayMap[day];
  if (wd === undefined) return false;
  const [h, m] = time.split(':').map(Number);
  const slotMins = h * 60 + m;

  const events = (state.calendar.events || []).filter((e) => e.source === 'allocate');
  for (const ev of events) {
    if (!ev.start_dt) continue;
    const st = new Date(ev.start_dt);
    const en = new Date(ev.end_dt || ev.start_dt);
    if (st.getDay() !== wd) continue;
    const stM = st.getHours() * 60 + st.getMinutes();
    const enM = en.getHours() * 60 + en.getMinutes();
    if (slotMins >= stM && slotMins < enM) return true;
  }
  return false;
}

function renderVotingList() {
  const meetings = state.meetings || [];
  const el = document.getElementById('votingList');
  const pending = meetings.filter((m) => (m.status || 'pending') === 'pending');
  document.getElementById('pendingBadge').textContent = `${pending.length} PENDING`;

  const visibleMeetings = meetings.filter((m) => (m.status || 'pending') !== 'completed');
  if (!visibleMeetings.length) {
    el.innerHTML = '<div style="font-size:12.5px;color:var(--text3);text-align:center;padding:16px 0">No polls yet</div>';
    return;
  }

  el.innerHTML = visibleMeetings
    .map((mtg) => {
      const slots = mtg.slots || [];
      if (!slots.length) {
        return `<div class="voting-card">
        <div style="display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:2px;">
          <div class="voting-card-title">${esc(mtg.title)}</div>
          <button class="btn-mtg-complete" type="button" onclick="completeMeeting(${mtg.id})">✓ Complete</button>
        </div>
        <div class="voting-card-sub" style="color:var(--text3);font-style:italic">No time slots proposed yet…</div>
      </div>`;
      }
      const totalMembers = Math.max(mtg.member_count || 1, 1);
      return `<div class="voting-card">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:2px;">
        <div class="voting-card-title">${esc(mtg.title)}</div>
        <button class="btn-mtg-complete" type="button" onclick="completeMeeting(${mtg.id})">✓ Complete</button>
      </div>
      <div class="voting-card-sub">${esc(mtg.gname)}</div>
      ${slots
        .map((s) => {
          const vCnt = s.vote_count || 0;
          const blocked = isSlotBlocked(s.day, s.time);
          const myVote = s.my_vote;
          const pct = Math.min(100, Math.round((vCnt / totalMembers) * 100));
          const nextVote = blocked ? 0 : myVote === null || myVote === undefined ? 1 : myVote === 1 ? 0 : 1;
          return `<div class="voting-slot-row" style="flex-direction:column;gap:6px;align-items:stretch;margin-bottom:8px;padding-bottom:8px;border-bottom:1px solid var(--border);">
          <div style="display:flex;align-items:center;justify-content:space-between;">
            <div class="voting-slot-left">
              <div class="voting-slot-time">${s.day}, ${s.time}</div>
              ${blocked ? '<div class="blocked-chip">🚫 Class conflict</div>' : ''}
            </div>
            <div style="display:flex;align-items:center;gap:6px;">
              <span style="font-size:11px;font-weight:600;color:var(--text3)">${vCnt} vote${vCnt !== 1 ? 's' : ''}</span>
              <span class="match-pct ${pct >= 70 ? 'match-high' : 'match-low'}">${pct}%</span>
            </div>
          </div>
          <div style="height:4px;background:var(--border);border-radius:2px;overflow:hidden;">
            <div style="height:100%;width:${pct}%;background:${pct >= 70 ? 'var(--teal)' : 'var(--orange)'};border-radius:2px;transition:width .3s;"></div>
          </div>
          <button class="btn-vote ${myVote ? 'voted' : ''} ${blocked ? 'blocked-vote' : ''}"
            onclick="castVoteSlot(${s.id}, ${nextVote}, ${mtg.id})"
            style="${blocked ? 'background:var(--pink);opacity:0.7;' : ''}">
            ${
              blocked
                ? '🚫 Blocked'
                : myVote === 1
                  ? '✓ Available (click to undo)'
                  : myVote === 0
                    ? '✗ Unavailable (click to change)'
                    : '✓ Mark Available'
            }
          </button>
        </div>`;
        })
        .join('')}
    </div>`;
    })
    .join('');
}

async function castVoteSlot(slotId, available) {
  await apiPost('/api/vote', { slot_id: slotId, available });
  state.meetings = await apiGet('/api/meetings');
  renderVotingList();
  showToast(available ? '✓ Marked as available!' : '✗ Marked as unavailable');
}

async function completeMeeting(meetingId) {
  const ok = confirm('Mark this meeting as completed? It will be hidden from the sidebar.');
  if (!ok) return;
  await apiPost(`/api/meetings/${meetingId}/complete`, {});
  state.meetings = await apiGet('/api/meetings');
  renderVotingList();
  showToast('✓ Meeting marked as completed');
}

function openNewMeetingModal() {
  const sel = document.getElementById('mtgGroupSel');
  const groups = getMyGroups();
  if (!groups.length) {
    showToast('Create a group first');
    openNewGroupModal();
    return;
  }
  sel.innerHTML = groups.map((g) => `<option value="${g.id}">${esc(g.name)}</option>`).join('');
  if (currentGroupId) sel.value = currentGroupId;
  document.getElementById('mtgTitle').value = '';
  document.getElementById('mtgDesc').value = '';
  document.getElementById('slotContainer').innerHTML = '';
  document.getElementById('blockedWarn').style.display = 'none';
  addSlot();
  addSlot();
  openModal('modalNewMeeting');
}

function addSlot() {
  const DAYS = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'];
  const d = document.createElement('div');
  d.className = 'slot-row';
  d.innerHTML = `
    <select>${DAYS.map((day) => `<option>${day}</option>`).join('')}</select>
    <input type="time" value="10:00">
    <button class="btn-rm-slot" onclick="this.parentNode.remove();checkBlocked()">✕</button>`;
  d.querySelector('select').addEventListener('change', checkBlocked);
  d.querySelector('input').addEventListener('change', checkBlocked);
  document.getElementById('slotContainer').appendChild(d);
}

function checkBlocked() {
  const rows = document.querySelectorAll('#slotContainer .slot-row');
  let any = false;
  rows.forEach((r) => {
    if (isSlotBlocked(r.querySelector('select').value, r.querySelector('input').value)) any = true;
  });
  document.getElementById('blockedWarn').style.display = any ? '' : 'none';
}

async function createMeeting() {
  const title = document.getElementById('mtgTitle').value.trim();
  if (!title) {
    showToast('Please enter a meeting title');
    return;
  }
  const desc = document.getElementById('mtgDesc').value.trim();
  const gid = +document.getElementById('mtgGroupSel').value;
  if (!Number.isFinite(gid) || gid <= 0) {
    showToast('Select a group first');
    return;
  }
  const rows = document.querySelectorAll('#slotContainer .slot-row');
  if (!rows.length) {
    showToast('Add at least one time slot');
    return;
  }

  const slots = Array.from(rows).map((r) => ({
    day: r.querySelector('select').value,
    time: r.querySelector('input').value,
  }));

  try {
    await apiPost('/api/meetings', { group_id: gid, title, description: desc, slots });
    closeModal('modalNewMeeting');
    state.meetings = await apiGet('/api/meetings');
    state.messages.delete(gid);
    if (currentGroupId === gid) await renderChat(gid);
    renderVotingList();
    showToast('✓ Meeting poll created!');
  } catch (e) {
    showToast(e.message || 'Failed to create meeting poll');
  }
}

function openNewGroupModal() {
  document.getElementById('ngName').value = '';
  document.getElementById('ngDescription').value = '';
  document.getElementById('ngMembers').innerHTML = getAllUsers()
    .filter((u) => u.id !== ME)
    .map(
      (u) => `
    <label class="member-row">
      <input type="checkbox" value="${u.id}">
      <div class="avatar" style="background:${u.avatar_color};width:26px;height:26px;font-size:10px">${u.name[0]}</div>
      <span>${esc(u.name)}</span>
    </label>`,
    )
    .join('');
  openModal('modalNewGroup');
}

function pickColor(el) {
  document.querySelectorAll('#ngSwatches .cswatch').forEach((s) => s.classList.remove('sel'));
  el.classList.add('sel');
  selectedGroupColor = el.dataset.c;
}

function switchView(name, navEl) {
  document.querySelectorAll('.view').forEach((v) => v.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach((n) => n.classList.remove('active'));
  document.getElementById(`view-${name}`).classList.add('active');
  navEl.classList.add('active');
  if (name !== 'messages') closeAttachmentPreview();
  if (name === 'schedule') {
    renderCalendar();
    renderVotingList();
  }
}

Object.assign(window, {
  openModal,
  closeModal,
  showToast,
  esc,
  filterGroups,
  selectGroup,
  openNewGroupModal,
  createGroup,
  pickColor,
  sendMsg,
  msgKeyDown,
  toggleEmojiPicker,
  triggerFilePicker,
  openAttachmentPreview,
  closeAttachmentPreview,
  downloadCurrentPreview,
  calPrev,
  calNext,
  syncAllocate,
  syncFromPaste,
  openNewMeetingModal,
  openDailySchedule,
  openGroupMembersModal,
  openGroupInformationModal,
  openChatDropdown,
  openScheduleDropdown,
  closeDropdown,
  showTodaySchedule,
  leaveCurrentGroup,
  addSlot,
  checkBlocked,
  createMeeting,
  castVoteSlot,
  completeMeeting,
  openSettingsModal,
  openHelpModal,
  openUserProfile,
  openAnnouncementsModal,
  publishAnnouncement,
  deleteAnnouncement,
  startAnnouncementEdit,
  cancelAnnouncementEdit,
  markAnnouncementRead,
  markAllAnnouncementsRead,
  logout,
  resetTheme,
  reloadApp,
  toggleUserMenu,
  switchView,
});

boot();
