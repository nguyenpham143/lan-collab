// LanCollab browser UI. Plain JavaScript: it talks only to the local Go bridge
// (JSON API + Server-Sent Events); all networking happens in the Go client.
// All content is built with textContent and DOM calls, never innerHTML.
"use strict";

const BROADCAST = 65535;
const MAX_WINDOW = 64;
const MAX_FILE_BYTES = 64 * 1024 * 1024;
const IMAGE_EXT = /\.(png|jpe?g|gif|webp|bmp)$/i;

const state = {
  phase: "DISCONNECTED",
  userId: 0,
  username: "",
  peers: [],
  convs: new Map(),      // key -> { key, peerId, title, messages: [], unread }
  active: "all",
  transfers: new Map(),  // transfer key -> progress (side panel)
  files: new Map(),      // transfer key -> file message shown in a conversation
  previews: new Map(),   // transfer key -> object URL of a picture this user is sending
  seq: 0,
};

const $ = (id) => document.getElementById(id);

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function transferKey(t) {
  return `${t.direction}:${t.peer_id}:${t.stream_id}`;
}

function baseName(path) {
  return String(path || "").split(/[\\/]/).pop();
}

function downloadUrl(savedPath, inline) {
  return `/api/download?${inline ? "inline=1&" : ""}name=${encodeURIComponent(baseName(savedPath))}`;
}

// ---------------------------------------------------------------------------
// API
// ---------------------------------------------------------------------------

async function api(path, body) {
  const res = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {}),
  });
  let data = {};
  try { data = await res.json(); } catch (_) { /* empty body */ }
  if (!res.ok || data.ok === false) {
    throw new Error(data.error || `Request failed (${res.status})`);
  }
  return data;
}

// ---------------------------------------------------------------------------
// Conversations
// ---------------------------------------------------------------------------

function resetConversations() {
  state.convs = new Map();
  state.convs.set("all", { key: "all", peerId: BROADCAST, title: "Everyone", messages: [], unread: 0 });
  state.active = "all";
  state.files = new Map();
}

function peerName(id, fallback) {
  const p = state.peers.find((x) => x.id === id);
  return p ? p.name : (fallback || `User #${id}`);
}

function conversationFor(peerId, title) {
  const key = `u${peerId}`;
  if (!state.convs.has(key)) {
    state.convs.set(key, { key, peerId, title: title || peerName(peerId), messages: [], unread: 0 });
  }
  return state.convs.get(key);
}

function currentDirectConversation() {
  const conv = state.convs.get(state.active);
  return conv && conv.peerId !== BROADCAST ? conv : null;
}

function openConversation(key) {
  if (!state.convs.has(key)) return;
  state.active = key;
  state.convs.get(key).unread = 0;
  renderTabs();
  renderMessages();
  updateComposer();
  $("message").focus();
}

// Keeps a conversation ordered by time. A file's time is when its transfer started.
function insertMessage(conv, msg) {
  msg.id = ++state.seq;
  const list = conv.messages;
  list.push(msg);
  for (let i = list.length - 1; i > 0 && list[i - 1].ts > list[i].ts; i -= 1) {
    [list[i - 1], list[i]] = [list[i], list[i - 1]];
  }
}

function isNearBottom(list) {
  return list.scrollHeight - list.scrollTop - list.clientHeight < 60;
}

// Shows a message that was just inserted: appended in place when it is the newest one,
// otherwise the whole conversation is redrawn.
function showMessage(conv, msg) {
  if (conv.key !== state.active) return;
  const list = $("messages");
  const isLast = conv.messages[conv.messages.length - 1] === msg;
  if (!isLast || conv.messages.length === 1) {
    renderMessages();
    return;
  }
  const stick = isNearBottom(list) || msg.self;
  list.append(buildMessageNode(msg));
  if (stick) list.scrollTop = list.scrollHeight;
}

function addChat(ev) {
  const direct = Boolean(ev.direct);
  let conv;
  if (!direct) {
    conv = state.convs.get("all");
  } else {
    const otherId = ev.self ? ev.target_id : ev.from_id;
    conv = conversationFor(otherId, ev.self ? peerName(otherId) : ev.from);
  }
  const msg = {
    type: "chat",
    self: Boolean(ev.self),
    from: ev.self ? "You" : (ev.from || peerName(ev.from_id)),
    text: ev.text || "",
    ts: ev.ts || Date.now(),
  };
  insertMessage(conv, msg);
  if (conv.key !== state.active && !ev.self) conv.unread += 1;
  renderTabs();
  showMessage(conv, msg);
}

// Every file_progress event creates or updates one message in the conversation with the
// other person, so pictures and files appear inline like chat messages.
function upsertFile(t) {
  const key = transferKey(t);
  const conv = conversationFor(t.peer_id, t.peer_name || peerName(t.peer_id));
  let msg = state.files.get(key);
  if (!msg) {
    msg = {
      type: "file",
      key,
      t,
      self: t.direction === "send",
      ts: t.started_at || Date.now(),
      preview: state.previews.get(key) || "",
      node: null,
      refs: {},
    };
    state.files.set(key, msg);
    insertMessage(conv, msg);
    if (conv.key !== state.active && !msg.self) conv.unread += 1;
    renderTabs();
    showMessage(conv, msg);
    return;
  }
  const stageChanged = msg.t.stage !== t.stage;
  msg.t = t;
  if (conv.key === state.active) refreshFile(msg, stageChanged);
}

// A sent picture is shown at once from the local file; the server only confirms later.
function attachPreview(key, url) {
  state.previews.set(key, url);
  const msg = state.files.get(key);
  if (msg && !msg.preview) {
    msg.preview = url;
    refreshFile(msg, true);
  }
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

function renderStatus() {
  const dot = $("status-dot");
  const text = $("status-text");
  dot.className = "status-dot";
  const labels = {
    DISCONNECTED: "Offline",
    TLS_CONNECTING: "Connecting (TLS)",
    WAIT_HELLO_ACK: "Handshaking",
    AUTHENTICATING: "Signing in",
    ONLINE: "Online",
    CLOSING: "Signing out",
  };
  text.textContent = labels[state.phase] || state.phase;
  if (state.phase === "ONLINE") dot.classList.add("is-online");
  else if (state.phase !== "DISCONNECTED") dot.classList.add("is-busy");

  const online = state.phase === "ONLINE";
  $("signin").hidden = online;
  $("chat").hidden = !online;
  $("me").hidden = !online;
  $("me-name").textContent = online ? `${state.username} (#${state.userId})` : "";
  $("signin-btn").disabled = state.phase !== "DISCONNECTED";
}

function renderPeers() {
  const list = $("peer-list");
  list.replaceChildren();
  const online = state.phase === "ONLINE";
  $("peer-empty").hidden = online && state.peers.length > 0;
  if (!online) return;
  for (const p of state.peers) {
    const li = el("li");
    const btn = el("button");
    btn.type = "button";
    const isMe = p.id === state.userId;
    btn.disabled = isMe;
    btn.title = isMe ? "This is you" : `Message ${p.name}`;
    btn.append(el("span", "peer-dot"), el("span", "peer-name", isMe ? `${p.name} (you)` : p.name), el("span", "peer-meta", `#${p.id}`));
    if (!isMe) {
      btn.addEventListener("click", () => openConversation(conversationFor(p.id, p.name).key));
    }
    li.append(btn);
    list.append(li);
  }
}

function renderTabs() {
  const tabs = $("tabs");
  tabs.replaceChildren();
  for (const conv of state.convs.values()) {
    const btn = el("button", "tab");
    btn.type = "button";
    btn.setAttribute("role", "tab");
    btn.setAttribute("aria-selected", String(conv.key === state.active));
    const online = conv.peerId === BROADCAST || state.peers.some((p) => p.id === conv.peerId);
    btn.append(el("span", "", online ? conv.title : `${conv.title} (offline)`));
    if (conv.unread > 0) btn.append(el("span", "badge", String(conv.unread)));
    btn.addEventListener("click", () => openConversation(conv.key));
    tabs.append(btn);
  }
}

function buildMessageNode(msg) {
  return msg.type === "file" ? buildFileNode(msg) : buildChatNode(msg);
}

function buildChatNode(m) {
  const li = el("li", m.self ? "msg is-self" : "msg");
  const head = el("div", "msg-head");
  head.append(el("span", "msg-from", m.from), el("time", "", new Date(m.ts).toLocaleTimeString()));
  li.append(head, el("div", "msg-body", m.text));
  return li;
}

function renderMessages() {
  const list = $("messages");
  const stick = isNearBottom(list);
  list.replaceChildren();
  const conv = state.convs.get(state.active);
  if (!conv) return;
  if (conv.messages.length === 0) {
    const hint = conv.peerId === BROADCAST
      ? "No messages yet. Everything you write here goes to everyone online."
      : `No messages with ${conv.title} yet. Only the two of you see this conversation.`;
    list.append(el("li", "msg-system", hint));
    return;
  }
  for (const m of conv.messages) list.append(buildMessageNode(m));
  const last = conv.messages[conv.messages.length - 1];
  if (stick || last.self) list.scrollTop = list.scrollHeight;
}

// --- files and pictures inside the conversation -----------------------------

function fileIcon(name) {
  const ext = (String(name).split(".").pop() || "").toLowerCase();
  if (ext === "pdf") return "\u{1F4D5}";
  if (["zip", "rar", "7z", "gz", "tar"].includes(ext)) return "\u{1F5DC}";
  if (["mp3", "wav", "flac", "ogg", "m4a"].includes(ext)) return "\u{1F3B5}";
  if (["mp4", "mkv", "mov", "avi", "webm"].includes(ext)) return "\u{1F3AC}";
  if (["xls", "xlsx", "csv", "ods"].includes(ext)) return "\u{1F4CA}";
  if (["doc", "docx", "txt", "md", "rtf", "odt"].includes(ext)) return "\u{1F4DD}";
  return "\u{1F4C4}";
}

function formatBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

// The wording of the side panel, which also shows where a received file was saved.
function transferNote(t) {
  const who = t.peer_name || `#${t.peer_id}`;
  const pct = t.percent || 0;
  switch (t.stage) {
    case "sending": return `Sending to ${who}: ${pct}%`;
    case "awaiting_confirmation": return `Sent. Waiting for ${who} to verify the checksum.`;
    case "receiving": return `Receiving from ${who}: ${pct}%`;
    case "verified":
      if (t.direction === "send") return `Delivered to ${who}. SHA-256 verified.`;
      if (t.saved_path) return `Verified and saved to ${t.saved_path}`;
      return t.error ? t.error : "Verified.";
    case "failed": return `Failed: ${t.error || "unknown error"}`;
    default: return t.stage || "";
  }
}

// The shorter wording used inside the conversation.
function cardNote(t) {
  if (t.stage === "verified") {
    if (t.error) return t.error;
    return t.direction === "send" ? "Delivered. SHA-256 verified." : "Received. SHA-256 verified.";
  }
  return transferNote(t);
}

function placeholderText(t) {
  if (t.stage === "failed") return "Photo failed";
  if (t.stage === "verified") return t.error || "Photo received";
  return `Receiving photo\u2026 ${t.percent || 0}%`;
}

// A picture is shown as a picture when it is being sent (we have the local file) or when
// it is being received (a placeholder first, the real image once verified).
function isPhoto(msg) {
  if (!IMAGE_EXT.test(msg.t.filename)) return false;
  return msg.self ? Boolean(msg.preview) : true;
}

function photoSource(msg) {
  if (msg.self) return msg.preview;
  return msg.t.stage === "verified" && msg.t.saved_path ? downloadUrl(msg.t.saved_path, true) : "";
}

function progressBar(t, refs) {
  const bar = el("div", "bar bar-thin");
  bar.setAttribute("role", "progressbar");
  bar.setAttribute("aria-valuemin", "0");
  bar.setAttribute("aria-valuemax", "100");
  bar.setAttribute("aria-valuenow", String(t.percent || 0));
  bar.setAttribute("aria-label", `${t.filename} progress`);
  const fill = el("div", "bar-fill");
  fill.style.width = `${t.percent || 0}%`;
  bar.append(fill);
  refs.bar = bar;
  refs.fill = fill;
  return bar;
}

function buildPhotoBody(msg, refs) {
  const t = msg.t;
  const box = el("div", "photo");
  const src = photoSource(msg);
  const inProgress = t.stage !== "verified" && t.stage !== "failed";
  if (src) {
    const link = el("a", "photo-link");
    link.href = src;
    link.target = "_blank";
    link.rel = "noopener";
    link.title = t.filename;
    const img = el("img", "photo-img");
    img.src = src;
    img.alt = t.filename;
    img.decoding = "async";
    img.addEventListener("error", () => {
      link.replaceChildren(el("span", "photo-broken", `Could not display ${t.filename}`));
    });
    link.append(img);
    box.append(link);
    if (inProgress) box.classList.add("is-pending");
  } else {
    const ph = el("div", "photo-ph");
    refs.label = el("span", "", placeholderText(t));
    ph.append(refs.label);
    box.append(ph);
  }
  if (inProgress) box.append(progressBar(t, refs));
  if (t.stage === "failed") {
    box.classList.add("is-failed");
    refs.note = el("div", "file-note", transferNote(t));
    box.append(refs.note);
  }
  return box;
}

function buildCardBody(msg, refs) {
  const t = msg.t;
  const card = el("div", "file-card");
  if (t.stage === "verified") card.classList.add("is-verified");
  if (t.stage === "failed") card.classList.add("is-failed");
  card.append(el("div", "file-icon", fileIcon(t.filename)));
  const info = el("div", "file-info");
  info.append(el("div", "file-name", t.filename));
  info.append(el("div", "file-meta", `${formatBytes(t.total || 0)}, stream ${t.stream_id}`));
  if (t.stage !== "verified") info.append(progressBar(t, refs));
  refs.note = el("div", "file-note", cardNote(t));
  info.append(refs.note);
  if (!msg.self && t.stage === "verified" && t.saved_path) {
    const dl = el("a", "file-dl", "Download");
    dl.href = downloadUrl(t.saved_path, false);
    dl.setAttribute("download", baseName(t.saved_path));
    info.append(dl);
  }
  card.append(info);
  return card;
}

function buildFileNode(msg) {
  const t = msg.t;
  const li = el("li", msg.self ? "msg msg-file is-self" : "msg msg-file");
  const head = el("div", "msg-head");
  head.append(
    el("span", "msg-from", msg.self ? "You" : (t.peer_name || peerName(t.peer_id))),
    el("time", "", new Date(msg.ts).toLocaleTimeString()),
  );
  const refs = {};
  li.append(head, isPhoto(msg) ? buildPhotoBody(msg, refs) : buildCardBody(msg, refs));
  msg.node = li;
  msg.refs = refs;
  return li;
}

// Updates a file message that is on screen. A change of stage rebuilds the message (for
// example the placeholder becomes the picture); a progress tick only moves the bar.
function refreshFile(msg, stageChanged) {
  if (!msg.node || !msg.node.isConnected) return;
  const list = $("messages");
  const stick = isNearBottom(list);
  if (stageChanged || !msg.refs.fill) {
    msg.node.replaceWith(buildFileNode(msg));
  } else {
    const pct = msg.t.percent || 0;
    msg.refs.fill.style.width = `${pct}%`;
    if (msg.refs.bar) msg.refs.bar.setAttribute("aria-valuenow", String(pct));
    if (msg.refs.label) msg.refs.label.textContent = placeholderText(msg.t);
    if (msg.refs.note) msg.refs.note.textContent = isPhoto(msg) ? transferNote(msg.t) : cardNote(msg.t);
  }
  if (stick) list.scrollTop = list.scrollHeight;
}

// --- composer ----------------------------------------------------------------

function updateComposer() {
  const conv = currentDirectConversation();
  $("message").placeholder = conv ? `Message ${conv.title}` : "Message everyone";
  const fileBtn = $("file-btn");
  fileBtn.disabled = !conv;
  fileBtn.title = conv ? `Attach files for ${conv.title}` : "Open a conversation with one person to attach files";
}

function renderTransfers() {
  const list = $("transfer-list");
  list.replaceChildren();
  const items = Array.from(state.transfers.values()).reverse();
  $("transfer-empty").hidden = items.length > 0;
  for (const t of items) {
    const li = el("li", "transfer");
    if (t.stage === "verified") li.classList.add("is-verified");
    if (t.stage === "failed") li.classList.add("is-failed");
    const top = el("div", "transfer-top");
    const arrow = t.direction === "send" ? "\u2191 " : "\u2193 ";
    top.append(el("span", "transfer-name", arrow + t.filename), el("span", "transfer-size", formatBytes(t.total || 0)));
    const bar = el("div", "bar");
    bar.setAttribute("role", "progressbar");
    bar.setAttribute("aria-valuemin", "0");
    bar.setAttribute("aria-valuemax", "100");
    bar.setAttribute("aria-valuenow", String(t.percent || 0));
    bar.setAttribute("aria-label", `${t.filename} progress`);
    const fill = el("div", "bar-fill");
    fill.style.width = `${t.percent || 0}%`;
    bar.append(fill);
    li.append(top, bar, el("div", "transfer-note", transferNote(t)));
    list.append(li);
  }
}

function buildWindowCells() {
  const box = $("window");
  for (let i = 0; i < MAX_WINDOW; i += 1) box.append(el("span", "cell"));
}

function renderStats(s) {
  const cells = $("window").children;
  if (!s) {
    $("rtt-value").textContent = "\u2013";
    for (const c of cells) c.className = "cell";
    ["st-cwnd", "st-rwnd", "st-rto", "st-retrans", "st-packets"].forEach((id) => { $(id).textContent = "\u2013"; });
    $("window-caption").textContent = "Packets in flight against the sending window.";
    return;
  }
  const rttMs = (s.rtt_us || 0) / 1000;
  $("rtt-value").textContent = rttMs < 10 ? rttMs.toFixed(2) : String(Math.round(rttMs));
  const cwnd = s.cwnd || 0;
  const rwnd = s.peer_rwnd || 0;
  const inFlight = s.in_flight || 0;
  const effective = Math.max(1, Math.min(cwnd, MAX_WINDOW));
  for (let i = 0; i < cells.length; i += 1) {
    let cls = "cell";
    if (i < effective) cls += " in-window";
    if (i < inFlight) cls += " in-flight";
    if (rwnd < MAX_WINDOW && i === Math.max(0, rwnd - 1)) cls += " rwnd-edge";
    cells[i].className = cls;
  }
  $("window-caption").textContent =
    `${inFlight} packet${inFlight === 1 ? "" : "s"} in flight. Window: ${effective} of ${MAX_WINDOW}.`;
  $("st-cwnd").textContent = `${cwnd} packets`;
  $("st-rwnd").textContent = `${rwnd} slots`;
  $("st-rto").textContent = `${s.rto_ms || 0} ms`;
  $("st-retrans").textContent = String(s.retransmissions || 0);
  $("st-packets").textContent = `${s.packets_sent || 0} / ${s.packets_acked || 0}`;
}

// ---------------------------------------------------------------------------
// Events from the Go client (Server-Sent Events)
// ---------------------------------------------------------------------------

function applyState(ev) {
  const previousUser = state.userId;
  state.phase = ev.state || "DISCONNECTED";
  if (state.phase === "ONLINE") {
    state.userId = ev.user_id || 0;
    state.username = ev.username || "";
    if (previousUser && previousUser !== state.userId) {
      resetConversations();
      state.transfers.clear();
    }
  }
  if (state.phase === "DISCONNECTED") {
    renderStats(null);
    if (ev.error) $("signin-error").textContent = `Disconnected: ${ev.error}`;
  }
  renderStatus();
  renderPeers();
  renderTabs();
  renderMessages();
  updateComposer();
  renderTransfers();
}

function handleEvent(ev) {
  switch (ev.kind) {
    case "state": applyState(ev); break;
    case "peers":
      state.peers = ev.peers || [];
      renderPeers();
      renderTabs();
      break;
    case "chat": addChat(ev); break;
    case "file_progress": {
      const t = ev.progress;
      if (!t) break;
      state.transfers.set(transferKey(t), t);
      renderTransfers();
      upsertFile(t);
      break;
    }
    case "stats": renderStats(ev.stats); break;
    case "error": $("composer-error").textContent = ev.error || ""; break;
    default: break;
  }
}

function connectEvents() {
  const es = new EventSource("/events");
  es.addEventListener("open", () => {
    // The bridge replays history on every (re)connection, so start from a clean slate.
    resetConversations();
    state.transfers.clear();
  });
  es.addEventListener("message", (msg) => {
    try { handleEvent(JSON.parse(msg.data)); } catch (err) { console.error("bad event", err); }
  });
  es.addEventListener("error", () => {
    if (es.readyState === EventSource.CLOSED) setTimeout(connectEvents, 2000);
  });
}

// ---------------------------------------------------------------------------
// User actions
// ---------------------------------------------------------------------------

function readFileAsBase64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const url = String(reader.result);
      resolve(url.slice(url.indexOf(",") + 1));
    };
    reader.onerror = () => reject(reader.error || new Error("Could not read the file"));
    reader.readAsDataURL(file);
  });
}

// Sends files, one after the other, to the person whose conversation is open.
async function sendFiles(files) {
  const errorBox = $("composer-error");
  errorBox.textContent = "";
  const conv = currentDirectConversation();
  if (!conv) {
    errorBox.textContent = "Files go to one person. Open a conversation with someone first.";
    return;
  }
  for (const file of files) {
    if (file.size > MAX_FILE_BYTES) {
      errorBox.textContent = `${file.name} is larger than 64 MB.`;
      continue;
    }
    try {
      const base64 = await readFileAsBase64(file);
      const res = await api("/api/file", { target_id: conv.peerId, filename: file.name, base64_data: base64 });
      if (IMAGE_EXT.test(file.name)) {
        attachPreview(`send:${conv.peerId}:${res.stream_id}`, URL.createObjectURL(file));
      }
    } catch (err) {
      errorBox.textContent = `${file.name}: ${err.message}`;
    }
  }
}

const PASTE_EXT = { "image/png": "png", "image/jpeg": "jpg", "image/gif": "gif", "image/webp": "webp", "image/bmp": "bmp" };

// Files on the clipboard. A pasted picture (a screenshot) has no useful name, so it is
// called pasted-<timestamp>.<ext>.
function pastedFiles(e) {
  const files = e.clipboardData ? Array.from(e.clipboardData.files || []) : [];
  const stamp = Date.now();
  return files.map((f, i) => {
    if (!f.type.startsWith("image/")) return f;
    return new File([f], `pasted-${stamp + i}.${PASTE_EXT[f.type] || "png"}`, { type: f.type });
  });
}

function hasFiles(e) {
  return Boolean(e.dataTransfer) && Array.from(e.dataTransfer.types || []).includes("Files");
}

function bindDropZone() {
  const chat = $("chat");
  let depth = 0;
  const clear = () => {
    depth = 0;
    chat.classList.remove("is-drop");
  };
  chat.addEventListener("dragenter", (e) => {
    if (!hasFiles(e)) return;
    e.preventDefault();
    depth += 1;
    const conv = currentDirectConversation();
    if (conv) {
      chat.dataset.drop = `Drop files to send to ${conv.title}`;
      chat.classList.add("is-drop");
    }
  });
  chat.addEventListener("dragover", (e) => {
    if (hasFiles(e)) e.preventDefault();
  });
  chat.addEventListener("dragleave", () => {
    depth -= 1;
    if (depth <= 0) clear();
  });
  chat.addEventListener("drop", (e) => {
    if (!hasFiles(e)) return;
    e.preventDefault();
    clear();
    sendFiles(Array.from(e.dataTransfer.files));
  });
  // A file dropped anywhere else must not make the browser navigate away from the app.
  document.addEventListener("dragover", (e) => { if (hasFiles(e)) e.preventDefault(); });
  document.addEventListener("drop", (e) => { if (hasFiles(e)) e.preventDefault(); });
}

function bindLossSlider() {
  const range = $("loss-range");
  const out = $("loss-out");
  range.addEventListener("input", () => { out.textContent = `${range.value}%`; });
  range.addEventListener("change", async () => {
    try {
      await api("/api/loss", { rate: Number(range.value) / 100 });
    } catch (err) {
      $("composer-error").textContent = err.message;
    }
  });
}

function bindActions() {
  $("signin").addEventListener("submit", async (e) => {
    e.preventDefault();
    $("signin-error").textContent = "";
    $("signin-btn").disabled = true;
    try {
      await api("/api/login", { username: $("username").value.trim(), password: $("password").value });
      $("password").value = "";
    } catch (err) {
      $("signin-error").textContent = err.message;
    } finally {
      $("signin-btn").disabled = state.phase !== "DISCONNECTED";
    }
  });

  $("logout-btn").addEventListener("click", async () => {
    try { await api("/api/logout"); } catch (err) { $("composer-error").textContent = err.message; }
  });

  $("composer").addEventListener("submit", async (e) => {
    e.preventDefault();
    const input = $("message");
    const text = input.value.trim();
    if (!text) return;
    const conv = state.convs.get(state.active);
    $("composer-error").textContent = "";
    try {
      await api("/api/chat", { target_id: conv ? conv.peerId : BROADCAST, text });
      input.value = "";
    } catch (err) {
      $("composer-error").textContent = err.message;
    }
  });

  $("file-btn").addEventListener("click", () => $("file-input").click());

  $("file-input").addEventListener("change", () => {
    const input = $("file-input");
    const files = Array.from(input.files || []);
    input.value = "";
    if (files.length > 0) sendFiles(files);
  });

  // Ctrl+V of a screenshot or a copied file. Plain text pastes are left to the browser.
  document.addEventListener("paste", (e) => {
    if (state.phase !== "ONLINE") return;
    const files = pastedFiles(e);
    if (files.length === 0) return;
    e.preventDefault();
    sendFiles(files);
  });

  bindDropZone();
  bindLossSlider();
}

async function init() {
  resetConversations();
  buildWindowCells();
  bindActions();
  try {
    const res = await fetch("/api/state");
    const snap = await res.json();
    $("server-hint").textContent = `Server: ${snap.server}`;
    const loss = Math.round((snap.drop_rate || 0) * 100);
    $("loss-range").value = String(loss);
    $("loss-out").textContent = `${loss}%`;
  } catch (_) { /* the event stream will report the state anyway */ }
  renderStatus();
  renderPeers();
  renderTabs();
  renderMessages();
  renderTransfers();
  connectEvents();
}

document.addEventListener("DOMContentLoaded", init);
