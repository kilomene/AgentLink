"use strict";
/*
 * Google Drive store for the archive service — the Firebase-side
 * backend behind archiveCore's store interface. THIS is the only
 * platform-specific piece of the archive service on Firebase:
 * Drive REST + the function's own service credential (obtained
 * from firebase-admin's app credential — agents never hold any
 * Drive credential; the write happens server-side only, per
 * DESIGN-BRIEF rule 5).
 *
 * Layout mirrors agentlink/archive.py exactly:
 *   <ARCHIVE_ROOT_FOLDER_ID>/<agent>/<conversation>/chain.jsonl
 * Folders are found-or-created by name under their parent. The
 * chain file is the append-only record: because the Drive API
 * has no append, an append downloads the current chain, verifies
 * it (via the core on read), and re-uploads it with the new line
 * — the hash chain makes any lost update or tamper evident on
 * the next read, and deposits are one-per-send events, never a
 * hot path.
 */
const admin = require("firebase-admin");

const API = "https://www.googleapis.com/drive/v3";
const UPLOAD = "https://www.googleapis.com/upload/drive/v3";

async function _token() {
  const cred = admin.app().options.credential;
  const t = await cred.getAccessToken();
  return t.access_token;
}

async function _api(path, opts = {}) {
  const token = await _token();
  const res = await fetch(API + path, {
    ...opts,
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
      ...(opts.headers || {}),
    },
  });
  if (!res.ok) {
    throw new Error(`Drive API ${path} -> HTTP ${res.status}`);
  }
  return res.status === 204 ? null : res.json();
}

async function _findChild(parentId, name, mimeType) {
  const q = encodeURIComponent(
    `'${parentId}' in parents and name = '${name.replace(/'/g, "\\'")}'` +
    (mimeType ? ` and mimeType = '${mimeType}'` : "") +
    " and trashed = false");
  const out = await _api(
    `/files?q=${q}&fields=files(id,name)&pageSize=1`);
  return (out.files && out.files[0]) || null;
}

async function _folder(parentId, name) {
  const found = await _findChild(
    parentId, name, "application/vnd.google-apps.folder");
  if (found) return found.id;
  const made = await _api("/files", {
    method: "POST",
    body: JSON.stringify({
      name,
      mimeType: "application/vnd.google-apps.folder",
      parents: [parentId],
    }),
  });
  return made.id;
}

async function _chainFileId(rootId, agent, conversationId) {
  const agentDir = await _folder(rootId, agent);
  const convDir = await _folder(
    agentDir, conversationId.replace(/\//g, "_"));
  const found = await _findChild(convDir, "chain.jsonl");
  return { convDir, fileId: found ? found.id : null };
}

class DriveStore {
  constructor(rootFolderId) {
    this.rootId = rootFolderId;
  }

  async readChain(agent, conversationId) {
    const { fileId } = await _chainFileId(
      this.rootId, agent, conversationId);
    if (!fileId) return [];
    const token = await _token();
    const res = await fetch(`${API}/files/${fileId}?alt=media`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) {
      throw new Error(`Drive chain read -> HTTP ${res.status}`);
    }
    const text = await res.text();
    return text.split("\n").filter((l) => l.trim())
      .map((l) => JSON.parse(l));
  }

  async appendLine(agent, conversationId, line) {
    const { convDir, fileId } = await _chainFileId(
      this.rootId, agent, conversationId);
    let current = "";
    if (fileId) {
      const token = await _token();
      const res = await fetch(`${API}/files/${fileId}?alt=media`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) {
        throw new Error(`Drive chain read -> HTTP ${res.status}`);
      }
      current = await res.text();
    }
    const next = (current && !current.endsWith("\n")
      ? current + "\n" : current) + line + "\n";
    const token = await _token();
    if (fileId) {
      const res = await fetch(
        `${UPLOAD}/files/${fileId}?uploadType=media`, {
          method: "PATCH",
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/jsonl",
          },
          body: next,
        });
      if (!res.ok) {
        throw new Error(`Drive chain write -> HTTP ${res.status}`);
      }
    } else {
      const boundary = "agentlink-archive";
      const meta = JSON.stringify(
        { name: "chain.jsonl", parents: [convDir] });
      const body = `--${boundary}\r\nContent-Type: application/json` +
        `\r\n\r\n${meta}\r\n--${boundary}\r\n` +
        `Content-Type: application/jsonl\r\n\r\n${next}\r\n` +
        `--${boundary}--`;
      const res = await fetch(
        `${UPLOAD}/files?uploadType=multipart`, {
          method: "POST",
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": `multipart/related; boundary=${boundary}`,
          },
          body,
        });
      if (!res.ok) {
        throw new Error(`Drive chain create -> HTTP ${res.status}`);
      }
    }
  }
}

module.exports = { DriveStore };
