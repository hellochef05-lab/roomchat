const fs = require("fs");
const path = require("path");
const http = require("http");

const express = require("express");
const WebSocket = require("ws");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const multer = require("multer");

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// ---------- Uploads (TEMP on Render free) ----------
const UPLOAD_DIR = path.join(__dirname, "uploads");
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });
app.use("/uploads", express.static(UPLOAD_DIR));

const upload = multer({
  dest: UPLOAD_DIR,
  limits: { fileSize: 25 * 1024 * 1024 } // 25MB
});

// ---------- Database ----------
const db = new sqlite3.Database(path.join(__dirname, "data.db"));

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS rooms (
      roomId TEXT PRIMARY KEY,
      roomPassHash TEXT NOT NULL,
      adminPassHash TEXT NOT NULL,
      enabled INTEGER NOT NULL DEFAULT 1
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      roomId TEXT NOT NULL,
      sender TEXT NOT NULL,
      kind TEXT NOT NULL DEFAULT 'text',   -- text | file
      text TEXT,
      fileUrl TEXT,
      fileMime TEXT,
      fileName TEXT,
      ts INTEGER NOT NULL
    )
  `);
});

function now() { return Date.now(); }
function makeId() { return crypto.randomBytes(10).toString("hex"); }

function send(ws, obj) {
  if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(obj));
}

function dbGet(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => err ? reject(err) : resolve(row || null));
  });
}
function dbAll(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => err ? reject(err) : resolve(rows || []));
  });
}
function dbRun(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      err ? reject(err) : resolve(this);
    });
  });
}

async function getRoom(roomId) {
  return await dbGet("SELECT * FROM rooms WHERE roomId = ?", [roomId]);
}

async function getHistory(roomId, limit = 200) {
  const rows = await dbAll(
    "SELECT sender, kind, text, fileUrl, fileMime, fileName, ts FROM messages WHERE roomId=? ORDER BY id ASC LIMIT ?",
    [roomId, limit]
  );
  return rows;
}

async function addText(roomId, sender, text) {
  await dbRun(
    "INSERT INTO messages(roomId, sender, kind, text, ts) VALUES(?,?,?,?,?)",
    [roomId, sender, "text", text, now()]
  );
}

async function addFile(roomId, sender, fileUrl, fileMime, fileName) {
  await dbRun(
    "INSERT INTO messages(roomId, sender, kind, fileUrl, fileMime, fileName, ts) VALUES(?,?,?,?,?,?,?)",
    [roomId, sender, "file", fileUrl, fileMime, fileName, now()]
  );
}

async function clearChat(roomId) {
  await dbRun("DELETE FROM messages WHERE roomId=?", [roomId]);
}

async function setRoomEnabled(roomId, enabled) {
  await dbRun("UPDATE rooms SET enabled=? WHERE roomId=?", [enabled ? 1 : 0, roomId]);
}

// ---------- Runtime state ----------
const clientsByRoom = new Map(); // roomId -> Set(ws) (joined users + admin if joined)
const adminsByRoom = new Map();  // roomId -> Set(ws) (admin control connections)
const pending = new Map();       // requestId -> { ws, roomId, sender, createdAt }

function addTo(map, key, ws) {
  if (!map.has(key)) map.set(key, new Set());
  map.get(key).add(ws);
}
function removeFrom(map, key, ws) {
  if (!map.has(key)) return;
  map.get(key).delete(ws);
  if (map.get(key).size === 0) map.delete(key);
}

function broadcastToRoom(roomId, msg) {
  const set = clientsByRoom.get(roomId);
  if (!set) return;
  for (const ws of set) send(ws, msg);
}

function broadcastToAdmins(roomId, msg) {
  const set = adminsByRoom.get(roomId);
  if (!set) return;
  for (const ws of set) send(ws, msg);
}

// kick everyone (including admin chat sessions)
function kickRoom(roomId, reason) {
  const set = clientsByRoom.get(roomId);
  if (!set) return;
  for (const ws of set) {
    send(ws, { type: "kicked", reason });
    try { ws.close(); } catch {}
  }
  clientsByRoom.delete(roomId);
}

// deny pending requests
function denyPendingForRoom(roomId, reason) {
  for (const [rid, r] of pending.entries()) {
    if (r.roomId === roomId) {
      send(r.ws, { type: "error", error: reason });
      try { r.ws.close(); } catch {}
      pending.delete(rid);
    }
  }
}

// ---------- Admin HTTP APIs ----------
app.post("/api/admin/create-room", async (req, res) => {
  try {
    const { roomId, roomPassword, adminPassword } = req.body || {};
    if (!roomId || !roomPassword || !adminPassword) return res.status(400).json({ error: "Missing fields" });

    const exists = await getRoom(roomId);
    if (exists) return res.status(409).json({ error: "Room already exists" });

    const roomPassHash = await bcrypt.hash(roomPassword, 10);
    const adminPassHash = await bcrypt.hash(adminPassword, 10);

    await dbRun(
      "INSERT INTO rooms(roomId, roomPassHash, adminPassHash, enabled) VALUES(?,?,?,1)",
      [roomId, roomPassHash, adminPassHash]
    );

    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: "Create room failed" });
  }
});

app.post("/api/admin/action", async (req, res) => {
  try {
    const { roomId, adminPassword, action } = req.body || {};
    if (!roomId || !adminPassword || !action) return res.status(400).json({ error: "Missing fields" });

    const room = await getRoom(roomId);
    if (!room) return res.status(404).json({ error: "Room not found" });

    const okAdmin = await bcrypt.compare(adminPassword, room.adminPassHash);
    if (!okAdmin) return res.status(403).json({ error: "Wrong admin password" });

    if (action === "enable") {
      await setRoomEnabled(roomId, true);
      broadcastToRoom(roomId, { type: "room-status", enabled: true });
      broadcastToAdmins(roomId, { type: "room-status", enabled: true });
      return res.json({ ok: true });
    }

    if (action === "disable") {
      await setRoomEnabled(roomId, false);
      broadcastToAdmins(roomId, { type: "room-status", enabled: false });
      kickRoom(roomId, "Room disabled by admin");
      denyPendingForRoom(roomId, "Room disabled by admin");
      return res.json({ ok: true });
    }

    if (action === "clear") {
      await clearChat(roomId);
      broadcastToRoom(roomId, { type: "chat-cleared" });
      broadcastToAdmins(roomId, { type: "chat-cleared" });
      return res.json({ ok: true });
    }

    res.status(400).json({ error: "Unknown action" });
  } catch {
    res.status(500).json({ error: "Admin action failed" });
  }
});

// ---------- Upload API (image/video/audio) ----------
app.post("/api/upload", upload.single("file"), async (req, res) => {
  try {
    const { roomId, roomPassword, sender } = req.body || {};
    if (!req.file) return res.status(400).json({ error: "No file" });
    if (!roomId || !roomPassword) return res.status(400).json({ error: "Missing room/password" });

    const room = await getRoom(roomId);
    if (!room) return res.status(404).json({ error: "Room not found" });
    if (!room.enabled) return res.status(403).json({ error: "Room disabled" });

    const okPass = await bcrypt.compare(roomPassword, room.roomPassHash);
    if (!okPass) return res.status(403).json({ error: "Wrong passkey" });

    const mime = (req.file.mimetype || "").toLowerCase();
    const isOk = mime.startsWith("image/") || mime.startsWith("video/") || mime.startsWith("audio/");
    if (!isOk) {
      try { fs.unlinkSync(req.file.path); } catch {}
      return res.status(400).json({ error: "Only image/video/audio allowed" });
    }

    const safeSender = (sender || "User").toString().slice(0, 20);

    const original = req.file.originalname || "file";
    const ext = path.extname(original).slice(0, 10) || "";
    const newName = req.file.filename + ext;
    const newPath = path.join(UPLOAD_DIR, newName);
    try { fs.renameSync(req.file.path, newPath); } catch {}

    const fileUrl = `/uploads/${newName}`;

    // store in DB + broadcast
    await addFile(roomId, safeSender, fileUrl, mime, original);

    const payload = { type: "file", sender: safeSender, url: fileUrl, mime, name: original };
    broadcastToRoom(roomId, payload);
    broadcastToAdmins(roomId, payload);

    res.json({ ok: true, url: fileUrl });
  } catch {
    res.status(500).json({ error: "Upload failed" });
  }
});

// ---------- WebSocket ----------
wss.on("connection", (ws) => {
  ws.roomId = null;
  ws.sender = "User";
  ws.isAdmin = false;

  ws.on("message", async (raw) => {
    let msg;
    try { msg = JSON.parse(raw.toString()); } catch { return; }

    // ADMIN connects for control + approvals + chat
    if (msg.type === "admin-attach") {
      const roomId = (msg.roomId || "").toString().trim();
      const adminPassword = (msg.adminPassword || "").toString();
      const sender = (msg.sender || "Admin").toString().slice(0, 20);

      const room = await getRoom(roomId);
      if (!room) return send(ws, { type: "error", error: "Room not found" });

      const okAdmin = await bcrypt.compare(adminPassword, room.adminPassHash);
      if (!okAdmin) return send(ws, { type: "error", error: "Wrong admin password" });

      ws.isAdmin = true;
      ws.roomId = roomId;
      ws.sender = sender;

      // admin receives join requests
      addTo(adminsByRoom, roomId, ws);

      // admin can also chat inside room
      addTo(clientsByRoom, roomId, ws);

      send(ws, { type: "admin-attached", roomId, enabled: !!room.enabled });

      // send pending list
      const pend = [];
      for (const [rid, r] of pending.entries()) {
        if (r.roomId === roomId) pend.push({ requestId: rid, sender: r.sender, createdAt: r.createdAt });
      }
      send(ws, { type: "pending-list", pending: pend });

      // send chat history
      const history = await getHistory(roomId, 200);
      send(ws, { type: "history", messages: history });

      broadcastToRoom(roomId, { type: "system", text: `${sender} (admin) joined.` });
      return;
    }

    // USER requests to join (admin approval needed)
    if (msg.type === "request-join") {
      const roomId = (msg.roomId || "").toString().trim();
      const roomPassword = (msg.roomPassword || "").toString();
      const sender = (msg.sender || "User").toString().slice(0, 20);

      const room = await getRoom(roomId);
      if (!room) return send(ws, { type: "error", error: "Room not found" });
      if (!room.enabled) return send(ws, { type: "error", error: "Room disabled" });

      const okPass = await bcrypt.compare(roomPassword, room.roomPassHash);
      if (!okPass) return send(ws, { type: "error", error: "Wrong passkey" });

      ws.sender = sender;

      const requestId = makeId();
      pending.set(requestId, { ws, roomId, sender, createdAt: now() });

      send(ws, { type: "waiting", requestId });

      // notify admins
      broadcastToAdmins(roomId, { type: "join-request", requestId, sender, createdAt: now() });
      return;
    }

    // ADMIN approve/deny
    if (msg.type === "approve" || msg.type === "deny") {
      if (!ws.isAdmin || !ws.roomId) return send(ws, { type: "error", error: "Not admin" });

      const requestId = (msg.requestId || "").toString();
      const req = pending.get(requestId);
      if (!req) return send(ws, { type: "error", error: "Request not found" });
      if (req.roomId !== ws.roomId) return send(ws, { type: "error", error: "Wrong room" });

      pending.delete(requestId);
      broadcastToAdmins(req.roomId, { type: "join-request-closed", requestId });

      if (msg.type === "deny") {
        send(req.ws, { type: "join-denied" });
        try { req.ws.close(); } catch {}
        return;
      }

      // approve
      req.ws.roomId = req.roomId;
      addTo(clientsByRoom, req.roomId, req.ws);
      send(req.ws, { type: "joined", roomId: req.roomId });

      const history = await getHistory(req.roomId, 200);
      send(req.ws, { type: "history", messages: history });

      broadcastToRoom(req.roomId, { type: "system", text: `${req.sender} joined.` });
      return;
    }

    // CHAT (admin + users)
    if (msg.type === "chat") {
      if (!ws.roomId) return send(ws, { type: "error", error: "Not joined" });

      const room = await getRoom(ws.roomId);
      if (!room || !room.enabled) {
        send(ws, { type: "error", error: "Room disabled" });
        try { ws.close(); } catch {}
        return;
      }

      const text = (msg.text || "").toString().trim();
      if (!text) return;

      await addText(ws.roomId, ws.sender, text);
      broadcastToRoom(ws.roomId, { type: "chat", sender: ws.sender, text, ts: now() });
      broadcastToAdmins(ws.roomId, { type: "chat", sender: ws.sender, text, ts: now() });
      return;
    }
  });

  ws.on("close", () => {
    // remove from room sets
    if (ws.roomId) {
      removeFrom(clientsByRoom, ws.roomId, ws);
      removeFrom(adminsByRoom, ws.roomId, ws);
    }

    // remove pending requests for this ws
    for (const [rid, r] of pending.entries()) {
      if (r.ws === ws) {
        pending.delete(rid);
        broadcastToAdmins(r.roomId, { type: "join-request-closed", requestId: rid });
      }
    }
  });
});

// Render port
const PORT = process.env.PORT || 8080;
server.listen(PORT, "0.0.0.0", () => console.log("Server running on port " + PORT));
