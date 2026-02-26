const express = require("express");
const path = require("path");
const http = require("http");
const WebSocket = require("ws");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const crypto = require("crypto");

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const db = new sqlite3.Database("data.db");

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
      text TEXT NOT NULL,
      ts INTEGER NOT NULL
    )
  `);
});

function send(ws, obj) {
  if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(obj));
}
function now() { return Date.now(); }
function makeId() { return crypto.randomBytes(8).toString("hex"); }

const clientsByRoom = new Map();
const adminsByRoom = new Map();
const pending = new Map();

function addTo(map, key, ws) {
  if (!map.has(key)) map.set(key, new Set());
  map.get(key).add(ws);
}
function removeFrom(map, key, ws) {
  if (!map.has(key)) return;
  map.get(key).delete(ws);
}

function broadcastRoom(roomId, msg) {
  if (!clientsByRoom.has(roomId)) return;
  for (const ws of clientsByRoom.get(roomId)) send(ws, msg);
}
function broadcastAdmins(roomId, msg) {
  if (!adminsByRoom.has(roomId)) return;
  for (const ws of adminsByRoom.get(roomId)) send(ws, msg);
}

function getRoom(roomId) {
  return new Promise((resolve, reject) => {
    db.get("SELECT * FROM rooms WHERE roomId=?", [roomId],
      (err,row)=> err?reject(err):resolve(row));
  });
}

app.post("/api/admin/create-room", async (req,res)=>{
  const {roomId, roomPassword, adminPassword} = req.body;
  if (!roomId || !roomPassword || !adminPassword)
    return res.status(400).json({error:"Missing fields"});
  const roomPassHash = await bcrypt.hash(roomPassword,10);
  const adminPassHash = await bcrypt.hash(adminPassword,10);
  db.run("INSERT INTO rooms(roomId,roomPassHash,adminPassHash,enabled) VALUES(?,?,?,1)",
    [roomId, roomPassHash, adminPassHash],
    err => err?res.status(500).json({error:"DB error"}):res.json({ok:true}));
});

app.post("/api/admin/action", async (req,res)=>{
  const {roomId, adminPassword, action} = req.body;
  const room = await getRoom(roomId);
  if (!room) return res.status(404).json({error:"Room not found"});
  const okAdmin = await bcrypt.compare(adminPassword, room.adminPassHash);
  if (!okAdmin) return res.status(403).json({error:"Wrong admin password"});

  if (action==="enable") {
    db.run("UPDATE rooms SET enabled=1 WHERE roomId=?", [roomId]);
    return res.json({ok:true});
  }
  if (action==="disable") {
    db.run("UPDATE rooms SET enabled=0 WHERE roomId=?", [roomId]);
    broadcastRoom(roomId,{type:"kicked",reason:"Room disabled"});
    return res.json({ok:true});
  }
  if (action==="clear") {
    db.run("DELETE FROM messages WHERE roomId=?", [roomId]);
    broadcastRoom(roomId,{type:"chat-cleared"});
    return res.json({ok:true});
  }
  res.status(400).json({error:"Unknown action"});
});

wss.on("connection",(ws)=>{
  ws.roomId=null;
  ws.mode=null;
  ws.sender="User";

  ws.on("message", async raw=>{
    const msg=JSON.parse(raw.toString());

    if (msg.type==="admin-attach") {
      const room=await getRoom(msg.roomId);
      if (!room) return send(ws,{type:"error",error:"Room not found"});
      const okAdmin=await bcrypt.compare(msg.adminPassword,room.adminPassHash);
      if (!okAdmin) return send(ws,{type:"error",error:"Wrong admin password"});
      ws.mode="admin"; ws.roomId=msg.roomId;
      addTo(adminsByRoom, msg.roomId, ws);
      send(ws,{type:"admin-attached"});
      return;
    }

    if (msg.type==="request-join") {
      const room=await getRoom(msg.roomId);
      if (!room) return send(ws,{type:"error",error:"Room not found"});
      if (!room.enabled) return send(ws,{type:"error",error:"Room disabled"});
      const okPass=await bcrypt.compare(msg.roomPassword,room.roomPassHash);
      if (!okPass) return send(ws,{type:"error",error:"Wrong passkey"});
      const id=makeId();
      pending.set(id,{ws,roomId:msg.roomId,sender:msg.sender});
      broadcastAdmins(msg.roomId,{type:"join-request",requestId:id,sender:msg.sender});
      send(ws,{type:"waiting"});
      return;
    }

    if (msg.type==="approve") {
      const req=pending.get(msg.requestId);
      if (!req) return;
      pending.delete(msg.requestId);
      req.ws.roomId=req.roomId;
      addTo(clientsByRoom,req.roomId,req.ws);
      send(req.ws,{type:"joined"});
      return;
    }

    if (msg.type==="chat") {
      if (!ws.roomId) return;
      db.run("INSERT INTO messages(roomId,sender,text,ts) VALUES(?,?,?,?)",
        [ws.roomId, ws.sender, msg.text, now()]);
      broadcastRoom(ws.roomId,{type:"chat",sender:ws.sender,text:msg.text});
    }
  });
});

server.listen(8080,()=>console.log("Server running"));
