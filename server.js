// server.js
const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const bodyParser = require("body-parser");

const app = express();
const db = new sqlite3.Database("./database.db");
const SECRET = "sekret_super_haslo";

app.use(cors());
app.use(bodyParser.json());
app.use(express.static("public"));

// ========== INICJALIZACJA BAZY ==========

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS employees (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code INTEGER UNIQUE,
    name TEXT,
    active INTEGER DEFAULT 1
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS processes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS stations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    process_id INTEGER,
    capacity INTEGER DEFAULT 1,
    active INTEGER DEFAULT 1
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    employee_code INTEGER,
    station_id INTEGER,
    process_id INTEGER,
    start_time INTEGER,
    end_time INTEGER,
    duration_sec INTEGER
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    employee_code INTEGER,
    process_id INTEGER,
    order_number TEXT,
    ts INTEGER
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS config (
    key TEXT PRIMARY KEY,
    value TEXT
  )`);

  // PIN admina - domyślnie "0000"
  db.get(`SELECT value FROM config WHERE key="adminPin"`, (err, row) => {
    if (!row) {
      const hash = bcrypt.hashSync("0000", 10);
      db.run(`INSERT INTO config(key,value) VALUES("adminPin",?)`, hash);
      console.log("✅ PIN admina ustawiony na: 0000");
    }
  });
});

// ========== AUTH MIDDLEWARE ==========
function verifyAdmin(req, res, next) {
  const token = req.headers["authorization"]?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Brak tokenu" });
  jwt.verify(token, SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ error: "Zły token" });
    req.admin = decoded;
    next();
  });
}

// ========== ENDPOINTY ==========

// 🔑 ADMIN
app.post("/api/admin/login", (req, res) => {
  const { pin } = req.body;
  db.get(`SELECT value FROM config WHERE key="adminPin"`, (err, row) => {
    if (row && bcrypt.compareSync(pin, row.value)) {
      const token = jwt.sign({ role: "admin" }, SECRET, { expiresIn: "8h" });
      res.json({ token });
    } else {
      res.status(401).json({ error: "Błędny PIN" });
    }
  });
});

// 👷 PRACOWNICY
app.get("/api/employees", (req, res) => {
  db.all(`SELECT * FROM employees ORDER BY code ASC`, (err, rows) => res.json(rows));
});
app.post("/api/employees", verifyAdmin, (req, res) => {
  const { code, name } = req.body;
  db.run(`INSERT INTO employees(code,name,active) VALUES(?,?,1)`, [code, name], function(err){
    if (err) return res.status(400).json({ error: err.message });
    res.json({ id: this.lastID, code, name, active: 1 });
  });
});
app.patch("/api/employees/:code", verifyAdmin, (req, res) => {
  const { name, active } = req.body;
  db.run(`UPDATE employees SET name=?, active=? WHERE code=?`, [name, active?1:0, req.params.code], function(err){
    if (err) return res.status(400).json({ error: err.message });
    res.json({ updated: this.changes });
  });
});
app.delete("/api/employees/:code", verifyAdmin, (req, res) => {
  db.run(`DELETE FROM employees WHERE code=?`, [req.params.code], function(err){
    if (err) return res.status(400).json({ error: err.message });
    res.json({ deleted: this.changes });
  });
});

// 🕒 SESJE
app.post("/api/login", (req, res) => {
  const { code, stationId, processId } = req.body;
  const start = Date.now();
  db.run(`INSERT INTO sessions(employee_code,station_id,process_id,start_time) VALUES(?,?,?,?)`, [code, stationId, processId, start], function(err){
    if (err) return res.status(400).json({ error: err.message });
    res.json({ session_id: this.lastID, start });
  });
});
app.post("/api/logout", (req, res) => {
  const { code } = req.body;
  const end = Date.now();
  db.get(`SELECT * FROM sessions WHERE employee_code=? AND end_time IS NULL ORDER BY start_time DESC LIMIT 1`, [code], (err, row)=>{
    if (!row) return res.status(404).json({ error: "Brak aktywnej sesji" });
    const duration = Math.floor((end-row.start_time)/1000);
    db.run(`UPDATE sessions SET end_time=?, duration_sec=? WHERE id=?`, [end, duration, row.id], () => res.json({ code, duration }));
  });
});
app.get("/api/active", (req,res)=>{
  db.all(`SELECT * FROM sessions WHERE end_time IS NULL`, (err,rows)=> res.json(rows));
});
app.get("/api/logs", (req,res)=>{
  const startOfDay = new Date(); startOfDay.setHours(0,0,0,0);
  db.all(`SELECT * FROM sessions WHERE start_time >= ? ORDER BY start_time DESC`, [startOfDay.getTime()], (err,rows)=> res.json(rows));
});

// 📦 ZLECENIA
app.post("/api/orders", (req,res)=>{
  const { code, processId, order } = req.body;
  const ts = Date.now();
  db.run(`INSERT INTO orders(employee_code,process_id,order_number,ts) VALUES(?,?,?,?)`, [code,processId,order,ts], function(err){
    if (err) return res.status(400).json({ error: err.message });
    res.json({id:this.lastID, order, ts});
  });
});
app.get("/api/orders", (req,res)=>{
  db.all(`SELECT * FROM orders ORDER BY ts DESC LIMIT 100`, (err,rows)=> res.json(rows));
});

// ⚙️ CONFIG
app.get("/api/config", (req,res)=>{
  db.all(`SELECT * FROM config`, (err,rows)=>{
    const out={}; rows.forEach(r=> out[r.key]=r.value); res.json(out);
  });
});
app.post("/api/config", verifyAdmin, (req,res)=>{
  const {key,value}=req.body;
  db.run(`INSERT INTO config(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, [key,value], (err)=>{
    if (err) return res.status(400).json({ error: err.message });
    res.json({key,value});
  });
});

// 🔧 PROCESY / STACJE
app.get("/api/processes", (req,res)=>{
  db.all(`SELECT * FROM processes ORDER BY id ASC`, (err,rows)=> res.json(rows));
});
app.get("/api/stations", (req,res)=>{
  db.all(`SELECT * FROM stations ORDER BY id ASC`, (err,rows)=> res.json(rows));
});

// ========== START ==========
const PORT = process.env.PORT || 3000;
app.listen(PORT, ()=> console.log(`✅ Serwer działa na porcie ${PORT}`));
