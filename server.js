require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const Database = require("better-sqlite3");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(helmet());
app.use(express.json({ limit: "20kb" }));
app.use(rateLimit({
  windowMs: 60 * 1000,
  limit: 100
}));

// Database
const dbPath = process.env.DB_PATH || "./data/game.db";
fs.mkdirSync(path.dirname(dbPath), { recursive: true });

const db = new Database(dbPath);
db.pragma("journal_mode = WAL");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT,
    coins INTEGER NOT NULL DEFAULT 500,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS cards (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    rarity TEXT NOT NULL,
    attack INTEGER NOT NULL,
    defense INTEGER NOT NULL,
    hp INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS inventory (
    user_id TEXT NOT NULL,
    card_id TEXT NOT NULL,
    quantity INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, card_id)
  );

  CREATE TABLE IF NOT EXISTS battles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    result TEXT NOT NULL,
    reward INTEGER NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );
`);

// Initial test cards
const cards = [
  ["leo", "Leonardo", "rare", 80, 75, 100],
  ["raph", "Raphael", "rare", 95, 60, 100],
  ["mike", "Michelangelo", "common", 65, 65, 90],
  ["don", "Donatello", "common", 70, 85, 95],
  ["splinter", "Splinter", "epic", 90, 95, 120],
  ["shredder", "Shredder", "legendary", 110, 90, 130],
  ["casey", "Casey Jones", "rare", 85, 70, 100],
  ["april", "April O'Neil", "common", 60, 60, 85],
  ["bebop", "Bebop", "epic", 100, 65, 115],
  ["rocksteady", "Rocksteady", "epic", 95, 80, 120],
  ["karai", "Karai", "rare", 90, 75, 100],
  ["krang", "Krang", "legendary", 105, 100, 125]
];

const insertCard = db.prepare(`
  INSERT OR IGNORE INTO cards
  (id, name, rarity, attack, defense, hp)
  VALUES (?, ?, ?, ?, ?, ?)
`);

for (const card of cards) insertCard.run(...card);

// Telegram authentication
function authenticate(req, res, next) {
  const initData = req.headers["x-telegram-init-data"];

  // Development mode only
  if (process.env.DEV_AUTH === "true" && req.headers["x-dev-user-id"]) {
    req.user = {
      id: String(req.headers["x-dev-user-id"]),
      username: "TestPlayer"
    };
    return next();
  }

  const botToken = process.env.BOT_TOKEN;

  if (!botToken || !initData) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    const params = new URLSearchParams(initData);
    const receivedHash = params.get("hash");
    params.delete("hash");

    const authDate = Number(params.get("auth_date"));

    if (!receivedHash || !authDate ||
        Date.now() / 1000 - authDate > 3600) {
      return res.status(401).json({ error: "Invalid session" });
    }

    const dataCheckString = [...params.entries()]
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, value]) => `${key}=${value}`)
      .join("\n");

    const secretKey = crypto
      .createHmac("sha256", "WebAppData")
      .update(botToken)
      .digest();

    const calculatedHash = crypto
      .createHmac("sha256", secretKey)
      .update(dataCheckString)
      .digest("hex");

    const a = Buffer.from(receivedHash, "hex");
    const b = Buffer.from(calculatedHash, "hex");

    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      return res.status(401).json({ error: "Invalid signature" });
    }

    const telegramUser = JSON.parse(params.get("user") || "{}");

    if (!telegramUser.id) {
      return res.status(401).json({ error: "Invalid user" });
    }

    req.user = {
      id: String(telegramUser.id),
      username: telegramUser.username || "Player"
    };

    next();
  } catch {
    return res.status(401).json({ error: "Authentication failed" });
  }
}

// Health check
app.get("/health", (req, res) => {
  res.json({ status: "ok", game: "TMNT CARD WARS" });
});

// Public card list
app.get("/api/cards", (req, res) => {
  res.json(db.prepare("SELECT * FROM cards").all());
});

// Player profile
app.get("/api/me", authenticate, (req, res) => {
  db.prepare(`
    INSERT OR IGNORE INTO users (id, username)
    VALUES (?, ?)
  `).run(req.user.id, req.user.username);

  const user = db.prepare(
    "SELECT * FROM users WHERE id = ?"
  ).get(req.user.id);

  const inventory = db.prepare(`
    SELECT cards.*, inventory.quantity
    FROM inventory
    JOIN cards ON cards.id = inventory.card_id
    WHERE inventory.user_id = ?
  `).all(req.user.id);

  res.json({ user, inventory });
});

// Leaderboard
app.get("/api/leaderboard", (req, res) => {
  const players = db.prepare(`
    SELECT username, coins
    FROM users
    ORDER BY coins DESC
    LIMIT 50
  `).all();

  res.json(players);
});

// Serve game interface
app.use(express.static(path.join(__dirname, "public")));

app.listen(PORT, () => {
  console.log(`TMNT CARD WARS server running on port ${PORT}`);
});
