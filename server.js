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
// Ensure player exists
function ensureUser(user) {
  db.prepare(`
    INSERT OR IGNORE INTO users (id, username)
    VALUES (?, ?)
  `).run(user.id, user.username);
}

// Open card pack
app.post("/api/open-pack", authenticate, (req, res) => {
  ensureUser(req.user);

  const packs = {
    basic: { price: 100, count: 1 },
    premium: { price: 250, count: 3 },
    legendary: { price: 500, count: 5 }
  };

  const pack = packs[req.body.packType];

  if (!pack) {
    return res.status(400).json({ error: "Unknown pack" });
  }

  const openPack = db.transaction(() => {
    const user = db.prepare(
      "SELECT coins FROM users WHERE id = ?"
    ).get(req.user.id);

    if (user.coins < pack.price) {
      throw new Error("NOT_ENOUGH_COINS");
    }

    db.prepare(
      "UPDATE users SET coins = coins - ? WHERE id = ?"
    ).run(pack.price, req.user.id);

    const availableCards = db.prepare(
      "SELECT * FROM cards"
    ).all();

    const obtained = [];

    for (let i = 0; i < pack.count; i++) {
      const roll = Math.random() * 100;

      let rarity = "common";
      if (roll >= 98) rarity = "legendary";
      else if (roll >= 85) rarity = "epic";
      else if (roll >= 55) rarity = "rare";

      let pool = availableCards.filter(
        card => card.rarity === rarity
      );

      if (!pool.length) pool = availableCards;

      const card = pool[
        Math.floor(Math.random() * pool.length)
      ];

      db.prepare(`
        INSERT INTO inventory (user_id, card_id, quantity)
        VALUES (?, ?, 1)
        ON CONFLICT(user_id, card_id)
        DO UPDATE SET quantity = quantity + 1
      `).run(req.user.id, card.id);

      obtained.push(card);
    }

    const balance = db.prepare(
      "SELECT coins FROM users WHERE id = ?"
    ).get(req.user.id).coins;

    return { obtained, balance };
  });

  try {
    res.json(openPack());
  } catch (error) {
    if (error.message === "NOT_ENOUGH_COINS") {
      return res.status(400).json({
        error: "Not enough coins"
      });
    }

    console.error(error);
    res.status(500).json({ error: "Pack opening failed" });
  }
});

// PvE battle
app.post("/api/battle", authenticate, (req, res) => {
  ensureUser(req.user);

  const cardId = req.body.cardId;

  if (typeof cardId !== "string" || cardId.length > 50) {
    return res.status(400).json({ error: "Invalid card" });
  }

  const ownedCard = db.prepare(`
    SELECT cards.*
    FROM inventory
    JOIN cards ON cards.id = inventory.card_id
    WHERE inventory.user_id = ?
      AND inventory.card_id = ?
      AND inventory.quantity > 0
  `).get(req.user.id, cardId);

  if (!ownedCard) {
    return res.status(400).json({
      error: "You do not own this card"
    });
  }

  const enemies = db.prepare(
    "SELECT * FROM cards WHERE id != ?"
  ).all(cardId);

  const enemy = enemies[
    Math.floor(Math.random() * enemies.length)
  ];

  const playerPower =
    ownedCard.attack +
    ownedCard.defense * 0.35 +
    ownedCard.hp * 0.2 +
    Math.random() * 30;

  const enemyPower =
    enemy.attack +
    enemy.defense * 0.35 +
    enemy.hp * 0.2 +
    Math.random() * 30;

  let result = "loss";
  let reward = 5;

  if (playerPower > enemyPower) {
    result = "win";
    reward = 25;
  } else if (playerPower === enemyPower) {
    result = "draw";
    reward = 10;
  }

  const saveBattle = db.transaction(() => {
    db.prepare(`
      INSERT INTO battles (user_id, result, reward)
      VALUES (?, ?, ?)
    `).run(req.user.id, result, reward);

    db.prepare(`
      UPDATE users SET coins = coins + ?
      WHERE id = ?
    `).run(reward, req.user.id);
  });

  saveBattle();

  const balance = db.prepare(
    "SELECT coins FROM users WHERE id = ?"
  ).get(req.user.id).coins;

  res.json({
    result,
    reward,
    balance,
    player: ownedCard,
    enemy
  });
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
