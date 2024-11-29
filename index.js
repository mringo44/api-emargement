const express = require("express");
const fs = require("fs");
const os = require("os");
const z = require("zod");
const mysql2 = require("mysql2/promise");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

const app = express();
const currentPath = process.cwd();
const jwtKey =
  "310b12b065a697b433ca578b74b64d394e9f0f8a3432ed7c5a59628f9baac6bee347ef65a3a85e3c0d530c2c5c0dc261ade2657718ed11816cffd09866051234b0d1f0410af13736d23be2e525ec3dab3549437fe009f0e0e108869e9673cccef23613947afbfe5523bc6b0961148f2059e44fd692d8dd43674bd7610758279f96f2cfcb93a3e7fc5d977612df25cff38ebe00c1f79f155dc2d37c3e5f8830a863722d4b06f48ae82d64207833b843363f459d2752418f427709fff59264c638743bce45c715cad30c539346bd8c7f7288b3ac5ce80dc52389999615f512a30a8a414d6619ba8861d3315d2476aa8d5443254b26db72a6815ebe74b24dd5fe3a";

let db = null;
async function connectDb() {
  db = await mysql2.createConnection({
    host: "localhost",
    user: "admin",
    database: "api",
    password: "Passw0rd",
  });
}
connectDb();

app.get("/files", async function (req, res) {
  const directory = await fs.promises.readdir(currentPath);

  const files = [];
  for (const element of directory) {
    const stats = await fs.promises.stat(`${currentPath}/${element}`);

    if (stats.isFile()) {
      files.push({
        name: element,
        size: stats.size,
        lastUpdate: `${stats.mtime.toLocaleDateString()} ${stats.mtime.toLocaleTimeString()}`,
      });
    }
  }

  res.send(files);
});

app.get("/today", (req, res) => {
  const today = new Date();
  const dateString = today.toLocaleDateString();
  const timeString = today.toLocaleTimeString();
  res.send(`${dateString} ${timeString}`);
});

app.get("/print-headers", (req, res) => {
  const { headers } = req;
  console.log(headers);
  res.header("App-Version", "1.0");
  res.send("OK");
});

const users = [
  { id: 1, name: "John", email: "john@example.com" },
  { id: 2, name: "Jane", email: "jane@example.com" },
  { id: 3, name: "Bob", email: "bob@example.com" },
  { id: 4, name: "Alice", email: "alice@example.com" },
  { id: 5, name: "Kate", email: "kate@example.com" },
  { id: 6, name: "Doe", email: "doe@example.com" },
  { id: 7, name: "Smith", email: "smith@example.com" },
  { id: 8, name: "Tom", email: "tom@example.com" },
  { id: 9, name: "Jerry", email: "jerry@example.com" },
  { id: 10, name: "Mike", email: "mike@example.com" },
];

// Exemple requête paginée
// http://localhost:8080/users?page=3&size=2
app.get("/users", async (req, res) => {
  const page = parseInt(req.query.page || "1");
  console.log("page", page);

  if (Number.isNaN(page)) {
    res.status(400);
    res.send('Invalid query parameter "page"');
    return;
  }

  const size = parseInt(req.query.size || "5");
  console.log("size", size);

  if (Number.isNaN(size)) {
    res.status(400);
    res.send('Invalid query parameter "size"');
    return;
  }

  const start = (page - 1) * size;

  const [rows] = await db.query(
    "SELECT id, name, email FROM users LIMIT ?, ?",
    [start, size]
  );

  res.json(rows);
});

// Créer une route /users/:id qui renvoie uniquement l'utilisateur avec l'id correspondant
// Renvoyer un code 404 si l'utilisateur n'existe pas
app.get("/users/:id(\\d+)", async (req, res) => {
  const id = parseInt(req.params.id);
  const [rows] = await db.query(
    "SELECT id, name, email FROM users WHERE id = ?",
    [id]
  );

  if (rows.length === 0) {
    res.status(404);
    res.send("User not found");
    return;
  }

  res.json(rows[0]);
});

// Créer une route POST /users qui permet d'ajouter un utilisateur avec les informations fournies
// au format JSON : name et email --
const userSchema = z.object({
  name: z.string().min(2),
  email: z.string().email(),
  password: z.string().min(8),
});

app.post("/users", express.json(), async (req, res) => {
  let data;
  try {
    data = userSchema.parse(req.body);
  } catch (error) {
    res.status(400);
    res.json({ error: error.errors });
    return;
  }

  try {
    const [result] = await db.execute(
      "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
      [data.name, data.email, data.password]
    );

    res.status(200);
    res.json({ id: result.insertId, name: data.name, email: data.email });
  } catch (error) {
    res.status(500);
    res.json({ error: error.message });
  }
});

// On attend une requête JSON avec email + password
const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
});

// Route POST /login pour s'authentifier
app.post("/login", express.json(), async (req, res) => {
  let data;
  try {
    data = loginSchema.parse(req.body);
  } catch (error) {
    res.status(400);
    res.json({ error: error.errors });
    return;
  }

  // On vérifie en base de données si email + password sont OK
  const [rows] = await db.query(
    "SELECT id FROM users WHERE email = ? AND password = ?",
    [data.email, data.password]
  );

  if (rows.length === 0) {
    res.status(401);
    res.send("Unauthorized");
    return;
  }

  // Générer un token JWT
  const payload = rows[0];
  const token = jwt.sign(payload, jwtKey);

  // Renvoyer le token si tout est OK
  res.json({ token });
});

async function checkAuth(req, res, next) {
  const { authorization } = req.headers;

  try {
    const decoded = jwt.verify(authorization, jwtKey);
    const [rows] = await db.query(
      "SELECT id, name, email FROM users WHERE id = ?",
      [decoded.id]
    );

    if (rows.length === 0) {
      throw new Error("User not found");
    }

    req.user = rows[0];
    return next();
  } catch (error) {}

  res.status(401);
  res.send("Unauthorized");
  return;
}

function logger(req, res, next) {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
}

app.get("/me", logger, checkAuth, (req, res) => {
  console.log("Utilisateur authentifié", req.user);
  res.json(req.user);
});

// Route GET /protected pour tester le token
app.get("/protected", logger, checkAuth, (req, res) => {
  res.send("OK");
});

app.listen(8080, () => {
  console.log("Server is running on port 8080");
});

/*

const id = parseInt(req.params.id);

  const user = users.find((user) => user.id === id);

  if (!user) {
    res.status(404);
    res.send("User not found");
    return;
  }

  res.json(user);

// Récupérer page et size depuis les query parameters
  const page = parseInt(req.query.page) || 1;
  const size = parseInt(req.query.size) || 5;

  const start = (page - 1) * size;
  const end = start + size;

  const paginatedUsers = users.slice(start, end);
  res.json({
    users: paginatedUsers,
    total: users.length,
  });
  */
