import "dotenv/config";

import express from "express";
import fs from "fs";
import z from "zod";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";

import { connectDb } from "./lib.js";
import { validateData, logger, checkAuth } from "./middleware.js";

const app = express();
const currentPath = process.cwd();

let db = await connectDb();

// --------------------------Gestion des utilisateurs----------------------------

const userSchema = z.object({
  name: z.string().min(2),
  email: z.string().email(),
  password: z.string().min(8)
});

// Route POST /auth/signup pour ajouter un utilisateur
app.post(
  "/auth/signup",
  express.json(),
  validateData(userSchema),
  async (req, res) => {
    const data = req.body;
    try {
      const hashedPassword = await bcrypt.hash(data.password, 10);
      const [result] = await db.execute(
        "INSERT INTO Utilisateur (name, email, password, role) VALUES (?, ?, ?, ?)",
        [data.name, data.email, hashedPassword, data.role]
      );

      res.status(200);
      res.json({ id: result.insertId, name: data.name, email: data.email });
    } catch (error) {
      res.status(500);
      res.json({ error: error.message });
    }
  }
);

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
});

// Route POST /auth/login pour s'authentifier
app.post(
  "/auth/login",
  express.json(),
  validateData(loginSchema),
  async (req, res) => {
    const data = req.body;
    
    // On vérifie en base de données si email + password sont OK
    const [rows] = await db.query(
      "SELECT id, password FROM Utilisateur WHERE email = ?",
      [data.email]
    );

    if (rows.length === 0) {
      res.status(401);
      res.send("Unauthorized");
      return;
    }

    const isRightPassword = await bcrypt.compare(
      data.password,
      rows[0].password
    );
    if (!isRightPassword) {
      res.status(401);
      res.send("Unauthorized");
      return;
    }

    // Générer un token JWT
    const payload = { id: rows[0].id };
    const token = jwt.sign(payload, process.env.JWT_KEY);

    // Renvoyer le token si tout est OK
    res.json({ token });
  }
);

// ---------------------------------Gestion des sessions de cours----------------------------------

const sessionSchema = z.object({
  title: z.string().min(5)
});

// Route POST /sessions pour ajouter une session
app.post(
  "/sessions",
  express.json(),
  checkAuth,
  validateData(sessionSchema),
  async (req, res) => {
    const data = req.body;
    try {
      const [result] = await db.execute(
        "INSERT INTO Session (title, date, formateur_id) VALUES (?, ?, ?)",
        [data.title, data.date, data.formateur_id]
      );

      res.status(200);
      res.json({ id: result.insertId, title: data.title, date: data.date, formateur_id: data.formateur_id });
    } catch (error) {
      res.status(500);
      res.json({ error: error.message });
    }
  }
);

// Route GET /sessions pour voir toutes les sessions
app.get("/sessions", async (req, res) => {
  const page = parseInt(req.query.page || "1");
  console.log("page", page);

  // Validation du paramètre "page"
  if (Number.isNaN(page)) {
    res.status(400);
    res.send('Invalid query parameter "page"');
    return;
  }

  const size = parseInt(req.query.size || "5");
  console.log("size", size);

  // Validation du paramètre "size"
  if (Number.isNaN(size)) {
    res.status(400);
    res.send('Invalid query parameter "size"');
    return;
  }

  const start = (page - 1) * size;

  const [rows] = await db.query(
    "SELECT title, date, formateur_id FROM Session LIMIT ?, ?",
    [start, size]
  );

  res.json(rows);
});

// Route GET /sessions/:id pour voir une session en particulier
// (\\d+) : contrainte pour un id en décimal uniquement
app.get("/sessions/:id(\\d+)", async (req, res) => {
  const id = parseInt(req.params.id);
  const [rows] = await db.query(
    "SELECT title, date, formateur_id FROM Session WHERE id = ?",
    [id]
  );

  if (rows.length === 0) {
    res.status(404);
    res.send("Session not found");
    return;
  }

  res.json(rows[0]);
});

// Route PUT /sessions/id: pour modifier une session
app.put(
  "/sessions/:id(\\d+)",
  express.json(),
  checkAuth,
  validateData(sessionSchema),
  async (req, res) => {
    const id = parseInt(req.params.id);
    const data = req.body;
    try {
      const [result] = await db.execute(
        "UPDATE Session SET title = ?, date = ?, formateur_id = ? WHERE id = ?",
        [data.title, data.date, data.formateur_id, id]
      );

      res.status(200);
      res.json({ id: result.insertId, title: data.title, date: data.date, formateur_id: data.formateur_id });
    } catch (error) {
      res.status(500);
      res.json({ error: error.message });
    }
  }
);

// ------------------------------------------------------------------------------------------------
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
