import "dotenv/config";

import express from "express";
import z from "zod"; // Permet de valider les données en entrée par le biais de schéma de données
import jwt from "jsonwebtoken"; // Permet de générer des tokens
import bcrypt from "bcrypt"; // Permet de crypter un mot de passe par un protocole de hash ou autre

import { connectDb } from "./lib.js";
import { validateData, checkAuthForm, checkAuthStud } from "./middleware.js";

const app = express();

let db = await connectDb();

// --------------------------Gestion des utilisateurs----------------------------

// Schéma de données pour l'inscription
const userSchema = z.object({
  name: z.string().min(2), // minimum 2 caractères
  email: z.string().email(), // format email
  password: z.string().min(8)
});

// Route POST /auth/signup pour ajouter un utilisateur
app.post("/auth/signup",
  express.json(),
  validateData(userSchema), // validation du schéma de données en entrée
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

// Schéma de données pour la connexion
const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
});

// Route POST /auth/login pour s'authentifier
app.post("/auth/login",
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
    const payload = { id: rows[0].id, role: rows[0].role };
    const token = jwt.sign(payload, process.env.JWT_KEY);

    // Renvoyer le token si tout est OK
    res.json({ token });
  }
);

// ---------------------------------Gestion des sessions de cours----------------------------------

// Schéma de données pour la création d'une session
const sessionSchema = z.object({
  title: z.string().min(5)
});

// Route POST /sessions pour ajouter une session
app.post("/sessions",
  express.json(),
  checkAuthForm,
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

  const [rows] = await db.query(
    "SELECT title, date, formateur_id FROM Session"
  );

  res.json(rows);
});

// Route GET /sessions/:id pour voir une session en particulier
// (\\d+) : contrainte pour un id en décimal uniquement
app.get("/sessions/:id(\\d+)", async (req, res) => {
  const id = parseInt(req.params.id);
  const [rows] = await db.query(
    "SELECT s.title, s.date, u.name FROM Session s LEFT JOIN Utilisateur u ON s.id = u.id WHERE s.id = ?",
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
app.put("/sessions/:id(\\d+)",
  express.json(),
  checkAuthForm,
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
      res.json({ title: data.title, date: data.date, formateur_id: data.formateur_id });
    } catch (error) {
      res.status(500);
      res.json({ error: error.message });
    }
  }
);

// Route DELETE /sessions/:id pour supprimer une session en particulier
app.delete("/sessions/:id(\\d+)",
  checkAuthForm,
  async (req, res) => {
  const id = parseInt(req.params.id);
  const [rows] = await db.query(
    "DELETE FROM Session WHERE id = ?",
    [id]
  );

  if (rows.length === 0) {
    res.status(404);
    res.send("Session not found");
    return;
  }

  res.send("Session deleted");
});

// ------------------------------------Gestion des émargements-------------------------------------

// Route POST /sessions/:id/emargement pour émarger à une session
app.post("/sessions/:id(\\d+)/emargement",
  express.json(),
  checkAuthStud,
  async (req, res) => {
    const id = parseInt(req.params.id);
    const data = req.body;
    try {
      const [result] = await db.execute(
        "INSERT INTO Emargement (session_id, etudiant_id, status) VALUES (?, ?, True)",
        [id, data.etudiant_id]
      );

      res.status(200);
      res.json({ id: result.insertId, session_id: data.session_id, etudiant_id: data.etudiant_id, status: result.status });
    } catch (error) {
      res.status(500);
      res.json({ error: error.message });
    }
  }
);

// Route GET /sessions/:id/emargement pour voir tous les élèves présents à une session
app.get("/sessions/:id/emargement",
  checkAuthForm,
  async (req, res) => {

  const [rows] = await db.query(
    "SELECT u.name FROM Utilisateur u INNER JOIN Emargement e ON u.id = e.etudiant_id"
  );

  res.json(rows);
});

// ------------------------------------------------------------------------------------------------

app.listen(8080, () => {
  console.log("Server is running on port 8080");
});