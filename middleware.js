import { connectDb } from "./lib.js";
import jwt from "jsonwebtoken";

// Vérification des conditions fixées avec zod
function validateData(schema) {
  return (req, res, next) => {
    try {
      schema.parse(req.body);
    } catch (error) {
      res.status(400);
      res.json({ error: error.errors });
      return;
    }

    next();
  };
}

// Vérification des autorisations nécessaires pour effectuer une action en tant que formateur
async function checkAuthForm(req, res, next) {
  const { authorization } = req.headers;

  try {
    const decoded = jwt.verify(authorization, process.env.JWT_KEY);
    const db = await connectDb();
    const [rows] = await db.query(
      "SELECT id, name, email FROM Utilisateur WHERE id = ? AND role = 'formateur'",
      [decoded.id]
    );

    if (rows.length === 0) {
      throw new Error("User not found");
    }

    req.user = rows[0];
    return next();
  } catch (error) {
    console.error(error);
  }

  res.status(401);
  res.send("Unauthorized");
  return;
}

// Vérification des autorisations nécessaires pour effectuer une action en tant qu'étudiant
async function checkAuthStud(req, res, next) {
  const { authorization } = req.headers;

  try {
    const decoded = jwt.verify(authorization, process.env.JWT_KEY);
    const db = await connectDb();
    const [rows] = await db.query(
      "SELECT id, name, email FROM Utilisateur WHERE id = ? AND role = 'etudiant'",
      [decoded.id]
    );

    if (rows.length === 0) {
      throw new Error("User not found");
    }

    req.user = rows[0];
    return next();
  } catch (error) {
    console.error(error);
  }

  res.status(401);
  res.send("Unauthorized");
  return;
}

export { validateData, checkAuthForm,  checkAuthStud };