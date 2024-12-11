import mysql2 from "mysql2/promise";

// Connexion à la base de données
async function connectDb() {
  let db = await mysql2.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    database: process.env.DB_DATABASE,
    password: process.env.DB_PASSWORD,
  });

  return db;
}

export { connectDb };