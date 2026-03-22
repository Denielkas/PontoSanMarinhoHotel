const pool = require("../database/pool");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

exports.login = async (req, res) => {
  try {
    console.log("=== INICIO LOGIN ===");
    console.log("BODY:", req.body);

    const { username, password } = req.body || {};

    if (!username || !password) {
      console.log("FALHOU: username ou password ausente");
      return res.status(400).json({ error: "Username e password são obrigatórios" });
    }

    console.log("Buscando admin...");
    const { rows } = await pool.query(
      "SELECT * FROM admins WHERE username = $1 LIMIT 1",
      [username]
    );

    console.log("ROWS:", rows);

    const admin = rows[0];

    if (!admin) {
      console.log("FALHOU: admin não encontrado");
      return res.status(401).json({ error: "Credenciais inválidas" });
    }

    console.log("ADMIN ID:", admin.id);
    console.log("HASH:", admin.password_hash);
    console.log("JWT_SECRET existe?", !!process.env.JWT_SECRET);

    const ok = bcrypt.compareSync(password, admin.password_hash);
    console.log("COMPARE OK:", ok);

    if (!ok) {
      console.log("FALHOU: senha inválida");
      return res.status(401).json({ error: "Credenciais inválidas" });
    }

    console.log("Gerando token...");
    const token = jwt.sign(
      {
        sub: admin.id,
        username: admin.username,
        role: "admin",
      },
      process.env.JWT_SECRET,
      { expiresIn: "5h" }
    );

    console.log("LOGIN OK");

    return res.json({
      token,
      username: admin.username,
    });
  } catch (err) {
    console.error("ERRO LOGIN:", err);
    return res.status(500).json({
      error: "Erro interno no login",
      detalhe: err.message,
    });
  }
};