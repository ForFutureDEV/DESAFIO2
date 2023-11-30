// Importando as dependências
const express = require("express");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");

// Inicializando o Express
const app = express();
app.use(bodyParser.json());

// Configuração do pool do PostgreSQL
const pool = new Pool({
  connectionString:
    "postgres://default:ah36NbtoscnG@ep-wandering-meadow-14403252-pooler.us-east-1.postgres.vercel-storage.com:5432/verceldb?sslmode=require",
});

// Criando a tabela de usuários
pool.query(`CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  nome TEXT,
  email TEXT UNIQUE,
  senha TEXT,
  telefones TEXT,
  data_criacao TEXT,
  data_atualizacao TEXT,
  ultimo_login TEXT
)`);

// Função para buscar usuário por email
async function findUserByEmail(email) {
  const result = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
  return result.rows[0];
}

// Endpoint de Sign Up (Criação de Cadastro)
app.post("/signup", async (req, res) => {
  const { nome, email, senha, telefones } = req.body;

  try {
    const userExists = await findUserByEmail(email);
    if (userExists) {
      return res.status(400).json({ mensagem: "E-mail já existente" });
    }

    const hashedPassword = bcrypt.hashSync(senha, 10);
    const newUser = {
      id: Math.random().toString(36).substr(2, 9),
      nome,
      email,
      senha: hashedPassword,
      telefones: JSON.stringify(telefones),
      data_criacao: new Date().toISOString(),
      data_atualizacao: new Date().toISOString(),
      ultimo_login: new Date().toISOString(),
    };

    await pool.query(
      "INSERT INTO users (id, nome, email, senha, telefones, data_criacao, data_atualizacao, ultimo_login) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
      [
        newUser.id,
        newUser.nome,
        newUser.email,
        newUser.senha,
        newUser.telefones,
        newUser.data_criacao,
        newUser.data_atualizacao,
        newUser.ultimo_login,
      ]
    );

    const token = jwt.sign({ userId: newUser.id }, "segredo", { expiresIn: "30m" });

    return res.status(200).json({
      id: newUser.id,
      data_criacao: newUser.data_criacao,
      data_atualizacao: newUser.data_atualizacao,
      ultimo_login: newUser.ultimo_login,
      token,
    });
  } catch (err) {
    console.log(err);
    return res.status(500).json({ mensagem: "Erro ao criar usuário" });
  }
});

// Endpoint de Sign In (Autenticação)
app.post("/signin", async (req, res) => {
  const { email, senha } = req.body;

  try {
    const user = await findUserByEmail(email);
    if (!user || !bcrypt.compareSync(senha, user.senha)) {
      return res.status(401).json({ mensagem: "Usuário e/ou senha inválidos" });
    }

    user.ultimo_login = new Date().toISOString();
    await pool.query("UPDATE users SET ultimo_login = $1 WHERE id = $2", [user.ultimo_login, user.id]);

    const token = jwt.sign({ userId: user.id }, "segredo", { expiresIn: "30m" });

    return res.status(200).json({
      id: user.id,
      data_criacao: user.data_criacao,
      data_atualizacao: user.data_atualizacao,
      ultimo_login: user.ultimo_login,
      token,
    });
  } catch (err) {
    return res.status(500).json({ mensagem: "Erro ao buscar usuário" });
  }
});

// Endpoint para buscar usuário
app.get("/user", async (req, res) => {
  const token = req.headers.authorization;

  if (!token || !token.startsWith("Bearer ")) {
    return res.status(401).json({ mensagem: "Não autorizado" });
  }

  try {
    const decoded = jwt.verify(token.split(" ")[1], "segredo");
    const result = await pool.query("SELECT * FROM users WHERE id = $1", [decoded.userId]);
    const user = result.rows[0];

    if (!user) {
      return res.status(401).json({ mensagem: "Não autorizado" });
    }

    const diff = (new Date() - new Date(user.ultimo_login)) / 1000 / 60;
    if (diff > 30) {
      return res.status(401).json({ mensagem: "Sessão inválida" });
    }

    return res.status(200).json({
      id: user.id,
      data_criacao: user.data_criacao,
      data_atualizacao: user.data_atualizacao,
      ultimo_login: user.ultimo_login,
      token,
    });
  } catch (err) {
    return res.status(401).json({ mensagem: "Não autorizado" });
  }
});

// Iniciando o servidor na porta 3000
app.listen(3000, () => {
  console.log("Servidor iniciado na porta 3000");
});