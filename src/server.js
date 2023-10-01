import "dotenv/config";
import express from "express";
import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();
const app = express();
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import cors from "cors";
const port = 3333;

app.use(express.json());
app.use(cors());

const verifyJWT = (req, res, next) => {
  const token = req.headers["authorization"]?.split(" ")[1];

  if (!token) {
    return res
      .status(401)
      .json({ message: "Acesso negado, token não fornecido" });
  }

  try {
    const decoded = jwt.verify(token, process.env.KEY_JWT);
    console.log(decoded);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ message: "Token inválido" });
  }
};

const verifyAdmin = (req, res, next) => {
  const token = req.headers["authorization"]?.split(" ")[1];

  if (!token) {
    return res
      .status(401)
      .json({ message: "Acesso negado, token não fornecido" });
  }

  try {
    const decoded = jwt.verify(token, process.env.KEY_JWT);
    if (decoded.roles !== "ADMIN") {
      return res
        .status(403)
        .json({ message: "Acesso negado, você não é um administrador" });
    }
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ message: "Token inválido" });
  }
};

app.get("/carros", verifyJWT, async (req, res) => {
  const carros = await prisma.carro.findMany();
  res.status(200).json(carros);
});

app.get("/carros/:id", verifyJWT, async (req, res) => {
  const { id } = req.params;
  const carro = await prisma.carro.findUnique({ where: { id: id } });
  res.status(200).json(carro);
});

app.post("/carros", verifyAdmin, async (req, res) => {
  const { placa, marca, modelo, valor } = req.body;

  const carroExistente = await prisma.carro.findUnique({
    where: {
      placa: placa,
    },
  });

  if (carroExistente) {
    return res.status(400).json({ error: "Placa já registrada." });
  }

  const newCarro = await prisma.carro.create({
    data: { placa, marca, modelo, valor },
  });

  res.status(201).json(newCarro);
});

app.put("/carros/:id", verifyAdmin, async (req, res) => {
  const { id } = req.params;
  const updateData = req.body;
  const updatedCarro = await prisma.carro.update({
    where: { id: id },
    data: updateData,
  });
  res.status(200).json(updatedCarro);
});

app.delete("/carros/:id", verifyAdmin, async (req, res) => {
  const { id } = req.params;
  await prisma.carro.delete({ where: { id: id } });
  res.status(200).json({ message: "Carro deletado com sucesso!" });
});

app.post("/seguranca/register", verifyAdmin, async (req, res) => {
  const { nome, email, login, senha } = req.body;

  const hashedPassword = await bcrypt.hash(senha, 10);
  const newUser = await prisma.usuario.create({
    data: {
      nome,
      email,
      login,
      senha: hashedPassword,
    },
  });

  res.status(201).json(newUser);
});

app.post("/seguranca/login", async (req, res) => {
  const { login, senha } = req.body;

  const user = await prisma.usuario.findUnique({ where: { login } });

  if (!user) {
    return res.status(404).json({ error: "Usuário não encontrado" });
  }

  const isPasswordValid = await bcrypt.compare(senha, user.senha);

  if (!isPasswordValid) {
    return res.status(401).json({ error: "Senha inválida" });
  }

  const token = jwt.sign(
    { id: user.id, login: user.login, roles: user.roles },
    process.env.KEY_JWT,
    { expiresIn: "1h" }
  );

  res.status(200).json({ token });
});

app.listen(port, () => {
  console.log(`Servidor rodando na porta ${port}`);
});
