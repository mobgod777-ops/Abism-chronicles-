"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const path = require("node:path");
const cors = require("cors");
const express = require("express");

const root = __dirname;
const app = express();
app.disable("x-powered-by");
app.set("trust proxy", 1);
app.use(cors());
const dataDirectory = process.env.ABISM_DATA_DIR || path.join(root, "data");
const dataFile = path.join(dataDirectory, "accounts.json");
const PORT = process.env.PORT || 3000;
const sessionLifetime = 1000 * 60 * 60 * 24 * 14;
const sessions = new Map();
const authAttempts = new Map();
let accounts = new Map();
let saveQueue = Promise.resolve();

const titleAwards = {
  level: ["Magnata dos níveis", "Mestre dos níveis", "Aventureiro de elite"],
  dungeons: ["Doido por grind", "Desbravador do Abismo", "Caçador de masmorras"],
};

async function loadAccounts() {
  try {
    const data = JSON.parse(await fs.readFile(dataFile, "utf8"));
    accounts = new Map((Array.isArray(data.accounts) ? data.accounts : []).map((account) => [account.key, account]));
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
}

function saveAccounts() {
  const data = JSON.stringify({ accounts: [...accounts.values()] });
  saveQueue = saveQueue.then(async () => {
    await fs.mkdir(dataDirectory, { recursive: true });
    const temporaryFile = `${dataFile}.tmp`;
    await fs.writeFile(temporaryFile, data, { mode: 0o600 });
    await fs.rename(temporaryFile, dataFile);
  });
  return saveQueue;
}

function sendJson(response, status, value) {
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
  });
  response.end(JSON.stringify(value));
}

function readJson(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let length = 0;
    request.on("data", (chunk) => {
      length += chunk.length;
      if (length > 8192) {
        reject(Object.assign(new Error("Corpo da requisição muito grande."), { status: 413 }));
        request.destroy();
        return;
      }
      chunks.push(chunk);
    });
    request.on("end", () => {
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}"));
      } catch {
        reject(Object.assign(new Error("JSON inválido."), { status: 400 }));
      }
    });
    request.on("error", reject);
  });
}

function requestIp(request) {
  return request.ip || request.socket.remoteAddress || "unknown";
}

function checkAuthRate(request) {
  const now = Date.now();
  const key = requestIp(request);
  const entry = authAttempts.get(key) || { count: 0, resetAt: now + 15 * 60 * 1000 };
  if (now > entry.resetAt) {
    entry.count = 0;
    entry.resetAt = now + 15 * 60 * 1000;
  }
  entry.count++;
  authAttempts.set(key, entry);
  return entry.count <= 12;
}

function makeSession(account) {
  const token = crypto.randomBytes(32).toString("base64url");
  sessions.set(token, { key: account.key, expiresAt: Date.now() + sessionLifetime });
  return token;
}

function getAccount(request) {
  const token = request.headers.authorization?.match(/^Bearer\s+(.+)$/i)?.[1];
  const session = token && sessions.get(token);
  if (!session || session.expiresAt < Date.now()) {
    if (token) sessions.delete(token);
    return null;
  }
  return accounts.get(session.key) || null;
}

function publicAccount(account) {
  return {
    username: account.username,
    level: account.level,
    dungeons: account.dungeons,
  };
}

function sortBoard(field) {
  return [...accounts.values()]
    .sort((left, right) => right[field] - left[field] || left.username.localeCompare(right.username, "pt-BR"));
}

function makeBoard(field, boardName) {
  return sortBoard(field).slice(0, 100).map((account, index) => ({
    position: index + 1,
    username: account.username,
    score: account[field],
    title: index < 3 ? titleAwards[boardName][index] : "",
  }));
}

function titlesForAccount(account) {
  if (!account) return [];
  const titles = [];
  for (const [boardName, field] of [["level", "level"], ["dungeons", "dungeons"]]) {
    const position = sortBoard(field).findIndex((entry) => entry.key === account.key);
    if (position >= 0 && position < 3)
      titles.push({ id: `${boardName}-${position + 1}`, name: titleAwards[boardName][position] });
  }
  return titles;
}

function leaderboardResponse(account) {
  return {
    level: makeBoard("level", "level"),
    dungeons: makeBoard("dungeons", "dungeons"),
    awardedTitles: titlesForAccount(account),
  };
}

function safeEqual(left, right) {
  const a = Buffer.from(left, "hex");
  const b = Buffer.from(right, "hex");
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

async function handleApi(request, response, pathname) {
  if (pathname === "/api/register" && request.method === "POST") {
    if (!checkAuthRate(request)) return sendJson(response, 429, { error: "Muitas tentativas. Aguarde 15 minutos." });
    const body = await readJson(request);
    const username = String(body.username || "").trim();
    const key = username.toLowerCase();
    const password = String(body.password || "");
    if (!/^[\p{L}\p{N}_-]{3,20}$/u.test(username))
      return sendJson(response, 400, { error: "Use um nome de 3 a 20 letras, números, _ ou -." });
    if (password.length < 10 || password.length > 128)
      return sendJson(response, 400, { error: "A senha deve ter entre 10 e 128 caracteres." });
    if (accounts.has(key)) return sendJson(response, 409, { error: "Esse nome de usuário já existe." });
    const salt = crypto.randomBytes(16).toString("hex");
    const hash = crypto.scryptSync(password, salt, 64).toString("hex");
    const now = new Date().toISOString();
    const account = { key, username, salt, hash, level: 1, dungeons: 0, createdAt: now };
    accounts.set(key, account);
    await saveAccounts();
    return sendJson(response, 201, { token: makeSession(account), user: publicAccount(account) });
  }

  if (pathname === "/api/login" && request.method === "POST") {
    if (!checkAuthRate(request)) return sendJson(response, 429, { error: "Muitas tentativas. Aguarde 15 minutos." });
    const body = await readJson(request);
    const account = accounts.get(String(body.username || "").trim().toLowerCase());
    const password = String(body.password || "");
    const candidate = account ? crypto.scryptSync(password, account.salt, 64).toString("hex") : crypto.scryptSync(password || "invalid", "abismo-invalid-salt", 64).toString("hex");
    if (!account || !safeEqual(candidate, account.hash))
      return sendJson(response, 401, { error: "Usuário ou senha incorretos." });
    return sendJson(response, 200, { token: makeSession(account), user: publicAccount(account) });
  }

  const account = getAccount(request);
  if (pathname === "/api/me" && request.method === "GET") {
    if (!account) return sendJson(response, 401, { error: "Entre na sua conta." });
    return sendJson(response, 200, { user: publicAccount(account), awardedTitles: titlesForAccount(account) });
  }
  if (pathname === "/api/logout" && request.method === "POST") {
    const token = request.headers.authorization?.match(/^Bearer\s+(.+)$/i)?.[1];
    if (token) sessions.delete(token);
    return sendJson(response, 200, { ok: true });
  }
  if (pathname === "/api/score" && request.method === "POST") {
    if (!account) return sendJson(response, 401, { error: "Entre na sua conta." });
    const body = await readJson(request);
    const level = Number(body.level);
    const dungeons = Number(body.dungeons);
    if (!Number.isSafeInteger(level) || level < 1 || level > 120 || !Number.isSafeInteger(dungeons) || dungeons < 0 || dungeons > 50)
      return sendJson(response, 400, { error: "Pontuação inválida." });
    account.level = Math.max(account.level, level);
    account.dungeons = Math.max(account.dungeons, dungeons);
    await saveAccounts();
    return sendJson(response, 200, { user: publicAccount(account), awardedTitles: titlesForAccount(account) });
  }
  if (pathname === "/api/leaderboard" && request.method === "GET")
    return sendJson(response, 200, leaderboardResponse(account));
  return sendJson(response, 404, { error: "Rota não encontrada." });
}

app.get("/", (_request, response) => response.redirect(302, "/Abism%20v4.2/index.html"));
app.all("/api/:action", async (request, response) => {
  try {
    await handleApi(request, response, `/api/${request.params.action}`);
  } catch (error) {
    if (!response.headersSent)
      sendJson(response, error.status || 500, { error: error.status ? error.message : "Erro interno do servidor." });
    else response.end();
    if (!error.status) console.error(error);
  }
});
app.use("/api", (_request, response) => sendJson(response, 404, { error: "Rota não encontrada." }));
app.use("/data", (_request, response) => response.sendStatus(404));
app.use(express.static(root, {
  dotfiles: "ignore",
  index: false,
  redirect: false,
  setHeaders(response) {
    response.setHeader("x-content-type-options", "nosniff");
  },
}));
app.use((_request, response) => response.status(404).send("Not found"));

async function start() {
  await loadAccounts();
  app.listen(PORT, "0.0.0.0", () => console.log(`Crônicas do Abismo ouvindo na porta ${PORT}`));
}

start().catch((error) => {
  console.error("Não foi possível iniciar o servidor:", error);
  process.exitCode = 1;
});