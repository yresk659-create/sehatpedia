import { createServer } from "node:http";
import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { promisify } from "node:util";
import {
  randomBytes,
  randomUUID,
  scrypt as callbackScrypt,
  scryptSync,
  timingSafeEqual
} from "node:crypto";

const root = path.dirname(fileURLToPath(import.meta.url));
const host = process.env.HOST || "127.0.0.1";
const port = Number(process.env.PORT || 3000);
const dataDirectory = process.env.DATA_DIR ? path.resolve(process.env.DATA_DIR) : path.join(root, "data");
const usersFile = path.join(dataDirectory, "users.json");
const maxRequestBytes = 16 * 1024;
const rateLimitWindowMs = 60 * 1000;
const rateLimitMax = 12;
const requestsByAddress = new Map();
const loginAttempts = new Map();
const registrationAttempts = new Map();
const usersByEmail = new Map();
const usersById = new Map();
const sessions = new Map();
const sessionLifetimeMs = 7 * 24 * 60 * 60 * 1000;
const sessionCookieName = "sehatpedia_session";
const passwordKeyLength = 64;
const scrypt = promisify(callbackScrypt);
const dummySalt = randomBytes(16);
const dummyHash = scryptSync(randomBytes(32), dummySalt, passwordKeyLength, { N: 1 << 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
let registrationQueue = Promise.resolve();

const systemPrompt = [
  "Kamu adalah asisten edukasi kesehatan berbahasa Indonesia.",
  "Berikan informasi umum yang ringkas, jelas, empatik, dan tidak menghakimi.",
  "Jangan mendiagnosis, memastikan penyebab gejala, meresepkan obat, atau menyarankan perubahan dosis.",
  "Jelaskan bahwa informasi umum tidak menggantikan pemeriksaan tenaga kesehatan dan sarankan konsultasi untuk keluhan pribadi atau menetap.",
  "Untuk tanda gawat seperti sesak berat, nyeri dada berat, pingsan, perdarahan hebat, tanda stroke, atau risiko menyakiti diri, arahkan segera ke IGD atau layanan darurat setempat.",
  "Jangan meminta nama lengkap, NIK, alamat, nomor telepon, atau informasi pribadi lain.",
  "Jika tidak yakin, katakan dengan jujur dan sarankan bantuan tenaga kesehatan."
].join(" ");

function sendJson(response, statusCode, payload) {
  response.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff"
  });
  response.end(JSON.stringify(payload));
}

function readJsonBody(request) {
  return new Promise((resolve, reject) => {
    let size = 0;
    let tooLarge = false;
    const chunks = [];
    request.on("data", (chunk) => {
      size += chunk.length;
      if (size > maxRequestBytes) {
        tooLarge = true;
        chunks.length = 0;
        return;
      }
      if (!tooLarge) chunks.push(chunk);
    });
    request.on("end", () => {
      if (tooLarge) {
        reject(Object.assign(new Error("Permintaan terlalu besar."), { statusCode: 413 }));
        return;
      }
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")));
      } catch {
        reject(Object.assign(new Error("Format permintaan tidak valid."), { statusCode: 400 }));
      }
    });
    request.on("error", reject);
  });
}

function isRateLimited(address) {
  const now = Date.now();
  const entry = requestsByAddress.get(address);
  if (!entry || now - entry.startedAt >= rateLimitWindowMs) {
    requestsByAddress.set(address, { startedAt: now, count: 1 });
    return false;
  }
  entry.count += 1;
  return entry.count > rateLimitMax;
}

function validateMessages(value) {
  if (!Array.isArray(value) || value.length < 1 || value.length > 10) return null;
  const messages = [];
  for (const item of value) {
    if (!item || !["user", "assistant"].includes(item.role) ||
        typeof item.content !== "string" || item.content.trim().length === 0 ||
        item.content.length > 1800) return null;
    messages.push({ role: item.role, content: item.content.trim() });
  }
  return messages.at(-1).role === "user" ? messages : null;
}

function getClientAddress(request) {
  return request.socket.remoteAddress || "unknown";
}

function isWithinLimit(store, address, windowMs, maximum) {
  const now = Date.now();
  const entry = store.get(address);
  if (!entry || now - entry.startedAt >= windowMs) {
    store.set(address, { startedAt: now, count: 1 });
    return false;
  }
  entry.count += 1;
  return entry.count > maximum;
}

function publicUser(user) {
  return { id: user.id, name: user.name, email: user.email };
}

function serializeUsers() {
  return JSON.stringify([...usersByEmail.values()], null, 2);
}

async function persistUsers() {
  const directory = path.dirname(usersFile);
  const temporaryFile = path.join(directory, `.users-${randomBytes(8).toString("hex")}.tmp`);
  await writeFile(temporaryFile, serializeUsers(), { encoding: "utf8", mode: 0o600, flag: "wx" });
  try {
    await rename(temporaryFile, usersFile);
  } catch (error) {
    await rm(temporaryFile, { force: true });
    throw error;
  }
}

async function loadUsers() {
  await mkdir(path.dirname(usersFile), { recursive: true });
  let contents;
  try {
    contents = await readFile(usersFile, "utf8");
  } catch (error) {
    if (error.code === "ENOENT") return;
    throw error;
  }

  const savedUsers = JSON.parse(contents);
  if (!Array.isArray(savedUsers)) throw new Error("File akun tidak memiliki format yang valid.");
  for (const user of savedUsers) {
    if (!user || typeof user.id !== "string" || typeof user.email !== "string" ||
        typeof user.name !== "string" || typeof user.passwordSalt !== "string" ||
        typeof user.passwordHash !== "string") {
      throw new Error("File akun berisi data yang tidak valid; server tidak dimulai demi keamanan.");
    }
    const email = user.email.toLocaleLowerCase("en-US");
    if (usersByEmail.has(email) || usersById.has(user.id)) {
      throw new Error("File akun memiliki identitas duplikat; server tidak dimulai demi keamanan.");
    }
    usersByEmail.set(email, { ...user, email });
    usersById.set(user.id, usersByEmail.get(email));
  }
}

function parseCookies(request) {
  const cookieHeader = request.headers.cookie || "";
  const cookie = cookieHeader.split(";").map((part) => part.trim())
    .find((part) => part.startsWith(`${sessionCookieName}=`));
  return cookie ? cookie.slice(sessionCookieName.length + 1) : "";
}

function getAuthenticatedUser(request) {
  const token = parseCookies(request);
  if (!/^[A-Za-z0-9_-]{40,50}$/.test(token)) return null;
  const session = sessions.get(token);
  if (!session) return null;
  if (session.expiresAt <= Date.now()) {
    sessions.delete(token);
    return null;
  }
  return usersById.get(session.userId) || null;
}

function setSessionCookie(response, token) {
  const secure = process.env.COOKIE_SECURE === "true" ? "; Secure" : "";
  response.setHeader(
    "Set-Cookie",
    `${sessionCookieName}=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${sessionLifetimeMs / 1000}${secure}`
  );
}

function clearSessionCookie(response) {
  const secure = process.env.COOKIE_SECURE === "true" ? "; Secure" : "";
  response.setHeader("Set-Cookie", `${sessionCookieName}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0${secure}`);
}

function hasTrustedOrigin(request) {
  const origin = request.headers.origin;
  if (!origin) return false;
  const defaultOrigin = `${request.socket.encrypted ? "https" : "http"}://${request.headers.host || "localhost"}`;
  try {
    return new URL(origin).origin === new URL(process.env.PUBLIC_ORIGIN || defaultOrigin).origin;
  } catch {
    return false;
  }
}

function hasJsonContentType(request) {
  return (request.headers["content-type"] || "").split(";")[0].trim().toLowerCase() === "application/json";
}

function validateAccountInput(body, includeName) {
  if (!body || typeof body !== "object" || Array.isArray(body)) return null;
  const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
  const password = typeof body.password === "string" ? body.password : "";
  const name = typeof body.name === "string" ? body.name.trim() : "";
  if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) return null;
  if (password.length < 10 || password.length > 128) return null;
  if (includeName && (!name || name.length > 60 || /[\u0000-\u001f\u007f]/.test(name))) return null;
  return { email, password, name };
}

async function hashPassword(password, salt = randomBytes(16)) {
  const hash = await scrypt(password, salt, passwordKeyLength, {
    N: 1 << 15,
    r: 8,
    p: 1,
    maxmem: 64 * 1024 * 1024
  });
  return { salt: salt.toString("base64"), hash: Buffer.from(hash).toString("base64") };
}

async function verifyPassword(password, user) {
  const salt = Buffer.from(user.passwordSalt, "base64");
  const expected = Buffer.from(user.passwordHash, "base64");
  if (salt.length !== 16 || expected.length !== passwordKeyLength) return false;
  const actual = await scrypt(password, salt, passwordKeyLength, {
    N: 1 << 15,
    r: 8,
    p: 1,
    maxmem: 64 * 1024 * 1024
  });
  return timingSafeEqual(Buffer.from(actual), expected);
}

async function readJsonRequest(request, response) {
  if (!hasJsonContentType(request)) {
    sendJson(response, 415, { error: "Permintaan harus menggunakan JSON." });
    return null;
  }
  try {
    return await readJsonBody(request);
  } catch (error) {
    sendJson(response, error.statusCode || 400, { error: error.message || "Permintaan tidak dapat dibaca." });
    return null;
  }
}

async function handleAuth(request, response, pathname) {
  if (pathname === "/api/auth/me" && request.method === "GET") {
    const user = getAuthenticatedUser(request);
    sendJson(response, 200, { user: user ? publicUser(user) : null });
    return;
  }

  if (!["POST"].includes(request.method)) {
    response.setHeader("Allow", pathname.endsWith("/logout") ? "POST" : "GET, POST");
    sendJson(response, 405, { error: "Metode tidak diizinkan." });
    return;
  }
  if (!hasTrustedOrigin(request)) {
    sendJson(response, 403, { error: "Asal permintaan tidak diizinkan." });
    return;
  }

  if (pathname === "/api/auth/logout") {
    const token = parseCookies(request);
    if (token) sessions.delete(token);
    clearSessionCookie(response);
    sendJson(response, 200, { ok: true });
    return;
  }

  const isRegister = pathname === "/api/auth/register";
  if (!isRegister && pathname !== "/api/auth/login") {
    sendJson(response, 404, { error: "Halaman tidak ditemukan." });
    return;
  }

  const address = getClientAddress(request);
  const limited = isRegister
    ? isWithinLimit(registrationAttempts, address, 15 * 60 * 1000, 5)
    : isWithinLimit(loginAttempts, address, 15 * 60 * 1000, 10);
  if (limited) {
    sendJson(response, 429, { error: "Terlalu banyak percobaan. Silakan coba lagi nanti." });
    return;
  }

  const body = await readJsonRequest(request, response);
  if (body === null) return;
  const account = validateAccountInput(body, isRegister);
  if (!account) {
    sendJson(response, 400, {
      error: isRegister
        ? "Isi nama, email yang valid, dan kata sandi minimal 10 karakter."
        : "Masukkan email dan kata sandi yang valid."
    });
    return;
  }

  let user;
  if (isRegister) {
    const registration = registrationQueue.then(async () => {
      if (usersByEmail.has(account.email)) {
        return { conflict: true };
      }
      const { salt, hash } = await hashPassword(account.password);
      user = {
        id: randomUUID(),
        name: account.name,
        email: account.email,
        passwordSalt: salt,
        passwordHash: hash,
        createdAt: new Date().toISOString()
      };
      usersByEmail.set(user.email, user);
      usersById.set(user.id, user);
      try {
        await persistUsers();
      } catch (error) {
        usersByEmail.delete(user.email);
        usersById.delete(user.id);
        throw error;
      }
      return { conflict: false };
    });
    registrationQueue = registration.catch(() => {});
    try {
      const result = await registration;
      if (result.conflict) {
        sendJson(response, 409, { error: "Email sudah terdaftar. Silakan masuk." });
        return;
      }
    } catch (error) {
      console.error("Could not save the new account.", error.message);
      sendJson(response, 500, { error: "Akun tidak dapat disimpan. Coba lagi nanti." });
      return;
    }
  } else {
    user = usersByEmail.get(account.email);
    const verified = await verifyPassword(account.password, user || {
      passwordSalt: dummySalt.toString("base64"),
      passwordHash: Buffer.from(dummyHash).toString("base64")
    });
    if (!user || !verified) {
      sendJson(response, 401, { error: "Email atau kata sandi salah." });
      return;
    }
  }

  const token = randomBytes(32).toString("base64url");
  const expiresAt = Date.now() + sessionLifetimeMs;
  sessions.set(token, { userId: user.id, expiresAt });
  setSessionCookie(response, token);
  sendJson(response, isRegister ? 201 : 200, { user: publicUser(user) });
}

async function handleChat(request, response) {
  const address = request.socket.remoteAddress || "unknown";
  if (!hasTrustedOrigin(request)) {
    sendJson(response, 403, { error: "Asal permintaan tidak diizinkan." });
    return;
  }
  if (!getAuthenticatedUser(request)) {
    sendJson(response, 401, { error: "Masuk ke akun terlebih dahulu untuk menggunakan asisten AI." });
    return;
  }
  if (isRateLimited(address)) {
    sendJson(response, 429, { error: "Terlalu banyak permintaan. Silakan tunggu sebentar lalu coba lagi." });
    return;
  }

  if (!process.env.OPENAI_API_KEY) {
    sendJson(response, 503, { error: "Asisten AI belum dikonfigurasi. Atur OPENAI_API_KEY lalu jalankan ulang server." });
    return;
  }

  let body;
  try {
    body = await readJsonBody(request);
  } catch (error) {
    sendJson(response, error.statusCode || 400, { error: error.message || "Permintaan tidak dapat dibaca." });
    return;
  }

  const messages = validateMessages(body?.messages);
  if (!messages) {
    sendJson(response, 400, { error: "Pesan tidak valid. Kirim 1–10 pesan teks dengan pertanyaan terakhir." });
    return;
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 30_000);
  try {
    const upstream = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${process.env.OPENAI_API_KEY}`,
        "Content-Type": "application/json"
      },
      signal: controller.signal,
      body: JSON.stringify({
        model: process.env.OPENAI_MODEL || "gpt-4o-mini",
        messages: [{ role: "system", content: systemPrompt }, ...messages],
        max_tokens: 700,
        temperature: 0.4
      })
    });

    if (!upstream.ok) {
      console.error(`OpenAI returned HTTP ${upstream.status}.`);
      sendJson(response, 502, { error: "Layanan AI sedang bermasalah. Coba lagi nanti." });
      return;
    }

    const result = await upstream.json();
    const reply = result.choices?.[0]?.message?.content;
    if (typeof reply !== "string" || !reply.trim()) {
      console.error("OpenAI response did not contain a text reply.");
      sendJson(response, 502, { error: "Layanan AI mengirim jawaban yang tidak dapat dibaca. Coba lagi." });
      return;
    }
    sendJson(response, 200, { reply: reply.trim() });
  } catch (error) {
    console.error(error.name === "AbortError" ? "OpenAI request timed out." : "OpenAI request failed.");
    sendJson(response, 502, { error: "Tidak dapat menghubungi layanan AI. Periksa koneksi lalu coba lagi." });
  } finally {
    clearTimeout(timeout);
  }
}

const server = createServer(async (request, response) => {
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  response.setHeader("X-Frame-Options", "DENY");
  response.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self' https://api.openai.com; img-src 'self' data:; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
  );

  const url = new URL(request.url, `http://${request.headers.host || "localhost"}`);
  if (url.pathname.startsWith("/api/auth/")) {
    try {
      await handleAuth(request, response, url.pathname);
    } catch (error) {
      console.error("Authentication request failed.", error.message);
      if (!response.headersSent) {
        sendJson(response, 500, { error: "Permintaan akun gagal diproses. Coba lagi nanti." });
      } else {
        response.destroy();
      }
    }
    return;
  }

  if (url.pathname === "/api/chat") {
    if (request.method !== "POST") {
      response.setHeader("Allow", "POST");
      sendJson(response, 405, { error: "Metode tidak diizinkan." });
      return;
    }
    await handleChat(request, response);
    return;
  }

  if (request.method === "GET" && (url.pathname === "/" || url.pathname === "/index.html")) {
    try {
      const html = await readFile(path.join(root, "index.html"));
      response.writeHead(200, {
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "no-cache"
      });
      response.end(html);
    } catch (error) {
      console.error("Could not read index.html.", error.message);
      sendJson(response, 500, { error: "Halaman tidak dapat dimuat." });
    }
    return;
  }

  sendJson(response, 404, { error: "Halaman tidak ditemukan." });
});

loadUsers().then(() => {
  server.listen(port, host, () => {
    console.log(`Sehatpedia berjalan di http://${host}:${port}`);
  });
}).catch((error) => {
  console.error("Could not load account data. Server will not start.", error.message);
  process.exitCode = 1;
});
