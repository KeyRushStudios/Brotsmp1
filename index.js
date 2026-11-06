import express from 'express';
import cors from 'cors';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import mysql from 'mysql2/promise';

// ---------- Konfiguration ----------
const {
  PORT = 10000,
  DB_HOST, DB_PORT = 3306, DB_USER, DB_PASSWORD, DB_NAME, DB_SSL,
  JWT_SECRET,
  ALLOWED_ORIGINS = '',
} = process.env;

if (!JWT_SECRET || !DB_HOST || !DB_USER || !DB_NAME) {
  throw new Error('Fehlende Umgebungsvariablen: JWT_SECRET, DB_HOST, DB_USER, DB_NAME');
}

const BCRYPT_ROUNDS = 12;
const TOKEN_TTL = '7d';

// ---------- Datenbank ----------
const pool = mysql.createPool({
  host: DB_HOST,
  port: Number(DB_PORT),
  user: DB_USER,
  password: DB_PASSWORD,
  database: DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  ssl: DB_SSL === 'true' ? { rejectUnauthorized: true } : undefined,
});

// ---------- Hilfsfunktionen ----------
const NAME_RE = /^[\p{L}][\p{L}\s'-]{0,49}$/u;
const MC_RE = /^[A-Za-z0-9_]{3,16}$/;

function ageOn(date, today = new Date()) {
  let age = today.getFullYear() - date.getFullYear();
  const m = today.getMonth() - date.getMonth();
  if (m < 0 || (m === 0 && today.getDate() < date.getDate())) age--;
  return age;
}

function validateRegister(body) {
  const firstName = String(body.firstName ?? '').trim();
  const lastName = body.lastName ? String(body.lastName).trim() : null;
  const mcName = String(body.mcName ?? '').trim();
  const birthDate = String(body.birthDate ?? '');
  const password = String(body.password ?? '');

  if (!NAME_RE.test(firstName)) return { error: 'Bitte gib deinen echten Vornamen an' };
  if (lastName !== null && !NAME_RE.test(lastName)) return { error: 'Ungültiger Nachname' };
  if (!MC_RE.test(mcName)) return { error: 'Ungültiger Minecraft-Name (3–16 Zeichen: Buchstaben, Zahlen, _)' };

  const bd = new Date(birthDate);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(birthDate) || isNaN(bd)) return { error: 'Ungültiges Geburtsdatum' };
  if (bd > new Date()) return { error: 'Geburtsdatum liegt in der Zukunft' };
  if (ageOn(bd) < 13) return { error: 'Mindestalter 13 Jahre' };

  if (password.length < 8 || password.length > 128) {
    return { error: 'Passwort muss zwischen 8 und 128 Zeichen haben' };
  }

  return { value: { firstName, lastName, mcName, birthDate, password } };
}

// ---------- App ----------
const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '10kb' }));

const allowed = ALLOWED_ORIGINS.split(',').map((s) => s.trim()).filter(Boolean);
app.use(cors({
  origin: (origin, cb) => {
    // Ohne Origin (z. B. curl, Health-Checks) erlauben
    if (!origin || allowed.includes(origin)) return cb(null, true);
    cb(new Error('Origin nicht erlaubt'));
  },
}));

app.get('/api/health', async (_req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true });
  } catch {
    res.status(503).json({ ok: false });
  }
});

app.post('/api/register', async (req, res) => {
  const result = validateRegister(req.body || {});
  if (result.error) return res.status(400).json({ error: result.error });
  const { firstName, lastName, mcName, birthDate, password } = result.value;

  try {
    const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);
    await pool.execute(
      'INSERT INTO users (first_name, last_name, mc_name, birth_date, password_hash) VALUES (?, ?, ?, ?, ?)',
      [firstName, lastName, mcName, birthDate, hash],
    );
    res.status(201).json({ ok: true });
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ error: 'Dieser Minecraft-Name ist bereits registriert' });
    }
    console.error('Register-Fehler:', err);
    res.status(500).json({ error: 'Serverfehler, bitte später erneut versuchen' });
  }
});

app.post('/api/login', async (req, res) => {
  const mcName = String(req.body?.mcName ?? '').trim();
  const password = String(req.body?.password ?? '');

  try {
    const [rows] = await pool.execute(
      'SELECT id, mc_name, password_hash FROM users WHERE mc_name = ? LIMIT 1',
      [mcName],
    );
    const user = rows[0];
    // Immer bcrypt laufen lassen, damit die Antwortzeit nicht verrät, ob der Name existiert
    const hash = user?.password_hash ?? '$2b$12$invalidinvalidinvalidinvalidinvalidinvalidinvalidinv';
    const valid = await bcrypt.compare(password, hash);

    if (!user || !valid) {
      return res.status(401).json({ error: 'Falscher Name oder Passwort' });
    }

    const token = jwt.sign({ id: user.id, name: user.mc_name }, JWT_SECRET, { expiresIn: TOKEN_TTL });
    res.json({ token, name: user.mc_name });
  } catch (err) {
    console.error('Login-Fehler:', err);
    res.status(500).json({ error: 'Serverfehler, bitte später erneut versuchen' });
  }
});

app.get('/api/me', (req, res) => {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Nicht angemeldet' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    res.json({ id: payload.id, name: payload.name });
  } catch {
    res.status(401).json({ error: 'Sitzung abgelaufen' });
  }
});

app.use((_req, res) => res.status(404).json({ error: 'Nicht gefunden' }));

app.listen(PORT, () => console.log(`BrotSMP-API läuft auf Port ${PORT}`));
