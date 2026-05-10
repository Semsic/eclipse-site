const express = require('express');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.urlencoded({ extended: true }));

const usersFile = path.join(__dirname, 'users.json');

// ===================== UTILITÁRIOS =====================
function loadUsers() {
  try {
    return JSON.parse(fs.readFileSync(usersFile, 'utf-8'));
  } catch (e) {
    return { users: [] };
  }
}

function saveUsers(data) {
  fs.writeFileSync(usersFile, JSON.stringify(data, null, 2), 'utf-8');
}

// Armazenamento volátil das mensagens do chat Eclipse
const chatMessages = [];
const MAX_CHAT_MESSAGES = 50;

// ===================== ROTAS =====================

// Teste
app.get('/', (req, res) => {
  res.json({ status: 'OK', message: 'Eclipse API is running' });
});

// ---------- EclipseIdentity (mapeamento mc_name -> eclipse_name) ----------
app.get('/eclipse-users', (req, res) => {
  const data = loadUsers();
  const mappings = data.users.map(u => ({
    mc_name: u.mc_name || u.username,
    eclipse_name: u.username
  }));
  res.json({ success: true, users: mappings });
});

// ---------- Chat Eclipse ----------
// POST – envia mensagem para o chat Eclipse
app.post('/ec-chat', (req, res) => {
  const { username, message } = req.body;
  if (!username || !message) {
    return res.status(400).json({ success: false, message: 'Missing username or message' });
  }
  chatMessages.push({
    username: username,
    message: message,
    timestamp: Date.now()
  });
  // Mantém apenas as últimas MAX_CHAT_MESSAGES mensagens
  while (chatMessages.length > MAX_CHAT_MESSAGES) {
    chatMessages.shift();
  }
  console.log(`[Chat] ${username}: ${message}`);
  res.json({ success: true });
});

// GET – obtém as últimas N mensagens (padrão 20)
app.get('/ec-chat', (req, res) => {
  const limit = parseInt(req.query.limit) || 20;
  const recent = chatMessages.slice(-limit);
  res.json({ success: true, messages: recent });
});

// ---------- LOGIN ----------
app.post('/api.php', (req, res) => {
  const { action, username, password, hwid } = req.body;

  if (action !== 'login') {
    return res.status(400).json({ success: false, message: 'Invalid action' });
  }

  if (!username || !password) {
    return res.status(400).json({ success: false, message: 'Username or password empty' });
  }

  const data = loadUsers();
  const userIndex = data.users.findIndex(u => u.username === username);

  if (userIndex === -1) {
    return res.status(400).json({ success: false, message: 'User not found' });
  }

  const user = data.users[userIndex];

  // Verifica senha
  if (!bcrypt.compareSync(password, user.password_hash)) {
    return res.status(400).json({ success: false, message: 'Wrong password' });
  }

  // ---- LÓGICA DO HWID (com trim e preenchimento automático) ----
  const cleanHwid = (hwid || '').trim();

  if (!user.hwid || user.hwid.trim() === '') {
    // Primeiro login ou HWID limpo → guarda o HWID recebido
    data.users[userIndex].hwid = cleanHwid;
    saveUsers(data);
    console.log(`[OK] HWID vinculado para ${username}: ${cleanHwid}`);
  } else if (user.hwid.trim() !== cleanHwid) {
    // HWID diferente → rejeita
    console.log(`[ERRO] HWID mismatch para ${username}. Recebido: ${cleanHwid}, Armazenado: ${user.hwid}`);
    return res.status(400).json({ success: false, message: 'HWID mismatch' });
  }

  return res.json({ success: true, message: 'Login successful' });
});

// ---------- RESET DE HWID (usado pelo fallback do cliente) ----------
app.post('/resethwid', (req, res) => {
  const { username, password } = req.body;
  const data = loadUsers();
  const userIndex = data.users.findIndex(u => u.username === username);

  if (userIndex === -1 || !bcrypt.compareSync(password, data.users[userIndex].password_hash)) {
    return res.status(400).json({ success: false, message: 'Invalid credentials' });
  }

  data.users[userIndex].hwid = '';
  saveUsers(data);
  console.log(`[RESET] HWID de ${username} foi limpo.`);
  res.json({ success: true, message: 'HWID cleared. Next login will rebind.' });
});

// ===================== INICIAR SERVIDOR =====================
app.listen(PORT, () => {
  console.log(`Eclipse API rodando na porta ${PORT}`);
  if (!fs.existsSync(usersFile)) {
    saveUsers({ users: [] });
  }
});
