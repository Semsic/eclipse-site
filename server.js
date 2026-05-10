const express = require('express');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.urlencoded({ extended: true }));

const usersFile = path.join(__dirname, 'users.json');

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

// Rota de teste
app.get('/', (req, res) => {
  res.json({ status: 'OK', message: 'Eclipse API is running' });
});

// Endpoint para o EclipseIdentity (lista de mapeamentos mc_name -> eclipse_name)
app.get('/eclipse-users', (req, res) => {
  const data = loadUsers();
  const mappings = data.users.map(u => ({
    mc_name: u.mc_name || u.username,
    eclipse_name: u.username
  }));
  res.json({ success: true, users: mappings });
});

// LOGIN
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
    // PRIMEIRO LOGIN OU HWID LIMPO → guarda o HWID recebido
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

// Rota auxiliar para RESETAR o HWID (requer senha correta)
app.post('/resethwid', (req, res) => {
  const { username, password } = req.body;
  const data = loadUsers();
  const userIndex = data.users.findIndex(u => u.username === username);

  if (userIndex === -1 || !bcrypt.compareSync(password, data.users[userIndex].password_hash)) {
    return res.status(400).json({ success: false, message: 'Invalid credentials' });
  }

  data.users[userIndex].hwid = '';
  saveUsers(data);
  res.json({ success: true, message: 'HWID cleared. Next login will rebind.' });
});

// Iniciar o servidor
app.listen(PORT, () => {
  console.log(`Eclipse API rodando na porta ${PORT}`);
  if (!fs.existsSync(usersFile)) {
    saveUsers({ users: [] });
  }
});
