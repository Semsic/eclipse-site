const express = require('express');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Configuração para aceitar POST com corpo urlencoded (formulário)
app.use(express.urlencoded({ extended: true }));

// Caminho do ficheiro de utilizadores
const usersFile = path.join(__dirname, 'users.json');

// Função auxiliar para ler/gravar o users.json
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

// Rota de teste (GET)
app.get('/', (req, res) => {
  res.json({ status: 'OK', message: 'Eclipse API is running' });
});

// Endpoint de login (POST) – usa o mesmo caminho que o cliente Java espera
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

  // Verifica a senha com bcrypt
  const passwordValid = bcrypt.compareSync(password, user.password_hash);

  if (!passwordValid) {
    return res.status(400).json({ success: false, message: 'Wrong password' });
  }

  // HWID
  if (!user.hwid || user.hwid.trim() === '') {
    // Primeiro login – guarda o HWID
    data.users[userIndex].hwid = hwid || '';
    saveUsers(data);
  } else if (user.hwid !== hwid) {
    return res.status(400).json({ success: false, message: 'HWID mismatch' });
  }

  return res.json({ success: true, message: 'Login successful' });
});

// Iniciar o servidor
app.listen(PORT, () => {
  console.log(`Eclipse API a correr na porta ${PORT}`);

  // Cria o users.json se não existir
  if (!fs.existsSync(usersFile)) {
    saveUsers({ users: [] });
  }
});
