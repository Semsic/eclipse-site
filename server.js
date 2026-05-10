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

// ---------- Atualizar o mc_name do utilizador (chamado pelo cliente) ----------
app.post('/update-mc-name', (req, res) => {
  const { username, mc_name } = req.body;
  if (!username || !mc_name) {
    return res.status(400).json({ success: false, message: 'Missing data' });
  }

  const data = loadUsers();
  const userIndex = data.users.findIndex(u => u.username === username);
  if (userIndex === -1) {
    return res.status(400).json({ success: false, message: 'User not found' });
  }

  data.users[userIndex].mc_name = mc_name;
  saveUsers(data);
  console.log(`[MC_NAME] ${username} → ${mc_name}`);
  res.json({ success: true, message: 'MC name updated' });
});

// ---------- EclipseIdentity (mapeamento mc_name -> eclipse_name) ----------
    public static void updateMcName(String eclipseUser, String mcName) {
        try {
            URL url = new URL(UPDATE_MCNAME_URL);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setRequestProperty("User-Agent", "EclipseClient/1.0");
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8");

            String postData = "username=" + URLEncoder.encode(eclipseUser, "UTF-8")
                    + "&mc_name=" + URLEncoder.encode(mcName, "UTF-8");
            byte[] postBytes = postData.getBytes(StandardCharsets.UTF_8);
            conn.setRequestProperty("Content-Length", String.valueOf(postBytes.length));

            OutputStream os = conn.getOutputStream();
            os.write(postBytes);
            os.flush();
            os.close();

            int code = conn.getResponseCode();
            // Lê a resposta para depuração
            BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8));
            String response = br.readLine();
            br.close();
            System.out.println("[WebLogin.updateMcName] HTTP " + code + ": " + response);
        } catch (Exception e) {
            System.err.println("[WebLogin.updateMcName] Erro ao atualizar mc_name: " + e.getMessage());
        }
    }

// ---------- Chat Eclipse ----------
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
  while (chatMessages.length > MAX_CHAT_MESSAGES) {
    chatMessages.shift();
  }
  console.log(`[Chat] ${username}: ${message}`);
  res.json({ success: true });
});

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

  if (!bcrypt.compareSync(password, user.password_hash)) {
    return res.status(400).json({ success: false, message: 'Wrong password' });
  }

  const cleanHwid = (hwid || '').trim();

  if (!user.hwid || user.hwid.trim() === '') {
    data.users[userIndex].hwid = cleanHwid;
    saveUsers(data);
    console.log(`[OK] HWID vinculado para ${username}: ${cleanHwid}`);
  } else if (user.hwid.trim() !== cleanHwid) {
    console.log(`[ERRO] HWID mismatch para ${username}. Recebido: ${cleanHwid}, Armazenado: ${user.hwid}`);
    return res.status(400).json({ success: false, message: 'HWID mismatch' });
  }

  return res.json({ success: true, message: 'Login successful' });
});

// ---------- RESET DE HWID ----------
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

// ---------- CHAT RESET -----------
app.post('/ec-chat-reset', (req, res) => {
  const { token } = req.body;
  if (token !== 'EclipseOwner123') {
    return res.status(401).json({ success: false, message: 'Unauthorized' });
  }
  chatMessages.length = 0; // limpa o array
  res.json({ success: true, message: 'Chat messages cleared.' });
});

// ===================== INICIAR SERVIDOR =====================
app.listen(PORT, () => {
  console.log(`Eclipse API rodando na porta ${PORT}`);
  if (!fs.existsSync(usersFile)) {
    saveUsers({ users: [] });
  }
});
