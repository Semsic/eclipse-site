const express = require('express');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware para processar dados de formulários (application/x-www-form-urlencoded)
app.use(express.urlencoded({ extended: true }));

// Caminho para o arquivo JSON que armazena os utilizadores
const usersFile = path.join(__dirname, 'users.json');

// ===================== UTILITÁRIOS =====================

/**
 * Carrega a lista de utilizadores a partir do arquivo users.json.
 * Se o arquivo não existir ou estiver corrompido, retorna uma estrutura vazia.
 * @returns {Object} Objeto contendo o array 'users'.
 */
function loadUsers() {
  try {
    return JSON.parse(fs.readFileSync(usersFile, 'utf-8'));
  } catch (e) {
    return { users: [] };
  }
}

/**
 * Salva os dados dos utilizadores no arquivo users.json.
 * @param {Object} data - Objeto com a estrutura { users: [...] }.
 */
function saveUsers(data) {
  fs.writeFileSync(usersFile, JSON.stringify(data, null, 2), 'utf-8');
}

// Armazenamento volátil (em memória) das mensagens do chat Eclipse
// As mensagens NÃO persistem após reinicialização do servidor
const chatMessages = [];           // Array que guarda as mensagens na ordem de chegada
const MAX_CHAT_MESSAGES = 50;      // Limite máximo de mensagens armazenadas

// ===================== ROTAS =====================

// Rota de teste / health check
app.get('/', (req, res) => {
  res.json({ status: 'OK', message: 'Eclipse API is running' });
});

/**
 * Rota para atualizar o nome de Minecraft (mc_name) de um utilizador.
 * Espera receber username e mc_name no corpo da requisição (form-urlencoded).
 * Atualiza o campo mc_name no objeto do utilizador e persiste no arquivo.
 */
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

/**
 * Rota para obter o mapeamento entre mc_name e eclipse_name (username).
 * Útil para o servidor Minecraft identificar qual jogador está no Eclipse.
 * Retorna um array de objetos com mc_name e eclipse_name.
 */
app.get('/eclipse-users', (req, res) => {
  const data = loadUsers();
  const mappings = data.users.map(u => ({
    mc_name: u.mc_name || u.username,   // fallback: se mc_name não existir, usa o próprio username
    eclipse_name: u.username
  }));
  res.json({ success: true, users: mappings });
});

/**
 * Rota para enviar uma mensagem para o chat Eclipse.
 * Armazena a mensagem no array volátil, mantendo no máximo MAX_CHAT_MESSAGES mensagens.
 * Remove as mais antigas quando o limite é atingido.
 */
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
    chatMessages.shift();   // remove a mensagem mais antiga
  }
  console.log(`[Chat] ${username}: ${message}`);
  res.json({ success: true });
});

/**
 * Rota para obter as mensagens recentes do chat Eclipse.
 * Suporta query parameter 'limit' (padrão 20) para controlar quantas mensagens retornar.
 * As mensagens são retornadas da mais recente para a mais antiga (através do slice).
 */
app.get('/ec-chat', (req, res) => {
  const limit = parseInt(req.query.limit) || 20;
  const recent = chatMessages.slice(-limit); // pega as últimas 'limit' mensagens
  res.json({ success: true, messages: recent });
});

/**
 * Rota de login (originalmente api.php).
 * Realiza as seguintes etapas:
 * 1. Verifica se action é 'login'.
 * 2. Valida username e password.
 * 3. Compara a password com o hash armazenado (bcrypt).
 * 4. Lida com HWID: se o utilizador não tiver HWID, vincula o HWID informado.
 *    Se já tiver HWID, verifica se é igual ao informado.
 * 5. Retorna sucesso ou erro.
 */
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

  // Compara a senha fornecida com o hash armazenado
  if (!bcrypt.compareSync(password, user.password_hash)) {
    return res.status(400).json({ success: false, message: 'Wrong password' });
  }

  const cleanHwid = (hwid || '').trim();

  // Se ainda não há HWID vinculado, vincula o HWID recebido
  if (!user.hwid || user.hwid.trim() === '') {
    data.users[userIndex].hwid = cleanHwid;
    saveUsers(data);
    console.log(`[OK] HWID vinculado para ${username}: ${cleanHwid}`);
  } 
  // Se já existe HWID, verifica se coincide
  else if (user.hwid.trim() !== cleanHwid) {
    console.log(`[ERRO] HWID mismatch para ${username}. Recebido: ${cleanHwid}, Armazenado: ${user.hwid}`);
    return res.status(400).json({ success: false, message: 'HWID mismatch' });
  }

  return res.json({ success: true, message: 'Login successful' });
});

/**
 * Rota para resetar (limpar) o HWID de um utilizador.
 * Requer username e password corretos para autorização.
 * Útil quando o utilizador troca de máquina e precisa vincular um novo HWID.
 */
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

/**
 * Rota administrativa para limpar todas as mensagens do chat Eclipse.
 * Requer um token fixo (EclipseOwner123) - isso é frágil e deveria ser uma variável de ambiente.
 * Apenas para uso interno/demo.
 */
app.post('/ec-chat-reset', (req, res) => {
  const { token } = req.body;
  if (token !== 'EclipseOwner123') {
    return res.status(401).json({ success: false, message: 'Unauthorized' });
  }
  chatMessages.length = 0;   // esvazia o array de mensagens
  res.json({ success: true, message: 'Chat messages cleared.' });
});

// ===================== INICIAR SERVIDOR =====================
app.listen(PORT, () => {
  console.log(`Eclipse API rodando na porta ${PORT}`);
  // Se o arquivo users.json não existir, cria um com estrutura inicial vazia
  if (!fs.existsSync(usersFile)) {
    saveUsers({ users: [] });
  }
});
