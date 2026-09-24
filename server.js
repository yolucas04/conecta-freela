const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'chave_secreta_conectafreela_2026';

// Configurações e Middlewares de Segurança
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Configuração de Upload de Arquivos Seguro (RF08)
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  }
});
const upload = multer({ storage });

// Banco de Dados em Memória / Arquivo (SQLite)
const db = new sqlite3.Database(':memory:');

db.serialize(() => {
  // Usuários
  db.run(`CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    email TEXT UNIQUE,
    password TEXT,
    role TEXT, -- 'cliente', 'freelancer', 'admin'
    plan TEXT DEFAULT 'free', -- 'free', 'mid', 'enterprise'
    cpf_cnpj TEXT UNIQUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Habilidades e Perfil Freelancer
  db.run(`CREATE TABLE freelancer_profiles (
    user_id INTEGER PRIMARY KEY,
    skills TEXT,
    bio TEXT,
    hourly_rate REAL,
    badge TEXT, -- 'none', 'blue', 'gold'
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);

  // Solicitações de Serviços
  db.run(`CREATE TABLE service_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id INTEGER,
    title TEXT,
    description TEXT,
    status TEXT DEFAULT 'open',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Propostas e Contratações (Escrow / Custódia)
  db.run(`CREATE TABLE contracts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id INTEGER,
    freelancer_id INTEGER,
    client_id INTEGER,
    amount REAL,
    platform_fee REAL,
    status TEXT DEFAULT 'pending', -- 'pending', 'in_progress', 'dispute', 'completed'
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Criar Usuário Admin Padrão
  const adminHash = bcrypt.hashSync('admin123', 10);
  db.run(`INSERT INTO users (name, email, password, role, plan) VALUES ('Admin GQSO', 'admin@conectafreela.com', '${adminHash}', 'admin', 'enterprise')`);
});

// ==========================================
// MIDDLEWARES DE AUTENTICAÇÃO E PLANOS (JWT)
// ==========================================

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Acesso não autorizado. Token ausente.' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Token inválido ou expirado.' });
    req.user = user;
    next();
  });
}

function authorizePlan(requiredPlans) {
  return (req, res, next) => {
    if (!requiredPlans.includes(req.user.plan)) {
      return res.status(403).json({ 
        error: `Recurso restrito. Seu plano atual (${req.user.plan.toUpperCase()}) não permite esta ação.` 
      });
    }
    next();
  };
}

function authorizeRole(roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Acesso negado para este perfil de usuário.' });
    }
    next();
  };
}

// ==========================================
// ROTAS PÚBLICAS
// ==========================================

// Cadastro de Usuários (RF01, RF02, RF03)
app.post('/api/auth/register', (req, res) => {
  const { name, email, password, role, plan, cpf_cnpj, skills } = req.body;

  if (!email || !password || !role || !name) {
    return res.status(400).json({ error: 'Preencha todos os campos obrigatórios.' });
  }

  if (role === 'freelancer' && (!skills || skills.length === 0)) {
    return res.status(400).json({ error: 'Freelancers precisam cadastrar ao menos uma habilidade.' });
  }

  const hashedPassword = bcrypt.hashSync(password, 10);
  const userPlan = plan || 'free';

  db.run(
    `INSERT INTO users (name, email, password, role, plan, cpf_cnpj) VALUES (?, ?, ?, ?, ?, ?)`,
    [name, email, hashedPassword, role, userPlan, cpf_cnpj],
    function (err) {
      if (err) return res.status(400).json({ error: 'E-mail ou CPF/CNPJ já cadastrados.' });

      const userId = this.lastID;
      if (role === 'freelancer') {
        const badge = userPlan === 'enterprise' ? 'gold' : userPlan === 'mid' ? 'blue' : 'none';
        db.run(
          `INSERT INTO freelancer_profiles (user_id, skills, badge) VALUES (?, ?, ?)`,
          [userId, JSON.stringify(skills), badge]
        );
      }

      res.status(201).json({ message: 'Usuário cadastrado com sucesso!', userId });
    }
  );
});

// Login e Geração do JWT
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;

  db.get(`SELECT * FROM users WHERE email = ?`, [email], (err, user) => {
    if (err || !user) return res.status(401).json({ error: 'Credenciais inválidas.' });

    const passwordIsValid = bcrypt.compareSync(password, user.password);
    if (!passwordIsValid) return res.status(401).json({ error: 'Credenciais inválidas.' });

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role, plan: user.plan },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      message: 'Autenticado com sucesso!',
      token,
      user: { id: user.id, name: user.name, role: user.role, plan: user.plan }
    });
  });
});

// Pesquisa Pública de Freelancers (RF05)
app.get('/api/freelancers', (req, res) => {
  const { search } = req.query;
  let query = `
    SELECT u.id, u.name, u.plan, fp.skills, fp.bio, fp.hourly_rate, fp.badge 
    FROM users u
    JOIN freelancer_profiles fp ON u.id = fp.user_id
    WHERE u.role = 'freelancer'
  `;

  db.all(query, [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Erro ao buscar freelancers.' });
    
    // Ordenação por Plano/Selo (Enterprise > Mid > Free)
    const sorted = rows.sort((a, b) => {
      const priority = { enterprise: 3, mid: 2, free: 1 };
      return priority[b.plan] - priority[a.plan];
    });

    res.json(sorted);
  });
});

// ==========================================
// ROTAS PRIVADAS (Requer Autenticação JWT)
// ==========================================

// Perfil do Usuário
app.get('/api/user/profile', authenticateToken, (req, res) => {
  db.get(`SELECT id, name, email, role, plan, cpf_cnpj FROM users WHERE id = ?`, [req.user.id], (err, user) => {
    res.json(user);
  });
});

// Atualização de Plano de Assinatura (RF15)
app.post('/api/user/upgrade-plan', authenticateToken, (req, res) => {
  const { newPlan } = req.body; // 'free', 'mid', 'enterprise'
  if (!['free', 'mid', 'enterprise'].includes(newPlan)) {
    return res.status(400).json({ error: 'Plano inválido.' });
  }

  const newBadge = newPlan === 'enterprise' ? 'gold' : newPlan === 'mid' ? 'blue' : 'none';

  db.run(`UPDATE users SET plan = ? WHERE id = ?`, [newPlan, req.user.id], function (err) {
    if (err) return res.status(500).json({ error: 'Erro ao atualizar plano.' });

    if (req.user.role === 'freelancer') {
      db.run(`UPDATE freelancer_profiles SET badge = ? WHERE user_id = ?`, [newBadge, req.user.id]);
    }

    // Emitir Novo Token com o Plano Atualizado
    const newToken = jwt.sign(
      { id: req.user.id, email: req.user.email, role: req.user.role, plan: newPlan },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({ message: 'Plano atualizado com sucesso!', token: newToken });
  });
});

// Publicar Solicitação de Serviço (RF07) - Clientes
app.post('/api/requests', authenticateToken, authorizeRole(['cliente']), (req, res) => {
  const { title, description } = req.body;
  db.run(
    `INSERT INTO service_requests (client_id, title, description) VALUES (?, ?, ?)`,
    [req.user.id, title, description],
    function (err) {
      if (err) return res.status(500).json({ error: 'Erro ao criar solicitação.' });
      res.status(201).json({ id: this.lastID, title, description, status: 'open' });
    }
  );
});

// Envio de Proposta e Aceite (Custódia com 10% de Taxa) (RF10, RF11)
app.post('/api/contracts/accept', authenticateToken, authorizeRole(['cliente']), (req, res) => {
  const { requestId, freelancerId, amount } = req.body;
  const platformFee = amount * 0.10; // 10% de comissão

  db.run(
    `INSERT INTO contracts (request_id, freelancer_id, client_id, amount, platform_fee, status) VALUES (?, ?, ?, ?, ?, 'in_progress')`,
    [requestId, freelancerId, req.user.id, amount, platformFee],
    function (err) {
      if (err) return res.status(500).json({ error: 'Erro ao processar contrato.' });
      res.status(201).json({ 
        contractId: this.lastID, 
        status: 'in_progress', 
        escrowAmount: amount, 
        feeDeducted: platformFee 
      });
    }
  );
});

// Upload de Anexos no Chat (RF08)
app.post('/api/chat/upload', authenticateToken, upload.single('attachment'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Nenhum arquivo enviado.' });
  res.json({ fileUrl: `/uploads/${req.file.filename}` });
});

// ==========================================
// ROTAS RESTRITAS POR PLANO (JWT Plan Check)
// ==========================================

// Rota Exclusiva para Plano Médio e Empresas (Acesso a Estatísticas Avançadas)
app.get('/api/analytics/pro', authenticateToken, authorizePlan(['mid', 'enterprise']), (req, res) => {
  res.json({
    insights: 'Relatório avançado de visibilidade e taxas de conversão de propostas.',
    accessLevel: req.user.plan
  });
});

// Rota Exclusiva para Empresas (Atendimento Prioritário e Suporte 24/7)
app.get('/api/enterprise/priority-support', authenticateToken, authorizePlan(['enterprise']), (req, res) => {
  res.json({ message: 'Conectado diretamente ao Gerente de Contas ConectaFreela.' });
});

// ==========================================
// ROTAS ADMINISTRATIVAS (RF16, RF17)
// ==========================================

app.get('/api/admin/disputes', authenticateToken, authorizeRole(['admin']), (req, res) => {
  db.all(`SELECT * FROM contracts WHERE status = 'dispute'`, [], (err, rows) => {
    res.json(rows);
  });
});

app.post('/api/admin/resolve-dispute', authenticateToken, authorizeRole(['admin']), (req, res) => {
  const { contractId, resolution } = req.body; // 'refund_client' ou 'release_freelancer'
  const newStatus = resolution === 'refund_client' ? 'refunded' : 'completed';

  db.run(`UPDATE contracts SET status = ? WHERE id = ?`, [newStatus, contractId], function (err) {
    if (err) return res.status(500).json({ error: 'Erro ao resolver disputa.' });
    res.json({ message: `Disputa encerrada com a resolução: ${resolution}` });
  });
});

// Inicialização do Servidor
app.listen(PORT, () => {
  console.log(`API ConectaFreela rodando na porta ${PORT}`);
});