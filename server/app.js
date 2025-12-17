const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const http = require('http');
const socketIo = require('socket.io');
const compression = require('compression');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
const server = http.createServer(app);
const allowedOrigins = process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : '*';

const io = socketIo(server, {
  cors: { origin: allowedOrigins, methods: ['GET', 'POST'] },
  transports: ['websocket', 'polling'],
  pingInterval: 25000,
  pingTimeout: 60000
});
// Track connected socket users (socket.id -> username)
let connectedUsers = {};
const PORT = Number(process.env.PORT) || 5000;

// In-memory caches for frequently accessed data
const memoryCache = {
  questions: null,
  users: null,
  categories: null,
  lastQuestionsUpdate: 0,
  lastUsersUpdate: 0
};
const CACHE_EXPIRE_MS = 60000; // 1 minute
const SECRET_KEY = 'dennie-softs-secure-key-2025';
const ENCRYPTION_KEY = crypto.scryptSync('dennie-softs-game-encryption', 'salt', 32);
const DATA_DIR = path.join(__dirname, '../data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const CODES_FILE = path.join(DATA_DIR, 'registrationCodes.json');
const TASKS_FILE = path.join(DATA_DIR, 'tasks.json');
const EVENTS_FILE = path.join(DATA_DIR, 'events.json');
const ANNOUNCEMENTS_FILE = path.join(DATA_DIR, 'announcements.json');
const POSTS_FILE = path.join(DATA_DIR, 'posts.json');
const CHAT_FILE = path.join(DATA_DIR, 'chat.json');
const RESET_REQUESTS_FILE = path.join(DATA_DIR, 'passwordResetRequests.json');
const CODE_REQUESTS_FILE = path.join(DATA_DIR, 'codeRequests.json');
const CHAT_MESSAGE_RETENTION_MS = 7 * 24 * 60 * 60 * 1000; // 7 days in milliseconds
const PASSWORD_RESET_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes auto-reset timeout

// Role hierarchy and permissions
const ROLES = {
  SYSTEM_ADMIN: 'system-admin',
  ADMIN: 'admin',
  MODERATOR: 'moderator',
  CHAIRPERSON: 'chairperson',
  VICE_CHAIR: 'vice-chair',
  SECRETARY: 'secretary',
  ORGANIZING_SECRETARY: 'organizing-secretary',
  TREASURER: 'treasurer',
  GENERAL: 'general'
};

const ROLE_PERMISSIONS = {
  [ROLES.SYSTEM_ADMIN]: ['manage_codes', 'manage_users', 'manage_game', 'view_all'],
  [ROLES.ADMIN]: ['manage_users', 'view_all'],
  [ROLES.MODERATOR]: ['manage_game', 'view_all'],
  [ROLES.CHAIRPERSON]: ['manage_events', 'manage_announcements', 'manage_tasks'],
  [ROLES.VICE_CHAIR]: ['view_events', 'view_announcements'],
  [ROLES.SECRETARY]: ['manage_announcements', 'manage_events'],
  [ROLES.ORGANIZING_SECRETARY]: ['manage_events'],
  [ROLES.TREASURER]: ['view_events'],
  [ROLES.GENERAL]: []
};

// Roles allowed to manage tasks, events, and announcements (admins and ministry roles)
const MANAGEMENT_ROLES = [ROLES.SYSTEM_ADMIN, ROLES.ADMIN, ROLES.MODERATOR, ROLES.CHAIRPERSON, ROLES.SECRETARY, ROLES.ORGANIZING_SECRETARY];

// Middleware - Compression FIRST
app.use(compression({ level: 6, threshold: 512 }));

app.use(bodyParser.json({ limit: '10mb' }));

// Rate limiting (API + auth)
const apiLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100, standardHeaders: true, legacyHeaders: false });
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 8, message: { message: 'Too many authentication attempts, please try again later.' }, standardHeaders: true, legacyHeaders: false });
app.use('/api/', apiLimiter);
app.use('/api/login', authLimiter);
app.use('/api/signup', authLimiter);

// Helmet (basic) - disable CSP here to set custom policy below
app.use(helmet({ contentSecurityPolicy: false, crossOriginResourcePolicy: false }));

// Security & Performance Headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'no-referrer-when-downgrade');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');

  if (req.secure || req.headers['x-forwarded-proto'] === 'https') {
    res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  }

  next();
});

// Content Security Policy (permissive for inline handlers currently used in front-end)
const scriptSrc = ["'self'", "'unsafe-inline'"];
const styleSrc = ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'];
const imgSrc = ["'self'", 'data:'];
const connectSrc = ["'self'", 'ws:', 'wss:'];
app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy', `default-src 'self'; script-src ${scriptSrc.join(' ')}; style-src ${styleSrc.join(' ')}; img-src ${imgSrc.join(' ')}; connect-src ${connectSrc.join(' ')}; base-uri 'self'; manifest-src 'self'`);
  next();
});

// Cache Headers
app.use((req, res, next) => {
  const filePath = req.path;
  
  // Manifest and Service Worker: revalidate frequently
  if (filePath === '/manifest.json' || filePath === '/service-worker.js') {
    res.setHeader('Cache-Control', 'public, max-age=3600, must-revalidate');
    res.setHeader('Content-Type', filePath === '/manifest.json' ? 'application/manifest+json' : 'application/javascript');
  }
  // HTML files: no cache, always revalidate
  else if (filePath.endsWith('.html')) {
    res.setHeader('Cache-Control', 'public, max-age=0, must-revalidate');
  }
  // CSS and JS: cache for 1 year
  else if (filePath.endsWith('.css') || filePath.endsWith('.js')) {
    res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
  }
  
  next();
});

app.use(express.static(path.join(__dirname, '../public'), { 
  maxAge: '1d',
  etag: false 
}));

// Ensure data directory exists
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

// Auto-reset job - runs on server startup and every 30 seconds
setInterval(processExpiredResetRequests, 30 * 1000);
processExpiredResetRequests();

// Auto-approve code requests job - runs every 2 minutes regardless of admin login
setInterval(autoApproveRequestsJob, 2 * 60 * 1000);
autoApproveRequestsJob();

// Cleanup job - delete users without phone numbers and ensure only one system admin
function cleanupUsersAndValidateAdmin() {
  try {
    const users = loadUsers();
    let deletedCount = 0;
    let systemAdminCount = 0;
    let systemAdminUsername = null;

    // Count system admins and delete users without phone numbers
    Object.keys(users).forEach(username => {
      if (users[username].role === ROLES.SYSTEM_ADMIN) {
        systemAdminCount++;
        systemAdminUsername = username;
      }
      // Delete users without phone numbers, but NEVER delete system admin
      if (!users[username].phoneNumber && users[username].role !== ROLES.SYSTEM_ADMIN) {
        delete users[username];
        deletedCount++;
      }
    });

    // Ensure only one system admin exists
    if (systemAdminCount > 1) {
      Object.keys(users).forEach((username, index) => {
        if (users[username].role === ROLES.SYSTEM_ADMIN && index !== 0) {
          users[username].role = ROLES.ADMIN;
          console.log(`Demoted ${username} from system-admin to admin (only one system admin allowed)`);
        }
      });
    }

    if (deletedCount > 0 || systemAdminCount > 1) {
      saveUsers(users);
      console.log(`Cleanup: Deleted ${deletedCount} users without phone numbers. System admins: ${Math.min(systemAdminCount, 1)}`);
    }
  } catch (error) {
    console.error('Cleanup error:', error);
  }
}

// Run cleanup on startup and every hour
cleanupUsersAndValidateAdmin();
setInterval(cleanupUsersAndValidateAdmin, 60 * 60 * 1000);

// Utility Functions

// Normalize church names to consistent title case
function normalizeChurch(church) {
  if (!church) return 'Aic Kitanga';
  return church.trim()
    .split(' ')
    .map(word => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
    .join(' ');
}

function encryptData(data) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
  let encrypted = cipher.update(JSON.stringify(data), 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return iv.toString('hex') + ':' + encrypted;
}

function decryptData(encryptedData) {
  const parts = encryptedData.split(':');
  const iv = Buffer.from(parts[0], 'hex');
  const decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
  let decrypted = decipher.update(parts[1], 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return JSON.parse(decrypted);
}

function loadUsers() {
  if (!fs.existsSync(USERS_FILE)) {
    return {};
  }
  try {
    const data = fs.readFileSync(USERS_FILE, 'utf8');
    return JSON.parse(data);
  } catch (error) {
    return {};
  }
}

function saveUsers(users) {
  try {
    const jsonString = JSON.stringify(users, null, 2);
    fs.writeFileSync(USERS_FILE, jsonString);
  } catch (error) {
    console.error('Error saving users:', error);
    throw error;
  }
}

function getUserStats(username) {
  const users = loadUsers();
  if (!users[username]) return null;
  return decryptData(users[username].stats);
}

function saveUserStats(username, stats) {
  const users = loadUsers();
  if (users[username]) {
    users[username].stats = encryptData(stats);
    saveUsers(users);
  }
}

// Password Reset Requests Functions
function loadResetRequests() {
  if (!fs.existsSync(RESET_REQUESTS_FILE)) {
    return {};
  }
  try {
    const data = fs.readFileSync(RESET_REQUESTS_FILE, 'utf8');
    return JSON.parse(data);
  } catch (error) {
    return {};
  }
}

function saveResetRequests(requests) {
  try {
    const jsonString = JSON.stringify(requests, null, 2);
    fs.writeFileSync(RESET_REQUESTS_FILE, jsonString);
  } catch (error) {
    console.error('Error saving reset requests:', error);
  }
}

// Auto-reset expired password reset requests
function processExpiredResetRequests() {
  const resetRequests = loadResetRequests();
  const now = Date.now();
  let processed = false;

  Object.entries(resetRequests).forEach(([username, request]) => {
    if (request.expiryTime && now >= request.expiryTime) {
      // Auto-generate password for expired request
      const users = loadUsers();
      if (users[username]) {
        const tempPassword = generateDefaultPassword(username);
        bcrypt.hashSync(tempPassword, 10);
        const hashedPassword = bcrypt.hashSync(tempPassword, 10);
        const newExpiryTime = Date.now() + (10 * 60 * 1000);

        users[username].password = hashedPassword;
        users[username].tempPassword = tempPassword;
        users[username].tempPasswordExpiry = newExpiryTime;
        users[username].passwordResetNeeded = false;
        delete users[username].passwordResetRequestedAt;
        saveUsers(users);

        // Update reset request
        request.autoGenerated = true;
        request.autoGeneratedAt = new Date().toISOString();
        request.tempPassword = tempPassword;
        request.expiryTime = newExpiryTime;
        processed = true;
        console.log(`Auto-generated password for user: ${username}`);
      }
    }
  });

  if (processed) {
    saveResetRequests(resetRequests);
  }
}

// Registration Codes Functions
function loadCodes() {
  if (!fs.existsSync(CODES_FILE)) {
    // Create default system admin code if not exists
    const defaultCodes = {
      'SYSADMIN2025': { role: ROLES.SYSTEM_ADMIN, used: false, createdAt: new Date().toISOString(), createdBy: 'system' }
    };
    saveCodes(defaultCodes);
    return defaultCodes;
  }
  try {
    const data = fs.readFileSync(CODES_FILE, 'utf8');
    return JSON.parse(data);
  } catch (error) {
    return {};
  }
}

function saveCodes(codes) {
  fs.writeFileSync(CODES_FILE, JSON.stringify(codes, null, 2));
}

function generateCode(length = 8) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let code = '';
  for (let i = 0; i < length; i++) {
    code += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return code;
}

function validateAndConsumeCode(code) {
  const codes = loadCodes();
  if (!codes[code]) {
    return { valid: false, error: 'Invalid registration code' };
  }
  if (codes[code].used && !codes[code].multiUse) {
    return { valid: false, error: 'This code has already been used' };
  }
  const role = codes[code].role;
  
  // Mark as used only if not multi-use, otherwise just track usage
  if (!codes[code].multiUse) {
    codes[code].used = true;
    codes[code].usedAt = new Date().toISOString();
  } else {
    // For multi-use codes, track count
    codes[code].usageCount = (codes[code].usageCount || 0) + 1;
    codes[code].lastUsedAt = new Date().toISOString();
  }
  
  saveCodes(codes);
  return { valid: true, role };
}

// Code Request Functions
function loadCodeRequests() {
  if (!fs.existsSync(CODE_REQUESTS_FILE)) {
    return [];
  }
  try {
    const data = fs.readFileSync(CODE_REQUESTS_FILE, 'utf8');
    return JSON.parse(data);
  } catch (error) {
    return [];
  }
}

function saveCodeRequests(requests) {
  fs.writeFileSync(CODE_REQUESTS_FILE, JSON.stringify(requests, null, 2));
}

// Tasks, Events, Announcements Functions
function loadTasks() {
  if (!fs.existsSync(TASKS_FILE)) return [];
  try {
    const data = fs.readFileSync(TASKS_FILE, 'utf8');
    return JSON.parse(data);
  } catch { return []; }
}

function saveTasks(tasks) {
  fs.writeFileSync(TASKS_FILE, JSON.stringify(tasks, null, 2));
}

function loadEvents() {
  if (!fs.existsSync(EVENTS_FILE)) return [];
  try {
    const data = fs.readFileSync(EVENTS_FILE, 'utf8');
    return JSON.parse(data);
  } catch { return []; }
}

function saveEvents(events) {
  fs.writeFileSync(EVENTS_FILE, JSON.stringify(events, null, 2));
}

function loadAnnouncements() {
  if (!fs.existsSync(ANNOUNCEMENTS_FILE)) return [];
  try {
    const data = fs.readFileSync(ANNOUNCEMENTS_FILE, 'utf8');
    return JSON.parse(data);
  } catch { return []; }
}

function saveAnnouncements(announcements) {
  fs.writeFileSync(ANNOUNCEMENTS_FILE, JSON.stringify(announcements, null, 2));
}

function loadPosts() {
  if (!fs.existsSync(POSTS_FILE)) return [];
  try {
    const data = fs.readFileSync(POSTS_FILE, 'utf8');
    return JSON.parse(data);
  } catch { return []; }
}

function savePosts(posts) {
  fs.writeFileSync(POSTS_FILE, JSON.stringify(posts, null, 2));
}

// Save image from data URL to public assets and validate basic constraints
function saveImageFromData(imageData) {
  if (!imageData || typeof imageData !== 'string' || !imageData.startsWith('data:')) {
    throw new Error('Invalid image data');
  }

  const matches = imageData.match(/^data:(image\/\w+);base64,(.+)$/);
  if (!matches) throw new Error('Unsupported image format');

  const mime = matches[1];
  const base64 = matches[2];
  const allowed = ['image/png', 'image/jpeg', 'image/jpg', 'image/webp', 'image/gif'];
  if (!allowed.includes(mime)) throw new Error('Unsupported image type');

  const buffer = Buffer.from(base64, 'base64');
  const MAX_BYTES = 2 * 1024 * 1024; // 2MB
  if (buffer.length > MAX_BYTES) throw new Error('Image too large');

  const ext = mime.split('/')[1] || 'png';
  const filename = `post_${Date.now()}_${Math.random().toString(36).slice(2,8)}.${ext}`;
  const imagesDir = path.join(__dirname, '../public/assets/images');
  if (!fs.existsSync(imagesDir)) fs.mkdirSync(imagesDir, { recursive: true });
  const filePath = path.join(imagesDir, filename);
  fs.writeFileSync(filePath, buffer);
  return `/assets/images/${filename}`;
}

// Chat Functions with auto-delete after 7 days
function loadChatMessages() {
  if (!fs.existsSync(CHAT_FILE)) return [];
  try {
    const data = fs.readFileSync(CHAT_FILE, 'utf8');
    let messages = JSON.parse(data);
    
    // Filter out messages older than 7 days
    const now = Date.now();
    const filteredMessages = messages.filter(msg => {
      const msgTime = new Date(msg.createdAt).getTime();
      return (now - msgTime) < CHAT_MESSAGE_RETENTION_MS;
    });
    
    // If we removed any old messages, save the cleaned list
    if (filteredMessages.length !== messages.length) {
      saveChatMessages(filteredMessages);
    }
    
    return filteredMessages;
  } catch { return []; }
}

function saveChatMessages(messages) {
  fs.writeFileSync(CHAT_FILE, JSON.stringify(messages, null, 2));
}

// Extract user from token
function getUserFromToken(authHeader) {
  if (!authHeader) return { role: 'general', username: 'unknown' };
  const token = authHeader.replace('Bearer ', '');
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    return { role: decoded.role, username: decoded.username };
  } catch {
    return { role: 'general', username: 'unknown' };
  }
}

// Token verification middleware
function verifyToken(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    req.username = decoded.username;
    req.userRole = decoded.role || 'general';
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// Role-based access middleware
function requireRole(...allowedRoles) {
  return (req, res, next) => {
    if (!allowedRoles.includes(req.userRole)) {
      return res.status(403).json({ error: 'Access denied. Insufficient permissions.' });
    }
    next();
  };
}

// Permission check middleware
function hasPermission(permission) {
  return (req, res, next) => {
    const userPermissions = ROLE_PERMISSIONS[req.userRole] || [];
    if (!userPermissions.includes(permission) && req.userRole !== ROLES.SYSTEM_ADMIN) {
      return res.status(403).json({ error: 'Access denied. Insufficient permissions.' });
    }
    next();
  };
}

// Landing page as default home
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/landing.html'));
});

// ========================
// CODE REQUESTS
// ========================
app.post('/api/code-request', async (req, res) => {
  try {
    const { name, phone, church } = req.body;
    
    if (!name || !phone || !church) {
      return res.status(400).json({ error: 'All fields required' });
    }
    
    const requests = loadCodeRequests();
    const newRequest = {
      id: Date.now().toString(),
      name: name.trim(),
      phone: phone.trim(),
      church: church.trim(),
      status: 'pending',
      createdAt: new Date().toISOString()
    };
    
    requests.push(newRequest);
    saveCodeRequests(requests);
    
    res.json({ message: 'Code request submitted successfully', request: newRequest });
  } catch (error) {
    console.error('Code request error:', error);
    res.status(500).json({ error: 'Failed to submit code request' });
  }
});

// Auto-approve requests older than 3 minutes - Background job
function autoApproveRequestsJob() {
  try {
    const requests = loadCodeRequests();
    const codes = loadCodes();
    const now = new Date().getTime();
    const autoApproveTime = 3 * 60 * 1000; // 3 minutes
    let updated = false;

    requests.forEach(req => {
      if (req.status === 'pending') {
        const createdTime = new Date(req.createdAt).getTime();
        if (now - createdTime > autoApproveTime && !req.auto) {
          let newCode;
          do {
            newCode = generateCode();
          } while (codes[newCode]);
          
          codes[newCode] = {
            role: ROLES.GENERAL,
            used: false,
            createdAt: new Date().toISOString(),
            createdBy: 'system',
            requestedBy: req.phone
          };
          
          req.status = 'approved';
          req.approvedAt = new Date().toISOString();
          req.approvedBy = 'system';
          req.generatedCode = newCode;
          req.auto = true;
          req.autoApprovedAt = new Date().toISOString();
          updated = true;
          console.log(`Auto-approved code request for ${req.name} (${req.phone})`);
        }
      }
    });

    if (updated) {
      saveCodes(codes);
      saveCodeRequests(requests);
    }
  } catch (error) {
    console.error('Auto-approve job error:', error);
  }
}

app.get('/api/admin/code-requests', verifyToken, requireRole(ROLES.SYSTEM_ADMIN, ROLES.ADMIN), (req, res) => {
  try {
    const requests = loadCodeRequests();
    res.json({ requests });
  } catch (error) {
    res.status(500).json({ error: 'Failed to load code requests' });
  }
});

app.post('/api/admin/code-requests/:id/approve', verifyToken, requireRole(ROLES.SYSTEM_ADMIN, ROLES.ADMIN), (req, res) => {
  try {
    const { id } = req.params;
    const { role } = req.body;
    
    const requests = loadCodeRequests();
    const requestIndex = requests.findIndex(r => r.id === id);
    
    if (requestIndex === -1) {
      return res.status(404).json({ error: 'Request not found' });
    }
    
    const codeRequest = requests[requestIndex];
    
    // Generate a new code
    const codes = loadCodes();
    let newCode;
    do {
      newCode = generateCode();
    } while (codes[newCode]);
    
    codes[newCode] = {
      role: role || ROLES.GENERAL,
      used: false,
      createdAt: new Date().toISOString(),
      createdBy: req.username,
      requestedBy: codeRequest.email
    };
    
    saveCodes(codes);
    
    // Mark request as approved
    codeRequest.status = 'approved';
    codeRequest.approvedAt = new Date().toISOString();
    codeRequest.approvedBy = req.username;
    codeRequest.generatedCode = newCode;
    codeRequest.requestedBy = codeRequest.phone;
    requests[requestIndex] = codeRequest;
    saveCodeRequests(requests);
    
    res.json({ message: 'Code request approved', code: newCode, request: codeRequest });
  } catch (error) {
    console.error('Approval error:', error);
    res.status(500).json({ error: 'Failed to approve code request' });
  }
});

app.post('/api/admin/code-requests/approve-all/pending', verifyToken, requireRole(ROLES.SYSTEM_ADMIN, ROLES.ADMIN), (req, res) => {
  try {
    const requests = loadCodeRequests();
    const codes = loadCodes();
    const pendingRequests = requests.filter(r => r.status === 'pending');
    let approvedCount = 0;

    pendingRequests.forEach(codeRequest => {
      let newCode;
      do {
        newCode = generateCode();
      } while (codes[newCode]);
      
      codes[newCode] = {
        role: ROLES.GENERAL,
        used: false,
        createdAt: new Date().toISOString(),
        createdBy: req.username,
        requestedBy: codeRequest.phone
      };
      
      codeRequest.status = 'approved';
      codeRequest.approvedAt = new Date().toISOString();
      codeRequest.approvedBy = req.username;
      codeRequest.generatedCode = newCode;
      approvedCount++;
    });

    saveCodes(codes);
    saveCodeRequests(requests);
    
    res.json({ message: `Approved ${approvedCount} requests`, count: approvedCount });
  } catch (error) {
    console.error('Approve all error:', error);
    res.status(500).json({ error: 'Failed to approve all requests' });
  }
});

// Check if a code request has been approved by phone number
app.post('/api/check-approval', (req, res) => {
  try {
    const { phone, name } = req.body;
    
    if (!phone || !name) {
      return res.status(400).json({ approved: false });
    }
    
    const requests = loadCodeRequests();
    const trimmedPhone = phone.trim();
    const trimmedName = name.trim();
    const approvedRequest = requests.find(r => r.phone.trim() === trimmedPhone && r.name.trim() === trimmedName && r.status === 'approved');
    
    if (approvedRequest) {
      res.json({ approved: true, code: approvedRequest.generatedCode, church: approvedRequest.church });
    } else {
      res.json({ approved: false });
    }
  } catch (error) {
    res.json({ approved: false });
  }
});

app.delete('/api/admin/code-requests/:id', verifyToken, requireRole(ROLES.SYSTEM_ADMIN, ROLES.ADMIN), (req, res) => {
  try {
    const { id } = req.params;
    let requests = loadCodeRequests();
    requests = requests.filter(r => r.id !== id);
    saveCodeRequests(requests);
    res.json({ message: 'Request deleted' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete request' });
  }
});

// ========================
// SIGNUP with Registration Code
// ========================
app.post('/api/signup', async (req, res) => {
  try {
    const { username, password, registrationCode, phoneNumber } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }

    if (!registrationCode) {
      return res.status(400).json({ error: 'Registration code required' });
    }

    // Normalize inputs
    const normalizedUsername = username.toLowerCase();
    const normalizedPhone = phoneNumber ? phoneNumber.trim() : null;

    // Validate registration code
    const codeResult = validateAndConsumeCode(registrationCode.toUpperCase());
    if (!codeResult.valid) {
      return res.status(400).json({ error: codeResult.error });
    }

    const users = loadUsers();

    // Check if username exists
    if (users[normalizedUsername]) {
      const codes = loadCodes();
      if (codes[registrationCode.toUpperCase()]) {
        codes[registrationCode.toUpperCase()].used = false;
        delete codes[registrationCode.toUpperCase()].usedAt;
        saveCodes(codes);
      }
      return res.status(400).json({ error: 'User already exists' });
    }

    // Check if phone number already registered    // Check if phone number already registered (only if provided)
    if (normalizedPhone) {
      const existingPhoneUser = Object.values(users).find(u => u.phoneNumber === normalizedPhone);
      if (existingPhoneUser) {
        const codes = loadCodes();
        if (codes[registrationCode.toUpperCase()]) {
          codes[registrationCode.toUpperCase()].used = false;
          delete codes[registrationCode.toUpperCase()].usedAt;
          saveCodes(codes);
        }
        return res.status(400).json({ error: 'Phone number already registered' });
      }
    }
    

    const userRole = codeResult.role;
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Get church name from code request if it exists
    let churchName = 'Aic Kitanga';
    const codeRequests = loadCodeRequests();
    const approvedRequest = codeRequests.find(r => r.generatedCode === registrationCode.toUpperCase());
    if (approvedRequest) {
      churchName = normalizeChurch(approvedRequest.church);
    } else {
      churchName = normalizeChurch(churchName);
    }

    const initialStats = {
      totalGamesPlayed: 0,
      totalWins: 0,
      totalLosses: 0,
      balance: 100,
      gamesWonToday: 0,
      lastGameTime: null,
      joinDate: new Date().toISOString(),
      role: userRole,
      church: churchName
    };

    users[normalizedUsername] = {
      password: hashedPassword,
      stats: encryptData(initialStats),
      createdAt: new Date().toISOString(),
      role: userRole,
      church: churchName,
      username: normalizedUsername,
      phoneNumber: normalizedPhone
    };

    saveUsers(users);

    const token = jwt.sign({ username: normalizedUsername, role: userRole }, SECRET_KEY, { expiresIn: '24h' });

    res.json({ message: 'User created successfully', token, username: normalizedUsername, role: userRole, church: churchName, stats: initialStats });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ error: 'Signup failed' });
  }
});

// Validate code without consuming it
app.post('/api/validate-code', async (req, res) => {
  try {
    const { registrationCode } = req.body;
    
    if (!registrationCode) {
      return res.status(400).json({ valid: false, error: 'Code required' });
    }
    
    const codes = loadCodes();
    const code = codes[registrationCode.toUpperCase()];
    
    if (!code) {
      return res.status(400).json({ valid: false, error: 'Invalid code' });
    }
    
    if (code.used) {
      return res.status(400).json({ valid: false, error: 'Code already used' });
    }
    
    res.json({ valid: true, role: code.role });
  } catch (error) {
    res.status(500).json({ valid: false, error: 'Validation failed' });
  }
});

// ========================
// LOGIN
// ========================
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }

    // Normalize username to lowercase for case-insensitive login
    const normalizedUsername = username.toLowerCase();
    const users = loadUsers();

    if (!users[normalizedUsername]) {
      return res.status(400).json({ error: 'User not found' });
    }

    const passwordMatch = await bcrypt.compare(password, users[normalizedUsername].password);

    if (!passwordMatch) {
      return res.status(400).json({ error: 'Invalid password' });
    }

    const userRole = users[normalizedUsername].role || 'general';
    const token = jwt.sign({ username: normalizedUsername, role: userRole }, SECRET_KEY, { expiresIn: '24h' });
    const stats = decryptData(users[normalizedUsername].stats);

    res.json({ message: 'Login successful', token, username: normalizedUsername, role: userRole, stats });

  } catch (error) {
    res.status(500).json({ error: 'Login failed' });
  }
});

// Verify token and return user role
app.get('/api/verify-token', verifyToken, (req, res) => {
  res.json({ valid: true, username: req.username, role: req.userRole });
});

// GET STATS
app.get('/api/stats', verifyToken, (req, res) => {
  const stats = getUserStats(req.username);
  if (stats) res.json(stats);
  else res.status(400).json({ error: 'User stats not found' });
});

// ========================
// PROFILE MANAGEMENT
// ========================
app.put('/api/profile/username', verifyToken, async (req, res) => {
  try {
    const { newUsername, password } = req.body;
    
    if (!newUsername || !password) {
      return res.status(400).json({ error: 'New username and password required' });
    }

    if (newUsername.length < 3) {
      return res.status(400).json({ error: 'Username must be at least 3 characters' });
    }

    const normalizedNewUsername = newUsername.toLowerCase();
    const normalizedCurrentUsername = req.username.toLowerCase();
    const users = loadUsers();

    // Check if user exists
    if (!users[normalizedCurrentUsername]) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Verify password
    const passwordMatch = await bcrypt.compare(password, users[normalizedCurrentUsername].password);
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid password' });
    }

    // Check if new username is already taken
    if (normalizedNewUsername !== normalizedCurrentUsername && users[normalizedNewUsername]) {
      return res.status(400).json({ error: 'Username already taken' });
    }

    // If username is different, update the key
    if (normalizedNewUsername !== normalizedCurrentUsername) {
      const userData = users[normalizedCurrentUsername];
      delete users[normalizedCurrentUsername];
      users[normalizedNewUsername] = { ...userData };
      users[normalizedNewUsername].updatedAt = new Date().toISOString();
      saveUsers(users);
    }

    res.json({ message: 'Username updated successfully', username: normalizedNewUsername });
  } catch (error) {
    console.error('Profile username update error:', error);
    res.status(500).json({ error: 'Failed to update username' });
  }
});

app.put('/api/profile/password', verifyToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: 'Current and new password required' });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({ error: 'New password must be at least 6 characters' });
    }

    const normalizedUsername = req.username.toLowerCase();
    const users = loadUsers();

    // Check if user exists
    if (!users[normalizedUsername]) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Verify current password
    const passwordMatch = await bcrypt.compare(currentPassword, users[normalizedUsername].password);
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    users[normalizedUsername].password = hashedPassword;
    users[normalizedUsername].updatedAt = new Date().toISOString();
    saveUsers(users);

    res.json({ message: 'Password updated successfully' });
  } catch (error) {
    console.error('Profile password update error:', error);
    res.status(500).json({ error: 'Failed to update password' });
  }
});

// ========================
// ADMIN: Registration Code Management (System Admin Only)
// ========================
app.get('/api/admin/codes', verifyToken, requireRole(ROLES.SYSTEM_ADMIN), (req, res) => {
  try {
    const codes = loadCodes();
    const codeList = Object.entries(codes).map(([code, data]) => ({
      code,
      ...data
    }));
    res.json({ codes: codeList });
  } catch (error) {
    res.status(500).json({ error: 'Failed to load codes' });
  }
});

app.post('/api/admin/codes', verifyToken, requireRole(ROLES.SYSTEM_ADMIN), (req, res) => {
  try {
    const { role, quantity = 1, multiUse = false } = req.body;
    
    const validRoles = Object.values(ROLES);
    if (!validRoles.includes(role)) {
      return res.status(400).json({ error: 'Invalid role specified' });
    }
    
    // Multi-use codes are only allowed for general members
    if (multiUse && role !== ROLES.GENERAL) {
      return res.status(400).json({ error: 'Multi-use codes can only be generated for General Members' });
    }
    
    const codes = loadCodes();
    const newCodes = [];
    
    for (let i = 0; i < quantity; i++) {
      let newCode;
      do {
        newCode = generateCode();
      } while (codes[newCode]);
      
      codes[newCode] = {
        role,
        used: false,
        multiUse: multiUse || false,
        usageCount: 0,
        createdAt: new Date().toISOString(),
        createdBy: req.username
      };
      newCodes.push({ code: newCode, role, multiUse: multiUse || false });
    }
    
    saveCodes(codes);
    res.json({ message: `Created ${quantity} code(s) ${multiUse ? '(Multi-use)' : ''}`, codes: newCodes });
  } catch (error) {
    res.status(500).json({ error: 'Failed to create codes' });
  }
});

app.delete('/api/admin/codes/:code', verifyToken, requireRole(ROLES.SYSTEM_ADMIN), (req, res) => {
  try {
    const codes = loadCodes();
    const codeToDelete = req.params.code.toUpperCase();
    
    if (!codes[codeToDelete]) {
      return res.status(404).json({ error: 'Code not found' });
    }
    
    delete codes[codeToDelete];
    saveCodes(codes);
    res.json({ message: 'Code deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete code' });
  }
});

// ========================
// ADMIN: User Management (Admin + System Admin)
// ========================
app.get('/api/admin/users', verifyToken, requireRole(ROLES.SYSTEM_ADMIN, ROLES.ADMIN), (req, res) => {
  try {
    const users = loadUsers();
    const userList = Object.entries(users).map(([username, user]) => {
      const stats = decryptData(user.stats);
      return {
        username,
        role: user.role,
        balance: stats.balance || 0,
        wins: stats.totalWins || 0,
        losses: stats.totalLosses || 0,
        gamesPlayed: stats.totalGamesPlayed || 0,
        createdAt: user.createdAt
      };
    });
    res.json({ users: userList });
  } catch (error) {
    res.status(500).json({ error: 'Failed to load users' });
  }
});

app.post('/api/admin/users/:username/reset', verifyToken, requireRole(ROLES.SYSTEM_ADMIN, ROLES.ADMIN), (req, res) => {
  try {
    const { username } = req.params;
    const users = loadUsers();
    
    if (!users[username]) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const currentStats = decryptData(users[username].stats);
    const resetStats = {
      totalGamesPlayed: 0,
      totalWins: 0,
      totalLosses: 0,
      balance: 100,
      gamesWonToday: 0,
      lastGameTime: null,
      joinDate: currentStats.joinDate,
      role: users[username].role
    };
    
    users[username].stats = encryptData(resetStats);
    saveUsers(users);
    
    res.json({ message: `Stats reset for ${username}` });
  } catch (error) {
    res.status(500).json({ error: 'Failed to reset stats' });
  }
});

app.post('/api/admin/users/:username/balance', verifyToken, requireRole(ROLES.SYSTEM_ADMIN, ROLES.ADMIN), (req, res) => {
  try {
    const { username } = req.params;
    const { amount, operation } = req.body;
    
    if (typeof amount !== 'number' || amount < 0) {
      return res.status(400).json({ error: 'Invalid amount' });
    }
    
    const users = loadUsers();
    
    if (!users[username]) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const stats = decryptData(users[username].stats);
    
    if (operation === 'add') {
      stats.balance += amount;
    } else if (operation === 'deduct') {
      stats.balance = Math.max(0, stats.balance - amount);
    } else {
      return res.status(400).json({ error: 'Invalid operation. Use "add" or "deduct"' });
    }
    
    users[username].stats = encryptData(stats);
    saveUsers(users);
    
    res.json({ message: `Balance updated for ${username}`, newBalance: stats.balance });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update balance' });
  }
});

app.post('/api/admin/users/:username/role', verifyToken, requireRole(ROLES.SYSTEM_ADMIN), (req, res) => {
  try {
    const { username } = req.params;
    const { role } = req.body;
    
    const validRoles = Object.values(ROLES);
    if (!validRoles.includes(role)) {
      return res.status(400).json({ error: 'Invalid role' });
    }
    
    const users = loadUsers();
    
    if (!users[username]) {
      return res.status(404).json({ error: 'User not found' });
    }

    const currentRole = users[username].role;

    // Prevent removing system admin role (only one system admin allowed)
    if (currentRole === ROLES.SYSTEM_ADMIN && role !== ROLES.SYSTEM_ADMIN) {
      return res.status(400).json({ error: 'Cannot remove the system admin role from the only system admin in the system' });
    }

    // Prevent creating a new system admin (only one allowed)
    if (role === ROLES.SYSTEM_ADMIN && currentRole !== ROLES.SYSTEM_ADMIN) {
      const existingSystemAdmin = Object.entries(users).find(([u, userData]) => userData.role === ROLES.SYSTEM_ADMIN);
      if (existingSystemAdmin) {
        return res.status(400).json({ error: 'Cannot create another system admin. Only one system admin is allowed. Current system admin: ' + existingSystemAdmin[0] });
      }
    }
    
    users[username].role = role;
    const stats = decryptData(users[username].stats);
    stats.role = role;
    users[username].stats = encryptData(stats);
    saveUsers(users);
    
    res.json({ message: `Role updated for ${username}` });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update role' });
  }
});

app.delete('/api/admin/users/:username', verifyToken, requireRole(ROLES.SYSTEM_ADMIN), (req, res) => {
  try {
    const { username } = req.params;
    const users = loadUsers();
    
    if (!users[username]) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    if (username === req.username) {
      return res.status(400).json({ error: 'Cannot delete your own account' });
    }
    
    delete users[username];
    saveUsers(users);
    
    res.json({ message: `User ${username} deleted` });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

// ========================
// MODERATOR: Game Management (Moderator + System Admin)
// ========================
// Questions database (in-memory, initialized with expanded Bible content)
// Initialize questions object that will be populated after bibleContent is defined
let questions = {};

// Function to initialize questions from bibleContent
function initializeQuestions() {
  if (!bibleContent || !bibleContent.triviaQuestions) return;
  
  Object.entries(bibleContent.triviaQuestions).forEach(([category, sourceQuestions]) => {
    questions[category] = sourceQuestions.map((q, i) => ({
      ...q,
      questionId: `${category}_${i}`
    }));
  });
}

app.get('/api/admin/questions', verifyToken, requireRole(ROLES.SYSTEM_ADMIN, ROLES.MODERATOR), (req, res) => {
  res.json({ questions });
});

app.post('/api/admin/questions', verifyToken, requireRole(ROLES.SYSTEM_ADMIN, ROLES.MODERATOR), (req, res) => {
  try {
    const { category, question, options, correctIndex, hints } = req.body;
    
    if (!category || !question || !options || correctIndex === undefined) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    
    if (!questions[category]) {
      questions[category] = [];
    }
    
    const newQuestion = {
      questionId: `${category}_${Date.now()}`,
      question,
      options,
      correctIndex,
      hints: hints || []
    };
    
    questions[category].push(newQuestion);
    res.json({ message: 'Question added', question: newQuestion });
  } catch (error) {
    res.status(500).json({ error: 'Failed to add question' });
  }
});

app.delete('/api/admin/questions/:category/:questionId', verifyToken, requireRole(ROLES.SYSTEM_ADMIN, ROLES.MODERATOR), (req, res) => {
  try {
    const { category, questionId } = req.params;
    
    if (!questions[category]) {
      return res.status(404).json({ error: 'Category not found' });
    }
    
    const index = questions[category].findIndex(q => q.questionId === questionId);
    if (index === -1) {
      return res.status(404).json({ error: 'Question not found' });
    }
    
    questions[category].splice(index, 1);
    res.json({ message: 'Question deleted' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete question' });
  }
});

// ========================
// OTHER GAMES MANAGEMENT
// ========================
let otherGames = {
  character: [
    { id: 'char1', name: 'Moses', clues: ['Led Israel out of Egypt', 'Received the Ten Commandments', 'Staff turned to serpent'], difficulty: 'medium' },
    { id: 'char2', name: 'David', clues: ['King of Israel', 'Defeated Goliath', 'Wrote many Psalms'], difficulty: 'easy' }
  ],
  fillin: [
    { id: 'fill1', verse: 'In the beginning was the ___', answer: 'Word', reference: 'John 1:1', difficulty: 'easy' },
    { id: 'fill2', verse: 'For God so loved the world that he gave his ___ ___', answer: 'only son', reference: 'John 3:16', difficulty: 'medium' }
  ],
  wordscramble: [
    { id: 'ws1', scrambled: 'SSUEJ', answer: 'JESUS', difficulty: 'easy' },
    { id: 'ws2', scrambled: 'NEVEHS', answer: 'HEAVENS', difficulty: 'medium' }
  ],
  memory: [
    { id: 'mem1', verse: 'For all have sinned and fall short of the glory of God', reference: 'Romans 3:23', difficulty: 'medium' },
    { id: 'mem2', verse: 'I am the way and the truth and the life', reference: 'John 14:6', difficulty: 'easy' }
  ],
  puzzle: [
    { id: 'puz1', clue: 'Turned water into wine at wedding', answer: 'CANA', difficulty: 'medium' },
    { id: 'puz2', clue: 'Mountain where Jesus was baptized', answer: 'JORDAN', difficulty: 'hard' }
  ],
  wordsearch: [
    { id: 'ws1', words: ['JESUS', 'LOVE', 'FAITH', 'HOPE'], gridSize: 10, difficulty: 'easy' },
    { id: 'ws2', words: ['TESTAMENT', 'GOSPEL', 'APOSTLE', 'DISCIPLE'], gridSize: 12, difficulty: 'hard' }
  ]
};

app.get('/api/admin/games/:gameType', verifyToken, requireRole(ROLES.SYSTEM_ADMIN, ROLES.MODERATOR), (req, res) => {
  const { gameType } = req.params;
  if (!otherGames[gameType]) {
    return res.status(404).json({ error: 'Game type not found' });
  }
  res.json({ content: otherGames[gameType] });
});

app.post('/api/admin/games/:gameType', verifyToken, requireRole(ROLES.SYSTEM_ADMIN, ROLES.MODERATOR), (req, res) => {
  try {
    const { gameType } = req.params;
    const newItem = req.body;
    
    if (!otherGames[gameType]) {
      return res.status(404).json({ error: 'Game type not found' });
    }
    
    newItem.id = `${gameType}_${Date.now()}`;
    otherGames[gameType].push(newItem);
    res.json({ message: 'Content added', item: newItem });
  } catch (error) {
    res.status(500).json({ error: 'Failed to add content' });
  }
});

app.delete('/api/admin/games/:gameType/:itemId', verifyToken, requireRole(ROLES.SYSTEM_ADMIN, ROLES.MODERATOR), (req, res) => {
  try {
    const { gameType, itemId } = req.params;
    
    if (!otherGames[gameType]) {
      return res.status(404).json({ error: 'Game type not found' });
    }
    
    const index = otherGames[gameType].findIndex(item => item.id === itemId);
    if (index === -1) {
      return res.status(404).json({ error: 'Item not found' });
    }
    
    otherGames[gameType].splice(index, 1);
    res.json({ message: 'Content deleted' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete content' });
  }
});

// ========================
// AUTO-POPULATE GAMES FROM BIBLE CONTENT
// ========================
const bibleContent = {
  triviaQuestions: {
    oldTestament: [
      { question: 'Who was the first man according to the Bible?', options: ['Noah', 'Abraham', 'Adam', 'Enoch'], correctIndex: 2, hints: [{ text: 'Created in God\'s image', cost: 10 }] },
      { question: 'How many commandments did God give to Moses?', options: ['5', '8', '10', '12'], correctIndex: 2, hints: [{ text: 'Written on stone tablets', cost: 10 }] },
      { question: 'Who built the ark to save his family from the flood?', options: ['Abraham', 'Moses', 'Noah', 'Jacob'], correctIndex: 2, hints: [{ text: 'Had sons named Shem, Ham, Japheth', cost: 10 }] },
      { question: 'How many plagues did God send to Egypt?', options: ['7', '9', '10', '12'], correctIndex: 2, hints: [{ text: 'Included frogs, locusts, hail', cost: 10 }] },
      { question: 'Who defeated Goliath with a slingshot?', options: ['Samson', 'Joshua', 'David', 'Jonathan'], correctIndex: 2, hints: [{ text: 'Later became King of Israel', cost: 10 }] },
      { question: 'What was the name of Job\'s suffering test?', options: ['Trial', 'Tribulation', 'Affliction', 'Torment'], correctIndex: 0, hints: [{ text: 'God tested his faith', cost: 10 }] },
      { question: 'How many years did the Israelites wander in the wilderness?', options: ['10', '20', '40', '50'], correctIndex: 2, hints: [{ text: 'A generation\'s time', cost: 10 }] },
      { question: 'Who was swallowed by a great fish?', options: ['Isaiah', 'Jonah', 'Jeremiah', 'Zechariah'], correctIndex: 1, hints: [{ text: 'Preached to Nineveh', cost: 10 }] },
      { question: 'What did Abraham receive from God as a covenant?', options: ['A sword', 'A son and descendants', 'Gold and silver', 'A kingdom'], correctIndex: 1, hints: [{ text: 'His son was Isaac', cost: 10 }] },
      { question: 'Who interpreted the pharaoh\'s dream about the famine?', options: ['Joseph', 'Moses', 'Benjamin', 'Potiphar'], correctIndex: 0, hints: [{ text: 'He was sold as a slave', cost: 10 }] },
      { question: 'What was the name of Samson\'s love interest?', options: ['Delilah', 'Gideon\'s wife', 'Ruth', 'Naomi'], correctIndex: 0, hints: [{ text: 'She betrayed him', cost: 10 }] },
      { question: 'Who was the wisest person in the Old Testament?', options: ['Moses', 'Solomon', 'David', 'Job'], correctIndex: 1, hints: [{ text: 'God granted him his wish', cost: 10 }] }
    ],
    newTestament: [
      { question: 'How many gospels are in the New Testament?', options: ['2', '3', '4', '5'], correctIndex: 2, hints: [{ text: 'Matthew, Mark, Luke, and...', cost: 10 }] },
      { question: 'What is the shortest book in the Bible?', options: ['1 John', '2 John', '3 John', 'Philemon'], correctIndex: 2, hints: [{ text: 'Only 25 verses long', cost: 10 }] },
      { question: 'How many letters did Paul write that are in the New Testament?', options: ['11', '13', '14', '16'], correctIndex: 1, hints: [{ text: 'Include Romans and Corinthians', cost: 10 }] },
      { question: 'What city did Jesus perform His first miracle in?', options: ['Jerusalem', 'Bethlehem', 'Cana', 'Nazareth'], correctIndex: 2, hints: [{ text: 'Turned water into wine', cost: 10 }] },
      { question: 'How many times did Jesus rise from the dead?', options: ['Never', 'Once', 'Twice', 'Three times'], correctIndex: 1, hints: [{ text: 'Rose on the third day', cost: 10 }] },
      { question: 'Which book is the longest in the New Testament?', options: ['Romans', 'Luke', 'Matthew', '1 Corinthians'], correctIndex: 1, hints: [{ text: 'A gospel account', cost: 10 }] },
      { question: 'Who was the first martyr of the early church?', options: ['Peter', 'Paul', 'Stephen', 'James'], correctIndex: 2, hints: [{ text: 'Stoned to death', cost: 10 }] },
      { question: 'On which day did the Holy Spirit come to the apostles?', options: ['Easter', 'Pentecost', 'Ascension', 'Passover'], correctIndex: 1, hints: [{ text: 'Day of Pentecost', cost: 10 }] },
      { question: 'What did Zacchaeus do for a living?', options: ['Fisherman', 'Tax collector', 'Carpenter', 'Shepherd'], correctIndex: 1, hints: [{ text: 'Climbed a tree to see Jesus', cost: 10 }] },
      { question: 'Which disciple betrayed Jesus for money?', options: ['Peter', 'John', 'Judas', 'Thomas'], correctIndex: 2, hints: [{ text: '30 pieces of silver', cost: 10 }] },
      { question: 'What was Nicodemus according to the Bible?', options: ['A fisherman', 'A teacher of Israel', 'An apostle', 'A beggar'], correctIndex: 1, hints: [{ text: 'Visited Jesus at night', cost: 10 }] },
      { question: 'How many times should we forgive according to Jesus?', options: ['7 times', '70 times 7', '100 times', 'Twice'], correctIndex: 1, hints: [{ text: 'A high number to emphasize unlimited forgiveness', cost: 10 }] }
    ],
    jesus: [
      { question: 'In which town was Jesus born?', options: ['Jerusalem', 'Nazareth', 'Bethlehem', 'Jericho'], correctIndex: 2, hints: [{ text: 'The City of David', cost: 10 }] },
      { question: 'What was Jesus\'s earthly father\'s occupation?', options: ['Fisherman', 'Carpenter', 'Shepherd', 'Pharisee'], correctIndex: 1, hints: [{ text: 'Worked with wood', cost: 10 }] },
      { question: 'How many disciples did Jesus choose?', options: ['7', '10', '12', '14'], correctIndex: 2, hints: [{ text: 'One betrayed Him', cost: 10 }] },
      { question: 'What did Jesus teach using parables?', options: ['Only money', 'Spiritual truths', 'Only farming', 'Genealogy'], correctIndex: 1, hints: [{ text: 'Moral lessons', cost: 10 }] },
      { question: 'Who denied knowing Jesus three times?', options: ['James', 'John', 'Peter', 'Andrew'], correctIndex: 2, hints: [{ text: 'Leading apostle', cost: 10 }] },
      { question: 'On which day of the week was Jesus crucified?', options: ['Monday', 'Friday', 'Saturday', 'Sunday'], correctIndex: 1, hints: [{ text: 'Before the Sabbath', cost: 10 }] },
      { question: 'Which Psalm did Jesus quote while on the cross?', options: ['Psalm 23', 'Psalm 42', 'Psalm 22', 'Psalm 91'], correctIndex: 2, hints: [{ text: '"My God, my God, why..."', cost: 10 }] },
      { question: 'What was Jesus\'s first recorded miracle?', options: ['Healing leper', 'Healing blind', 'Water to wine', 'Raising dead'], correctIndex: 2, hints: [{ text: 'At a wedding', cost: 10 }] },
      { question: 'Where was Jesus baptized?', options: ['Sea of Galilee', 'Jordan River', 'Red Sea', 'Mediterranean'], correctIndex: 1, hints: [{ text: 'By John the Baptist', cost: 10 }] },
      { question: 'How long did Jesus fast in the wilderness?', options: ['3 days', '7 days', '40 days', '60 days'], correctIndex: 2, hints: [{ text: 'After his baptism', cost: 10 }] },
      { question: 'What is the most famous prayer Jesus taught?', options: ['Psalm 23', 'The Lord\'s Prayer', 'Beatitudes', 'Sermon on Mount'], correctIndex: 1, hints: [{ text: 'It begins "Our Father"', cost: 10 }] },
      { question: 'How many times did Jesus appear after resurrection?', options: ['5 times', '8 times', '10 times', '12 times'], correctIndex: 1, hints: [{ text: 'Over 40 days to His disciples', cost: 10 }] }
    ],
    apostles: [
      { question: 'Which apostle was a tax collector before following Jesus?', options: ['Peter', 'Matthew', 'John', 'Andrew'], correctIndex: 1, hints: [{ text: 'Also called Levi', cost: 10 }] },
      { question: 'How many converts did Peter baptize on Pentecost?', options: ['120', '500', '3,000', '5,000'], correctIndex: 2, hints: [{ text: 'In the thousands', cost: 10 }] },
      { question: 'Who traveled extensively on missionary journeys spreading the Gospel?', options: ['John', 'Peter', 'Paul', 'Thomas'], correctIndex: 2, hints: [{ text: 'Previously called Saul', cost: 10 }] },
      { question: 'Which apostle is often called the "beloved disciple"?', options: ['Peter', 'John', 'James', 'Judas'], correctIndex: 1, hints: [{ text: 'Wrote the Gospel of John', cost: 10 }] },
      { question: 'What was Thomas known as besides his real name?', options: ['The Prophet', 'The Doubter', 'The Faithful', 'The Strong'], correctIndex: 1, hints: [{ text: 'Doubted the resurrection', cost: 10 }] },
      { question: 'Who was Jesus\'s brother among the apostles?', options: ['Thomas', 'James', 'Simon', 'Judas'], correctIndex: 1, hints: [{ text: 'Led the Jerusalem church', cost: 10 }] },
      { question: 'Which apostle was known as the "rock"?', options: ['Andrew', 'Peter', 'Thomas', 'Philip'], correctIndex: 1, hints: [{ text: 'His name means rock', cost: 10 }] },
      { question: 'How was Judas Iscariot identified by Jesus?', options: ['By name', 'With a kiss', 'By pointing', 'By voice'], correctIndex: 1, hints: [{ text: 'A sign of betrayal', cost: 10 }] },
      { question: 'Which apostle was also called the "Son of Thunder"?', options: ['Peter', 'James', 'John', 'Mark'], correctIndex: 1, hints: [{ text: 'Brother of John', cost: 10 }] },
      { question: 'What occupation did Peter and Andrew have?', options: ['Tax collectors', 'Fishermen', 'Carpenters', 'Farmers'], correctIndex: 1, hints: [{ text: 'They cast nets', cost: 10 }] },
      { question: 'Which apostle was skeptical about Jesus in the beginning?', options: ['Peter', 'James', 'Philip', 'Nathanael'], correctIndex: 2, hints: [{ text: '"Can anything good come from Nazareth?"', cost: 10 }] },
      { question: 'Who was martyred by being beheaded by King Herod?', options: ['Stephen', 'Peter', 'James', 'John'], correctIndex: 2, hints: [{ text: 'Brother of John', cost: 10 }] }
    ],
    kings: [
      { question: 'Who was the first king of Israel?', options: ['David', 'Saul', 'Solomon', 'Rehoboam'], correctIndex: 1, hints: [{ text: 'Chosen by prophet Samuel', cost: 10 }] },
      { question: 'How many wives did King Solomon have?', options: ['7', '100', '700', '1000'], correctIndex: 2, hints: [{ text: 'A very large number', cost: 10 }] },
      { question: 'Who built the first Temple in Jerusalem?', options: ['David', 'Solomon', 'Hezekiah', 'Josiah'], correctIndex: 1, hints: [{ text: 'His father gathered materials', cost: 10 }] },
      { question: 'How long did King David reign in Israel?', options: ['20 years', '30 years', '40 years', '50 years'], correctIndex: 2, hints: [{ text: 'A round number of decades', cost: 10 }] },
      { question: 'Which king of Israel was known for his wisdom?', options: ['Saul', 'David', 'Solomon', 'Asa'], correctIndex: 2, hints: [{ text: 'God gave him extraordinary wisdom', cost: 10 }] },
      { question: 'Who was the youngest king of Judah?', options: ['Josiah', 'Jehoash', 'Amon', 'Manasseh'], correctIndex: 0, hints: [{ text: 'Became king at age 8', cost: 10 }] },
      { question: 'How many years did the Kingdom of Israel last?', options: ['200', '300', '400', '500'], correctIndex: 1, hints: [{ text: 'About 3 centuries', cost: 10 }] },
      { question: 'Who was the last king of the unified kingdom?', options: ['David', 'Solomon', 'Rehoboam', 'Jeroboam'], correctIndex: 1, hints: [{ text: 'After him, kingdom divided', cost: 10 }] },
      { question: 'What was King David\'s army commander\'s name?', options: ['Caleb', 'Joab', 'Gad', 'Nathan'], correctIndex: 1, hints: [{ text: 'Remained loyal to David', cost: 10 }] },
      { question: 'Which king of Israel was anointed by the prophet Samuel as a young boy?', options: ['Saul', 'David', 'Solomon', 'Asa'], correctIndex: 1, hints: [{ text: 'The youngest son of Jesse', cost: 10 }] },
      { question: 'Who succeeded Solomon as king?', options: ['David', 'Rehoboam', 'Jeroboam', 'Asa'], correctIndex: 1, hints: [{ text: 'His son; kingdom divided after him', cost: 10 }] },
      { question: 'What caused Saul\'s downfall as king?', options: ['Disobedience to God', 'Enemy invasion', 'Illness', 'Age'], correctIndex: 0, hints: [{ text: 'Samuel withdrew support', cost: 10 }] }
    ],
    prophets: [
      { question: 'Who prophesied about Jesus being born in Bethlehem?', options: ['Isaiah', 'Jeremiah', 'Micah', 'Amos'], correctIndex: 2, hints: [{ text: 'A minor prophet', cost: 10 }] },
      { question: 'Which prophet was taken to heaven without dying?', options: ['Elijah', 'Elisha', 'Enoch', 'Moses'], correctIndex: 0, hints: [{ text: 'Went up in a whirlwind', cost: 10 }] },
      { question: 'How many books did Isaiah write in the Old Testament?', options: ['1', '2', '3', '4'], correctIndex: 0, hints: [{ text: 'One long book', cost: 10 }] },
      { question: 'Who was the prophet in the wilderness baptizing people?', options: ['Philip', 'John the Baptist', 'Peter', 'Andrew'], correctIndex: 1, hints: [{ text: 'Baptized Jesus in Jordan', cost: 10 }] },
      { question: 'Which prophet had a vision of dry bones coming to life?', options: ['Daniel', 'Ezekiel', 'Jeremiah', 'Isaiah'], correctIndex: 1, hints: [{ text: 'About restoration of Israel', cost: 10 }] },
      { question: 'Who was thrown into a den of lions?', options: ['Jeremiah', 'Daniel', 'Ezekiel', 'Hosea'], correctIndex: 1, hints: [{ text: 'Refused to stop praying', cost: 10 }] },
      { question: 'Which prophet said "Here am I, send me"?', options: ['Jeremiah', 'Isaiah', 'Ezekiel', 'Amos'], correctIndex: 1, hints: [{ text: 'Responded to God\'s call', cost: 10 }] },
      { question: 'Who was swallowed by a great fish for three days?', options: ['Isaiah', 'Jonah', 'Jeremiah', 'Nahum'], correctIndex: 1, hints: [{ text: 'Preached to Nineveh', cost: 10 }] },
      { question: 'Which prophet was called "the weeping prophet"?', options: ['Isaiah', 'Jeremiah', 'Ezekiel', 'Hosea'], correctIndex: 1, hints: [{ text: 'Lamentations is attributed to him', cost: 10 }] },
      { question: 'What miracle did Elijah perform to prove God\'s power?', options: ['Parted the Jordan', 'Called fire from heaven', 'Raised the dead', 'Healed lepers'], correctIndex: 1, hints: [{ text: 'On Mount Carmel', cost: 10 }] },
      { question: 'Who was the prophet that performed 16 miracles?', options: ['Elijah', 'Elisha', 'Isaiah', 'Jeremiah'], correctIndex: 1, hints: [{ text: 'Successor to Elijah', cost: 10 }] },
      { question: 'Which prophet wrote prophecies while in captivity in Babylon?', options: ['Jeremiah', 'Daniel', 'Ezekiel', 'Hosea'], correctIndex: 1, hints: [{ text: 'Interpreted the king\'s dreams', cost: 10 }] },
      { question: 'Who was fed by ravens in the wilderness?', options: ['Moses', 'Elijah', 'Elisha', 'John'], correctIndex: 1, hints: [{ text: 'Escaped King Ahab', cost: 10 }] },
      { question: 'Which prophet saw a burning bush?', options: ['Jeremiah', 'Moses', 'Isaiah', 'Ezekiel'], correctIndex: 1, hints: [{ text: 'Received God\'s call at Mount Horeb', cost: 10 }] },
      { question: 'Who was the prophet that wrote the book of Lamentations?', options: ['Jeremiah', 'Isaiah', 'Ezekiel', 'Daniel'], correctIndex: 0, hints: [{ text: 'Witnessed Jerusalem\'s fall', cost: 10 }] },
      { question: 'Which prophet had a vision of the valley of the bones?', options: ['Isaiah', 'Jeremiah', 'Ezekiel', 'Zechariah'], correctIndex: 2, hints: [{ text: 'About spiritual rebirth', cost: 10 }] },
      { question: 'Who was a prophet that also was a tax collector before Jesus?', options: ['Matthew', 'Levi', 'Mark', 'Luke'], correctIndex: 0, hints: [{ text: 'Wrote the first gospel', cost: 10 }] },
      { question: 'Which prophet predicted the seventy weeks?', options: ['Isaiah', 'Jeremiah', 'Daniel', 'Hosea'], correctIndex: 2, hints: [{ text: 'Interpreted visions in Babylon', cost: 10 }] },
      { question: 'Who was the last prophet of the Old Testament?', options: ['Jeremiah', 'Ezekiel', 'Malachi', 'Zephaniah'], correctIndex: 2, hints: [{ text: 'Before the 400 silent years', cost: 10 }] },
      { question: 'Which prophet was told to marry an unfaithful woman?', options: ['Jeremiah', 'Hosea', 'Amos', 'Jonah'], correctIndex: 1, hints: [{ text: 'Symbolic of Israel\'s unfaithfulness', cost: 10 }] },
      { question: 'Who was a prophet during the exile in Babylon?', options: ['Isaiah', 'Jeremiah', 'Daniel', 'Ezekiel'], correctIndex: 2, hints: [{ text: 'Saw visions of future kingdoms', cost: 10 }] }
    ],
    parables: [
      { question: 'In the parable of the sower, what do the seeds represent?', options: ['Money', 'God\'s Word', 'Possessions', 'Eternal life'], correctIndex: 1, hints: [{ text: 'About God\'s message', cost: 10 }] },
      { question: 'What is the main lesson of the Good Samaritan parable?', options: ['Avoid strangers', 'Love neighbors', 'Help friends only', 'Give to poor'], correctIndex: 1, hints: [{ text: 'About compassion', cost: 10 }] },
      { question: 'In the parable of the prodigal son, what does the father represent?', options: ['Judgment', 'God\'s forgiveness', 'Punishment', 'Wealth'], correctIndex: 1, hints: [{ text: 'About forgiveness', cost: 10 }] },
      { question: 'What does the mustard seed parable teach?', options: ['How to farm', 'Small faith grows great', 'Farming importance', 'Humility only'], correctIndex: 1, hints: [{ text: 'Kingdom of God', cost: 10 }] },
      { question: 'In the parable of the talents, what do talents represent?', options: ['Coins', 'Spiritual gifts', 'Hard work', 'Wealth'], correctIndex: 1, hints: [{ text: 'Using God\'s gifts', cost: 10 }] },
      { question: 'What does the parable of the ten virgins teach?', options: ['Party planning', 'Being prepared', 'Oil importance', 'Wedding customs'], correctIndex: 1, hints: [{ text: 'About readiness', cost: 10 }] },
      { question: 'In the parable of the lost sheep, how many sheep does the shepherd have?', options: ['50', '75', '100', '200'], correctIndex: 2, hints: [{ text: 'Leaves the flock to find one', cost: 10 }] },
      { question: 'What does leaven represent in Jesus\'s parables?', options: ['Bread', 'Sin/corruption', 'Blessing', 'Growth'], correctIndex: 1, hints: [{ text: 'Spreads through dough', cost: 10 }] },
      { question: 'In the parable of the wedding feast, what does the feast represent?', options: ['A party', 'God\'s kingdom', 'A business', 'Earthly riches'], correctIndex: 1, hints: [{ text: 'About God\'s invitation', cost: 10 }] },
      { question: 'What lesson does the parable of the two builders teach?', options: ['Building skills', 'Hearing and obeying God\'s word', 'Work ethic', 'Teamwork'], correctIndex: 1, hints: [{ text: 'One built on rock, one on sand', cost: 10 }] },
      { question: 'In the parable of the workers in the vineyard, what is the main point?', options: ['Fair wages', 'God\'s grace and generosity', 'Work hours', 'Labor disputes'], correctIndex: 1, hints: [{ text: 'All paid the same despite working different hours', cost: 10 }] },
      { question: 'What does the parable of the net teach?', options: ['Fishing techniques', 'God separates the righteous from unrighteous', 'Ocean life', 'Commerce'], correctIndex: 1, hints: [{ text: 'Catches both good and bad fish', cost: 10 }] }
    ],
    miracles: [
      { question: 'Which miracle did Jesus perform first according to John\'s Gospel?', options: ['Healing blind', 'Water to wine', 'Feeding 5,000', 'Walking on water'], correctIndex: 1, hints: [{ text: 'At a wedding', cost: 10 }] },
      { question: 'How many loaves and fish did Jesus use to feed the 5,000?', options: ['2 loaves, 2 fish', '5 loaves, 2 fish', '7 loaves, 5 fish', '10 loaves, 3 fish'], correctIndex: 1, hints: [{ text: 'A small meal', cost: 10 }] },
      { question: 'Which body of water did Jesus calm by saying "Peace, be still"?', options: ['Red Sea', 'Dead Sea', 'Sea of Galilee', 'Mediterranean'], correctIndex: 2, hints: [{ text: 'Called Sea of Tiberias', cost: 10 }] },
      { question: 'How many days was Jesus in the tomb before resurrection?', options: ['1', '2', '3', '4'], correctIndex: 2, hints: [{ text: 'Rose on the third day', cost: 10 }] },
      { question: 'Which person did Jesus raise from the dead?', options: ['His sister Mary', 'Lazarus', 'His mother', 'Peter\'s wife'], correctIndex: 1, hints: [{ text: 'Dead four days', cost: 10 }] },
      { question: 'How many demon-possessed pigs did Jesus send into the sea?', options: ['10', '100', '1000', '2000'], correctIndex: 3, hints: [{ text: 'A large herd', cost: 10 }] },
      { question: 'How many baskets of leftovers were collected after feeding the 5,000?', options: ['10', '11', '12', '13'], correctIndex: 2, hints: [{ text: 'One per disciple', cost: 10 }] },
      { question: 'How many people were healed at the pool of Bethesda?', options: ['1', '2', '3', '5'], correctIndex: 0, hints: [{ text: 'A specific man', cost: 10 }] },
      { question: 'Who was blind and healed by Jesus in Jericho?', options: ['Zacchaeus', 'Bartimaeus', 'Judas', 'Martha'], correctIndex: 1, hints: [{ text: 'Called out to Jesus', cost: 10 }] },
      { question: 'What did Jesus use to heal the blind man at Bethsaida?', options: ['His word', 'Mud and saliva', 'Oil', 'Water'], correctIndex: 1, hints: [{ text: 'Applied to his eyes', cost: 10 }] },
      { question: 'How many fish did the disciples catch on the miraculous catch?', options: ['100', '153', '200', '300'], correctIndex: 1, hints: [{ text: 'After Jesus told them where to cast net', cost: 10 }] },
      { question: 'Which leper did Jesus cleanse by touching him?', options: ['Named in Luke', 'Not specifically named', 'Zacchaeus', 'Bartimaeus'], correctIndex: 1, hints: [{ text: 'Jesus showed compassion', cost: 10 }] },
      { question: 'How many years was the woman bent over with an infirmity?', options: ['5 years', '10 years', '18 years', '25 years'], correctIndex: 2, hints: [{ text: 'Jesus healed her on the Sabbath', cost: 10 }] },
      { question: 'What did Jesus command the disciples to do during the storm?', options: ['Row faster', 'Pray', 'Fear not', 'Go to the stern'], correctIndex: 2, hints: [{ text: 'He walked on water toward them', cost: 10 }] },
      { question: 'How many people were fed in the second feeding miracle?', options: ['2,000', '4,000', '5,000', '7,000'], correctIndex: 1, hints: [{ text: 'Seven loaves and a few fish', cost: 10 }] },
      { question: 'What was wrong with the Canaanite woman\'s daughter?', options: ['Paralyzed', 'Blind', 'Possessed by a demon', 'Fever'], correctIndex: 2, hints: [{ text: 'Jesus healed her from a distance', cost: 10 }] },
      { question: 'How many times did Peter cut off an ear with a sword?', options: ['Once', 'Twice', 'Three times', 'Not at all'], correctIndex: 0, hints: [{ text: 'During Jesus\'s arrest', cost: 10 }] },
      { question: 'Who did Jesus heal by spitting in their eyes?', options: ['The blind man at Bethsaida', 'A leper', 'A paralytic', 'The Canaanite\'s daughter'], correctIndex: 0, hints: [{ text: 'In stages', cost: 10 }] },
      { question: 'What body part did Jesus say would not taste death for some standing there?', options: ['Hands', 'Eyes', 'Feet', 'Head'], correctIndex: 1, hints: [{ text: 'About the resurrection/kingdom', cost: 10 }] },
      { question: 'How many net catches broke due to the miraculous catch of fish?', options: ['One', 'Two', 'Three', 'None'], correctIndex: 0, hints: [{ text: 'Because of so many fish', cost: 10 }] },
      { question: 'Who touched Jesus\'s garment and was healed of bleeding?', options: ['Martha', 'Mary', 'A woman in the crowd', 'Joanna'], correctIndex: 2, hints: [{ text: 'Suffered for 12 years', cost: 10 }] }
    ]
  },
  memoryVerses: [
    { verse: 'For God so loved the world that he gave his one and only Son, that whoever believes in him shall not perish but have eternal life.', reference: 'John 3:16', difficulty: 'easy' },
    { verse: 'I can do all this through him who gives me strength.', reference: 'Philippians 4:13', difficulty: 'easy' },
    { verse: 'For the wages of sin is death, but the gift of God is eternal life in Christ Jesus our Lord.', reference: 'Romans 6:23', difficulty: 'medium' },
    { verse: 'Trust in the Lord with all your heart and lean not on your own understanding.', reference: 'Proverbs 3:5', difficulty: 'medium' },
    { verse: 'I am the way and the truth and the life. No one comes to the Father except through me.', reference: 'John 14:6', difficulty: 'easy' },
    { verse: 'All have sinned and fall short of the glory of God.', reference: 'Romans 3:23', difficulty: 'medium' },
    { verse: 'In the beginning was the Word, and the Word was with God, and the Word was God.', reference: 'John 1:1', difficulty: 'medium' },
    { verse: 'Blessed are those who hunger and thirst for righteousness, for they will be filled.', reference: 'Matthew 5:6', difficulty: 'hard' }
  ],
  fillinVerse: [
    { verse: 'For God so loved the world that he gave his ___ and only Son', answer: 'one', reference: 'John 3:16', difficulty: 'medium' },
    { verse: 'I can do all this through him who gives me ___', answer: 'strength', reference: 'Philippians 4:13', difficulty: 'easy' },
    { verse: 'The ___ of sin is death, but the gift of God is eternal life', answer: 'wages', reference: 'Romans 6:23', difficulty: 'hard' },
    { verse: 'Trust in the ___ with all your heart', answer: 'Lord', reference: 'Proverbs 3:5', difficulty: 'easy' },
    { verse: 'I am the ___ and the truth and the life', answer: 'way', reference: 'John 14:6', difficulty: 'easy' },
    { verse: 'All have ___ and fall short of the glory of God', answer: 'sinned', reference: 'Romans 3:23', difficulty: 'medium' }
  ],
  characters: [
    { name: 'Jesus', clues: ['Founder of Christianity', 'Born in Bethlehem', 'Crucified and rose from the dead'], difficulty: 'easy' },
    { name: 'Moses', clues: ['Led Israel out of Egypt', 'Received the Ten Commandments', 'Staff turned to serpent'], difficulty: 'medium' },
    { name: 'David', clues: ['King of Israel', 'Defeated Goliath', 'Wrote many Psalms'], difficulty: 'easy' },
    { name: 'Paul', clues: ['Formerly called Saul', 'Wrote epistles', 'Missionary to Gentiles'], difficulty: 'medium' },
    { name: 'Mary', clues: ['Mother of Jesus', 'Visited by angel Gabriel', 'Gave birth in Bethlehem'], difficulty: 'easy' },
    { name: 'Peter', clues: ['Denied Jesus three times', 'Walked on water', 'Called the Rock'], difficulty: 'medium' }
  ],
  wordscramble: [
    { scrambled: 'SSUEJ', answer: 'JESUS', difficulty: 'easy' },
    { scrambled: 'LEVOS', answer: 'LOVES', difficulty: 'easy' },
    { scrambled: 'HFIAT', answer: 'FAITH', difficulty: 'easy' },
    { scrambled: 'PEHPO', answer: 'HOPE', difficulty: 'easy' },
    { scrambled: 'TETSNAM', answer: 'TESTAMENT', difficulty: 'medium' },
    { scrambled: 'LESPOG', answer: 'GOSPEL', difficulty: 'medium' },
    { scrambled: 'ELTSOPA', answer: 'APOSTLE', difficulty: 'medium' }
  ],
  puzzles: [
    { clue: 'Turned water into wine at wedding', answer: 'CANA', difficulty: 'medium' },
    { clue: 'Place where Jesus was born', answer: 'BETHLEHEM', difficulty: 'easy' },
    { clue: 'Garden where Adam and Eve lived', answer: 'EDEN', difficulty: 'easy' },
    { clue: 'Mountain where Moses received commandments', answer: 'SINAI', difficulty: 'medium' },
    { clue: 'City where Jesus was crucified', answer: 'JERUSALEM', difficulty: 'medium' }
  ],
  wordsearch: [
    { words: ['JESUS', 'LOVE', 'FAITH', 'HOPE', 'GRACE'], gridSize: 10, difficulty: 'easy' },
    { words: ['GOSPEL', 'APOSTLE', 'DISCIPLE', 'TESTAMENT', 'SERMON'], gridSize: 12, difficulty: 'medium' },
    { words: ['RESURRECTION', 'SALVATION', 'REDEMPTION', 'SANCTIFICATION'], gridSize: 14, difficulty: 'hard' }
  ],
  trueOrFalse: [
    { type: 'trueOrFalse', question: 'Jesus performed His first miracle at a wedding in Cana', answer: true, difficulty: 'easy', explanation: 'Jesus turned water into wine at a wedding in Cana' },
    { type: 'trueOrFalse', question: 'Samson had 12 disciples', answer: false, difficulty: 'easy', explanation: 'Jesus had 12 disciples, not Samson' },
    { type: 'trueOrFalse', question: 'The Bible contains exactly 66 books', answer: true, difficulty: 'medium', explanation: 'The Protestant Bible has 66 books (39 Old Testament, 27 New Testament)' },
    { type: 'trueOrFalse', question: 'King Solomon had 700 wives', answer: true, difficulty: 'medium', explanation: 'Scripture records Solomon had 700 wives and 300 concubines' },
    { type: 'trueOrFalse', question: 'Jonah spent 3 days and 3 nights in the fish', answer: true, difficulty: 'easy', explanation: 'Jonah 1:17 records Jonah was in the fish\'s belly for 3 days and nights' },
    { type: 'trueOrFalse', question: 'The Ten Commandments were written on paper', answer: false, difficulty: 'easy', explanation: 'The Ten Commandments were written on stone tablets' },
    { type: 'trueOrFalse', question: 'Peter walked on water with Jesus', answer: true, difficulty: 'medium', explanation: 'Matthew 14:28-29 records Peter walking on water toward Jesus' },
    { type: 'trueOrFalse', question: 'Judas betrayed Jesus for 50 pieces of silver', answer: false, difficulty: 'medium', explanation: 'Judas was paid 30 pieces of silver for betraying Jesus' }
  ],
  shortAnswer: [
    { type: 'shortAnswer', question: 'What did Jesus turn into wine?', answer: 'water', difficulty: 'easy', hint: 'It was at a wedding in Cana' },
    { type: 'shortAnswer', question: 'Who was swallowed by a great fish?', answer: 'Jonah', difficulty: 'easy', hint: 'An Old Testament prophet' },
    { type: 'shortAnswer', question: 'What did Moses receive on Mount Sinai?', answer: 'Ten Commandments', difficulty: 'medium', hint: 'God\'s laws' },
    { type: 'shortAnswer', question: 'Who was the first king of Israel?', answer: 'Saul', difficulty: 'medium', hint: 'Chosen by prophet Samuel' },
    { type: 'shortAnswer', question: 'What animal did Elijah ride to heaven?', answer: 'chariot', difficulty: 'hard', hint: 'A vehicle of fire' },
    { type: 'shortAnswer', question: 'How many loaves and fish fed the 5,000?', answer: '5 loaves and 2 fish', difficulty: 'easy', hint: 'A small meal' },
    { type: 'shortAnswer', question: 'What city was Jesus born in?', answer: 'Bethlehem', difficulty: 'easy', hint: 'City of David' },
    { type: 'shortAnswer', question: 'Who was the first martyr of the early church?', answer: 'Stephen', difficulty: 'medium', hint: 'Stoned to death' }
  ],
  matchingQuestions: [
    { type: 'matching', pairs: [{ item: 'Moses', match: 'Led Israel out of Egypt' }, { item: 'David', match: 'Defeated Goliath' }, { item: 'Jonah', match: 'Swallowed by a fish' }, { item: 'Noah', match: 'Built the ark' }], difficulty: 'easy' },
    { type: 'matching', pairs: [{ item: 'John 3:16', match: 'For God so loved the world' }, { item: 'Psalm 23', match: 'The Lord is my shepherd' }, { item: 'Romans 6:23', match: 'The wages of sin is death' }, { item: 'Philippians 4:13', match: 'I can do all things' }], difficulty: 'medium' },
    { type: 'matching', pairs: [{ item: 'Matthew', match: 'Tax collector turned apostle' }, { item: 'Peter', match: 'Denied Jesus three times' }, { item: 'Judas', match: 'Betrayed Jesus' }, { item: 'James', match: 'Brother of John' }], difficulty: 'medium' }
  ]
};

// Initialize questions with expanded Bible content on server startup
initializeQuestions();

app.post('/api/admin/games/:gameType/auto-populate', verifyToken, requireRole(ROLES.SYSTEM_ADMIN, ROLES.MODERATOR), (req, res) => {
  try {
    const { gameType } = req.params;
    
    if (!otherGames[gameType]) {
      return res.status(404).json({ error: 'Game type not found' });
    }
    
    let sourceData = [];
    let addedCount = 0;
    
    switch (gameType) {
      case 'memory':
        sourceData = bibleContent.memoryVerses;
        otherGames[gameType] = sourceData.map((item, i) => ({
          ...item,
          id: `${gameType}_${i}_${Date.now()}`
        }));
        addedCount = sourceData.length;
        break;
        
      case 'fillin':
        sourceData = bibleContent.fillinVerse;
        otherGames[gameType] = sourceData.map((item, i) => ({
          ...item,
          id: `${gameType}_${i}_${Date.now()}`
        }));
        addedCount = sourceData.length;
        break;
        
      case 'character':
        sourceData = bibleContent.characters;
        otherGames[gameType] = sourceData.map((item, i) => ({
          ...item,
          id: `${gameType}_${i}_${Date.now()}`
        }));
        addedCount = sourceData.length;
        break;
        
      case 'wordscramble':
        sourceData = bibleContent.wordscramble;
        otherGames[gameType] = sourceData.map((item, i) => ({
          ...item,
          id: `${gameType}_${i}_${Date.now()}`
        }));
        addedCount = sourceData.length;
        break;
        
      case 'puzzle':
        sourceData = bibleContent.puzzles;
        otherGames[gameType] = sourceData.map((item, i) => ({
          ...item,
          id: `${gameType}_${i}_${Date.now()}`
        }));
        addedCount = sourceData.length;
        break;
        
      case 'wordsearch':
        sourceData = bibleContent.wordsearch;
        otherGames[gameType] = sourceData.map((item, i) => ({
          ...item,
          id: `${gameType}_${i}_${Date.now()}`
        }));
        addedCount = sourceData.length;
        break;
        
      default:
        return res.status(400).json({ error: 'Cannot auto-populate trivia (use manual entry)' });
    }
    
    res.json({ 
      message: `Auto-populated ${gameType} with ${addedCount} items from Bible content`,
      itemsAdded: addedCount,
      content: otherGames[gameType]
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to auto-populate' });
  }
});

// Auto-populate trivia questions from Bible content
app.post('/api/admin/questions/auto-populate/:category', verifyToken, requireRole(ROLES.SYSTEM_ADMIN, ROLES.MODERATOR), (req, res) => {
  try {
    const { category } = req.params;
    
    if (!bibleContent.triviaQuestions[category]) {
      return res.status(404).json({ error: `Category ${category} not found` });
    }
    
    const sourceQuestions = bibleContent.triviaQuestions[category];
    questions[category] = sourceQuestions.map((q, i) => {
      // Shuffle options and track new correct index
      const optionsWithIndex = q.options.map((opt, idx) => ({ text: opt, originalIdx: idx }));
      const shuffled = optionsWithIndex.sort(() => Math.random() - 0.5);
      const newCorrectIndex = shuffled.findIndex(item => item.originalIdx === q.correctIndex);
      
      return {
        questionId: `${category}_${i}_${Date.now()}`,
        question: q.question,
        options: shuffled.map(item => item.text),
        correctIndex: newCorrectIndex,
        hints: q.hints || [],
        difficulty: q.difficulty || 'medium'
      };
    });
    
    res.json({ 
      message: `Auto-populated ${category} with ${sourceQuestions.length} trivia questions (shuffled options)`,
      itemsAdded: sourceQuestions.length,
      questions: questions[category]
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to auto-populate trivia' });
  }
});

// Auto-populate all trivia categories at once
app.post('/api/admin/questions/auto-populate-all', verifyToken, requireRole(ROLES.SYSTEM_ADMIN, ROLES.MODERATOR), (req, res) => {
  try {
    let totalAdded = 0;
    const results = {};
    
    Object.entries(bibleContent.triviaQuestions).forEach(([category, sourceQuestions]) => {
      questions[category] = sourceQuestions.map((q, i) => {
        // Shuffle options and track new correct index
        const optionsWithIndex = q.options.map((opt, idx) => ({ text: opt, originalIdx: idx }));
        const shuffled = optionsWithIndex.sort(() => Math.random() - 0.5);
        const newCorrectIndex = shuffled.findIndex(item => item.originalIdx === q.correctIndex);
        
        return {
          questionId: `${category}_${i}_${Date.now()}`,
          question: q.question,
          options: shuffled.map(item => item.text),
          correctIndex: newCorrectIndex,
          hints: q.hints || [],
          difficulty: q.difficulty || 'medium'
        };
      });
      results[category] = sourceQuestions.length;
      totalAdded += sourceQuestions.length;
    });
    
    res.json({ 
      message: `Auto-populated all trivia categories with ${totalAdded} questions (shuffled options)`,
      totalAdded,
      categoryBreakdown: results,
      questions
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to auto-populate all trivia' });
  }
});

// ========================
// GAME LOGIC
// ========================
app.post('/api/play-game', verifyToken, (req, res) => {
  try {
    const { isCorrect, timeTaken } = req.body;

    if (typeof isCorrect !== 'boolean') {
      return res.status(400).json({ error: 'Invalid game result' });
    }

    const stats = getUserStats(req.username);
    if (!stats) return res.status(400).json({ error: 'User stats not found' });

    stats.totalGamesPlayed++;
    let pointsEarned = 0;

    if (isCorrect) {
      let points = 100;
      if (timeTaken > 10) points = 80;
      if (timeTaken > 20) points = 60;
      if (timeTaken > 30) points = 50;
      if (timeTaken > 45) points = 40;
      if (timeTaken > 60) points = 30;

      pointsEarned = points;
      stats.totalWins++;
      stats.gamesWonToday++;
      stats.balance += points;
    } else {
      pointsEarned = -5;
      stats.totalLosses++;
      stats.balance = Math.max(0, stats.balance - 5);
    }

    // Track trivia score separately for leaderboard aggregation
    if (!stats.triviaScore) stats.triviaScore = 0;
    // Only add positive points earned to triviaScore (penalties not counted)
    stats.triviaScore += Math.max(0, pointsEarned);

    stats.lastGameTime = new Date().toISOString();
    saveUserStats(req.username, stats);

    res.json({
      message: isCorrect ? 'Correct Answer!' : 'Wrong Answer',
      isCorrect,
      pointsEarned,
      newBalance: stats.balance
    });

  } catch (error) {
    res.status(500).json({ error: 'Game play failed' });
  }
});

// BUY HINT
app.post('/api/buy-hint', verifyToken, (req, res) => {
  try {
    const { hintCost } = req.body;

    if (typeof hintCost !== 'number' || hintCost < 0) {
      return res.status(400).json({ error: 'Invalid hint cost' });
    }

    const stats = getUserStats(req.username);
    if (!stats) return res.status(400).json({ error: 'User stats not found' });

    if (stats.balance < hintCost) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }

    stats.balance -= hintCost;
    saveUserStats(req.username, stats);

    res.json({ success: true, newBalance: stats.balance });

  } catch (error) {
    res.status(500).json({ error: 'Hint purchase failed' });
  }
});

// CATEGORY LIST
app.get('/api/categories', verifyToken, (req, res) => {
  res.json({
    categories: [
      { id: 'oldTestament', name: 'Old Testament', icon: '📖' },
      { id: 'newTestament', name: 'New Testament', icon: '📕' },
      { id: 'jesus', name: 'Jesus & Gospels', icon: '✝️' },
      { id: 'apostles', name: 'Apostles & Early Church', icon: '⛪' },
      { id: 'kings', name: 'Kings & Rulers', icon: '👑' },
      { id: 'prophets', name: 'Prophets', icon: '🕯️' },
      { id: 'parables', name: 'Parables', icon: '📚' },
      { id: 'miracles', name: 'Miracles', icon: '✨' }
    ],
    questionTypes: [
      { id: 'multipleChoice', name: 'Multiple Choice' },
      { id: 'trueOrFalse', name: 'True or False' },
      { id: 'shortAnswer', name: 'Short Answer' },
      { id: 'matching', name: 'Matching' }
    ]
  });
});

// GET QUESTION - with smart rotation to prevent repeats
app.get('/api/get-question', verifyToken, (req, res) => {
  try {
    const category = req.query.category;
    const questionType = req.query.type || 'multipleChoice';
    
    if (!category || !questions[category]) {
      return res.status(400).json({ error: 'Invalid category' });
    }
    
    const categoryQuestions = questions[category];
    if (categoryQuestions.length === 0) {
      return res.status(400).json({ error: 'No questions available' });
    }
    
    // Get user's recent questions to avoid repeats
    const stats = getUserStats(req.username);
    const recentQuestions = (stats && stats.recentQuestions && stats.recentQuestions[category]) || [];
    
    // Filter out recently shown questions (track last 8 per category)
    const availableQuestions = categoryQuestions.filter(q => !recentQuestions.includes(q.questionId));
    
    // If all questions have been recently shown, reset and show any question
    const questionPool = availableQuestions.length > 0 ? availableQuestions : categoryQuestions;
    const randomQuestion = questionPool[Math.floor(Math.random() * questionPool.length)];
    
    // Track this question as recently shown
    if (stats) {
      if (!stats.recentQuestions) stats.recentQuestions = {};
      if (!stats.recentQuestions[category]) stats.recentQuestions[category] = [];
      
      // Add to recent list and keep only last 8 (out of 20+ available per category)
      stats.recentQuestions[category] = [randomQuestion.questionId, ...stats.recentQuestions[category]].slice(0, 8);
      
      saveUserStats(req.username, stats);
    }
    
    res.json(randomQuestion);
  } catch (error) {
    res.status(500).json({ error: 'Failed to get question' });
  }
});

// GET TRUE/FALSE QUESTION
app.get('/api/get-trueorfalse', verifyToken, (req, res) => {
  try {
    const trueOrFalseQuestions = bibleContent.trueOrFalse || [];
    if (trueOrFalseQuestions.length === 0) {
      return res.status(400).json({ error: 'No true/false questions available' });
    }
    
    const stats = getUserStats(req.username);
    const recentTF = (stats && stats.recentTrueFalse) || [];
    const availableTF = trueOrFalseQuestions.filter(q => !recentTF.includes(q.question));
    const questionPool = availableTF.length > 0 ? availableTF : trueOrFalseQuestions;
    
    const randomQuestion = questionPool[Math.floor(Math.random() * questionPool.length)];
    
    if (stats) {
      stats.recentTrueFalse = [randomQuestion.question, ...recentTF].slice(0, 8);
      saveUserStats(req.username, stats);
    }
    
    res.json(randomQuestion);
  } catch (error) {
    res.status(500).json({ error: 'Failed to get true/false question' });
  }
});

// GET SHORT ANSWER QUESTION
app.get('/api/get-shortanswer', verifyToken, (req, res) => {
  try {
    const shortAnswerQuestions = bibleContent.shortAnswer || [];
    if (shortAnswerQuestions.length === 0) {
      return res.status(400).json({ error: 'No short answer questions available' });
    }
    
    const stats = getUserStats(req.username);
    const recentSA = (stats && stats.recentShortAnswer) || [];
    const availableSA = shortAnswerQuestions.filter(q => !recentSA.includes(q.question));
    const questionPool = availableSA.length > 0 ? availableSA : shortAnswerQuestions;
    
    const randomQuestion = questionPool[Math.floor(Math.random() * questionPool.length)];
    
    if (stats) {
      stats.recentShortAnswer = [randomQuestion.question, ...recentSA].slice(0, 8);
      saveUserStats(req.username, stats);
    }
    
    res.json(randomQuestion);
  } catch (error) {
    res.status(500).json({ error: 'Failed to get short answer question' });
  }
});

// GET MATCHING QUESTION
app.get('/api/get-matching', verifyToken, (req, res) => {
  try {
    const matchingQuestions = bibleContent.matchingQuestions || [];
    if (matchingQuestions.length === 0) {
      return res.status(400).json({ error: 'No matching questions available' });
    }
    
    const stats = getUserStats(req.username);
    const recentMatch = (stats && stats.recentMatching) || [];
    const availableMatch = matchingQuestions.filter((q, i) => !recentMatch.includes(i));
    const questionPool = availableMatch.length > 0 ? availableMatch : matchingQuestions;
    
    const randomQuestion = questionPool[Math.floor(Math.random() * questionPool.length)];
    const questionIndex = matchingQuestions.indexOf(randomQuestion);
    
    if (stats) {
      stats.recentMatching = [questionIndex, ...recentMatch].slice(0, 5);
      saveUserStats(req.username, stats);
    }
    
    res.json(randomQuestion);
  } catch (error) {
    res.status(500).json({ error: 'Failed to get matching question' });
  }
});

// ========================
// TASKS
// ========================
app.get('/api/tasks', verifyToken, (req, res) => {
  try {
    res.json(loadTasks());
  } catch (error) {
    res.status(500).json({ error: 'Failed to load tasks' });
  }
});

app.post('/api/tasks', verifyToken, (req, res) => {
  try {
    const user = getUserFromToken(req.headers.authorization);
    const canManageTasks = MANAGEMENT_ROLES.includes(user.role);
    
    if (!canManageTasks) {
      return res.status(403).json({ error: 'Only administrators and ministry leaders can manage tasks' });
    }
    
    const { id, title, assignee, priority, status } = req.body;
    const tasks = loadTasks();
    const index = tasks.findIndex(t => t.id === id);
    
    if (index >= 0) {
      tasks[index] = { ...tasks[index], title, assignee, priority, status };
    } else {
      tasks.push({ id: Date.now().toString(), title, assignee, priority, status });
    }
    
    saveTasks(tasks);
    res.json({ success: true, tasks });
  } catch (error) {
    res.status(500).json({ error: 'Failed to save task' });
  }
});

app.delete('/api/tasks/:id', verifyToken, (req, res) => {
  try {
    const user = getUserFromToken(req.headers.authorization);
    const canManageTasks = MANAGEMENT_ROLES.includes(user.role);
    
    if (!canManageTasks) {
      return res.status(403).json({ error: 'Only administrators and ministry leaders can delete tasks' });
    }
    
    const tasks = loadTasks().filter(t => t.id !== req.params.id);
    saveTasks(tasks);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete task' });
  }
});

// ========================
// EVENTS - Admins and ministry leaders can modify
// ========================
app.get('/api/events', verifyToken, (req, res) => {
  try {
    res.json(loadEvents());
  } catch (error) {
    res.status(500).json({ error: 'Failed to load events' });
  }
});

app.post('/api/events', verifyToken, (req, res) => {
  try {
    const user = getUserFromToken(req.headers.authorization);
    const canManageEvents = MANAGEMENT_ROLES.includes(user.role);
    
    if (!canManageEvents) {
      return res.status(403).json({ error: 'Only administrators and ministry leaders can manage activities' });
    }
    
    const { id, title, date, description } = req.body;
    const events = loadEvents();
    const index = events.findIndex(e => e.id === id);
    
    if (index >= 0) {
      events[index] = { ...events[index], title, date, description };
    } else {
      events.push({ id: Date.now().toString(), title, date, description, createdBy: user.username });
    }
    
    saveEvents(events);
    res.json({ success: true, events });
  } catch (error) {
    res.status(500).json({ error: 'Failed to save event' });
  }
});

app.delete('/api/events/:id', verifyToken, (req, res) => {
  try {
    const user = getUserFromToken(req.headers.authorization);
    const canManageEvents = MANAGEMENT_ROLES.includes(user.role);
    
    if (!canManageEvents) {
      return res.status(403).json({ error: 'Only administrators and ministry leaders can delete activities' });
    }
    
    const events = loadEvents().filter(e => e.id !== req.params.id);
    saveEvents(events);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete event' });
  }
});

// ========================
// ANNOUNCEMENTS - Admins and ministry leaders can modify
// ========================
app.get('/api/announcements', verifyToken, (req, res) => {
  try {
    res.json(loadAnnouncements());
  } catch (error) {
    res.status(500).json({ error: 'Failed to load announcements' });
  }
});

app.post('/api/announcements', verifyToken, (req, res) => {
  try {
    const user = getUserFromToken(req.headers.authorization);
    const canManageAnnouncements = MANAGEMENT_ROLES.includes(user.role);
    
    if (!canManageAnnouncements) {
      return res.status(403).json({ error: 'Only administrators and ministry leaders can manage announcements' });
    }
    
    const { id, title, content, date } = req.body;
    const announcements = loadAnnouncements();
    const index = announcements.findIndex(a => a.id === id);
    
    if (index >= 0) {
      announcements[index] = { ...announcements[index], title, content, date };
    } else {
      announcements.push({ id: Date.now().toString(), title, content, date, createdBy: user.username });
    }
    
    saveAnnouncements(announcements);
    res.json({ success: true, announcements });
  } catch (error) {
    res.status(500).json({ error: 'Failed to save announcement' });
  }
});

app.delete('/api/announcements/:id', verifyToken, (req, res) => {
  try {
    const user = getUserFromToken(req.headers.authorization);
    const canManageAnnouncements = MANAGEMENT_ROLES.includes(user.role);
    
    if (!canManageAnnouncements) {
      return res.status(403).json({ error: 'Only administrators and ministry leaders can delete announcements' });
    }
    
    const announcements = loadAnnouncements().filter(a => a.id !== req.params.id);
    saveAnnouncements(announcements);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete announcement' });
  }
});

// ========================
// POSTS - All users can create, anyone can view
// ========================
app.get('/api/posts', verifyToken, (req, res) => {
  try {
    res.json(loadPosts());
  } catch (error) {
    res.status(500).json({ error: 'Failed to load posts' });
  }
});

app.post('/api/posts', verifyToken, (req, res) => {
  try {
    const user = getUserFromToken(req.headers.authorization);
    const { content, caption, imageData } = req.body;

    if ((!content || !content.trim()) && !imageData && !caption) {
      return res.status(400).json({ error: 'Post cannot be empty' });
    }

    const posts = loadPosts();
    const newPost = {
      id: Date.now().toString(),
      author: user.username,
      role: (function(r){ if(!r) return 'general'; return r; })(user.role),
      content: content ? content.trim() : '',
      caption: caption ? caption.trim() : '',
      image: null,
      comments: [],
      likes: 0,
      loves: 0,
      likedBy: [],
      lovedBy: [],
      createdAt: new Date().toISOString()
    };

    // Handle imageData (data URL) if provided with validation
    if (imageData && typeof imageData === 'string' && imageData.startsWith('data:')) {
      try {
        newPost.image = saveImageFromData(imageData);
      } catch (err) {
        return res.status(400).json({ error: 'Invalid image: ' + err.message });
      }
    }

    posts.push(newPost);
    savePosts(posts);
    // Broadcast new post to all connected clients
    io.emit('newPost', newPost);

    res.json({ success: true, post: newPost, posts });
  } catch (error) {
    res.status(500).json({ error: 'Failed to create post' });
  }
});

// Update / edit existing post
app.put('/api/posts/:id', verifyToken, (req, res) => {
  try {
    const user = getUserFromToken(req.headers.authorization);
    const { content, caption, imageData } = req.body;

    if ((!content || !content.trim()) && !imageData && !caption) {
      return res.status(400).json({ error: 'Post cannot be empty' });
    }

    const posts = loadPosts();
    const post = posts.find(p => p.id === req.params.id);
    if (!post) return res.status(404).json({ error: 'Post not found' });

    // Only author or admins/moderators can edit
    const allowedEditors = ['system-admin', 'admin', 'moderator'];
    if (post.author !== user.username && !allowedEditors.includes(user.role)) {
      return res.status(403).json({ error: 'Not authorized to edit this post' });
    }

    post.content = content ? content.trim() : post.content;
    post.caption = caption ? caption.trim() : post.caption;

    if (imageData && typeof imageData === 'string' && imageData.startsWith('data:')) {
      try {
        const newImagePath = saveImageFromData(imageData);
        // Optionally remove old image file if it exists under assets/images
        try {
          if (post.image && post.image.startsWith('/assets/images/')) {
            const oldPath = path.join(__dirname, '../public', post.image.replace(/^\//, ''));
            if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath);
          }
        } catch (_) {}
        post.image = newImagePath;
      } catch (err) {
        return res.status(400).json({ error: 'Invalid image: ' + err.message });
      }
    }

    savePosts(posts);
    // Broadcast updated post if needed
    io.emit('postUpdated', post);
    res.json({ success: true, post });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update post' });
  }
});

// Add comment to a post
app.post('/api/posts/:id/comment', verifyToken, (req, res) => {
  try {
    const user = getUserFromToken(req.headers.authorization);
    const { text } = req.body;
    if (!text || !text.trim()) return res.status(400).json({ error: 'Comment cannot be empty' });

    const posts = loadPosts();
    const post = posts.find(p => p.id === req.params.id);
    if (!post) return res.status(404).json({ error: 'Post not found' });

    const comment = {
      id: Date.now().toString(),
      author: user.username,
      text: text.trim(),
      createdAt: new Date().toISOString()
    };

    post.comments = post.comments || [];
    post.comments.push(comment);
    savePosts(posts);

    // Broadcast new comment to connected clients
    io.emit('postComment', { postId: post.id, comment });

    res.json({ success: true, comment, post });
  } catch (err) {
    res.status(500).json({ error: 'Failed to add comment' });
  }
});

app.delete('/api/posts/:id', verifyToken, (req, res) => {
  try {
    const user = getUserFromToken(req.headers.authorization);
    const posts = loadPosts();
    const post = posts.find(p => p.id === req.params.id);
    
    if (!post) {
      return res.status(404).json({ error: 'Post not found' });
    }
    
    if (post.author !== user.username && !['system-admin', 'admin', 'moderator'].includes(user.role)) {
      return res.status(403).json({ error: 'Not authorized to delete this post' });
    }
    
    const filtered = posts.filter(p => p.id !== req.params.id);
    savePosts(filtered);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete post' });
  }
});

// Like/Love posts
app.post('/api/posts/:id/like', verifyToken, (req, res) => {
  try {
    const user = getUserFromToken(req.headers.authorization);
    const { type } = req.body; // 'like' or 'love'
    const posts = loadPosts();
    const post = posts.find(p => p.id === req.params.id);
    
    if (!post) {
      return res.status(404).json({ error: 'Post not found' });
    }
    
    if (!post.likedBy) post.likedBy = [];
    if (!post.lovedBy) post.lovedBy = [];
    
    const likeKey = `${user.username}:${type}`;
    const existingIndex = post.likedBy.findIndex(l => l === `${user.username}:like`);
    const existingLoveIndex = post.lovedBy.findIndex(l => l === `${user.username}:love`);
    
    if (type === 'like') {
      if (existingIndex >= 0) {
        post.likedBy.splice(existingIndex, 1);
      } else {
        post.likedBy.push(`${user.username}:like`);
        if (existingLoveIndex >= 0) post.lovedBy.splice(existingLoveIndex, 1);
      }
    } else if (type === 'love') {
      if (existingLoveIndex >= 0) {
        post.lovedBy.splice(existingLoveIndex, 1);
      } else {
        post.lovedBy.push(`${user.username}:love`);
        if (existingIndex >= 0) post.likedBy.splice(existingIndex, 1);
      }
    }
    
    post.likes = post.likedBy.length;
    post.loves = post.lovedBy.length;
    
    savePosts(posts);
    // Broadcast like update so other clients can update counts
    io.emit('postLiked', { postId: post.id, likes: post.likes, loves: post.loves, likedBy: post.likedBy || [], lovedBy: post.lovedBy || [] });

    res.json({ success: true, likes: post.likes, loves: post.loves });
  } catch (error) {
    res.status(500).json({ error: 'Failed to like post' });
  }
});

// ========================
// LEADERBOARD with Win Rate (Grouped by Church, excludes system admins)
// ========================
app.get('/api/leaderboard', (req, res) => {
  try {
    const sortBy = req.query.sortBy || 'wins';
    const limit = parseInt(req.query.limit) || 100;
    
    const users = loadUsers();
    const codeRequests = loadCodeRequests();
    const leaderboard = [];
    
    Object.entries(users).forEach(([username, user]) => {
      // Exclude system admins from leaderboard
      if (user.role === 'system-admin') {
        return;
      }
      
      const stats = decryptData(user.stats);
      const games = stats.totalGamesPlayed || 0;
      const wins = stats.totalWins || 0;
      const winRate = games > 0 ? ((wins / games) * 100).toFixed(1) : 0;
      
        // Calculate game score stats
          const totalGameScore = stats.totalGameScore || 0;
          const gamesPlayedTotal = stats.gamesPlayedTotal || 0;
          const avgGameScore = gamesPlayedTotal > 0 ? (totalGameScore / gamesPlayedTotal).toFixed(1) : 0;

          // Compute per-game breakdown and Bible Games aggregate
          const gameBreakdown = {};
          const bibleGameTypes = new Set(['character', 'fillin', 'wordscramble', 'memory', 'wordsearch', 'puzzle', 'daily']);
          let bibleGamesScore = 0;

          if (stats.gameStats && typeof stats.gameStats === 'object') {
            Object.entries(stats.gameStats).forEach(([gType, gStats]) => {
              gameBreakdown[gType] = {
                gamesPlayed: gStats.gamesPlayed || 0,
                totalScore: gStats.totalScore || 0,
                bestScore: gStats.bestScore || 0
              };

              if (bibleGameTypes.has(gType)) {
                bibleGamesScore += (gStats.totalScore || 0);
              }
            });
          }

          // Trivia score (accumulated from trivia play points)
          const triviaScore = stats.triviaScore || 0;

          // Combined score = bible games + trivia
          const combinedScore = bibleGamesScore + triviaScore;
      
      // Get church name - use stored church or default, normalized to title case
      const churchName = normalizeChurch(user.church);
      
      leaderboard.push({
        username: username,
        church: churchName,
        wins: wins,
        losses: stats.totalLosses || 0,
        games: games,
        balance: stats.balance || 0,
        winRate: parseFloat(winRate),
        totalGameScore: totalGameScore,
        gamesPlayedTotal: gamesPlayedTotal,
        avgGameScore: parseFloat(avgGameScore),
        bibleGamesScore: bibleGamesScore,
        triviaScore: triviaScore,
        combinedScore: combinedScore,
        gameBreakdown: gameBreakdown,
        joinDate: user.createdAt || new Date().toISOString(),
        rank: 0
      });
    });

    // Group by church (normalized)
    const groupedByChurch = {};
    leaderboard.forEach(player => {
      const normalizedChurch = normalizeChurch(player.church);
      if (!groupedByChurch[normalizedChurch]) {
        groupedByChurch[normalizedChurch] = [];
      }
      groupedByChurch[normalizedChurch].push(player);
    });

    // Sort within each church group and flatten
    const sortedLeaderboard = [];
    Object.keys(groupedByChurch).sort().forEach(church => {
      const churchPlayers = groupedByChurch[church];
      
      // Sort by specified criteria
      if (sortBy === 'wins') {
        churchPlayers.sort((a, b) => b.wins - a.wins);
      } else if (sortBy === 'balance') {
        churchPlayers.sort((a, b) => b.balance - a.balance);
      } else if (sortBy === 'games') {
        churchPlayers.sort((a, b) => b.gamesPlayedTotal - a.gamesPlayedTotal);
      } else if (sortBy === 'winRate') {
        churchPlayers.sort((a, b) => b.winRate - a.winRate);
      } else if (sortBy === 'gameScore') {
        churchPlayers.sort((a, b) => b.totalGameScore - a.totalGameScore);
      } else if (sortBy === 'combined') {
        churchPlayers.sort((a, b) => (b.combinedScore || 0) - (a.combinedScore || 0));
      }
      
      // Add church header
      sortedLeaderboard.push({
        isChurchHeader: true,
        church: church,
        playerCount: churchPlayers.length
      });
      
      // Add ranked players with church-specific ranks
      churchPlayers.forEach((player, index) => {
        player.rank = index + 1;
        player.churchRank = index + 1;
        sortedLeaderboard.push(player);
      });
    });

    // Limit results
    const limited = sortedLeaderboard.slice(0, limit);
    res.json({ leaderboard: limited });
  } catch (error) {
    console.error('Leaderboard error:', error);
    res.status(500).json({ error: 'Failed to load leaderboard' });
  }
});

// ========================
// ONLINE MEMBERS (for dashboard)
// ========================
app.get('/api/online-members', verifyToken, (req, res) => {
  try {
    const users = loadUsers();
    const currentlyOnline = new Set(Object.values(connectedUsers || {}));

    const members = Object.entries(users).map(([username, user]) => ({
      name: username,
      role: user.role,
      church: normalizeChurch(user.church),
      online: currentlyOnline.has(username)
    }));

    // Sort with online users first
    members.sort((a, b) => (b.online === a.online) ? a.name.localeCompare(b.name) : (b.online ? 1 : -1));

    res.json({ members: members.slice(0, 50) });
  } catch (error) {
    res.status(500).json({ error: 'Failed to load members' });
  }
});

// Get user role info
app.get('/api/user-info', verifyToken, (req, res) => {
  try {
    const users = loadUsers();
    const user = users[req.username];
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json({
      username: req.username,
      role: user.role,
      permissions: ROLE_PERMISSIONS[user.role] || []
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to get user info' });
  }
});

// ========================
// FORGOT PASSWORD & RESET (Admin)
// ========================

// Helper function to generate default password
function generateDefaultPassword(username) {
  const randomNum = Math.floor(10000 + Math.random() * 90000);
  return `${username}@${randomNum}`;
}

app.post('/api/forgot-password', (req, res) => {
  try {
    const { username } = req.body;
    const users = loadUsers();
    
    if (!users[username]) {
      return res.status(404).json({ message: 'Username not found' });
    }
    
    // Mark user as needing password reset
    users[username].passwordResetNeeded = true;
    users[username].passwordResetRequestedAt = new Date().toISOString();
    saveUsers(users);

    // Create persistent reset request with auto-expiry
    const resetRequests = loadResetRequests();
    resetRequests[username] = {
      username,
      requestedAt: new Date().toISOString(),
      expiryTime: Date.now() + PASSWORD_RESET_TIMEOUT_MS, // 5 minutes
      autoGenerated: false
    };
    saveResetRequests(resetRequests);
    
    res.json({ message: 'Password reset request sent to admin. Will auto-reset in 5 minutes if no action taken.' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to process request' });
  }
});

// Get users needing password reset WITH countdown timers (Admin only)
app.get('/api/admin/password-resets', verifyToken, requireRole(ROLES.SYSTEM_ADMIN, ROLES.ADMIN), (req, res) => {
  try {
    const users = loadUsers();
    const resetRequests = loadResetRequests();
    const now = Date.now();

    const resetNeeded = Object.entries(users)
      .filter(([_, user]) => user.passwordResetNeeded === true)
      .map(([username, user]) => {
        const request = resetRequests[username];
        const timeRemaining = request && request.expiryTime ? Math.max(0, request.expiryTime - now) : PASSWORD_RESET_TIMEOUT_MS;
        const secondsRemaining = Math.ceil(timeRemaining / 1000);

        return {
          username,
          role: user.role,
          requestedAt: user.passwordResetRequestedAt,
          expiryTime: request?.expiryTime || (now + PASSWORD_RESET_TIMEOUT_MS),
          timeRemainingMs: timeRemaining,
          secondsRemaining,
          autoGenerated: request?.autoGenerated || false
        };
      });
    
    res.json({ users: resetNeeded });
  } catch (error) {
    res.status(500).json({ error: 'Failed to load reset requests' });
  }
});

// Auto-reset user password (Admin only) - generates default password
app.post('/api/admin/users/:username/auto-reset', verifyToken, requireRole(ROLES.SYSTEM_ADMIN, ROLES.ADMIN), (req, res) => {
  try {
    const { username } = req.params;
    const users = loadUsers();
    
    if (!users[username]) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Generate default password
    const tempPassword = generateDefaultPassword(username);
    
    // Hash the password
    bcrypt.hash(tempPassword, 10, (err, hashedPassword) => {
      if (err) {
        return res.status(500).json({ error: 'Failed to hash password' });
      }
      
      // Set temp password with 10-minute expiry (600 seconds)
      const expiryTime = Date.now() + (10 * 60 * 1000);
      
      users[username].password = hashedPassword;
      users[username].tempPassword = tempPassword;
      users[username].tempPasswordExpiry = expiryTime;
      users[username].passwordResetNeeded = false;
      delete users[username].passwordResetRequestedAt;
      saveUsers(users);

      // Update reset request record
      const resetRequests = loadResetRequests();
      if (resetRequests[username]) {
        resetRequests[username].autoGenerated = true;
        resetRequests[username].autoGeneratedAt = new Date().toISOString();
        resetRequests[username].tempPassword = tempPassword;
        saveResetRequests(resetRequests);
      }
      
      res.json({ 
        message: `Password auto-generated for ${username}`,
        tempPassword,
        expiryTime
      });
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to reset password' });
  }
});

// Get temporary password for user (after admin reset)
app.post('/api/get-temp-password', (req, res) => {
  try {
    const { username } = req.body;
    const users = loadUsers();
    
    if (!users[username]) {
      return res.status(404).json({ message: 'Username not found' });
    }
    
    const user = users[username];
    
    // Check if temp password exists and hasn't expired
    if (!user.tempPassword || !user.tempPasswordExpiry) {
      return res.status(404).json({ message: 'No temporary password available. Please contact admin.' });
    }
    
    if (Date.now() > user.tempPasswordExpiry) {
      // Password expired, clean up
      delete user.tempPassword;
      delete user.tempPasswordExpiry;
      saveUsers(users);
      return res.status(410).json({ message: 'Temporary password expired. Please request a new reset.' });
    }
    
    const remainingTime = user.tempPasswordExpiry - Date.now();
    res.json({ 
      tempPassword: user.tempPassword,
      expiryTime: user.tempPasswordExpiry,
      remainingSeconds: Math.floor(remainingTime / 1000)
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to retrieve password' });
  }
});

// Reset user password (Admin only) - manual password
app.post('/api/admin/users/:username/password-reset', verifyToken, requireRole(ROLES.SYSTEM_ADMIN, ROLES.ADMIN), (req, res) => {
  try {
    const { username } = req.params;
    const { newPassword } = req.body;
    
    if (!newPassword || newPassword.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }
    
    const users = loadUsers();
    
    if (!users[username]) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    bcrypt.hash(newPassword, 10, (err, hashedPassword) => {
      if (err) {
        return res.status(500).json({ error: 'Failed to hash password' });
      }
      
      users[username].password = hashedPassword;
      users[username].passwordResetNeeded = false;
      delete users[username].passwordResetRequestedAt;
      saveUsers(users);
      
      res.json({ message: `Password reset for ${username}` });
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to reset password' });
  }
});

// ========================
// GAME SCORE TRACKING
// ========================

// Save game score and update user stats
app.post('/api/save-game-score', verifyToken, (req, res) => {
  try {
    const { gameType, difficulty, score, maxScore, percentage } = req.body;
    
    if (!gameType || !difficulty || score === undefined || !maxScore) {
      return res.status(400).json({ error: 'Invalid game score data' });
    }
    
    const users = loadUsers();
    const user = users[req.username];
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    let stats = decryptData(user.stats);
    
    // Initialize game stats if not present
    if (!stats.gameStats) {
      stats.gameStats = {};
    }
    if (!stats.gameStats[gameType]) {
      stats.gameStats[gameType] = {
        gamesPlayed: 0,
        totalScore: 0,
        bestScore: 0,
        difficultyStats: { easy: { played: 0, score: 0 }, medium: { played: 0, score: 0 }, hard: { played: 0, score: 0 } }
      };
    }
    
    const gameStats = stats.gameStats[gameType];
    gameStats.gamesPlayed++;
    gameStats.totalScore += score;
    gameStats.bestScore = Math.max(gameStats.bestScore, score);
    gameStats.difficultyStats[difficulty].played++;
    gameStats.difficultyStats[difficulty].score += score;
    
    // Update overall stats
    stats.totalGameScore = (stats.totalGameScore || 0) + score;
    stats.gamesPlayedTotal = (stats.gamesPlayedTotal || 0) + 1;
    
    user.stats = encryptData(stats);
    saveUsers(users);
    
    res.json({ success: true, stats });
  } catch (error) {
    console.error('Game score save error:', error);
    res.status(500).json({ error: 'Failed to save game score' });
  }
});

// ========================
// CHAT API ENDPOINTS
// ========================

// Track typing users
let typingUsers = {};
const TYPING_TIMEOUT = 3500;

// Get all chat messages
app.get('/api/chat', verifyToken, (req, res) => {
  try {
    const messages = loadChatMessages();
    res.json({ messages });
  } catch (error) {
    console.error('Chat load error:', error);
    res.status(500).json({ error: 'Failed to load chat messages' });
  }
});

// Send a new chat message
app.post('/api/chat', verifyToken, (req, res) => {
  try {
    const { message, replyTo } = req.body;
    
    if (!message || !message.trim()) {
      return res.status(400).json({ error: 'Message cannot be empty' });
    }
    
    const messages = loadChatMessages();
    const users = loadUsers();
    const user = users[req.username];
    
    const newMessage = {
      id: Date.now().toString() + Math.random().toString(36).substr(2, 9),
      username: req.username,
      role: user ? user.role : 'general',
      message: message.trim(),
      createdAt: new Date().toISOString(),
      reactions: {}
    };
    
    // Handle reply
    if (replyTo) {
      const replyToMessage = messages.find(m => m.id === replyTo);
      if (replyToMessage) {
        newMessage.replyTo = replyTo;
        newMessage.replyToUsername = replyToMessage.username;
        newMessage.replyToContent = replyToMessage.message;
      }
    }
    
    messages.push(newMessage);
    saveChatMessages(messages);
    
    // Broadcast new message to all connected clients in real-time
    io.emit('newMessage', newMessage);
    
    res.json({ success: true, message: newMessage });
  } catch (error) {
    console.error('Chat send error:', error);
    res.status(500).json({ error: 'Failed to send message' });
  }
});

// Clear all chat messages (non-general users only) - MUST be before /:id route
app.delete('/api/chat/clear', verifyToken, (req, res) => {
  try {
    // Only non-general users can clear messages
    if (req.userRole === 'general') {
      return res.status(403).json({ error: 'Not authorized to clear messages' });
    }
    
    // Clear all messages
    saveChatMessages([]);
    
    // Broadcast clear to all clients
    io.emit('chatCleared');
    
    res.json({ success: true, message: 'All messages cleared' });
  } catch (error) {
    console.error('Chat clear error:', error);
    res.status(500).json({ error: 'Failed to clear messages' });
  }
});

// Delete a chat message (own messages or admin)
app.delete('/api/chat/:id', verifyToken, (req, res) => {
  try {
    const { id } = req.params;
    let messages = loadChatMessages();
    
    const messageIndex = messages.findIndex(m => m.id === id);
    
    if (messageIndex === -1) {
      return res.status(404).json({ error: 'Message not found' });
    }
    
    const message = messages[messageIndex];
    
    // Allow deletion if user owns the message or is an admin
    const adminRoles = ['system-admin', 'admin', 'moderator'];
    if (message.username !== req.username && !adminRoles.includes(req.userRole)) {
      return res.status(403).json({ error: 'Not authorized to delete this message' });
    }
    
    messages.splice(messageIndex, 1);
    saveChatMessages(messages);
    
    // Broadcast deletion to all clients
    io.emit('messageDeleted', id);
    
    res.json({ success: true });
  } catch (error) {
    console.error('Chat delete error:', error);
    res.status(500).json({ error: 'Failed to delete message' });
  }
});

// Add/remove emoji reaction to a message
app.post('/api/chat/:id/reaction', verifyToken, (req, res) => {
  try {
    const { id } = req.params;
    const { emoji } = req.body;
    
    if (!emoji || emoji.length === 0) {
      return res.status(400).json({ error: 'Emoji required' });
    }
    
    let messages = loadChatMessages();
    const messageIndex = messages.findIndex(m => m.id === id);
    
    if (messageIndex === -1) {
      return res.status(404).json({ error: 'Message not found' });
    }
    
    const message = messages[messageIndex];
    if (!message.reactions) {
      message.reactions = {};
    }
    
    if (!message.reactions[emoji]) {
      message.reactions[emoji] = [];
    }
    
    // Check if user already reacted with this emoji
    const reactionIndex = message.reactions[emoji].indexOf(req.username);
    if (reactionIndex >= 0) {
      // Remove reaction (user already reacted)
      message.reactions[emoji].splice(reactionIndex, 1);
      if (message.reactions[emoji].length === 0) {
        delete message.reactions[emoji];
      }
      io.emit('reactionRemoved', { messageId: id, emoji, username: req.username });
    } else {
      // Add reaction (user hasn't reacted yet)
      message.reactions[emoji].push(req.username);
      io.emit('reactionAdded', { messageId: id, emoji, username: req.username });
    }
    
    saveChatMessages(messages);
    res.json({ success: true, reactions: message.reactions });
  } catch (error) {
    console.error('Chat reaction error:', error);
    res.status(500).json({ error: 'Failed to add reaction' });
  }
});

// Get new messages since a timestamp (for polling)
app.get('/api/chat/since/:timestamp', verifyToken, (req, res) => {
  try {
    const { timestamp } = req.params;
    const since = new Date(timestamp).getTime();
    
    const messages = loadChatMessages();
    const newMessages = messages.filter(m => new Date(m.createdAt).getTime() > since);
    
    res.json({ messages: newMessages });
  } catch (error) {
    console.error('Chat poll error:', error);
    res.status(500).json({ error: 'Failed to get new messages' });
  }
});

// Send typing status
app.post('/api/chat/typing', verifyToken, (req, res) => {
  try {
    const { isTyping } = req.body;
    
    if (isTyping) {
      typingUsers[req.username] = Date.now();
    } else {
      delete typingUsers[req.username];
    }
    
    res.json({ success: true });
  } catch (error) {
    console.error('Typing status error:', error);
    res.status(500).json({ error: 'Failed to update typing status' });
  }
});

// Get typing users
app.get('/api/chat/typing/users', verifyToken, (req, res) => {
  try {
    const now = Date.now();
    const activeTypingUsers = {};
    
    // Clean up expired typing status
    Object.entries(typingUsers).forEach(([user, timestamp]) => {
      if (now - timestamp < TYPING_TIMEOUT) {
        activeTypingUsers[user] = true;
      } else {
        delete typingUsers[user];
      }
    });
    
    res.json({ typingUsers: activeTypingUsers });
  } catch (error) {
    console.error('Get typing users error:', error);
    res.status(500).json({ error: 'Failed to get typing users' });
  }
});

// Socket.IO connection handler with online status tracking

io.on('connection', (socket) => {
  console.log('User connected:', socket.id);
  
  // When client requests online users
  socket.on('requestOnlineUsers', () => {
    const onlineUsersList = Object.values(connectedUsers);
    socket.emit('onlineUsers', onlineUsersList);
  });
  
  // When a user authenticates
  socket.on('authenticate', (username) => {
    if (username) {
      connectedUsers[socket.id] = username;
      // Broadcast user is online to all clients
      io.emit('userOnline', username);
      // Send updated list to requester
      socket.emit('onlineUsers', Object.values(connectedUsers));
    }
  });
  
  socket.on('disconnect', () => {
    const username = connectedUsers[socket.id];
    if (username) {
      delete connectedUsers[socket.id];
      // Broadcast user went offline
      io.emit('userOffline', username);
    }
    console.log('User disconnected:', socket.id);
  });
});

app.get("/api/check-permission", (req, res) => {
    const token = req.headers.authorization;

    if (!token) return res.status(401).json({ allowed: false });

    try {
        const decoded = jwt.verify(token, "your_secret_key_here");

        if (decoded.role === "admin" || decoded.role === "system-admin" || decoded.role === "moderator") {
            return res.json({ allowed: true, role: decoded.role });
        }

        return res.status(403).json({ allowed: false });

    } catch (err) {
        return res.status(401).json({ allowed: false });
    }
});

// FINAL START
server.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on http://0.0.0.0:${PORT}`);
});