/**
 * Updated app.js - Refactored to use SQLite database
 * This replaces the JSON file-based storage with proper SQL queries
 */

const express = require('express');
const bodyParser = require('body-parser');
const http = require('http');
const socketIo = require('socket.io');
const compression = require('compression');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const fs = require('fs');
const path = require('path');

const app = express();
const server = http.createServer(app);
const allowedOrigins = process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : '*';

const io = socketIo(server, {
  cors: { origin: allowedOrigins, methods: ['GET', 'POST'] },
  transports: ['websocket', 'polling'],
  pingInterval: 25000,
  pingTimeout: 60000
});

// Import database functions
const db = require('./database');
const dbHelpers = require('./db-helpers');

const PORT = Number(process.env.PORT) || 5000;
const SECRET_KEY = process.env.SECRET_KEY || 'dennie-softs-secure-key-2025';

// Track connected socket users
let connectedUsers = {};

// Role hierarchy
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

const MANAGEMENT_ROLES = [
  ROLES.SYSTEM_ADMIN,
  ROLES.ADMIN,
  ROLES.MODERATOR,
  ROLES.CHAIRPERSON,
  ROLES.SECRETARY,
  ROLES.ORGANIZING_SECRETARY
];

// Middleware
app.use(compression({ level: 6, threshold: 512 }));
app.use(bodyParser.json({ limit: '10mb' }));

// Rate limiting
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 8,
  message: { message: 'Too many authentication attempts, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false
});

app.use('/api/', apiLimiter);
app.use('/api/login', authLimiter);
app.use('/api/signup', authLimiter);

// Helmet security middleware (CSP tailored for current app)
app.use(helmet({
  crossOriginResourcePolicy: false,
  contentSecurityPolicy: false // set manually below to avoid blocking inline handlers for now
}));

// Additional security headers and HSTS in production
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'no-referrer-when-downgrade');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');

  if (req.secure || req.headers['x-forwarded-proto'] === 'https') {
    // 2 years recommended for HSTS when site is fully HTTPS
    res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  }

  next();
});

// Content Security Policy (allow 'self' and inline for now; consider migrating inline handlers)
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
  
  if (filePath === '/manifest.json' || filePath === '/service-worker.js') {
    res.setHeader('Cache-Control', 'public, max-age=3600, must-revalidate');
  } else if (filePath.endsWith('.html')) {
    res.setHeader('Cache-Control', 'public, max-age=0, must-revalidate');
  } else if (filePath.endsWith('.css') || filePath.endsWith('.js')) {
    res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
  }
  
  next();
});

app.use(express.static(path.join(__dirname, '../public'), { 
  maxAge: '1d',
  etag: false 
}));

// ==================== AUTHENTICATION MIDDLEWARE ====================

function verifyToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) {
    return res.status(401).json({ message: 'Token required' });
  }

  const token = authHeader.split(' ')[1];
  const verified = dbHelpers.verifyToken(token);

  if (!verified) {
    return res.status(403).json({ message: 'Invalid token' });
  }

  req.userId = verified.userId;
  req.username = verified.username;
  next();
}

function requireRole(allowedRoles) {
  return async (req, res, next) => {
    try {
      const user = dbHelpers.getUserById(req.userId);
      if (!user || !allowedRoles.includes(user.role)) {
        return res.status(403).json({ message: 'Insufficient permissions' });
      }
      req.user = user;
      next();
    } catch (err) {
      res.status(500).json({ message: 'Auth check error' });
    }
  };
}

// ==================== AUTHENTICATION ENDPOINTS ====================

// Signup
app.post('/api/signup', async (req, res) => {
  try {
    const { username, password, role = ROLES.GENERAL } = req.body;

    if (!username || !password) {
      return res.status(400).json({ message: 'Username and password required' });
    }

    // Check if user exists
    if (dbHelpers.getUserByUsername(username)) {
      return res.status(409).json({ message: 'Username already exists' });
    }

    // Hash password
    const hashedPassword = await dbHelpers.hashPassword(password);

    // Create user
    const user = dbHelpers.createUser(username, hashedPassword, role);
    const token = dbHelpers.generateToken(user.id, username);

    res.status(201).json({
      message: 'User created successfully',
      token,
      username,
      role
    });
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ message: err.message || 'Signup failed' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ message: 'Username and password required' });
    }

    const user = dbHelpers.getUserByUsername(username);
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const validPassword = await dbHelpers.verifyPassword(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = dbHelpers.generateToken(user.id, username);

    res.json({
      message: 'Login successful',
      token,
      username,
      role: user.role
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ message: 'Login failed' });
  }
});

// Get user profile
app.get('/api/user', verifyToken, (req, res) => {
  try {
    const user = dbHelpers.getUserById(req.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({
      id: user.id,
      username: user.username,
      role: user.role,
      church: user.church,
      created_at: user.created_at
    });
  } catch (err) {
    res.status(500).json({ message: 'Error fetching user' });
  }
});

// ==================== POSTS ENDPOINTS ====================

// Get all posts
app.get('/api/posts', (req, res) => {
  try {
    const posts = dbHelpers.getAllPosts();
    res.json(posts);
  } catch (err) {
    console.error('Get posts error:', err);
    res.status(500).json({ message: 'Error fetching posts' });
  }
});

// Create post
app.post('/api/posts', verifyToken, (req, res) => {
  try {
    const { content, image, imageAlt, caption } = req.body;

    if (!content) {
      return res.status(400).json({ message: 'Post content required' });
    }

    const postId = dbHelpers.createPost(req.userId, content, image, imageAlt, caption);

    res.status(201).json({
      id: postId,
      message: 'Post created successfully'
    });
  } catch (err) {
    console.error('Create post error:', err);
    res.status(500).json({ message: 'Error creating post' });
  }
});

// Update post
app.put('/api/posts/:id', verifyToken, (req, res) => {
  try {
    const { content, image, caption, imageAlt } = req.body;
    
    dbHelpers.updatePost(req.params.id, content, image, caption, imageAlt);

    res.json({ message: 'Post updated successfully' });
  } catch (err) {
    console.error('Update post error:', err);
    res.status(500).json({ message: 'Error updating post' });
  }
});

// Delete post
app.delete('/api/posts/:id', verifyToken, (req, res) => {
  try {
    dbHelpers.deletePost(req.params.id);
    res.json({ message: 'Post deleted successfully' });
  } catch (err) {
    console.error('Delete post error:', err);
    res.status(500).json({ message: 'Error deleting post' });
  }
});

// ==================== TASKS ENDPOINTS ====================

// Get all tasks
app.get('/api/tasks', (req, res) => {
  try {
    const tasks = dbHelpers.getAllTasks();
    res.json(tasks);
  } catch (err) {
    console.error('Get tasks error:', err);
    res.status(500).json({ message: 'Error fetching tasks' });
  }
});

// Create task (admin/management only)
app.post('/api/tasks', verifyToken, requireRole(MANAGEMENT_ROLES), (req, res) => {
  try {
    const { title, assignedTo, priority } = req.body;

    if (!title) {
      return res.status(400).json({ message: 'Task title required' });
    }

    const taskId = dbHelpers.createTask(title, assignedTo, priority);

    res.status(201).json({
      id: taskId,
      message: 'Task created successfully'
    });
  } catch (err) {
    console.error('Create task error:', err);
    res.status(500).json({ message: 'Error creating task' });
  }
});

// Update task
app.put('/api/tasks/:id', verifyToken, requireRole(MANAGEMENT_ROLES), (req, res) => {
  try {
    const { title, assignedTo, priority, status } = req.body;

    dbHelpers.updateTask(req.params.id, title, assignedTo, priority, status);

    res.json({ message: 'Task updated successfully' });
  } catch (err) {
    console.error('Update task error:', err);
    res.status(500).json({ message: 'Error updating task' });
  }
});

// Delete task
app.delete('/api/tasks/:id', verifyToken, requireRole(MANAGEMENT_ROLES), (req, res) => {
  try {
    dbHelpers.deleteTask(req.params.id);
    res.json({ message: 'Task deleted successfully' });
  } catch (err) {
    console.error('Delete task error:', err);
    res.status(500).json({ message: 'Error deleting task' });
  }
});

// ==================== EVENTS ENDPOINTS ====================

// Get all events
app.get('/api/events', (req, res) => {
  try {
    const events = dbHelpers.getAllEvents();
    res.json(events);
  } catch (err) {
    console.error('Get events error:', err);
    res.status(500).json({ message: 'Error fetching events' });
  }
});

// Create event
app.post('/api/events', verifyToken, requireRole(MANAGEMENT_ROLES), (req, res) => {
  try {
    const { title, description, eventDate } = req.body;

    if (!title) {
      return res.status(400).json({ message: 'Event title required' });
    }

    const eventId = dbHelpers.createEvent(title, description, eventDate, req.userId);

    res.status(201).json({
      id: eventId,
      message: 'Event created successfully'
    });
  } catch (err) {
    console.error('Create event error:', err);
    res.status(500).json({ message: 'Error creating event' });
  }
});

// Update event
app.put('/api/events/:id', verifyToken, requireRole(MANAGEMENT_ROLES), (req, res) => {
  try {
    const { title, description, eventDate } = req.body;

    dbHelpers.updateEvent(req.params.id, title, description, eventDate);

    res.json({ message: 'Event updated successfully' });
  } catch (err) {
    console.error('Update event error:', err);
    res.status(500).json({ message: 'Error updating event' });
  }
});

// Delete event
app.delete('/api/events/:id', verifyToken, requireRole(MANAGEMENT_ROLES), (req, res) => {
  try {
    dbHelpers.deleteEvent(req.params.id);
    res.json({ message: 'Event deleted successfully' });
  } catch (err) {
    console.error('Delete event error:', err);
    res.status(500).json({ message: 'Error deleting event' });
  }
});

// ==================== ANNOUNCEMENTS ENDPOINTS ====================

// Get all announcements
app.get('/api/announcements', (req, res) => {
  try {
    const announcements = dbHelpers.getAllAnnouncements();
    res.json(announcements);
  } catch (err) {
    console.error('Get announcements error:', err);
    res.status(500).json({ message: 'Error fetching announcements' });
  }
});

// Create announcement
app.post('/api/announcements', verifyToken, requireRole(MANAGEMENT_ROLES), (req, res) => {
  try {
    const { title, content, announcementDate } = req.body;

    if (!title || !content) {
      return res.status(400).json({ message: 'Title and content required' });
    }

    const announcementId = dbHelpers.createAnnouncement(title, content, announcementDate, req.userId);

    res.status(201).json({
      id: announcementId,
      message: 'Announcement created successfully'
    });
  } catch (err) {
    console.error('Create announcement error:', err);
    res.status(500).json({ message: 'Error creating announcement' });
  }
});

// Update announcement
app.put('/api/announcements/:id', verifyToken, requireRole(MANAGEMENT_ROLES), (req, res) => {
  try {
    const { title, content, announcementDate } = req.body;

    dbHelpers.updateAnnouncement(req.params.id, title, content, announcementDate);

    res.json({ message: 'Announcement updated successfully' });
  } catch (err) {
    console.error('Update announcement error:', err);
    res.status(500).json({ message: 'Error updating announcement' });
  }
});

// Delete announcement
app.delete('/api/announcements/:id', verifyToken, requireRole(MANAGEMENT_ROLES), (req, res) => {
  try {
    dbHelpers.deleteAnnouncement(req.params.id);
    res.json({ message: 'Announcement deleted successfully' });
  } catch (err) {
    console.error('Delete announcement error:', err);
    res.status(500).json({ message: 'Error deleting announcement' });
  }
});

// ==================== PASSWORD RESET ENDPOINTS ====================

// Helper to generate default password
function generateDefaultPassword(username) {
  const randomNum = Math.floor(10000 + Math.random() * 90000);
  return `${username}@${randomNum}`;
}

// Request password reset (public)
app.post('/api/password-reset-request', (req, res) => {
  try {
    const { username } = req.body;
    if (!username) {
      return res.status(400).json({ message: 'Username required' });
    }
    
    const user = dbHelpers.getUserByUsername(username);
    if (!user) {
      return res.status(404).json({ message: 'Username not found' });
    }
    
    // Store reset request in memory with expiry
    if (!global.passwordResetRequests) global.passwordResetRequests = {};
    
    global.passwordResetRequests[username] = {
      username,
      requestedAt: new Date().toISOString(),
      expiryTime: Date.now() + (5 * 60 * 1000) // 5 minutes
    };
    
    res.json({ message: 'Password reset request sent. Admin will generate temporary password.' });
  } catch (err) {
    console.error('Password reset request error:', err);
    res.status(500).json({ message: 'Error processing reset request' });
  }
});

// Get temporary password for user (public)
app.post('/api/get-temp-password', (req, res) => {
  try {
    const { username } = req.body;
    if (!username) {
      return res.status(400).json({ message: 'Username required' });
    }
    
    const user = dbHelpers.getUserByUsername(username);
    if (!user) {
      return res.status(404).json({ message: 'Username not found' });
    }
    
    // Check if temp password exists in memory
    if (!global.tempPasswords) global.tempPasswords = {};
    const tempData = global.tempPasswords[username];
    
    if (!tempData) {
      return res.status(404).json({ message: 'No temporary password available. Contact admin.' });
    }
    
    if (Date.now() > tempData.expiryTime) {
      delete global.tempPasswords[username];
      return res.status(410).json({ message: 'Temporary password expired. Request a new reset.' });
    }
    
    const remainingSeconds = Math.floor((tempData.expiryTime - Date.now()) / 1000);
    res.json({
      tempPassword: tempData.tempPassword,
      remainingSeconds
    });
  } catch (err) {
    console.error('Get temp password error:', err);
    res.status(500).json({ message: 'Error retrieving password' });
  }
});

// ==================== ADMIN ENDPOINTS ====================

// Get all users (admin only)
app.get('/api/admin/users', verifyToken, requireRole(MANAGEMENT_ROLES), (req, res) => {
  try {
    const users = db.prepare('SELECT id, username, role, created_at FROM users ORDER BY created_at DESC').all();
    res.json(users);
  } catch (err) {
    console.error('Get users error:', err);
    res.status(500).json({ message: 'Error fetching users' });
  }
});

// Get all registration codes (system admin only)
app.get('/api/admin/codes', verifyToken, requireRole([ROLES.SYSTEM_ADMIN]), (req, res) => {
  try {
    const codes = db.prepare('SELECT id, code, role, used, used_by, created_at FROM registration_codes ORDER BY created_at DESC').all();
    res.json(codes);
  } catch (err) {
    console.error('Get codes error:', err);
    res.status(500).json({ message: 'Error fetching codes' });
  }
});

// Delete a registration code (system admin only)
app.delete('/api/admin/codes/:code', verifyToken, requireRole([ROLES.SYSTEM_ADMIN]), (req, res) => {
  try {
    db.prepare('DELETE FROM registration_codes WHERE code = ?').run(req.params.code);
    res.json({ message: 'Code deleted successfully' });
  } catch (err) {
    console.error('Delete code error:', err);
    res.status(500).json({ message: 'Error deleting code' });
  }
});

// Update user role (system admin only)
app.post('/api/admin/users/:username/role', verifyToken, requireRole([ROLES.SYSTEM_ADMIN]), (req, res) => {
  try {
    const { role } = req.body;
    const user = dbHelpers.getUserByUsername(req.params.username);
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    dbHelpers.updateUserRole(user.id, role);
    res.json({ message: 'User role updated successfully' });
  } catch (err) {
    console.error('Update role error:', err);
    res.status(500).json({ message: 'Error updating user role' });
  }
});

// Delete a user (system admin only)
app.delete('/api/admin/users/:username', verifyToken, requireRole([ROLES.SYSTEM_ADMIN]), (req, res) => {
  try {
    const user = dbHelpers.getUserByUsername(req.params.username);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    db.prepare('DELETE FROM users WHERE id = ?').run(user.id);
    res.json({ message: 'User deleted successfully' });
  } catch (err) {
    console.error('Delete user error:', err);
    res.status(500).json({ message: 'Error deleting user' });
  }
});

// Adjust user balance (stub)
app.post('/api/admin/users/:username/balance', verifyToken, requireRole(MANAGEMENT_ROLES), (req, res) => {
  try {
    const { action, amount } = req.body;
    const user = dbHelpers.getUserByUsername(req.params.username);
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    res.json({ message: 'Balance adjustment received (stub - not yet implemented for SQLite)' });
  } catch (err) {
    console.error('Balance update error:', err);
    res.status(500).json({ message: 'Error updating balance' });
  }
});

// Auto-reset user password with temporary password (admin only)
app.post('/api/admin/users/:username/auto-reset', verifyToken, requireRole(MANAGEMENT_ROLES), async (req, res) => {
  try {
    const { username } = req.params;
    const user = dbHelpers.getUserByUsername(username);
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    // Generate temporary password
    const tempPassword = generateDefaultPassword(username);
    const hashedPassword = await dbHelpers.hashPassword(tempPassword);
    const expiryTime = Date.now() + (10 * 60 * 1000); // 10 minutes
    
    // Update user password in database
    db.prepare('UPDATE users SET password = ? WHERE id = ?').run(hashedPassword, user.id);
    
    // Store temp password in memory for retrieval
    if (!global.tempPasswords) global.tempPasswords = {};
    global.tempPasswords[username] = {
      tempPassword,
      expiryTime
    };
    
    res.json({
      message: `Temporary password generated for ${username}`,
      tempPassword,
      expiryTime
    });
  } catch (err) {
    console.error('Auto-reset error:', err);
    res.status(500).json({ message: 'Error resetting password' });
  }
});

// Get pending password resets (admin only)
app.get('/api/admin/password-resets', verifyToken, requireRole(MANAGEMENT_ROLES), (req, res) => {
  try {
    if (!global.passwordResetRequests) global.passwordResetRequests = {};
    
    const now = Date.now();
    const resetNeeded = Object.entries(global.passwordResetRequests)
      .filter(([_, req]) => req.expiryTime > now)
      .map(([username, req]) => ({
        username,
        requestedAt: req.requestedAt,
        secondsRemaining: Math.ceil((req.expiryTime - now) / 1000)
      }));
    
    res.json({ users: resetNeeded });
  } catch (err) {
    console.error('Get password resets error:', err);
    res.status(500).json({ message: 'Error retrieving reset requests' });
  }
});

// ==================== SOCKET.IO EVENTS ====================

io.on('connection', (socket) => {
  console.log('User connected:', socket.id);

  socket.on('join', (username) => {
    connectedUsers[socket.id] = username;
    io.emit('users-online', Object.keys(connectedUsers).length);
    io.emit('user-joined', {
      username,
      onlineCount: Object.keys(connectedUsers).length
    });
  });

  socket.on('send-message', (data) => {
    const { username, content } = data;
    
    try {
      // Save message to database
      dbHelpers.createMessage(data.userId || 0, username, content);

      // Broadcast to all clients
      io.emit('receive-message', {
        username,
        content,
        timestamp: new Date().toISOString()
      });
    } catch (err) {
      console.error('Error saving message:', err);
    }
  });

  socket.on('disconnect', () => {
    const username = connectedUsers[socket.id];
    delete connectedUsers[socket.id];
    
    io.emit('users-online', Object.keys(connectedUsers).length);
    if (username) {
      io.emit('user-left', {
        username,
        onlineCount: Object.keys(connectedUsers).length
      });
    }
    console.log('User disconnected:', socket.id);
  });
});

// ==================== HEALTH CHECK ====================

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ==================== SERVER START ====================

server.listen(PORT, () => {
  console.log(`✅ Server running on http://0.0.0.0:${PORT}`);
  console.log(`📁 Using SQLite database at: data/cya.db`);
});

module.exports = app;
