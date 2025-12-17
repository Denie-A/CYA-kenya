const db = require('./database');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const SECRET_KEY = process.env.SECRET_KEY || 'dennie-softs-secure-key-2025';

// ==================== USER OPERATIONS ====================

// Create or get user
async function findOrCreateUser(username, role = 'general') {
    const user = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
    if (user) return user;
    
    const insert = db.prepare('INSERT INTO users (username, password, role) VALUES (?, ?, ?)');
    const result = insert.run(username, 'temp', role);
    return { id: result.lastInsertRowid };
}

// Get user by username
function getUserByUsername(username) {
    return db.prepare('SELECT * FROM users WHERE username = ?').get(username);
}

// Get user by id
function getUserById(userId) {
    return db.prepare('SELECT id, username, role, church, created_at FROM users WHERE id = ?').get(userId);
}

// Create user with password
function createUser(username, hashedPassword, role = 'general') {
    try {
        const insert = db.prepare(
            'INSERT INTO users (username, password, role) VALUES (?, ?, ?)'
        );
        const result = insert.run(username, hashedPassword, role);
        return { id: result.lastInsertRowid, username };
    } catch (err) {
        if (err.message.includes('UNIQUE constraint failed')) {
            throw new Error('Username already exists');
        }
        throw err;
    }
}

// Get all users
function getAllUsers() {
    return db.prepare('SELECT id, username, role, church, created_at FROM users ORDER BY created_at DESC').all();
}

// Update user role
function updateUserRole(userId, role) {
    const stmt = db.prepare('UPDATE users SET role = ? WHERE id = ?');
    return stmt.run(role, userId);
}

// ==================== POST OPERATIONS ====================

// Get all posts with username
function getAllPosts() {
    return db.prepare(`
        SELECT p.*, u.username FROM posts p
        JOIN users u ON p.user_id = u.id
        ORDER BY p.created_at DESC
    `).all();
}

// Create post
function createPost(userId, content, imageUrl = null, imageAlt = null, caption = null) {
    const insert = db.prepare(
        'INSERT INTO posts (user_id, content, image_url, image_alt, caption) VALUES (?, ?, ?, ?, ?)'
    );
    const result = insert.run(userId, content, imageUrl, imageAlt, caption);
    return result.lastInsertRowid;
}

// Update post
function updatePost(postId, content, imageUrl = null, caption = null, imageAlt = null) {
    const stmt = db.prepare(
        'UPDATE posts SET content = ?, image_url = ?, caption = ?, image_alt = ? WHERE id = ?'
    );
    return stmt.run(content, imageUrl, caption, imageAlt, postId);
}

// Delete post
function deletePost(postId) {
    const stmt = db.prepare('DELETE FROM posts WHERE id = ?');
    return stmt.run(postId);
}

// ==================== TASK OPERATIONS ====================

// Get all tasks
function getAllTasks() {
    return db.prepare(`
        SELECT t.*, u.username as assigned_to_username FROM tasks t
        LEFT JOIN users u ON t.assigned_to = u.id
        ORDER BY t.created_at DESC
    `).all();
}

// Create task
function createTask(title, assignedTo = null, priority = 'medium') {
    const insert = db.prepare(
        'INSERT INTO tasks (title, assigned_to, priority) VALUES (?, ?, ?)'
    );
    const result = insert.run(title, assignedTo, priority);
    return result.lastInsertRowid;
}

// Update task
function updateTask(taskId, title, assignedTo = null, priority = 'medium', status = 'pending') {
    const stmt = db.prepare(
        'UPDATE tasks SET title = ?, assigned_to = ?, priority = ?, status = ? WHERE id = ?'
    );
    return stmt.run(title, assignedTo, priority, status, taskId);
}

// Delete task
function deleteTask(taskId) {
    const stmt = db.prepare('DELETE FROM tasks WHERE id = ?');
    return stmt.run(taskId);
}

// ==================== EVENT OPERATIONS ====================

// Get all events
function getAllEvents() {
    return db.prepare(`
        SELECT e.*, u.username as created_by_username FROM events e
        LEFT JOIN users u ON e.created_by = u.id
        ORDER BY e.event_date DESC
    `).all();
}

// Create event
function createEvent(title, description, eventDate, createdBy = null) {
    const insert = db.prepare(
        'INSERT INTO events (title, description, event_date, created_by) VALUES (?, ?, ?, ?)'
    );
    const result = insert.run(title, description, eventDate, createdBy);
    return result.lastInsertRowid;
}

// Update event
function updateEvent(eventId, title, description, eventDate) {
    const stmt = db.prepare(
        'UPDATE events SET title = ?, description = ?, event_date = ? WHERE id = ?'
    );
    return stmt.run(title, description, eventDate, eventId);
}

// Delete event
function deleteEvent(eventId) {
    const stmt = db.prepare('DELETE FROM events WHERE id = ?');
    return stmt.run(eventId);
}

// ==================== ANNOUNCEMENT OPERATIONS ====================

// Get all announcements
function getAllAnnouncements() {
    return db.prepare(`
        SELECT a.*, u.username as created_by_username FROM announcements a
        LEFT JOIN users u ON a.created_by = u.id
        ORDER BY a.created_at DESC
    `).all();
}

// Create announcement
function createAnnouncement(title, content, announcementDate = null, createdBy = null) {
    const insert = db.prepare(
        'INSERT INTO announcements (title, content, announcement_date, created_by) VALUES (?, ?, ?, ?)'
    );
    const result = insert.run(title, content, announcementDate, createdBy);
    return result.lastInsertRowid;
}

// Update announcement
function updateAnnouncement(announcementId, title, content, announcementDate = null) {
    const stmt = db.prepare(
        'UPDATE announcements SET title = ?, content = ?, announcement_date = ? WHERE id = ?'
    );
    return stmt.run(title, content, announcementDate, announcementId);
}

// Delete announcement
function deleteAnnouncement(announcementId) {
    const stmt = db.prepare('DELETE FROM announcements WHERE id = ?');
    return stmt.run(announcementId);
}

// ==================== MESSAGE OPERATIONS ====================

// Get recent messages (last 100)
function getRecentMessages(limit = 100) {
    return db.prepare(`
        SELECT id, user_id, username, content, created_at FROM messages
        ORDER BY created_at DESC
        LIMIT ?
    `).all(limit).reverse(); // Reverse to get chronological order
}

// Create message
function createMessage(userId, username, content) {
    const insert = db.prepare(
        'INSERT INTO messages (user_id, username, content) VALUES (?, ?, ?)'
    );
    const result = insert.run(userId, username, content);
    return result.lastInsertRowid;
}

// Clear old messages (keep last 7 days)
function clearOldMessages(daysToKeep = 7) {
    const stmt = db.prepare(`
        DELETE FROM messages 
        WHERE datetime(created_at) < datetime('now', '-' || ? || ' days')
    `);
    return stmt.run(daysToKeep);
}

// ==================== UTILITY FUNCTIONS ====================

// Generate JWT token
function generateToken(userId, username) {
    return jwt.sign(
        { userId, username },
        SECRET_KEY,
        { expiresIn: '24h' }
    );
}

// Verify JWT token
function verifyToken(token) {
    try {
        return jwt.verify(token, SECRET_KEY);
    } catch (err) {
        return null;
    }
}

// Hash password
async function hashPassword(password) {
    return bcrypt.hash(password, 10);
}

// Verify password
async function verifyPassword(password, hash) {
    return bcrypt.compare(password, hash);
}

module.exports = {
    // Users
    findOrCreateUser,
    getAllUsers,
    getUserByUsername,
    getUserById,
    createUser,
    updateUserRole,
    
    // Posts
    getAllPosts,
    createPost,
    updatePost,
    deletePost,
    
    // Tasks
    getAllTasks,
    createTask,
    updateTask,
    deleteTask,
    
    // Events
    getAllEvents,
    createEvent,
    updateEvent,
    deleteEvent,
    
    // Announcements
    getAllAnnouncements,
    createAnnouncement,
    updateAnnouncement,
    deleteAnnouncement,
    
    // Messages
    getRecentMessages,
    createMessage,
    clearOldMessages,
    
    // Auth utilities
    generateToken,
    verifyToken,
    hashPassword,
    verifyPassword
};
