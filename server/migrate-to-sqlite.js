/**
 * Migration script: Migrate data from JSON files to SQLite database
 * Run this script once: node server/migrate-to-sqlite.js
 */

const fs = require('fs');
const path = require('path');
const db = require('./database');
const { createUser, createPost, createTask, createEvent, createAnnouncement, createMessage, hashPassword } = require('./db-helpers');

// Data directory
const dataDir = path.join(__dirname, '../data');

async function migrateUsers() {
    console.log('\n📤 Migrating users...');
    try {
        const usersPath = path.join(dataDir, 'users.json');
        if (!fs.existsSync(usersPath)) {
            console.log('⚠️  users.json not found, skipping users migration');
            return 0;
        }

        const usersData = JSON.parse(fs.readFileSync(usersPath, 'utf8'));
        let count = 0;

        for (const [username, userData] of Object.entries(usersData)) {
            try {
                // Hash the password if it exists
                const password = userData.password || 'default';
                const hashedPassword = await hashPassword(password);
                
                createUser(
                    username,
                    hashedPassword,
                    userData.role || 'general'
                );
                count++;
            } catch (err) {
                if (!err.message.includes('already exists')) {
                    console.error(`Error migrating user ${username}:`, err.message);
                }
            }
        }

        console.log(`✅ Migrated ${count} users`);
        return count;
    } catch (err) {
        console.error('❌ Error migrating users:', err.message);
        return 0;
    }
}

async function migratePosts() {
    console.log('\n📤 Migrating posts...');
    try {
        const postsPath = path.join(dataDir, 'posts.json');
        if (!fs.existsSync(postsPath)) {
            console.log('⚠️  posts.json not found, skipping posts migration');
            return 0;
        }

        const postsData = JSON.parse(fs.readFileSync(postsPath, 'utf8'));
        let count = 0;

        for (const post of postsData) {
            try {
                // Get user by username to get ID
                const user = db.prepare('SELECT id FROM users WHERE username = ?').get(post.author || 'system');
                const userId = user ? user.id : 1;

                createPost(
                    userId,
                    post.content || '',
                    post.image || null,
                    post.imageAlt || null,
                    post.caption || null
                );
                count++;
            } catch (err) {
                console.error('Error migrating post:', err.message);
            }
        }

        console.log(`✅ Migrated ${count} posts`);
        return count;
    } catch (err) {
        console.error('❌ Error migrating posts:', err.message);
        return 0;
    }
}

async function migrateTasks() {
    console.log('\n📤 Migrating tasks...');
    try {
        const tasksPath = path.join(dataDir, 'tasks.json');
        if (!fs.existsSync(tasksPath)) {
            console.log('⚠️  tasks.json not found, skipping tasks migration');
            return 0;
        }

        const tasksData = JSON.parse(fs.readFileSync(tasksPath, 'utf8'));
        let count = 0;

        for (const task of tasksData) {
            try {
                // Get user if assigned
                let assignedToId = null;
                if (task.assignedTo) {
                    const user = db.prepare('SELECT id FROM users WHERE username = ?').get(task.assignedTo);
                    assignedToId = user ? user.id : null;
                }

                createTask(
                    task.title || 'Untitled Task',
                    assignedToId,
                    task.priority || 'medium'
                );
                count++;
            } catch (err) {
                console.error('Error migrating task:', err.message);
            }
        }

        console.log(`✅ Migrated ${count} tasks`);
        return count;
    } catch (err) {
        console.error('❌ Error migrating tasks:', err.message);
        return 0;
    }
}

async function migrateEvents() {
    console.log('\n📤 Migrating events...');
    try {
        const eventsPath = path.join(dataDir, 'events.json');
        if (!fs.existsSync(eventsPath)) {
            console.log('⚠️  events.json not found, skipping events migration');
            return 0;
        }

        const eventsData = JSON.parse(fs.readFileSync(eventsPath, 'utf8'));
        let count = 0;

        for (const event of eventsData) {
            try {
                createEvent(
                    event.title || 'Untitled Event',
                    event.description || '',
                    event.date || null,
                    null
                );
                count++;
            } catch (err) {
                console.error('Error migrating event:', err.message);
            }
        }

        console.log(`✅ Migrated ${count} events`);
        return count;
    } catch (err) {
        console.error('❌ Error migrating events:', err.message);
        return 0;
    }
}

async function migrateAnnouncements() {
    console.log('\n📤 Migrating announcements...');
    try {
        const announcementsPath = path.join(dataDir, 'announcements.json');
        if (!fs.existsSync(announcementsPath)) {
            console.log('⚠️  announcements.json not found, skipping announcements migration');
            return 0;
        }

        const announcementsData = JSON.parse(fs.readFileSync(announcementsPath, 'utf8'));
        let count = 0;

        for (const announcement of announcementsData) {
            try {
                createAnnouncement(
                    announcement.title || 'Untitled',
                    announcement.content || '',
                    announcement.date || null,
                    null
                );
                count++;
            } catch (err) {
                console.error('Error migrating announcement:', err.message);
            }
        }

        console.log(`✅ Migrated ${count} announcements`);
        return count;
    } catch (err) {
        console.error('❌ Error migrating announcements:', err.message);
        return 0;
    }
}

async function migrateMessages() {
    console.log('\n📤 Migrating chat messages...');
    try {
        const chatPath = path.join(dataDir, 'chat.json');
        if (!fs.existsSync(chatPath)) {
            console.log('⚠️  chat.json not found, skipping messages migration');
            return 0;
        }

        const chatData = JSON.parse(fs.readFileSync(chatPath, 'utf8'));
        let count = 0;

        for (const message of chatData) {
            try {
                // Get user ID by username
                const user = db.prepare('SELECT id FROM users WHERE username = ?').get(message.user || 'system');
                const userId = user ? user.id : 1;

                createMessage(
                    userId,
                    message.user || 'system',
                    message.content || ''
                );
                count++;
            } catch (err) {
                console.error('Error migrating message:', err.message);
            }
        }

        console.log(`✅ Migrated ${count} messages`);
        return count;
    } catch (err) {
        console.error('❌ Error migrating messages:', err.message);
        return 0;
    }
}

async function runMigration() {
    console.log('🚀 Starting migration from JSON to SQLite...\n');
    
    try {
        const totals = {
            users: await migrateUsers(),
            posts: await migratePosts(),
            tasks: await migrateTasks(),
            events: await migrateEvents(),
            announcements: await migrateAnnouncements(),
            messages: await migrateMessages()
        };

        console.log('\n' + '='.repeat(50));
        console.log('📊 MIGRATION SUMMARY');
        console.log('='.repeat(50));
        console.log(`✅ Users: ${totals.users}`);
        console.log(`✅ Posts: ${totals.posts}`);
        console.log(`✅ Tasks: ${totals.tasks}`);
        console.log(`✅ Events: ${totals.events}`);
        console.log(`✅ Announcements: ${totals.announcements}`);
        console.log(`✅ Messages: ${totals.messages}`);
        console.log('='.repeat(50));
        console.log('\n✨ Migration completed successfully!');
        console.log('📁 Database location: data/cya.db\n');
        process.exit(0);
    } catch (err) {
        console.error('❌ Migration failed:', err);
        process.exit(1);
    }
}

// Run migration
runMigration();
