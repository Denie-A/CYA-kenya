// Dashboard JavaScript
let currentUsername = null;
let authToken = null;
let userChurch = 'general';

// Toast Notification System
function showToast(message, type = 'success', duration = 3000) {
    const container = document.getElementById('notificationContainer');
    if (!container) return;
    
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    
    const icons = {
        success: '✓',
        error: '✕',
        info: 'ℹ'
    };
    
    toast.innerHTML = `
        <div class="toast-content">
            <span class="toast-icon">${icons[type] || '•'}</span>
            <span class="toast-message">${message}</span>
        </div>
        <button class="toast-close" onclick="this.parentElement.remove()">×</button>
    `;
    
    container.appendChild(toast);
    
    if (duration > 0) {
        setTimeout(() => {
            if (toast.parentElement) {
                toast.style.animation = 'slideInNotification 0.3s ease-out reverse';
                setTimeout(() => toast.remove(), 300);
            }
        }, duration);
    }
}

// Member roles
const memberChurchs = {
    'system-admin': 'System Administrator',
    'admin': 'Administrator',
    'moderator': 'Game Moderator',
    'chairperson': 'Chairperson',
    'vice-chair': 'Vice Chairperson',
    'secretary': 'Secretary',
    'organizing-secretary': 'Organizing Secretary',
    'treasurer': 'Treasurer',
    'general': 'General Member'
};

function getRoleLabel(role) {
    if (!role) return memberChurchs['general'] || 'General Member';
    if (memberChurchs[role]) return memberChurchs[role];
    const r = role.toString().toLowerCase();
    if (r.includes('system') && r.includes('admin')) return memberChurchs['system-admin'];
    if (r.includes('admin')) return memberChurchs['admin'];
    if (r.includes('moderator')) return memberChurchs['moderator'];
    if (r.includes('chair')) return memberChurchs['chairperson'];
    if (r.includes('vice')) return memberChurchs['vice-chair'];
    if (r.includes('organizing')) return memberChurchs['organizing-secretary'];
    if (r.includes('secretary')) return memberChurchs['secretary'];
    if (r.includes('treasurer')) return memberChurchs['treasurer'];
    return memberChurchs['general'] || role;
}

// Roles that can manage tasks, events, and announcements (admins and ministry leaders)
const managementRoles = ['system-admin', 'admin', 'moderator', 'chairperson', 'secretary', 'organizing-secretary'];

// Initialize dashboard
document.addEventListener('DOMContentLoaded', () => {
    checkAuth();
    setupTabNavigation();
    loadDashboardData();
    setupScrollNav();
    initializeFloatingChat();
});

function setupScrollNav() {
    const nav = document.querySelector('.navbar');
    if (!nav) return;
    
    window.addEventListener('scroll', () => {
        if (window.scrollY > 10) {
            nav.classList.add('scrolled');
        } else {
            nav.classList.remove('scrolled');
        }
    }, { passive: true });
}

function checkAuth() {
    const storedToken = localStorage.getItem('authToken');
    const storedUsername = localStorage.getItem('username');
    const storedRole = localStorage.getItem('userRole');

    if (!storedToken || !storedUsername) {
        window.location.href = 'landing.html';
        return;
    }

    authToken = storedToken;
    currentUsername = storedUsername;
    userChurch = storedRole || 'general';
    
    document.getElementById('navMiddle').style.display = 'flex';
    document.getElementById('userDisplay').innerHTML = `<a href="profile.html" class="user-link">👤 ${currentUsername}</a>`;
    document.getElementById('userDisplayMobile').innerHTML = `<a href="profile.html" class="user-link" onclick="toggleMobileMenu()">👤 ${currentUsername}</a>`;
    document.getElementById('memberChurch').textContent = memberChurchs[userChurch] || userChurch;
    document.getElementById('mobileMenuBtn').style.display = 'flex';
    
    // Show admin link for admin roles
    const adminRoles = ['system-admin', 'admin', 'moderator'];
    if (adminRoles.includes(userChurch)) {
        const adminLink = document.getElementById('adminLink');
        if (adminLink) adminLink.style.display = 'block';
    }
    
    // Setup permission-based UI
    setupPermissions();
}

function setupPermissions() {
    const canManage = managementRoles.includes(userChurch);
    
    // Show/hide management buttons based on role
    const newAnnouncementBtn = document.getElementById('newAnnouncementBtn');
    const newEventBtn = document.getElementById('newEventBtn');
    
    if (newAnnouncementBtn) {
        newAnnouncementBtn.style.display = canManage ? 'inline-block' : 'none';
    }
    
    if (newEventBtn) {
        newEventBtn.style.display = canManage ? 'inline-block' : 'none';
        newEventBtn.classList.toggle('hidden', !canManage);
    }
}

function setupTaskButtonVisibility() {
    const canManage = managementRoles.includes(userChurch);
    const newTaskBtn = document.querySelector('[onclick="showTaskForm()"]');
    if (newTaskBtn) {
        newTaskBtn.style.display = canManage ? 'inline-block' : 'none';
    }
}

function setupTabNavigation() {
    // Removed old tab navigation - now using direct tab buttons
}

function switchTab(tabId, btn) {
    document.querySelectorAll('.content-section').forEach(s => s.classList.remove('active'));
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    
    const section = document.getElementById(tabId);
    if (section) {
        section.classList.add('active');
    }
    if (btn) {
        btn.classList.add('active');
    }
}

function scrollToChat() {
    toggleChat();
}

// Floating Chat Functionality
let chatPosition = { x: window.innerWidth - 400, y: window.innerHeight - 540 };
let chatSize = { width: 380, height: 520 };
let isDragging = false;
let isResizing = false;
let dragOffset = { x: 0, y: 0 };
let chatState = { isOpen: false, isMinimized: false, isMaximized: false };

function saveChatState() {
    localStorage.setItem('chatState', JSON.stringify(chatState));
}

function loadChatState() {
    const saved = localStorage.getItem('chatState');
    if (saved) {
        try {
            chatState = JSON.parse(saved);
        } catch (e) {
            chatState = { isOpen: true, isMinimized: false, isMaximized: false };
        }
    }
}

function toggleChat() {
    const chat = document.getElementById('floatingChat');
    const btn = document.getElementById('chatToggleBtn');
    
    if (chat.style.display === 'none') {
        chat.style.display = 'flex';
        btn.classList.add('hidden');
        isChatOpen = true;
        chatState.isOpen = true;
        unreadMessageCount = 0;
        updateUnreadBadge();
    } else {
        chat.style.display = 'none';
        btn.classList.remove('hidden');
        isChatOpen = false;
        chatState.isOpen = false;
    }
    saveChatState();
}

function updateUnreadBadge() {
    const badge = document.getElementById('chatUnreadBadge');
    if (!badge) return;
    
    if (unreadMessageCount > 0) {
        badge.textContent = unreadMessageCount > 99 ? '99+' : unreadMessageCount;
        badge.style.display = 'flex';
    } else {
        badge.style.display = 'none';
    }
}

function minimizeChat() {
    const chat = document.getElementById('floatingChat');
    chat.classList.remove('maximized');
    chat.classList.add('minimized');
    document.getElementById('minimizeBtn').classList.add('hidden');
    document.getElementById('maximizeBtn').classList.remove('hidden');
    chatState.isMinimized = true;
    chatState.isMaximized = false;
    saveChatState();
}

function maximizeChat() {
    const chat = document.getElementById('floatingChat');
    chat.classList.remove('minimized');
    chat.classList.add('maximized');
    document.getElementById('minimizeBtn').classList.remove('hidden');
    document.getElementById('maximizeBtn').classList.add('hidden');
    chatState.isMaximized = true;
    chatState.isMinimized = false;
    saveChatState();
}

function closeChat() {
    const chat = document.getElementById('floatingChat');
    const btn = document.getElementById('chatToggleBtn');
    chat.style.display = 'none';
    btn.classList.remove('hidden');
    isChatOpen = false;
    chatState.isOpen = false;
    saveChatState();
}

function initChatDragResize() {
    const chat = document.getElementById('floatingChat');
    const header = document.getElementById('chatDragHandle');
    const resizeHandle = document.getElementById('chatResizeHandle');
    
    if (!header || !chat) return;
    
    // Dragging
    header.addEventListener('mousedown', (e) => {
        if (e.target.closest('.chat-control-btn')) return;
        
        isDragging = true;
        dragOffset.x = e.clientX - chat.offsetLeft;
        dragOffset.y = e.clientY - chat.offsetTop;
    });
    
    document.addEventListener('mousemove', (e) => {
        if (isDragging) {
            let x = e.clientX - dragOffset.x;
            let y = e.clientY - dragOffset.y;
            
            // Boundary check
            x = Math.max(0, Math.min(x, window.innerWidth - chat.offsetWidth));
            y = Math.max(0, Math.min(y, window.innerHeight - chat.offsetHeight));
            
            chat.style.left = x + 'px';
            chat.style.right = 'auto';
            chat.style.top = y + 'px';
            chat.style.bottom = 'auto';
        }
        
        if (isResizing) {
            let newWidth = e.clientX - chat.offsetLeft;
            let newHeight = e.clientY - chat.offsetTop;
            
            // Min/max sizes
            newWidth = Math.max(300, Math.min(newWidth, window.innerWidth - chat.offsetLeft - 10));
            newHeight = Math.max(350, Math.min(newHeight, window.innerHeight - chat.offsetTop - 10));
            
            chat.style.width = newWidth + 'px';
            chat.style.height = newHeight + 'px';
        }
    });
    
    document.addEventListener('mouseup', () => {
        isDragging = false;
        isResizing = false;
    });
    
    // Resizing
    if (resizeHandle) {
        resizeHandle.addEventListener('mousedown', (e) => {
            isResizing = true;
            e.preventDefault();
        });
    }
}

// Show chat on load
function initializeFloatingChat() {
    const chat = document.getElementById('floatingChat');
    const btn = document.getElementById('chatToggleBtn');
    const clearBtn = document.getElementById('clearChatBtn');
    
    if (chat && btn) {
        // Load saved chat state
        loadChatState();
        
        // Set initial position
        chat.style.left = 'auto';
        chat.style.right = '20px';
        chat.style.top = 'auto';
        chat.style.bottom = '20px';
        
        // Restore chat visibility state
        if (chatState.isOpen) {
            chat.style.display = 'flex';
            btn.classList.add('hidden');
            isChatOpen = true;
        } else {
            chat.style.display = 'none';
            btn.classList.remove('hidden');
            isChatOpen = false;
        }
        
        // Restore minimized/maximized state
        if (chatState.isMaximized) {
            chat.classList.add('maximized');
            document.getElementById('minimizeBtn').classList.remove('hidden');
            document.getElementById('maximizeBtn').classList.add('hidden');
        } else if (chatState.isMinimized) {
            chat.classList.add('minimized');
            document.getElementById('minimizeBtn').classList.add('hidden');
            document.getElementById('maximizeBtn').classList.remove('hidden');
        } else {
            chat.classList.remove('minimized');
        }
        
        // Show clear button only for non-general users
        if (clearBtn && userChurch !== 'general') {
            clearBtn.style.display = 'flex';
        }
        
        initChatDragResize();
        updateUnreadBadge();
    }
}

// Bible verses for daily memory verse
const BIBLE_VERSES = [
    { text: "For God so loved the world that he gave his one and only Son, that whoever believes in him shall not perish but have eternal life.", reference: "John 3:16" },
    { text: "Trust in the Lord with all your heart and lean not on your own understanding.", reference: "Proverbs 3:5" },
    { text: "Do not let any unwholesome talk come out of your mouths, but only what is helpful for building others up according to their needs.", reference: "Ephesians 4:29" },
    { text: "Don't let anyone look down on you because you are young, but set an example for the believers in speech, in conduct, in love, in faith and in purity.", reference: "1 Timothy 4:12" },
    { text: "I can do all this through him who gives me strength.", reference: "Philippians 4:13" },
    { text: "The Lord is my shepherd, I lack nothing.", reference: "Psalm 23:1" },
    { text: "Therefore do not worry about tomorrow, for tomorrow will worry about itself. Each day has enough trouble of its own.", reference: "Matthew 6:34" },
    { text: "Love one another as I have loved you.", reference: "John 13:34" },
    { text: "Be joyful always; pray continually; give thanks in all circumstances.", reference: "1 Thessalonians 5:16-18" },
    { text: "And we know that in all things God works for the good of those who love him.", reference: "Romans 8:28" }
];

let pendingConfirmation = null;

// Confirmation Modal Functions
function showConfirmationDialog(title, message, onConfirm) {
    pendingConfirmation = onConfirm;
    document.getElementById('confirmTitle').textContent = title;
    document.getElementById('confirmMessage').textContent = message;
    document.getElementById('confirmationModal').classList.remove('hidden');
}

function cancelConfirmation() {
    pendingConfirmation = null;
    document.getElementById('confirmationModal').classList.add('hidden');
}

function executeConfirmation() {
    if (pendingConfirmation && typeof pendingConfirmation === 'function') {
        pendingConfirmation();
    }
    cancelConfirmation();
}

// Load daily memory verse
function loadMemoryVerse() {
    const today = new Date();
    const dayOfYear = Math.floor((today - new Date(today.getFullYear(), 0, 0)) / 86400000);
    const verseIndex = dayOfYear % BIBLE_VERSES.length;
    const verse = BIBLE_VERSES[verseIndex];
    
    document.getElementById('memoryVerseText').textContent = verse.text;
    document.getElementById('memoryVerseReference').textContent = verse.reference;
}

function loadDashboardData() {
    loadAnnouncements();
    loadTasks();
    loadActivities();
    loadChatMessages();
    loadPosts();
    loadOnlineMembers();
    loadUserStats();
    loadMemoryVerse();
}

async function loadUserStats() {
    try {
        const response = await fetch('/api/stats', {
            headers: { 'Authorization': `Bearer ${authToken}` }
        });
        
        if (response.ok) {
            const stats = await response.json();
            updateQuickStats(stats);
        }
    } catch (error) {
        console.error('Error loading stats:', error);
    }
}

function updateQuickStats(stats) {
    const gamesPlayed = document.getElementById('quickGamesPlayed');
    const balance = document.getElementById('quickBalance');
    const wins = document.getElementById('quickWins');
    
    if (gamesPlayed) gamesPlayed.textContent = stats.totalGamesPlayed || 0;
    if (balance) balance.textContent = '$' + (stats.balance || 0).toFixed(0);
    if (wins) wins.textContent = stats.totalWins || 0;
}

async function loadAnnouncements() {
    const list = document.getElementById('announcementsList');
    const canManage = managementRoles.includes(userChurch);
    const newAnnouncementBtn = document.getElementById('newAnnouncementBtn');
    
    // Hide new announcement button for non-management users
    if (newAnnouncementBtn) {
        newAnnouncementBtn.style.display = canManage ? 'inline-block' : 'none';
    }
    
    try {
        const response = await fetch('/api/announcements', {
            headers: { 'Authorization': `Bearer ${authToken}` }
        });
        
        const announcements = await response.json();
        
        if (!announcements || announcements.length === 0) {
            list.innerHTML = '<div class="empty-state">No announcements yet</div>';
            return;
        }

        list.innerHTML = announcements.map(ann => {
            const actions = canManage ? `<div class="card-actions"><button class="btn-edit" onclick="editAnnouncement('${ann.id}', '${escapeHtml(ann.title)}', '${escapeHtml(ann.content)}', '${ann.date}')">Edit</button><button class="btn-delete" onclick="deleteAnnouncement('${ann.id}')">Delete</button></div>` : '';
            
            return `
                <div class="announcement-item">
                    <div class="announcement-title">${escapeHtml(ann.title)}</div>
                    <div class="announcement-content">${escapeHtml(ann.content)}</div>
                    <div class="announcement-date">Posted: ${new Date(ann.date).toLocaleDateString()}</div>
                    ${actions}
                </div>
            `;
        }).join('');
    } catch (err) {
        console.error('Error loading announcements:', err);
        list.innerHTML = '<div class="empty-state">Error loading announcements</div>';
    }
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

async function loadTasks() {
    try {
        const response = await fetch('/api/tasks', {
            headers: { 'Authorization': `Bearer ${authToken}` }
        });
        
        let tasks = await response.json();
        const list = document.getElementById('tasksList');
        const canManage = managementRoles.includes(userChurch);
        
        // Hide new task button for non-management users
        setupTaskButtonVisibility();
        
        if (!tasks || tasks.length === 0) {
            // Show sample tasks if none exist
            tasks = [
                { id: 'sample1', title: 'Prepare Sunday Lesson', assignee: 'Ministry Team', priority: 'High' },
                { id: 'sample2', title: 'Organize Youth Event', assignee: 'Event Coordinator', priority: 'Medium' },
                { id: 'sample3', title: 'Update Website Content', assignee: 'Communications', priority: 'Medium' },
                { id: 'sample4', title: 'Plan Prayer Meeting', assignee: 'Spiritual Leader', priority: 'High' }
            ];
        }

        list.innerHTML = tasks.map(task => {
            const actions = canManage ? `<div class="card-actions"><button class="btn-edit" onclick="editTask('${task.id}', '${escapeHtml(task.title)}', '${escapeHtml(task.assignee)}', '${task.priority}')">Edit</button><button class="btn-delete" onclick="deleteTaskPrompt('${task.id}')">Delete</button></div>` : '';
            return `
            <div class="task-item">
                <input type="checkbox" class="task-checkbox">
                <div class="task-content">
                    <div class="task-title">${escapeHtml(task.title)}</div>
                    <div class="task-assignee">Assigned to: ${escapeHtml(task.assignee)}</div>
                </div>
                <span class="task-priority ${task.priority.toLowerCase()}">${task.priority}</span>
                ${actions}
            </div>
        `}).join('');
    } catch (error) {
        console.error('Error loading tasks:', error);
        document.getElementById('tasksList').innerHTML = '<div class="empty-state">Error loading tasks</div>';
    }
}

async function loadActivities() {
    const newEventBtn = document.getElementById('newEventBtn');
    const missionStatement = document.getElementById('missionStatement');
    const canManageEvents = managementRoles.includes(userChurch);
    
    if (canManageEvents) {
        if (newEventBtn) newEventBtn.classList.remove('hidden');
        if (missionStatement) missionStatement.classList.add('hidden');
    } else {
        if (newEventBtn) newEventBtn.classList.add('hidden');
        if (missionStatement) missionStatement.classList.remove('hidden');
    }
    
    try {
        const response = await fetch('/api/events', {
            headers: { 'Authorization': `Bearer ${authToken}` }
        });
        
        let events = await response.json();
        
        const list = document.getElementById('activitiesList');
        
        if (!events || events.length === 0) {
            // Show sample events if none exist
            events = [
                { id: 'sample1', title: 'Weekly Bible Study', description: 'Join us for weekly Bible study and fellowship', date: getNextFriday() },
                { id: 'sample2', title: 'Youth Camp Registration', description: 'Register for the annual youth spiritual retreat', date: getNextMonth() },
                { id: 'sample3', title: 'Community Service Day', description: 'Volunteer with the group to serve our community', date: getNextSaturday() }
            ];
        }
        
        list.innerHTML = events.map(event => {
            const actions = canManageEvents ? `<div class="card-actions"><button class="btn-edit" onclick="editEvent('${event.id}', '${escapeHtml(event.title)}', '${event.date}', '${escapeHtml(event.description)}')">Edit</button><button class="btn-delete" onclick="deleteEventPrompt('${event.id}')">Delete</button></div>` : '';
            return `
                <div class="activity-card">
                    <div class="activity-date">${new Date(event.date).toLocaleDateString()}</div>
                    <div class="activity-title">${escapeHtml(event.title)}</div>
                    <div class="activity-description">${escapeHtml(event.description)}</div>
                    ${actions}
                </div>
            `;
        }).join('');
        
        // Hide new button for non-management users
        if (newEventBtn) {
            newEventBtn.style.display = canManageEvents ? 'inline-block' : 'none';
        }
    } catch (error) {
        console.error('Error loading events:', error);
    }
}

function getNextFriday() {
    const today = new Date();
    const daysUntilFriday = (5 - today.getDay() + 7) % 7 || 7;
    const nextFriday = new Date(today);
    nextFriday.setDate(today.getDate() + daysUntilFriday);
    return nextFriday.toISOString().split('T')[0];
}

function getNextSaturday() {
    const today = new Date();
    const daysUntilSaturday = (6 - today.getDay() + 7) % 7 || 7;
    const nextSaturday = new Date(today);
    nextSaturday.setDate(today.getDate() + daysUntilSaturday);
    return nextSaturday.toISOString().split('T')[0];
}

function getNextMonth() {
    const today = new Date();
    const nextMonth = new Date(today);
    nextMonth.setMonth(today.getMonth() + 1);
    return nextMonth.toISOString().split('T')[0];
}

async function loadPosts() {
    try {
        const response = await fetch('/api/posts', {
            headers: { 'Authorization': `Bearer ${authToken}` }
        });
        
        let posts = await response.json();
        const list = document.getElementById('postsList');
        
        if (!posts || posts.length === 0) {
            list.innerHTML = '<div class="empty-state">No posts yet. Be the first to share!</div>';
            return;
        }

        list.innerHTML = posts.map(post => buildPostHTML(post)).join('');
    } catch (error) {
        console.error('Error loading posts:', error);
        document.getElementById('postsList').innerHTML = '<div class="empty-state">Error loading posts</div>';
    }
}

function deletePostPrompt(id) {
    showConfirmationDialog('Delete Post', 'Are you sure you want to delete this post? This action cannot be undone.', () => deletePost(id));
}

async function deletePost(id) {
    try {
        const response = await fetch(`/api/posts/${id}`, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${authToken}` }
        });
        
        const data = await response.json();
        
        if (data.success) {
            showToast('Post deleted', 'success', 2000);
            loadPosts();
        } else {
            showToast(data.error || 'Failed to delete post', 'error');
        }
    } catch (err) {
        showToast('Failed to delete post', 'error');
    }
}

async function likePost(id, type) {
    try {
        const response = await fetch(`/api/posts/${id}/like`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authToken}`
            },
            body: JSON.stringify({ type })
        });
        
        const data = await response.json();
        
        if (data.success) {
            loadPosts();
        } else {
            showToast(data.error || 'Failed to like post', 'error');
        }
    } catch (err) {
        showToast('Failed to like post', 'error');
    }
}

async function addComment(postId) {
    const input = document.getElementById(`commentInput_${postId}`);
    if (!input) return;
    const text = input.value.trim();
    if (!text) return showToast('Comment cannot be empty', 'error');

    try {
        const response = await fetch(`/api/posts/${postId}/comment`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authToken}`
            },
            body: JSON.stringify({ text })
        });

        const data = await response.json();
        if (data.success) {
            input.value = '';
            loadPosts();
        } else {
            showToast(data.error || 'Failed to add comment', 'error');
        }
    } catch (err) {
        showToast('Failed to add comment', 'error');
    }
}

async function loadOnlineMembers() {
    const list = document.getElementById('membersList');
    
    try {
        const response = await fetch('/api/online-members', {
            headers: { 'Authorization': `Bearer ${authToken}` }
        });
        
        if (response.ok) {
            const data = await response.json();
            membersListData = data.members || [];
            renderMembersList();

            // Ensure socket is initialized to receive realtime online updates
            if (!socket) {
                initializeSocket();
                if (currentUsername) {
                    setTimeout(() => socket.emit('authenticate', currentUsername), 500);
                }
            }
        }
    } catch (error) {
        list.innerHTML = `
            <div class="member-item online">${currentUsername} (You)</div>
        `;
    }
}

// Chat functionality
let chatMessages = [];
let chatPollingInterval = null;
let lastChatTimestamp = null;
let unreadMessageCount = 0;
let isChatOpen = true;
let typingUsers = {};
let typingPollingInterval = null;
let typingTimeout = null;
let isCurrentlyTyping = false;

// Reply functionality
let replyingToMessageId = null;
let replyingToUsername = null;
let replyingToContent = null;

// Socket.IO connection
let socket = null;
let onlineUsers = [];
// Cached members list from API
let membersListData = [];

function renderMembersList() {
    const list = document.getElementById('membersList');
    if (!list) return;

    const onlineSet = new Set(onlineUsers || []);
    const online = membersListData.filter(m => (m.online === true) || onlineSet.has(m.name) || (m.name === currentUsername)).sort((a,b) => a.name.localeCompare(b.name));
    const offline = membersListData.filter(m => !((m.online === true) || onlineSet.has(m.name) || (m.name === currentUsername))).sort((a,b) => a.name.localeCompare(b.name));

    const renderMember = (m) => `\n                <div class="member-item ${((m.online === true) || onlineSet.has(m.name) || (m.name === currentUsername)) ? 'online' : 'offline'}">\n                    <span class="member-status"></span>\n                    <div class="member-meta">\n                        <div class="member-name">${escapeHtml(m.name)}</div>\n                        <div class="member-church">${escapeHtml(m.church || 'Unknown Church')}</div>\n                    </div>\n                </div>`;

    let html = '';
    html += '<div class="members-section"><div class="members-section-header">🟢 Online</div>';
    html += online.length ? online.map(renderMember).join('') : '<div class="empty-state">No one online</div>';
    html += '</div>';

    html += '<div class="members-section"><div class="members-section-header">⚪ Offline</div>';
    html += offline.length ? offline.map(renderMember).join('') : '<div class="empty-state">No offline members</div>';
    html += '</div>';

    list.innerHTML = html;
}

function initializeSocket() {
    if (socket) return;
    
    socket = io();
    
    // On connect, authenticate and request initial online users list
    socket.on('connect', () => {
        if (currentUsername) {
            socket.emit('authenticate', currentUsername);
        }
        socket.emit('requestOnlineUsers');
    });
    
    // Real-time online users list
    socket.on('onlineUsers', (users) => {
        onlineUsers = Array.isArray(users) ? users : [];
        renderOnlineUsers();
        renderMembersList();
    });
    
    // User came online
    socket.on('userOnline', (username) => {
        if (!onlineUsers.includes(username)) {
            onlineUsers.push(username);
            renderOnlineUsers();
            renderMembersList();
        }
    });
    
    // User went offline
    socket.on('userOffline', (username) => {
        onlineUsers = onlineUsers.filter(u => u !== username);
        renderOnlineUsers();
        renderMembersList();
    });
    
    // Real-time message listener - unified for all clients
    socket.on('newMessage', (newMessage) => {
        // Check if message already exists to prevent duplicates
        if (!chatMessages.find(m => m.id === newMessage.id)) {
            chatMessages.push(newMessage);
            lastChatTimestamp = newMessage.createdAt;
            renderChatMessages(true, true);
        }
    });
    
    // Real-time reaction added
    socket.on('reactionAdded', (data) => {
        const message = chatMessages.find(m => m.id === data.messageId);
        if (message) {
            if (!message.reactions) message.reactions = {};
            if (!message.reactions[data.emoji]) message.reactions[data.emoji] = [];
            if (!message.reactions[data.emoji].includes(data.username)) {
                message.reactions[data.emoji].push(data.username);
                updateMessageReactions(data.messageId);
            }
        }
    });
    
    // Real-time reaction removed
    socket.on('reactionRemoved', (data) => {
        const message = chatMessages.find(m => m.id === data.messageId);
        if (message && message.reactions && message.reactions[data.emoji]) {
            const index = message.reactions[data.emoji].indexOf(data.username);
            if (index > -1) {
                message.reactions[data.emoji].splice(index, 1);
                if (message.reactions[data.emoji].length === 0) {
                    delete message.reactions[data.emoji];
                }
                updateMessageReactions(data.messageId);
            }
        }
    });
    
    // Message deleted
    socket.on('messageDeleted', (messageId) => {
        const index = chatMessages.findIndex(m => m.id === messageId);
        if (index > -1) {
            chatMessages.splice(index, 1);
            renderChatMessages(true);
        }
    });
    
    // Chat cleared
    socket.on('chatCleared', () => {
        chatMessages = [];
        lastChatTimestamp = null;
        renderChatMessages();
    });
    
    // Real-time posts
    socket.on('newPost', (post) => {
        // insert new post at top
        insertPostAtTop(post);
    });

    socket.on('postLiked', (data) => {
        // data: { postId, likes, loves, likedBy, lovedBy }
        if (!data || !data.postId) return;
        updatePostReactions(data.postId, data.likes || 0, data.loves || 0, data.likedBy || [], data.lovedBy || []);
    });

    socket.on('postComment', ({ postId, comment }) => {
        if (!postId || !comment) return;
        appendCommentToPost(postId, comment);
    });
    
    console.log('Socket.IO connected for real-time chat');
}

// Build HTML for a single post (used by loadPosts and real-time inserts)
function buildPostHTML(post) {
    const canDelete = post.author === currentUsername || ['system-admin', 'admin', 'moderator'].includes(userChurch);
    const canEdit = post.author === currentUsername;
    const deleteBtn = canDelete ? `<button class="btn-delete" onclick="deletePostPrompt('${post.id}')">Delete</button>` : '';
    const editBtn = canEdit ? `<button class="btn-edit" onclick="editPost('${post.id}', '${escapeHtml(post.content)}')">Edit</button>` : '';
    const userLikedIt = post.likedBy && post.likedBy.includes(`${currentUsername}:like`);
    const userLovedIt = post.lovedBy && post.lovedBy.includes(`${currentUsername}:love`);
    const actionButtons = editBtn || deleteBtn ? `<div class="card-actions">${editBtn}${deleteBtn}</div>` : '';

    const imageHtml = post.image ? `<div class="post-image"><img src="${post.image}" alt="post image" /></div>` : '';
    const captionHtml = post.caption ? `<div class="post-caption">${escapeHtml(post.caption)}</div>` : '';
    const comments = (post.comments || []).slice(-5);
    const commentsHtml = comments.length ? `<div class="post-comments">${comments.map(c => `<div class="comment-item"><strong>${escapeHtml(c.author)}</strong> ${escapeHtml(c.text)} <span class="comment-time">${new Date(c.createdAt).toLocaleString()}</span></div>`).join('')}</div>` : '';

    return `
        <div class="post-item" data-id="${post.id}">
            <div class="post-header">
                <div>
                    <span class="post-author">${escapeHtml(post.author)}</span>
                    <span class="post-role">${escapeHtml(getRoleLabel(post.role))}</span>
                </div>
                <div class="post-date">${new Date(post.createdAt).toLocaleDateString()}</div>
            </div>
            <div class="post-content">${escapeHtml(post.content)}</div>
            ${imageHtml}
            ${captionHtml}
            <div class="post-reactions">
                <button class="post-reaction-btn like-btn ${userLikedIt ? 'active' : ''}" onclick="likePost('${post.id}', 'like')">👍 ${post.likes || 0}</button>
                <button class="post-reaction-btn love-btn ${userLovedIt ? 'active' : ''}" onclick="likePost('${post.id}', 'love')">❤️ ${post.loves || 0}</button>
                ${actionButtons}
            </div>
            ${commentsHtml}
            <div class="post-add-comment">
                <input type="text" id="commentInput_${post.id}" placeholder="Write a comment..." />
                <button class="btn btn-sm" onclick="addComment('${post.id}')">Comment</button>
            </div>
        </div>
    `;
}

function insertPostAtTop(post) {
    const container = document.getElementById('postsList');
    if (!container) return;
    container.insertAdjacentHTML('afterbegin', buildPostHTML(post));
}

function updatePostReactions(postId, likes, loves, likedBy = [], lovedBy = []) {
    const postEl = document.querySelector(`.post-item[data-id="${postId}"]`);
    if (!postEl) return;
    const likeBtn = postEl.querySelector('.like-btn');
    const loveBtn = postEl.querySelector('.love-btn');
    if (likeBtn) {
        likeBtn.innerHTML = `👍 ${likes}`;
        if (Array.isArray(likedBy) && likedBy.includes(`${currentUsername}:like`)) likeBtn.classList.add('active'); else likeBtn.classList.remove('active');
    }
    if (loveBtn) {
        loveBtn.innerHTML = `❤️ ${loves}`;
        if (Array.isArray(lovedBy) && lovedBy.includes(`${currentUsername}:love`)) loveBtn.classList.add('active'); else loveBtn.classList.remove('active');
    }
}

function appendCommentToPost(postId, comment) {
    const postEl = document.querySelector(`.post-item[data-id="${postId}"]`);
    if (!postEl) return;
    let commentsContainer = postEl.querySelector('.post-comments');
    const commentHtml = `<div class="comment-item"><strong>${escapeHtml(comment.author)}</strong> ${escapeHtml(comment.text)} <span class="comment-time">${new Date(comment.createdAt).toLocaleString()}</span></div>`;
    if (commentsContainer) {
        commentsContainer.insertAdjacentHTML('beforeend', commentHtml);
    } else {
        const node = document.createElement('div');
        node.className = 'post-comments';
        node.innerHTML = commentHtml;
        const addCommentEl = postEl.querySelector('.post-add-comment');
        postEl.insertBefore(node, addCommentEl);
    }
}

function updateMessageReactions(messageId) {
    const messageEl = document.querySelector(`[data-id="${messageId}"]`);
    if (!messageEl) return;
    
    const message = chatMessages.find(m => m.id === messageId);
    if (!message) return;
    
    const reactionsContainer = messageEl.querySelector('.chat-message-reactions');
    if (!reactionsContainer) return;
    
    const reactions = message.reactions || {};
    let reactionsHtml = '';
    
    if (Object.keys(reactions).length > 0) {
        Object.entries(reactions).forEach(([emoji, userList]) => {
            const userReacted = userList.includes(currentUsername);
            reactionsHtml += `<button class="emoji-reaction ${userReacted ? 'user-reacted' : ''}" onclick="toggleReaction('${message.id}', '${emoji}')" title="${userList.join(', ')}" data-emoji="${emoji}" data-msgid="${message.id}"><span>${emoji}</span><span class="reaction-count">${userList.length}</span></button>`;
        });
    }
    
    reactionsContainer.innerHTML = reactionsHtml;
}

function renderOnlineUsers() {
    const container = document.getElementById('onlineUsersList');
    if (!container) return;
    
    let html = '';
    
    // Show current user first
    html += `
        <div class="online-user-item" title="You (Online)">
            <span class="online-status"></span>
            <span class="online-user-name">You</span>
        </div>
    `;
    
    // Show other online users sorted alphabetically (exclude current user)
    const sortedUsers = (onlineUsers || []).filter(u => u !== currentUsername).slice().sort();
    sortedUsers.forEach(username => {
        // lookup church from cached members list
        const member = (membersListData || []).find(m => m.name === username);
        const church = member ? (member.church || 'Unknown Church') : 'Unknown Church';
        html += `
            <div class="online-user-item" title="${escapeHtml(username)} (Online)">
                <span class="online-status"></span>
                <span class="online-user-name">${escapeHtml(username)}</span>
                <span class="online-user-church"> — ${escapeHtml(church)}</span>
            </div>
        `;
    });
    
    if (sortedUsers.length === 0) {
        html = `
            <div class="online-user-item" style="flex: 1; text-align: center; color: #999;">
                <span>Just you here!</span>
            </div>
        `;
    }
    
    container.innerHTML = html;
    
    // Auto-scroll to end
    setTimeout(() => {
        container.scrollLeft = container.scrollWidth;
    }, 0);
}

async function loadChatMessages() {
    const messagesContainer = document.getElementById('chatMessages');
    
    try {
        const response = await fetch('/api/chat', {
            headers: { 'Authorization': `Bearer ${authToken}` }
        });
        
        if (response.ok) {
            const data = await response.json();
            chatMessages = data.messages || [];
            renderChatMessages();
            
            // Initialize Socket.IO for real-time updates
            if (!socket) {
                initializeSocket();
                // Authenticate with the server
                setTimeout(() => {
                    socket.emit('authenticate', currentUsername);
                }, 500);
            }
        }
    } catch (error) {
        console.error('Error loading chat:', error);
        messagesContainer.innerHTML = '<div class="empty-state">Error loading chat. Please refresh.</div>';
    }
}

async function pollNewMessages() {
    if (!isChatOpen) return;
    if (!lastChatTimestamp) {
        lastChatTimestamp = chatMessages.length > 0 ? chatMessages[chatMessages.length - 1].createdAt : new Date(0).toISOString();
    }
    
    try {
        const response = await fetch(`/api/chat/since/${encodeURIComponent(lastChatTimestamp)}`, {
            headers: { 'Authorization': `Bearer ${authToken}` }
        });
        
        if (response.ok) {
            const data = await response.json();
            if (data.messages && data.messages.length > 0) {
                chatMessages = [...chatMessages, ...data.messages];
                lastChatTimestamp = data.messages[data.messages.length - 1].createdAt;
                renderChatMessages(false, true);
            }
        }
    } catch (error) {
        console.error('Error polling chat:', error);
    }
}

function renderChatMessages(shouldAutoScroll = true, onlyNewMessages = false) {
    const messagesContainer = document.getElementById('chatMessages');
    const wasAtBottom = messagesContainer.scrollHeight - messagesContainer.scrollTop <= messagesContainer.clientHeight + 50;
    
    if (!chatMessages || chatMessages.length === 0) {
        messagesContainer.innerHTML = `
            <div class="empty-state">
                <span class="empty-icon">💬</span>
                <p>Start the conversation!</p>
                <p class="empty-subtitle">Be the first to send a message to the group.</p>
            </div>
        `;
        return;
    }
    
    const adminRoles = ['system-admin', 'admin', 'moderator'];
    const canDelete = adminRoles.includes(userChurch);
    
    let startIndex = 0;
    if (onlyNewMessages && messagesContainer.children.length > 0) {
        startIndex = chatMessages.length - 1;
    }
    
    let html = '';
    let lastDate = null;
    
    for (let i = startIndex; i < chatMessages.length; i++) {
        const msg = chatMessages[i];
        const msgDate = new Date(msg.createdAt).toLocaleDateString();
        
        if (msgDate !== lastDate) {
            html += `<div class="chat-date-divider"><span>${msgDate === new Date().toLocaleDateString() ? 'Today' : msgDate}</span></div>`;
            lastDate = msgDate;
        }
        
        const isOwn = msg.username === currentUsername;
        const showDelete = isOwn || canDelete;
        const reactions = msg.reactions || {};
        
        let reactionsHtml = '';
        if (Object.keys(reactions).length > 0) {
            reactionsHtml = '<div class="chat-message-reactions">';
            Object.entries(reactions).forEach(([emoji, userList]) => {
                const userReacted = userList.includes(currentUsername);
                reactionsHtml += `<button class="emoji-reaction ${userReacted ? 'user-reacted' : ''}" onclick="toggleReaction('${msg.id}', '${emoji}')" title="${userList.join(', ')}" data-emoji="${emoji}" data-msgid="${msg.id}"><span>${emoji}</span><span class="reaction-count">${userList.length}</span></button>`;
            });
            reactionsHtml += '</div>';
        }
        
        html += `
            <div class="chat-message ${isOwn ? 'own' : 'other'}" data-id="${msg.id}">
                ${showDelete ? `
                    <div class="chat-message-actions">
                        <button class="chat-delete-btn" onclick="deleteChatMessage('${msg.id}')" title="Delete message">×</button>
                        <button class="chat-add-reaction-btn" onclick="showMessageReactions('${msg.id}')" title="Add reaction">😊</button>
                    </div>
                ` : `
                    <div class="chat-message-actions">
                        <button class="chat-add-reaction-btn" onclick="showMessageReactions('${msg.id}')" title="Add reaction">😊</button>
                    </div>
                `}
                ${msg.replyTo ? `
                    <div class="chat-message-reply-context">
                        <div class="reply-context-label">↳ Replying to ${msg.replyToUsername || 'Unknown'}</div>
                        <div class="reply-context-text">${escapeHtml(msg.replyToContent || '...')}</div>
                    </div>
                ` : ''}
                <div class="chat-message-header">
                    <div class="chat-message-user">
                        ${isOwn ? 'You' : escapeHtml(msg.username)}
                    </div>
                    <div class="chat-message-time">${new Date(msg.createdAt).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}</div>
                </div>
                <div class="chat-message-content">${escapeHtml(msg.message)}</div>
                ${showDelete ? `
                    <div class="chat-message-actions-below">
                        <button class="chat-reply-btn" onclick="startReply('${msg.id}', '${escapeHtml(msg.username).replace(/'/g, "\\'")}', '${escapeHtml(msg.message).replace(/'/g, "\\'").substring(0, 50)}...')" title="Reply to this message">↩️ Reply</button>
                    </div>
                ` : `
                    <div class="chat-message-actions-below">
                        <button class="chat-reply-btn" onclick="startReply('${msg.id}', '${escapeHtml(msg.username).replace(/'/g, "\\'")}', '${escapeHtml(msg.message).replace(/'/g, "\\'").substring(0, 50)}...')" title="Reply to this message">↩️ Reply</button>
                    </div>
                `}
                ${reactionsHtml}
            </div>
        `;
    }
    
    if (onlyNewMessages && html && messagesContainer.children.length > 0) {
        messagesContainer.innerHTML += html;
    } else {
        messagesContainer.innerHTML = html;
    }
    
    if (shouldAutoScroll && wasAtBottom) {
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
    }
}

function startReply(messageId, username, content) {
    replyingToMessageId = messageId;
    replyingToUsername = username;
    replyingToContent = content;
    
    const indicator = document.getElementById('replyIndicator');
    const nameEl = document.getElementById('replyUsername');
    nameEl.textContent = username;
    indicator.classList.remove('hidden');
    
    document.getElementById('chatInput').focus();
}

function cancelReply() {
    replyingToMessageId = null;
    replyingToUsername = null;
    replyingToContent = null;
    
    const indicator = document.getElementById('replyIndicator');
    indicator.classList.add('hidden');
}

async function sendChatMessage() {
    const input = document.getElementById('chatInput');
    const message = input.value.trim();
    
    if (!message) return;
    
    const sendBtn = document.getElementById('chatSendBtn');
    const originalText = sendBtn.textContent;
    sendBtn.textContent = '⏳';
    sendBtn.disabled = true;
    
    try {
        const payload = { message };
        if (replyingToMessageId) {
            payload.replyTo = replyingToMessageId;
        }
        
        const response = await fetch('/api/chat', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authToken}`
            },
            body: JSON.stringify(payload)
        });
        
        if (response.ok) {
            const data = await response.json();
            // Don't manually push - let Socket.IO handle it for all clients (including sender)
            // to avoid duplicate messages
            input.value = '';
            updateCharCount();
            cancelReply();
            showToast('Message sent!', 'success', 2000);
        } else {
            const error = await response.json();
            showToast(error.error || 'Failed to send message', 'error');
        }
    } catch (error) {
        console.error('Error sending message:', error);
        showToast('Failed to send message. Please try again.', 'error');
    } finally {
        sendBtn.textContent = originalText;
        sendBtn.disabled = false;
        input.focus();
    }
}

async function clearAllMessages() {
    if (chatMessages.length === 0) {
        showToast('No messages to clear', 'info');
        return;
    }
    
    showConfirmationDialog(
        'Clear All Messages',
        'Are you sure you want to clear all chat messages? This cannot be undone.',
        async () => {
            try {
                const response = await fetch('/api/chat/clear', {
                    method: 'DELETE',
                    headers: { 'Authorization': `Bearer ${authToken}` }
                });
                
                if (response.ok) {
                    chatMessages = [];
                    lastChatTimestamp = null;
                    renderChatMessages();
                    showToast('All messages cleared', 'success', 2000);
                } else {
                    const error = await response.json();
                    showToast(error.error || 'Failed to clear messages', 'error');
                }
            } catch (error) {
                console.error('Error clearing chat:', error);
                showToast('Failed to clear messages', 'error');
            }
        }
    );
}

async function deleteChatMessage(id) {
    showConfirmationDialog(
        'Delete Message',
        'Are you sure you want to delete this message?',
        async () => {
            try {
                const response = await fetch(`/api/chat/${id}`, {
                    method: 'DELETE',
                    headers: { 'Authorization': `Bearer ${authToken}` }
                });
                
                if (response.ok) {
                    // Emit deletion through Socket.IO
                    if (socket) {
                        socket.emit('messageDeleted', id);
                    }
                    chatMessages = chatMessages.filter(m => m.id !== id);
                    renderChatMessages();
                    showToast('Message deleted', 'success', 2000);
                } else {
                    const error = await response.json();
                    showToast(error.error || 'Failed to delete message', 'error');
                }
            } catch (error) {
                console.error('Error deleting message:', error);
                showToast('Failed to delete message', 'error');
            }
        }
    );
}

function handleChatKeyPress(event) {
    if (event.key === 'Enter' && !event.shiftKey) {
        event.preventDefault();
        sendChatMessage();
    }
    updateCharCount();
    notifyTyping();
}

function notifyTyping() {
    if (!isCurrentlyTyping) {
        isCurrentlyTyping = true;
        sendTypingStatus(true);
    }
    
    clearTimeout(typingTimeout);
    typingTimeout = setTimeout(() => {
        isCurrentlyTyping = false;
        sendTypingStatus(false);
    }, 3000);
}

async function sendTypingStatus(isTyping) {
    try {
        await fetch('/api/chat/typing', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authToken}`
            },
            body: JSON.stringify({ isTyping })
        });
    } catch (error) {
        console.error('Error sending typing status:', error);
    }
}

async function pollTypingUsers() {
    try {
        const response = await fetch('/api/chat/typing/users', {
            headers: { 'Authorization': `Bearer ${authToken}` }
        });
        
        if (response.ok) {
            const data = await response.json();
            typingUsers = data.typingUsers || {};
            updateTypingIndicator();
        }
    } catch (error) {
        console.error('Error polling typing users:', error);
    }
}

function updateTypingIndicator() {
    const indicator = document.getElementById('typingIndicator');
    const typingUsersList = Object.keys(typingUsers).filter(user => user !== currentUsername);
    
    if (typingUsersList.length > 0) {
        const userText = typingUsersList.length === 1 
            ? `${typingUsersList[0]} is typing` 
            : `${typingUsersList.slice(0, -1).join(', ')} and ${typingUsersList[typingUsersList.length - 1]} are typing`;
        
        document.getElementById('typingUsers').textContent = userText;
        indicator.classList.remove('hidden');
    } else {
        indicator.classList.add('hidden');
    }
}

function updateCharCount() {
    const input = document.getElementById('chatInput');
    const counter = document.getElementById('chatCharCount');
    if (input && counter) {
        counter.textContent = `${input.value.length}/500`;
    }
}

const reactionEmojis = ['😊', '😂', '❤️', '😍', '🔥', '👍', '😎', '🙏', '😢', '😡', '👏', '🎉'];

function showMessageReactions(msgId) {
    const reactionsDiv = document.createElement('div');
    reactionsDiv.className = 'message-reactions-picker';
    reactionsDiv.innerHTML = `
        <div class="reactions-grid">
            ${reactionEmojis.map(emoji => `
                <button class="reaction-emoji-btn" onclick="toggleReaction('${msgId}', '${emoji}'); this.closest('.message-reactions-picker').remove();">
                    ${emoji}
                </button>
            `).join('')}
        </div>
    `;
    
    const messageEl = document.querySelector(`[data-id="${msgId}"]`);
    if (messageEl) {
        const existing = messageEl.querySelector('.message-reactions-picker');
        if (existing) existing.remove();
        messageEl.appendChild(reactionsDiv);
    }
}

async function toggleReaction(msgId, emoji) {
    try {
        const response = await fetch(`/api/chat/${msgId}/reaction`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authToken}`
            },
            body: JSON.stringify({ emoji })
        });
        
        if (response.ok) {
            // Don't manually update - let Socket.IO handle it
            // The backend will broadcast the reaction change to all clients
        } else {
            const error = await response.json();
            showToast(error.error || 'Failed to add reaction', 'error');
        }
    } catch (error) {
        console.error('Error adding reaction:', error);
        showToast('Failed to add reaction', 'error');
    }
}

// Update character count on input
function setupChatEventListeners() {
    const chatInput = document.getElementById('chatInput');
    if (chatInput) {
        chatInput.addEventListener('input', updateCharCount);
        updateCharCount();
    }
}

document.addEventListener('DOMContentLoaded', () => {
    setupChatEventListeners();
});

// Announcement functions
function showAnnouncementForm() {
    document.getElementById('newAnnouncementForm').classList.remove('hidden');
    document.getElementById('announcementTitle').focus();
    document.getElementById('announcementTitle').value = '';
    document.getElementById('announcementContent').value = '';
    document.getElementById('announcementDate').value = new Date().toISOString().split('T')[0];
    document.getElementById('newAnnouncementForm').removeAttribute('data-edit-id');
}

function cancelAnnouncement() {
    document.getElementById('newAnnouncementForm').classList.add('hidden');
}

async function saveAnnouncement() {
    const title = document.getElementById('announcementTitle').value.trim();
    const content = document.getElementById('announcementContent').value.trim();
    const date = document.getElementById('announcementDate').value;
    const editId = document.getElementById('newAnnouncementForm').getAttribute('data-edit-id');
    
    if (!title || !content || !date) {
        showToast('Please fill in all fields', 'error');
        return;
    }
    
    try {
        const response = await fetch('/api/announcements', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authToken}`
            },
            body: JSON.stringify({ id: editId, title, content, date })
        });
        
        const data = await response.json();
        
        if (data.success) {
            showToast(editId ? 'Announcement updated!' : 'Announcement created!', 'success', 2000);
            cancelAnnouncement();
            loadAnnouncements();
        } else {
            showToast(data.error || 'Failed to save announcement', 'error');
        }
    } catch (err) {
        showToast('Failed to save announcement: ' + err.message, 'error');
    }
}

function editAnnouncement(id, title, content, date) {
    document.getElementById('announcementTitle').value = title;
    document.getElementById('announcementContent').value = content;
    document.getElementById('announcementDate').value = date;
    document.getElementById('newAnnouncementForm').classList.remove('hidden');
    document.getElementById('newAnnouncementForm').setAttribute('data-edit-id', id);
    document.getElementById('announcementTitle').focus();
}

async function deleteAnnouncement(id) {
    if (!confirm('Delete this announcement?')) return;
    
    try {
        const response = await fetch(`/api/announcements/${id}`, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${authToken}` }
        });
        
        const data = await response.json();
        
        if (data.success) {
            showToast('Announcement deleted', 'success', 2000);
            loadAnnouncements();
        } else {
            showToast(data.error || 'Failed to delete announcement', 'error');
        }
    } catch (err) {
        showToast('Failed to delete announcement', 'error');
    }
}

// Event functions
function showEventForm() {
    document.getElementById('newEventForm').classList.remove('hidden');
    document.getElementById('eventTitle').focus();
}

function editEvent(id, title, date, description) {
    document.getElementById('eventTitle').value = title;
    document.getElementById('eventDate').value = date;
    document.getElementById('eventDescription').value = description;
    document.getElementById('eventEditId').value = id;
    document.getElementById('newEventForm').classList.remove('hidden');
    document.getElementById('eventTitle').focus();
}

function cancelEvent() {
    document.getElementById('newEventForm').classList.add('hidden');
    document.getElementById('eventTitle').value = '';
    document.getElementById('eventDate').value = '';
    document.getElementById('eventDescription').value = '';
    document.getElementById('eventEditId').value = '';
}

async function saveEvent() {
    const title = document.getElementById('eventTitle').value.trim();
    const date = document.getElementById('eventDate').value;
    const description = document.getElementById('eventDescription').value.trim();
    const editId = document.getElementById('eventEditId').value;
    
    if (!title || !date || !description) {
        showToast('Please fill in all fields', 'error');
        return;
    }
    
    try {
        const response = await fetch('/api/events', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authToken}`
            },
            body: JSON.stringify({ id: editId || null, title, date, description })
        });
        
        const data = await response.json();
        
        if (data.success) {
            showToast(editId ? 'Activity updated!' : 'Activity created!', 'success', 2000);
            cancelEvent();
            loadActivities();
        } else {
            showToast(data.error || 'Failed to save activity', 'error');
        }
    } catch (err) {
        showToast('Failed to save activity', 'error');
    }
}

function deleteEventPrompt(id) {
    showConfirmationDialog('Delete Activity', 'Are you sure you want to delete this activity? This action cannot be undone.', () => deleteEvent(id));
}

async function deleteEvent(id) {
    try {
        const response = await fetch(`/api/events/${id}`, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${authToken}` }
        });
        
        const data = await response.json();
        
        if (data.success) {
            showToast('Activity deleted', 'success', 2000);
            loadActivities();
        } else {
            showToast(data.error || 'Failed to delete activity', 'error');
        }
    } catch (err) {
        showToast('Failed to delete activity', 'error');
    }
}

// Task functions
function showTaskForm() {
    document.getElementById('newTaskForm').classList.remove('hidden');
    document.getElementById('taskTitle').focus();
    document.getElementById('taskTitle').value = '';
    document.getElementById('taskAssignee').value = '';
    document.getElementById('taskEditId').value = '';
    document.getElementById('taskPriority').value = 'medium';
}

function editTask(id, title, assignee, priority) {
    document.getElementById('taskTitle').value = title;
    document.getElementById('taskAssignee').value = assignee;
    document.getElementById('taskPriority').value = priority;
    document.getElementById('taskEditId').value = id;
    document.getElementById('newTaskForm').classList.remove('hidden');
    document.getElementById('taskTitle').focus();
}

function cancelTask() {
    document.getElementById('newTaskForm').classList.add('hidden');
    document.getElementById('taskTitle').value = '';
    document.getElementById('taskAssignee').value = '';
    document.getElementById('taskEditId').value = '';
}

async function saveTask() {
    const title = document.getElementById('taskTitle').value.trim();
    const assignee = document.getElementById('taskAssignee').value.trim();
    const priority = document.getElementById('taskPriority').value;
    const editId = document.getElementById('taskEditId').value;
    
    if (!title || !assignee) {
        showToast('Please fill in all fields', 'error');
        return;
    }
    
    try {
        const response = await fetch('/api/tasks', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authToken}`
            },
            body: JSON.stringify({ id: editId || null, title, assignee, priority, status: 'pending' })
        });
        
        const data = await response.json();
        
        if (data.success) {
            showToast(editId ? 'Task updated!' : 'Task created!', 'success', 2000);
            cancelTask();
            loadTasks();
        } else {
            showToast(data.error || 'Failed to save task', 'error');
        }
    } catch (err) {
        showToast('Failed to save task', 'error');
    }
}

function deleteTaskPrompt(id) {
    showConfirmationDialog('Delete Task', 'Are you sure you want to delete this task? This action cannot be undone.', () => deleteTask(id));
}

async function deleteTask(id) {
    try {
        const response = await fetch(`/api/tasks/${id}`, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${authToken}` }
        });
        
        const data = await response.json();
        
        if (data.success) {
            showToast('Task deleted', 'success', 2000);
            loadTasks();
        } else {
            showToast(data.error || 'Failed to delete task', 'error');
        }
    } catch (err) {
        showToast('Failed to delete task', 'error');
    }
}

// Post functions
function initPostForm() {
    const newPostBtn = document.getElementById('newPostBtn');
    if (newPostBtn) {
        newPostBtn.addEventListener('click', () => {
            const form = document.getElementById('newPostForm');
            form.classList.toggle('hidden');
        });
    }
}

initPostForm();

function editPost(id, content) {
    document.getElementById('postContent').value = content;
    document.getElementById('postEditId').value = id;
    document.getElementById('postSubmitBtn').textContent = 'Update';
    document.getElementById('newPostForm').classList.remove('hidden');
    document.getElementById('postContent').focus();
}

async function createPost() {
    const content = document.getElementById('postContent').value.trim();
    const caption = document.getElementById('postCaption') ? document.getElementById('postCaption').value.trim() : '';
    const imageInput = document.getElementById('postImage');
    const file = imageInput && imageInput.files && imageInput.files[0] ? imageInput.files[0] : null;
    const editId = document.getElementById('postEditId').value;
    if (!content && !file && !caption) {
        showToast('Please write something or attach an image', 'error');
        return;
    }
    
    try {
        const url = editId ? `/api/posts/${editId}` : '/api/posts';
        const method = editId ? 'PUT' : 'POST';
        // If there's an image file, read it as data URL
        let imageData = null;
        if (file) {
            imageData = await new Promise((resolve, reject) => {
                const reader = new FileReader();
                reader.onload = () => resolve(reader.result);
                reader.onerror = reject;
                reader.readAsDataURL(file);
            });
        }

        const body = { content, caption };
        if (imageData) body.imageData = imageData;

        const response = await fetch(url, {
            method: method,
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authToken}`
            },
            body: JSON.stringify(body)
        });
        
        const data = await response.json();
        
        if (data.success) {
            showToast(editId ? 'Post updated!' : 'Post shared!', 'success', 2000);
            document.getElementById('postContent').value = '';
            if (document.getElementById('postCaption')) document.getElementById('postCaption').value = '';
            if (document.getElementById('postImage')) document.getElementById('postImage').value = '';
            document.getElementById('postEditId').value = '';
            document.getElementById('postSubmitBtn').textContent = 'Post';
            document.getElementById('newPostForm').classList.add('hidden');
            // If server returned the created post, prepend it so image shows immediately
            if (!editId && data.post) {
                prependPost(data.post);
            } else {
                loadPosts();
            }
        } else {
            showToast(data.error || 'Failed to save post', 'error');
        }
    } catch (err) {
        showToast('Failed to save post', 'error');
    }
}

function cancelPost() {
    document.getElementById('newPostForm').classList.add('hidden');
    document.getElementById('postContent').value = '';
    document.getElementById('postEditId').value = '';
    document.getElementById('postSubmitBtn').textContent = 'Post';
}

// Render a single post as HTML (used to prepend newly created posts)
function renderPostHtml(post) {
    const canDelete = post.author === currentUsername || ['system-admin', 'admin', 'moderator'].includes(userChurch);
    const canEdit = post.author === currentUsername;
    const deleteBtn = canDelete ? `<button class="btn-delete" onclick="deletePostPrompt('${post.id}')">Delete</button>` : '';
    const editBtn = canEdit ? `<button class="btn-edit" onclick="editPost('${post.id}', '${escapeHtml(post.content || '')}')">Edit</button>` : '';
    const userLikedIt = post.likedBy && post.likedBy.includes(`${currentUsername}:like`);
    const userLovedIt = post.lovedBy && post.lovedBy.includes(`${currentUsername}:love`);
    const actionButtons = editBtn || deleteBtn ? `<div class="card-actions">${editBtn}${deleteBtn}</div>` : '';

    const imageHtml = post.image ? `<div class="post-image"><img src="${post.image}" alt="post image"></div>` : '';
    const captionHtml = post.caption ? `<div class="post-caption">${escapeHtml(post.caption)}</div>` : '';
    const comments = (post.comments || []).slice(-5);
    const commentsHtml = comments.length ? `<div class="post-comments">${comments.map(c => `<div class="comment-item"><strong>${escapeHtml(c.author)}</strong> ${escapeHtml(c.text)} <span class="comment-time">${new Date(c.createdAt).toLocaleString()}</span></div>`).join('')}</div>` : '';

    return `
        <div class="post-item" id="post_${post.id}" data-id="${post.id}">
            <div class="post-header">
                <div>
                    <span class="post-author">${escapeHtml(post.author)}</span>
                    <span class="post-role">${escapeHtml(getRoleLabel(post.role))}</span>
                </div>
                <div class="post-date">${new Date(post.createdAt).toLocaleDateString()}</div>
            </div>
            <div class="post-content">${escapeHtml(post.content || '')}</div>
            ${imageHtml}
            ${captionHtml}
            <div class="post-reactions">
                <button class="post-reaction-btn ${userLikedIt ? 'active' : ''}" onclick="likePost('${post.id}', 'like')">👍 ${post.likes || 0}</button>
                <button class="post-reaction-btn ${userLovedIt ? 'active' : ''}" onclick="likePost('${post.id}', 'love')">❤️ ${post.loves || 0}</button>
                ${actionButtons}
            </div>
            ${commentsHtml}
            <div class="post-add-comment">
                <input type="text" id="commentInput_${post.id}" placeholder="Write a comment..." />
                <button class="btn btn-sm" onclick="addComment('${post.id}')">Comment</button>
            </div>
        </div>
    `;
}

function prependPost(post) {
    const list = document.getElementById('postsList');
    if (!list) return;
    const html = renderPostHtml(post);
    // If postsList currently shows empty-state, replace it
    if (list.querySelector('.empty-state')) {
        list.innerHTML = html;
    } else {
        list.innerHTML = html + list.innerHTML;
    }
}

function toggleMobileMenu() {
    const mobileNav = document.getElementById('mobileNav');
    mobileNav.classList.toggle('active');
}

function logoutMobile() {
    logout();
}

function logout() {
    localStorage.removeItem('authToken');
    localStorage.removeItem('username');
    localStorage.removeItem('userChurch');
    window.location.href = 'landing.html';
}

// Emoji Picker Functions
function toggleEmojiPicker() {
    const picker = document.getElementById('emojiPicker');
    picker.classList.toggle('hidden');
}

document.addEventListener('click', (e) => {
    const picker = document.getElementById('emojiPicker');
    if (picker && !picker.contains(e.target) && !e.target.classList.contains('emoji-picker-btn')) {
        picker.classList.add('hidden');
    }
});

document.querySelectorAll('.emoji-grid')[0]?.childNodes.forEach((child, idx) => {
    if (child.nodeType === Node.TEXT_NODE) {
        const emojis = child.textContent.trim().split(' ').filter(e => e.length > 0);
        emojis.forEach(emoji => {
            const span = document.createElement('span');
            span.textContent = emoji;
            span.onclick = () => {
                const input = document.getElementById('chatInput');
                input.value += emoji;
                updateCharCount();
                document.getElementById('emojiPicker').classList.add('hidden');
            };
            document.querySelector('.emoji-grid').appendChild(span);
        });
        child.remove();
    }
});

// Mobile Quick Links / Quick Access slide-over panels
function ensureBackdrop() {
    let b = document.getElementById('panelBackdrop');
    if (!b) {
        b = document.createElement('div');
        b.id = 'panelBackdrop';
        b.className = 'panel-backdrop';
        b.addEventListener('click', closePanels);
        document.body.appendChild(b);
    }
    return b;
}

function closePanels() {
    document.querySelectorAll('.sidebar, .right-sidebar').forEach(el => el.classList.remove('panel-open'));
    const b = document.getElementById('panelBackdrop');
    if (b) b.classList.remove('visible');
    document.body.classList.remove('no-scroll');
    document.body.classList.remove('panel-open-active');
}

function toggleQuickLinks() {
    const sidebar = document.querySelector('.sidebar');
    if (!sidebar) return;
    const opened = sidebar.classList.toggle('panel-open');
    const b = ensureBackdrop();
    if (opened) {
        b.classList.add('visible');
        document.body.classList.add('no-scroll');
        document.body.classList.add('panel-open-active');
    } else {
        b.classList.remove('visible');
        document.body.classList.remove('no-scroll');
        document.body.classList.remove('panel-open-active');
    }
}

function toggleQuickAccess() {
    const panel = document.querySelector('.right-sidebar');
    if (!panel) return;
    const opened = panel.classList.toggle('panel-open');
    const b = ensureBackdrop();
    if (opened) {
        b.classList.add('visible');
        document.body.classList.add('no-scroll');
        document.body.classList.add('panel-open-active');
    } else {
        b.classList.remove('visible');
        document.body.classList.remove('no-scroll');
        document.body.classList.remove('panel-open-active');
    }
}

// Close panels on Escape
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closePanels();
});
