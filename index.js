const express = require('express');
const sqlite3 = require('sqlite3');
const { open } = require('sqlite');
const bcrypt = require('bcrypt');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Configure file uploads with 80MB limit
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 80 * 1024 * 1024 },
});

// Initialize database
let db;
(async () => {
  db = await open({
    filename: './chattg.db',
    driver: sqlite3.Database,
  });

  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password TEXT,
      display_name TEXT,
      bio TEXT,
      is_admin BOOLEAN DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      content TEXT,
      user_id INTEGER,
      file_data TEXT,
      file_name TEXT,
      file_type TEXT,
      file_size INTEGER,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(user_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      user_id INTEGER,
      expires_at DATETIME,
      FOREIGN KEY(user_id) REFERENCES users(id)
    );
  `);

  // Create admin user if none exists
  const adminExists = await db.get("SELECT id FROM users WHERE is_admin = 1");
  if (!adminExists) {
    const hashedPassword = await bcrypt.hash("admin123", 10);
    await db.run(
      "INSERT INTO users (username, password, display_name, is_admin) VALUES (?, ?, ?, ?)",
      "admin",
      hashedPassword,
      "Admin",
      1
    );
  }
})();

// HTML Templates
const loginPage = `
<!DOCTYPE html>
<html>
<head>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Login - Chat App</title>
  <style>
    body { 
      margin: 0; 
      font-family: Arial, sans-serif; 
      background: #f5f5f5; 
      display: flex;
      justify-content: center;
      align-items: center;
      height: 100vh;
    }
    .auth-container {
      width: 100%;
      max-width: 400px;
      padding: 20px;
      background: white;
      border-radius: 8px;
      box-shadow: 0 0 10px rgba(0,0,0,0.1);
    }
    .auth-header {
      text-align: center;
      margin-bottom: 20px;
    }
    .auth-header h1 {
      color: #0088cc;
      margin: 0;
    }
    .auth-form input {
      width: 100%;
      padding: 12px;
      margin: 8px 0;
      border: 1px solid #ddd;
      border-radius: 4px;
      box-sizing: border-box;
    }
    .auth-form button {
      width: 100%;
      padding: 12px;
      background: #0088cc;
      color: white;
      border: none;
      border-radius: 4px;
      cursor: pointer;
      margin-top: 10px;
    }
    .auth-form button:hover {
      background: #0077bb;
    }
    .auth-footer {
      text-align: center;
      margin-top: 15px;
    }
    .auth-footer a {
      color: #0088cc;
      text-decoration: none;
    }
    .error {
      color: #ff3333;
      text-align: center;
      margin-top: 10px;
    }
  </style>
</head>
<body>
  <div class="auth-container">
    <div class="auth-header">
      <h1>Chat App</h1>
    </div>
    <form id="login-form" class="auth-form">
      <input type="text" id="username" placeholder="Username" required>
      <input type="password" id="password" placeholder="Password" required>
      <button type="submit">Login</button>
      <div id="error" class="error"></div>
    </form>
    <div class="auth-footer">
      <p>Don't have an account? <a href="/register">Register</a></p>
    </div>
  </div>
  <script>
    document.getElementById('login-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const username = document.getElementById('username').value;
      const password = document.getElementById('password').value;
      
      try {
        const response = await fetch('/api/login', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ username, password })
        });
        
        const data = await response.json();
        
        if (response.ok) {
          localStorage.setItem('sessionId', data.sessionId);
          window.location.href = '/';
        } else {
          document.getElementById('error').textContent = data.error || 'Login failed';
        }
      } catch (error) {
        document.getElementById('error').textContent = 'Network error';
      }
    });
  </script>
</body>
</html>
`;

const registerPage = `
<!DOCTYPE html>
<html>
<head>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Register - Chat App</title>
  <style>
    body { 
      margin: 0; 
      font-family: Arial, sans-serif; 
      background: #f5f5f5; 
      display: flex;
      justify-content: center;
      align-items: center;
      height: 100vh;
    }
    .auth-container {
      width: 100%;
      max-width: 400px;
      padding: 20px;
      background: white;
      border-radius: 8px;
      box-shadow: 0 0 10px rgba(0,0,0,0.1);
    }
    .auth-header {
      text-align: center;
      margin-bottom: 20px;
    }
    .auth-header h1 {
      color: #0088cc;
      margin: 0;
    }
    .auth-form input {
      width: 100%;
      padding: 12px;
      margin: 8px 0;
      border: 1px solid #ddd;
      border-radius: 4px;
      box-sizing: border-box;
    }
    .auth-form button {
      width: 100%;
      padding: 12px;
      background: #0088cc;
      color: white;
      border: none;
      border-radius: 4px;
      cursor: pointer;
      margin-top: 10px;
    }
    .auth-form button:hover {
      background: #0077bb;
    }
    .auth-footer {
      text-align: center;
      margin-top: 15px;
    }
    .auth-footer a {
      color: #0088cc;
      text-decoration: none;
    }
    .error {
      color: #ff3333;
      text-align: center;
      margin-top: 10px;
    }
  </style>
</head>
<body>
  <div class="auth-container">
    <div class="auth-header">
      <h1>Chat App</h1>
    </div>
    <form id="register-form" class="auth-form">
      <input type="text" id="username" placeholder="Username" required>
      <input type="password" id="password" placeholder="Password" required>
      <input type="text" id="display-name" placeholder="Display Name (optional)">
      <button type="submit">Register</button>
      <div id="error" class="error"></div>
    </form>
    <div class="auth-footer">
      <p>Already have an account? <a href="/login">Login</a></p>
    </div>
  </div>
  <script>
    document.getElementById('register-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const username = document.getElementById('username').value;
      const password = document.getElementById('password').value;
      const displayName = document.getElementById('display-name').value || username;
      
      try {
        const response = await fetch('/api/register', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ 
            username, 
            password, 
            display_name: displayName 
          })
        });
        
        const data = await response.json();
        
        if (response.ok) {
          window.location.href = '/login';
        } else {
          document.getElementById('error').textContent = data.error || 'Registration failed';
        }
      } catch (error) {
        document.getElementById('error').textContent = 'Network error';
      }
    });
  </script>
</body>
</html>
`;

const chatPage = (sessionId) => `
<!DOCTYPE html>
<html>
<head>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Chat App</title>
  <style>
    :root {
      --primary-color: #0088cc;
      --secondary-color: #e5f5ff;
      --message-sent: #dcf8c6;
      --message-received: #ffffff;
      --text-color: #333333;
      --light-text: #666666;
      --border-color: #dddddd;
    }
    
    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }
    
    body {
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
      background-color: #f5f5f5;
      color: var(--text-color);
      height: 100vh;
      display: flex;
      flex-direction: column;
    }
    
    .header {
      background-color: var(--primary-color);
      color: white;
      padding: 15px 20px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      box-shadow: 0 2px 5px rgba(0,0,0,0.1);
    }
    
    .header h1 {
      font-size: 1.5rem;
      margin: 0;
    }
    
    .user-info {
      display: flex;
      align-items: center;
      gap: 15px;
    }
    
    .user-info span {
      font-weight: bold;
    }
    
    .logout-btn {
      background: none;
      border: 1px solid white;
      color: white;
      padding: 5px 10px;
      border-radius: 4px;
      cursor: pointer;
      font-size: 0.9rem;
    }
    
    .logout-btn:hover {
      background: rgba(255,255,255,0.1);
    }
    
    .chat-container {
      flex: 1;
      display: flex;
      flex-direction: column;
      max-width: 1200px;
      margin: 0 auto;
      width: 100%;
      height: calc(100vh - 120px);
      background-color: white;
      box-shadow: 0 0 10px rgba(0,0,0,0.05);
    }
    
    .messages {
      flex: 1;
      overflow-y: auto;
      padding: 20px;
      background-color: var(--secondary-color);
      display: flex;
      flex-direction: column;
      gap: 15px;
    }
    
    .message {
      max-width: 70%;
      padding: 12px 15px;
      border-radius: 18px;
      position: relative;
      word-wrap: break-word;
    }
    
    .message.sent {
      align-self: flex-end;
      background-color: var(--message-sent);
      border-bottom-right-radius: 4px;
    }
    
    .message.received {
      align-self: flex-start;
      background-color: var(--message-received);
      border-bottom-left-radius: 4px;
      box-shadow: 0 1px 1px rgba(0,0,0,0.1);
    }
    
    .message-header {
      display: flex;
      justify-content: space-between;
      margin-bottom: 5px;
      font-size: 0.8rem;
      color: var(--light-text);
    }
    
    .message-sender {
      font-weight: bold;
      margin-right: 10px;
    }
    
    .message-time {
      opacity: 0.8;
    }
    
    .message-content {
      margin-bottom: 5px;
    }
    
    .message-file {
      margin-top: 10px;
    }
    
    .message-file img {
      max-width: 100%;
      max-height: 300px;
      border-radius: 8px;
      display: block;
    }
    
    .message-file a {
      color: var(--primary-color);
      text-decoration: none;
      display: inline-block;
      padding: 5px;
      border-radius: 4px;
      background-color: rgba(0,0,0,0.05);
    }
    
    .message-file a:hover {
      text-decoration: underline;
    }
    
    .input-area {
      display: flex;
      padding: 15px;
      background-color: white;
      border-top: 1px solid var(--border-color);
      gap: 10px;
    }
    
    .file-input {
      display: none;
    }
    
    .file-btn {
      background: none;
      border: none;
      font-size: 1.5rem;
      cursor: pointer;
      color: var(--primary-color);
      padding: 5px 10px;
    }
    
    .message-input {
      flex: 1;
      padding: 12px 15px;
      border: 1px solid var(--border-color);
      border-radius: 24px;
      outline: none;
      font-size: 1rem;
    }
    
    .message-input:focus {
      border-color: var(--primary-color);
    }
    
    .send-btn {
      background-color: var(--primary-color);
      color: white;
      border: none;
      border-radius: 24px;
      padding: 0 20px;
      cursor: pointer;
      font-size: 1rem;
    }
    
    .send-btn:hover {
      background-color: #0077bb;
    }
    
    .file-info {
      padding: 0 15px 10px;
      font-size: 0.9rem;
      color: var(--light-text);
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    
    .file-info button {
      background: none;
      border: none;
      color: #ff4444;
      cursor: pointer;
    }
    
    @media (max-width: 768px) {
      .chat-container {
        height: calc(100vh - 60px);
      }
      
      .message {
        max-width: 85%;
      }
    }
  </style>
</head>
<body>
  <div class="header">
    <h1>Chat App</h1>
    <div class="user-info">
      <span id="username-display"></span>
      <button class="logout-btn" id="logout-btn">Logout</button>
    </div>
  </div>
  
  <div class="chat-container">
    <div class="messages" id="messages"></div>
    
    <div id="file-info" class="file-info" style="display: none;">
      <span id="file-name"></span>
      <button id="remove-file">✕</button>
    </div>
    
    <div class="input-area">
      <input type="file" id="file-input" class="file-input">
      <button class="file-btn" id="attach-btn">📎</button>
      <input type="text" id="message-input" class="message-input" placeholder="Type a message...">
      <button class="send-btn" id="send-btn">Send</button>
    </div>
  </div>

  <script>
    const sessionId = '${sessionId}';
    if (!sessionId) {
      window.location.href = '/login';
    }
    
    // DOM elements
    const messagesEl = document.getElementById('messages');
    const messageInput = document.getElementById('message-input');
    const sendBtn = document.getElementById('send-btn');
    const attachBtn = document.getElementById('attach-btn');
    const fileInput = document.getElementById('file-input');
    const usernameDisplay = document.getElementById('username-display');
    const logoutBtn = document.getElementById('logout-btn');
    const fileInfoEl = document.getElementById('file-info');
    const fileNameEl = document.getElementById('file-name');
    const removeFileBtn = document.getElementById('remove-file');
    
    let currentUser = null;
    let currentFile = null;
    
    // Initialize
    fetchUser();
    loadMessages();
    setupEventListeners();
    
    // Scroll to bottom of messages
    function scrollToBottom() {
      messagesEl.scrollTop = messagesEl.scrollHeight;
    }
    
    // Format date/time
    function formatDateTime(dateString) {
      const date = new Date(dateString);
      return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    }
    
    // Format file size
    function formatFileSize(bytes) {
      if (bytes < 1024) return bytes + ' bytes';
      else if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
      else return (bytes / 1048576).toFixed(1) + ' MB';
    }
    
    // Get current user
    async function fetchUser() {
      try {
        const response = await fetch('/api/user', {
          headers: { 'Authorization': sessionId }
        });
        
        if (response.ok) {
          currentUser = await response.json();
          usernameDisplay.textContent = currentUser.display_name || currentUser.username;
        } else {
          window.location.href = '/login';
        }
      } catch (error) {
        console.error('Error fetching user:', error);
      }
    }
    
    // Load messages
    async function loadMessages() {
      try {
        const response = await fetch('/api/messages', {
          headers: { 'Authorization': sessionId }
        });
        
        if (response.ok) {
          const messages = await response.json();
          messagesEl.innerHTML = '';
          
          messages.forEach(msg => {
            addMessage(msg, msg.user_id === currentUser.id);
          });
          
          scrollToBottom();
        }
      } catch (error) {
        console.error('Error loading messages:', error);
      }
    }
    
    // Add message to UI
    function addMessage(msg, isSent) {
      const messageDiv = document.createElement('div');
      messageDiv.className = `message ${isSent ? 'sent' : 'received'}`;
      
      let fileContent = '';
      if (msg.file_data) {
        if (msg.file_type.startsWith('image/')) {
          fileContent = \`
            <div class="message-file">
              <img src="data:\${msg.file_type};base64,\${msg.file_data}" alt="\${msg.file_name}">
            </div>
          \`;
        } else {
          fileContent = \`
            <div class="message-file">
              <a href="data:\${msg.file_type};base64,\${msg.file_data}" download="\${msg.file_name}">
                Download \${msg.file_name} (\${formatFileSize(msg.file_size)})
              </a>
            </div>
          \`;
        }
      }
      
      messageDiv.innerHTML = \`
        <div class="message-header">
          <span class="message-sender">\${msg.display_name || msg.username}</span>
          <span class="message-time">\${formatDateTime(msg.created_at)}</span>
        </div>
        <div class="message-content">\${msg.content || ''}</div>
        \${fileContent}
      \`;
      
      messagesEl.appendChild(messageDiv);
      scrollToBottom();
    }
    
    // Send message
    async function sendMessage() {
      const content = messageInput.value.trim();
      
      if (!content && !currentFile) {
        return;
      }
      
      try {
        const response = await fetch('/api/message', {
          method: 'POST',
          headers: {
            'Authorization': sessionId,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            content,
            file_data: currentFile?.file_data,
            file_name: currentFile?.file_name,
            file_type: currentFile?.file_type,
            file_size: currentFile?.file_size
          })
        });
        
        if (response.ok) {
          messageInput.value = '';
          clearFile();
          loadMessages();
        }
      } catch (error) {
        console.error('Error sending message:', error);
      }
    }
    
    // Handle file upload
    function handleFileUpload(event) {
      const file = event.target.files[0];
      if (!file) return;
      
      if (file.size > 80 * 1024 * 1024) {
        alert('File is too large. Maximum size is 80MB.');
        return;
      }
      
      const reader = new FileReader();
      reader.onload = function(e) {
        const fileData = e.target.result.split(',')[1];
        currentFile = {
          file_data: fileData,
          file_name: file.name,
          file_type: file.type,
          file_size: file.size
        };
        
        fileNameEl.textContent = \`\${file.name} (\${formatFileSize(file.size)})\`;
        fileInfoEl.style.display = 'flex';
      };
      reader.readAsDataURL(file);
    }
    
    // Clear selected file
    function clearFile() {
      currentFile = null;
      fileInput.value = '';
      fileInfoEl.style.display = 'none';
    }
    
    // Setup event listeners
    function setupEventListeners() {
      sendBtn.addEventListener('click', sendMessage);
      messageInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
          sendMessage();
        }
      });
      attachBtn.addEventListener('click', () => fileInput.click());
      fileInput.addEventListener('change', handleFileUpload);
      logoutBtn.addEventListener('click', logout);
      removeFileBtn.addEventListener('click', clearFile);
    }
    
    // Logout
    async function logout() {
      try {
        await fetch('/api/logout', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ sessionId })
        });
        
        localStorage.removeItem('sessionId');
        window.location.href = '/login';
      } catch (error) {
        console.error('Error logging out:', error);
      }
    }
  </script>
</body>
</html>
`;

// Routes and API endpoints (same as before)
app.get('/', async (req, res) => {
  const sessionId = req.headers.authorization || req.query.sessionId;
  if (!sessionId) return res.redirect('/login');
  
  const session = await db.get("SELECT * FROM sessions WHERE id = ? AND expires_at > datetime('now')", sessionId);
  if (!session) return res.redirect('/login');
  
  res.send(chatPage(sessionId));
});

app.get('/login', (req, res) => res.send(loginPage));
app.get('/register', (req, res) => res.send(registerPage));

// API Routes (same as before)
app.post('/api/register', async (req, res) => {
  const { username, password, display_name } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await db.run(
      "INSERT INTO users (username, password, display_name) VALUES (?, ?, ?)",
      username,
      hashedPassword,
      display_name || username
    );
    res.json({ id: result.lastID, username });
  } catch (error) {
    res.status(400).json({ error: "Username already exists" });
  }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await db.get("SELECT * FROM users WHERE username = ?", username);
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: "Invalid credentials" });
  }
  
  const sessionId = uuidv4();
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
  
  await db.run(
    "INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)",
    sessionId,
    user.id,
    expiresAt.toISOString()
  );
  
  res.json({ 
    id: user.id, 
    username: user.username, 
    display_name: user.display_name, 
    sessionId 
  });
});

app.post('/api/logout', async (req, res) => {
  const { sessionId } = req.body;
  await db.run("DELETE FROM sessions WHERE id = ?", sessionId);
  res.json({ success: true });
});

app.get('/api/user', async (req, res) => {
  const sessionId = req.headers.authorization;
  if (!sessionId) return res.status(401).json({ error: "Unauthorized" });
  
  const session = await db.get(
    "SELECT * FROM sessions WHERE id = ? AND expires_at > datetime('now')", 
    sessionId
  );
  if (!session) return res.status(401).json({ error: "Session expired" });
  
  const user = await db.get(
    "SELECT id, username, display_name, bio FROM users WHERE id = ?", 
    session.user_id
  );
  
  res.json(user);
});

app.post('/api/upload', upload.single('file'), async (req, res) => {
  const sessionId = req.headers.authorization;
  if (!sessionId || !await db.get(
    "SELECT * FROM sessions WHERE id = ? AND expires_at > datetime('now')", 
    sessionId
  )) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  
  if (!req.file) return res.status(400).json({ error: "No file uploaded" });
  
  // Check file size (80MB limit)
  if (req.file.size > 80 * 1024 * 1024) {
    return res.status(413).json({ error: "File too large (max 80MB)" });
  }

  // Convert file to base64
  const fileData = req.file.buffer.toString('base64');
  
  res.json({ 
    file_data: fileData,
    file_name: req.file.originalname,
    file_type: req.file.mimetype,
    file_size: req.file.size
  });
});

app.post('/api/message', async (req, res) => {
  const sessionId = req.headers.authorization;
  const session = await db.get(
    "SELECT * FROM sessions WHERE id = ? AND expires_at > datetime('now')", 
    sessionId
  );
  if (!session) return res.status(401).json({ error: "Unauthorized" });
  
  const { content, file_data, file_name, file_type, file_size } = req.body;
  
  // Verify file size if present
  if (file_size && file_size > 80 * 1024 * 1024) {
    return res.status(413).json({ error: "File too large (max 80MB)" });
  }

  // Insert message into database
  const result = await db.run(
    "INSERT INTO messages (content, user_id, file_data, file_name, file_type, file_size) VALUES (?, ?, ?, ?, ?, ?)",
    content,
    session.user_id,
    file_data,
    file_name,
    file_type,
    file_size
  );
  
  // Get the full message with user details
  const message = await db.get(
    `SELECT m.*, u.username, u.display_name 
     FROM messages m 
     JOIN users u ON m.user_id = u.id 
     WHERE m.id = ?`,
    result.lastID
  );
  
  // Add data URL for file if present
  if (message.file_data) {
    message.file_url = `data:${message.file_type};base64,${message.file_data}`;
  }
  
  res.json(message);
});

app.get('/api/messages', async (req, res) => {
  const { before = '', limit = 50 } = req.query;
  const query = `SELECT m.*, u.username, u.display_name 
                FROM messages m 
                JOIN users u ON m.user_id = u.id
                ${before ? 'WHERE m.id < ?' : ''} 
                ORDER BY m.id DESC 
                LIMIT ?`;
  
  const params = before ? [before, limit] : [limit];
  const messages = await db.all(query, ...params);
  
  // Convert file_data to data URLs
  const processedMessages = messages.reverse().map(msg => {
    if (msg.file_data) {
      msg.file_url = `data:${msg.file_type};base64,${msg.file_data}`;
    }
    return msg;
  });
  
  res.json(processedMessages);
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Something broke!');
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
