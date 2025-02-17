const express = require('express');
const multer = require('multer');
const sqlite3 = require('sqlite3');
const bcrypt = require('bcrypt');
const path = require('path');
const cors = require('cors');
const fs = require('fs').promises;

// Constants
const UPLOAD_DIR = 'uploads';
const MAX_UPLOAD_SIZE = 20 * 1024 * 1024; // 20 MB
const DB_FILE = 'cdn.db';

// Configure Express app
const app = express();
app.use(cors());
app.use(express.json());


// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, UPLOAD_DIR);
  },
  filename: (req, file, cb) => {
    cb(null, file.originalname);
  }
});

const upload = multer({
  storage: storage,
  limits: {
    fileSize: MAX_UPLOAD_SIZE
  },
  fileFilter: (req, file, cb) => {
    if (!file.originalname.endsWith('.bin')) {
      return cb(new Error('Only .bin files are allowed'));
    }
    cb(null, true);
  }
});

// Database setup
const db = new sqlite3.Database(DB_FILE, async (err) => {
  if (err) {
    console.error('Database connection error:', err);
    process.exit(1);
  }

  // Create tables
  const tables = [
    `CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL
    )`,
    `CREATE TABLE IF NOT EXISTS files (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      description TEXT,
      username TEXT NOT NULL
    )`,
    `CREATE TABLE IF NOT EXISTS stars (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      file_id INTEGER NOT NULL,
      username TEXT NOT NULL,
      UNIQUE(file_id, username),
      FOREIGN KEY(file_id) REFERENCES files(id),
      FOREIGN KEY(username) REFERENCES users(username)
    )`
  ];

  for (const table of tables) {
    await dbRun(table);
  }
});

// Database helper functions
function dbRun(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function(err) {
      if (err) reject(err);
      else resolve(this);
    });
  });
}

function dbGet(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });
}

function dbAll(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });
}

// Route handlers
app.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    
    await dbRun('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword]);
    res.status(201).send();
  } catch (err) {
    if (err.message.includes('UNIQUE constraint failed')) {
      res.status(400).json({ error: 'Username already exists' });
    } else {
      res.status(500).json({ error: err.message });
    }
  }
});

app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await dbGet('SELECT password FROM users WHERE username = ?', [username]);
    
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }
    
    res.status(200).send();
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/upload', upload.single('file'), async (req, res) => {
  try {
    const { username, password, description } = req.body;
    const file = req.file;

    if (!file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    // Verify credentials
    const user = await dbGet('SELECT password FROM users WHERE username = ?', [username]);
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    // Check for duplicate filename
    const existingFile = await dbGet('SELECT COUNT(*) as count FROM files WHERE name = ?', [file.filename]);
    if (existingFile.count > 0) {
      return res.status(409).json({ error: 'A file with this name already exists' });
    }

    await dbRun('INSERT INTO files (name, description, username) VALUES (?, ?, ?)', 
      [file.filename, description, username]);

    const fileUrl = `http://${req.get('host')}/files/${file.filename}`;
    res.status(200).json({ url: fileUrl });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/search', async (req, res) => {
  try {
    const { term, username } = req.query;
    
    if (!term) {
      return res.status(400).json({ error: 'Search term is required' });
    }

    const query = `
      SELECT f.name, f.description, f.username,
             (SELECT COUNT(*) FROM stars WHERE file_id = f.id) as star_count,
             (SELECT COUNT(*) FROM stars WHERE file_id = f.id AND username = ?) as is_starred
      FROM files f
      WHERE f.name LIKE ? OR f.description LIKE ?
    `;

    const results = await dbAll(query, [username, `%${term}%`, `%${term}%`]);
    
    const filesWithUrls = results.map(file => ({
      ...file,
      url: `http://${req.get('host')}/files/${file.name}`,
      isStarred: file.is_starred > 0
    }));

    res.json(filesWithUrls);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/user-files', async (req, res) => {
  try {
    const { username, currentUser } = req.query;

    if (!username) {
      return res.status(400).json({ error: 'Username is required' });
    }

    const query = `
      SELECT f.name, f.description,
             (SELECT COUNT(*) FROM stars WHERE file_id = f.id) as star_count,
             (SELECT COUNT(*) FROM stars WHERE file_id = f.id AND username = ?) as is_starred
      FROM files f
      WHERE f.username = ?
    `;

    const files = await dbAll(query, [currentUser, username]);
    
    const filesWithUrls = files.map(file => ({
      ...file,
      url: `http://${req.get('host')}/files/${file.name}`,
      isStarred: file.is_starred > 0
    }));

    res.json(filesWithUrls);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/remove', async (req, res) => {
  try {
    const { username, password, filename } = req.body;

    // Verify credentials
    const user = await dbGet('SELECT password FROM users WHERE username = ?', [username]);
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    // Check file ownership
    const file = await dbGet('SELECT COUNT(*) as count FROM files WHERE username = ? AND name = ?', 
      [username, filename]);
    
    if (file.count === 0) {
      return res.status(403).json({ error: 'File not found or you don\'t have permission to remove it' });
    }

    // Remove from database
    await dbRun('DELETE FROM files WHERE username = ? AND name = ?', [username, filename]);

    // Remove file from filesystem
    try {
      await fs.unlink(path.join(UPLOAD_DIR, filename));
    } catch (err) {
      console.error('Error removing file from filesystem:', err);
    }

    res.status(200).send();
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/star', async (req, res) => {
  try {
    const { username, filename, action } = req.body;

    if (action !== 'star' && action !== 'unstar') {
      return res.status(400).json({ error: 'Invalid action' });
    }

    const file = await dbGet('SELECT id FROM files WHERE name = ?', [filename]);
    if (!file) {
      return res.status(404).json({ error: 'File not found' });
    }

    if (action === 'star') {
      await dbRun('INSERT OR IGNORE INTO stars (file_id, username) VALUES (?, ?)', 
        [file.id, username]);
    } else {
      await dbRun('DELETE FROM stars WHERE file_id = ? AND username = ?', 
        [file.id, username]);
    }

    res.status(200).send();
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/starred-files', async (req, res) => {
  try {
    const { username } = req.query;

    if (!username) {
      return res.status(400).json({ error: 'Username is required' });
    }

    const query = `
      SELECT f.name, f.description, f.username,
             (SELECT COUNT(*) FROM stars WHERE file_id = f.id) as star_count
      FROM files f
      JOIN stars s ON f.id = s.file_id
      WHERE s.username = ?
    `;

    const files = await dbAll(query, [username]);
    
    const filesWithUrls = files.map(file => ({
      ...file,
      url: `http://${req.get('host')}/files/${file.name}`,
      isStarred: true
    }));

    res.json(filesWithUrls);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/reset', async (req, res) => {
  try {
    const { username, current_password, new_password } = req.body;

    // Verify current password
    const user = await dbGet('SELECT password FROM users WHERE username = ?', [username]);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    if (!(await bcrypt.compare(current_password, user.password))) {
      return res.status(401).json({ error: 'Incorrect current password' });
    }

    // Hash and update new password
    const hashedNewPassword = await bcrypt.hash(new_password, 10);
    await dbRun('UPDATE users SET password = ? WHERE username = ?', [hashedNewPassword, username]);

    res.status(200).send();
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Serve static files
app.use('/files', express.static(UPLOAD_DIR));

// Create uploads directory if it doesn't exist
fs.mkdir(UPLOAD_DIR, { recursive: true }).catch(console.error);

// Start server
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
