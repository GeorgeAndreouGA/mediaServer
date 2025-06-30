require('dotenv').config({ path: './passwordHash.env' });
const express = require('express');
const basicAuth = require('express-basic-auth');
const bcrypt = require('bcrypt');
const fs = require('fs');
const path = require('path');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = 3000;
const MUSIC_DIR = '/mnt/disk_0/MyFatNas/Music/Armin van buuren/Asot/my mix'; //Path to load the music
const PUBLISHED_JSON = path.join(__dirname, 'published.json');

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use('/html', express.static(path.join(__dirname, 'html')));
app.use('/music', express.static(MUSIC_DIR));
app.use('/published.json', express.static(PUBLISHED_JSON));

// Main route
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'html/index.html'));
});

// Rate limiter: 5 requests per 5 minutes for /admin
const adminLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 5,
  message: 'Too many login attempts. Please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

// Custom middleware to check basic auth manually and reset rate limiter on success
app.use('/admin', adminLimiter, (req, res, next) => {
  // Parse basic auth header manually
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Basic ')) {
    // No auth header, respond with 401 to trigger browser prompt
    res.set('WWW-Authenticate', 'Basic realm="EchoRiftSounds Admin Panel"');
    return res.status(401).send('Authentication required.');
  }

  // Decode base64 credentials
  const base64Credentials = authHeader.split(' ')[1];
  const credentials = Buffer.from(base64Credentials, 'base64').toString('utf8');
  const [username, password] = credentials.split(':');

  if (
    !process.env.ADMIN_USERNAME ||
    !process.env.ADMIN_PASSWORD_HASH
  ) {
    console.error('ADMIN_USERNAME or ADMIN_PASSWORD_HASH not set in environment variables');
    return res.status(500).send('Server configuration error');
  }

  const validUsername = basicAuth.safeCompare(username, process.env.ADMIN_USERNAME);
  const validPassword = bcrypt.compareSync(password, process.env.ADMIN_PASSWORD_HASH);

  if (validUsername && validPassword) {
    // Successful login! Reset rate limit for this IP
    adminLimiter.resetKey(req.ip);
    return next();
  }

  // Failed auth — respond with 401 and challenge
  res.set('WWW-Authenticate', 'Basic realm="EchoRiftSounds Admin Panel"');
  return res.status(401).send('Invalid credentials');
});

// Admin routes
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'html/admin.html'));
});

app.get('/admin/files', (req, res) => {
  fs.readdir(MUSIC_DIR, (err, files) => {
    if (err) {
      console.error('Error reading music directory:', err);
      return res.status(500).json({ error: 'Unable to read music directory' });
    }
    const audioFiles = files.filter(f => f.match(/\.(mp3|wav|flac)$/i));
    res.json(audioFiles);
  });
});

// Update published list (Publish form)
app.post('/admin/publish', (req, res) => {
  let selectedFiles = req.body.files || [];
  if (!Array.isArray(selectedFiles)) selectedFiles = [selectedFiles];

  fs.writeFile(PUBLISHED_JSON, JSON.stringify(selectedFiles, null, 2), err => {
    if (err) {
      console.error('Error updating published list:', err);
      return res.status(500).send('Failed to update published list');
    }
    console.log('Published list updated:', selectedFiles.length, 'tracks');
    res.redirect('/admin');
  });
});

// Remove selected files from published list (Delete form)
app.post('/admin/delete', (req, res) => {
  let filesToDelete = req.body.filesToDelete || [];
  if (!Array.isArray(filesToDelete)) filesToDelete = [filesToDelete];

  fs.readFile(PUBLISHED_JSON, 'utf8', (err, data) => {
    if (err) {
      console.error('Error reading published list:', err);
      return res.status(500).send('Failed to read published list');
    }

    let publishedList;
    try {
      publishedList = JSON.parse(data);
    } catch (parseErr) {
      console.error('Error parsing published list:', parseErr);
      publishedList = [];
    }

    const updatedList = publishedList.filter(file => !filesToDelete.includes(file));

    fs.writeFile(PUBLISHED_JSON, JSON.stringify(updatedList, null, 2), err => {
      if (err) {
        console.error('Error updating published list:', err);
        return res.status(500).send('Failed to update published list');
      }
      console.log('Removed tracks:', filesToDelete);
      res.redirect('/admin');
    });
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`🎵 EchoRiftSounds server running at http://localhost:${PORT}`);
  console.log(`🔐 Admin panel: http://localhost:${PORT}/admin`);

  if (!process.env.ADMIN_USERNAME || !process.env.ADMIN_PASSWORD_HASH) {
    console.warn('⚠️  WARNING: Admin credentials not found in environment variables!');
    console.warn('   Make sure to create a .env file with ADMIN_USERNAME and ADMIN_PASSWORD_HASH');
  } else {
    console.log(`👤 Admin user: ${process.env.ADMIN_USERNAME}`);
  }
});

