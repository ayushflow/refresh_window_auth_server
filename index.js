const express = require('express');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const axios = require('axios');
const crypto = require('crypto'); // To generate secret key

const app = express();
app.use(cors()); // Allow all CORS headers
app.use(express.json());

const SECRET_KEY = crypto.randomBytes(64).toString('hex'); // Generate a secure random key
// const TOKEN_EXPIRY = 1800; // 30 minutes
const TOKEN_EXPIRY = 120; // 2 minutes for testing
// const REFRESH_WINDOW_START = 300; // 5 minutes before token expiry
const REFRESH_WINDOW_START = 60; // 1 minute before token expiry

let users = {
    user1: { password: 'password123' }
};

// Login endpoint
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    if (users[username] && users[username].password === password) {
        const issueTime = Math.floor(Date.now() / 1000); // Current time in seconds
        const accessToken = jwt.sign({ username, issueTime }, SECRET_KEY, { expiresIn: TOKEN_EXPIRY });
        return res.json({
            accessToken,
            expiresAtInSeconds: issueTime + TOKEN_EXPIRY,
            refreshWindowInSeconds: REFRESH_WINDOW_START,
        });
    }
    res.status(401).json({ message: 'Invalid credentials' });
});

// Refresh endpoint
app.post('/refresh', (req, res) => {
    const token = req.headers['authorization'];
    if (!token) {
        return res.status(401).json({ message: 'No token provided' });
    }

    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        const currentTime = Math.floor(Date.now() / 1000); // Current time in seconds
        const issueTime = decoded.issueTime;
        const expiryTime = issueTime + TOKEN_EXPIRY;

        if (currentTime >= expiryTime) {
            return res.status(403).json({ message: 'Token has expired' });
        }

        const refreshStartTime = expiryTime - REFRESH_WINDOW_START;
        if (currentTime >= refreshStartTime) {
            // Generate new token
            const newAccessToken = jwt.sign({ username: decoded.username, issueTime: currentTime }, SECRET_KEY, { expiresIn: TOKEN_EXPIRY });
            return res.json({
                accessToken: newAccessToken,
                expiresAtInSeconds: expiryTime,
                refreshWindowInSeconds: REFRESH_WINDOW_START,
            });
        } else {
            // Return existing token
            return res.json({
                accessToken: token,
                expiresAtInSeconds: expiryTime,
                refreshWindowInSeconds: REFRESH_WINDOW_START,
            });
        }
    } catch (err) {
        return res.status(403).json({ message: 'Invalid token' });
    }
});

// Posts endpoint (requires valid token)
app.get('/posts', async (req, res) => {
    const token = req.headers['authorization'];
    if (!token) {
        return res.status(401).json({ message: 'No token provided' });
    }

    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        const currentTime = Math.floor(Date.now() / 1000); // Current time in seconds
        const issueTime = decoded.issueTime;
        const expiryTime = issueTime + TOKEN_EXPIRY;

        if (currentTime >= expiryTime) {
            return res.status(403).json({ message: 'Token has expired' });
        }

        // Fetch posts from the external API
        const postsResponse = await axios.get('https://jsonplaceholder.typicode.com/posts');
        return res.json(postsResponse.data);
    } catch (err) {
        return res.status(403).json({ message: 'Invalid token' });
    }
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});