const express = require('express');
const cors = require('cors');

const app = express();

app.use(cors());
app.use(express.json());

// Simple health check
app.get('/', (req, res) => {
    res.json({ message: 'API is working', status: 'OK' });
});

app.get('/api/health', (req, res) => {
    res.json({ message: 'Health check passed', timestamp: new Date().toISOString() });
});

module.exports = app;