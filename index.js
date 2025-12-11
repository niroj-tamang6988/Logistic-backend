const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();

// CORS middleware
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
    if (req.method === 'OPTIONS') return res.status(200).end();
    next();
});

app.use(express.json());

// Database connection
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT || 3306
});

// Auth middleware
const auth = (req, res, next) => {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ message: 'No token provided' });
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        res.status(401).json({ message: 'Invalid token' });
    }
};

// Health check
app.get('/', (req, res) => {
    res.json({ message: 'API is running' });
});

// Login
app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
        if (err) return res.status(500).json({ message: 'Server error' });
        if (results.length === 0) return res.status(400).json({ message: 'User not found' });
        
        const user = results[0];
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ message: 'Invalid password' });
        
        const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET);
        res.json({ token, user: { id: user.id, name: user.name, role: user.role } });
    });
});

// Get parcels
app.get('/api/parcels', auth, (req, res) => {
    let query = 'SELECT p.*, u.name as vendor_name, r.name as rider_name FROM parcels p LEFT JOIN users u ON p.vendor_id = u.id LEFT JOIN users r ON p.assigned_rider_id = r.id';
    let params = [];
    
    if (req.user.role === 'vendor') {
        query += ' WHERE p.vendor_id = ?';
        params = [req.user.id];
    }
    
    db.query(query, params, (err, results) => {
        if (err) {
            console.error('Parcels error:', err);
            return res.status(500).json({ message: 'Error fetching parcels' });
        }
        res.json(results);
    });
});

// Create parcel
app.post('/api/parcels', auth, (req, res) => {
    const { recipient_name, recipient_address, recipient_phone, cod_amount } = req.body;
    db.query('INSERT INTO parcels (vendor_id, recipient_name, address, recipient_phone, cod_amount, status) VALUES (?, ?, ?, ?, ?, ?)',
        [req.user.id, recipient_name, recipient_address, recipient_phone, cod_amount || 0, 'pending'], (err, result) => {
        if (err) {
            console.error('Create parcel error:', err);
            return res.status(500).json({ message: 'Error creating parcel' });
        }
        res.json({ message: 'Parcel placed successfully', id: result.insertId });
    });
});

// Get riders
app.get('/api/riders', auth, (req, res) => {
    db.query('SELECT id, name FROM users WHERE role = "rider" AND is_approved = 1', (err, results) => {
        if (err) return res.status(500).json({ message: 'Error fetching riders' });
        res.json(results);
    });
});

// Get stats
app.get('/api/stats', auth, (req, res) => {
    let query = 'SELECT status, COUNT(*) as count FROM parcels';
    let params = [];
    
    if (req.user.role === 'vendor') {
        query += ' WHERE vendor_id = ?';
        params = [req.user.id];
    }
    
    query += ' GROUP BY status';
    
    db.query(query, params, (err, results) => {
        if (err) return res.status(500).json({ message: 'Error fetching stats' });
        res.json(results);
    });
});

// Financial reports
app.get('/api/financial-report', auth, (req, res) => {
    let query = 'SELECT status, COUNT(*) as count, SUM(COALESCE(cod_amount, 0)) as total_cod FROM parcels';
    let params = [];
    
    if (req.user.role === 'vendor') {
        query += ' WHERE vendor_id = ?';
        params = [req.user.id];
    }
    
    query += ' GROUP BY status';
    
    db.query(query, params, (err, results) => {
        if (err) {
            console.error('Financial report error:', err);
            return res.status(500).json({ message: 'Error fetching financial report' });
        }
        res.json(results);
    });
});

// Daily financial reports
app.get('/api/financial-report-daily', auth, (req, res) => {
    let query = 'SELECT DATE(created_at) as date, status, COUNT(*) as count, SUM(COALESCE(cod_amount, 0)) as total_cod FROM parcels';
    let params = [];
    
    if (req.user.role === 'vendor') {
        query += ' WHERE vendor_id = ?';
        params = [req.user.id];
    }
    
    query += ' GROUP BY DATE(created_at), status ORDER BY date DESC';
    
    db.query(query, params, (err, results) => {
        if (err) {
            console.error('Daily financial report error:', err);
            return res.status(500).json({ message: 'Error fetching daily financial report' });
        }
        res.json(results);
    });
});

// Assign rider
app.put('/api/parcels/:id/assign', auth, (req, res) => {
    const { rider_id } = req.body;
    db.query('UPDATE parcels SET assigned_rider_id = ?, status = "assigned" WHERE id = ?',
        [rider_id, req.params.id], (err, result) => {
        if (err) return res.status(500).json({ message: 'Error assigning parcel' });
        res.json({ message: 'Parcel assigned successfully' });
    });
});

// Simplified endpoints for missing functionality
app.get('/api/users', auth, (req, res) => res.json([]));
app.get('/api/vendor-report', auth, (req, res) => res.json([]));
app.get('/api/rider-reports', auth, (req, res) => res.json([]));
app.get('/api/rider-daybook-details/:riderId', auth, (req, res) => res.json([]));

module.exports = app;