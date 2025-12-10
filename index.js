const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();

app.use(cors({
    origin: ['http://localhost:3000', 'https://logistic-green-six.vercel.app'],
    credentials: true
}));
app.use(express.json());

// Health check routes
app.get('/', (req, res) => {
    res.json({ message: 'Delivery Management System API', status: 'OK' });
});

app.get('/api/health', (req, res) => {
    res.json({ message: 'API is healthy', timestamp: new Date().toISOString() });
});

// Debug endpoint to check database
app.get('/api/debug/users', (req, res) => {
    db.query('SELECT id, name, email, role FROM users', (err, results) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json({ users: results, count: results.length });
    });
});

// Debug endpoint to check specific user
app.get('/api/debug/user/:email', (req, res) => {
    const email = req.params.email;
    db.query('SELECT id, name, email, role FROM users WHERE email = ?', [email], (err, results) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json({ found: results.length > 0, user: results[0] || null });
    });
});

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

// Register route
app.post('/api/register', async (req, res) => {
    try {
        const { name, email, password, role } = req.body;
        console.log('Register attempt:', { name, email, role });
        
        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);
        const isApproved = role === 'admin' ? true : false;
        
        db.query('INSERT INTO users (name, email, password, role, is_approved) VALUES (?, ?, ?, ?, ?)', 
            [name, email, hashedPassword, role, isApproved], (err, result) => {
            if (err) {
                console.error('Register error:', err);
                if (err.code === 'ER_DUP_ENTRY') {
                    return res.status(400).json({ message: 'Email already exists' });
                }
                return res.status(500).json({ message: 'Server error' });
            }
            const message = role === 'admin' ? 'Admin registered successfully' : 'Registration successful. Please wait for admin approval to login.';
            res.json({ message });
        });
    } catch (error) {
        console.error('Register error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Login route
app.post('/api/login', (req, res) => {
    try {
        const { email, password } = req.body;
        console.log('Login attempt:', { email, passwordLength: password?.length });
        
        db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
            if (err) {
                console.error('Login query error:', err);
                return res.status(500).json({ message: 'Server error' });
            }
            
            console.log('Query results:', { count: results.length, email });
            
            if (results.length === 0) {
                return res.status(400).json({ 
                    message: 'User not found',
                    debug: { searchedEmail: email, emailLength: email?.length }
                });
            }
            
            const user = results[0];
            console.log('User found:', { id: user.id, email: user.email, role: user.role });
            
            const isMatch = await bcrypt.compare(password, user.password);
            console.log('Password match:', isMatch);
            
            if (!isMatch) return res.status(400).json({ message: 'Invalid password' });
            
            if (!user.is_approved && user.role !== 'admin') {
                return res.status(403).json({ message: 'Account pending admin approval' });
            }
            
            const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET);
            res.json({ token, user: { id: user.id, name: user.name, role: user.role } });
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Get parcels
app.get('/api/parcels', auth, (req, res) => {
    try {
        let query = 'SELECT p.*, u.name as vendor_name, r.name as rider_name FROM parcels p LEFT JOIN users u ON p.vendor_id = u.id LEFT JOIN users r ON p.assigned_rider_id = r.id';
        let params = [];
        
        if (req.user.role === 'vendor') {
            query += ' WHERE p.vendor_id = ?';
            params = [req.user.id];
        } else if (req.user.role === 'rider') {
            query += ' WHERE p.assigned_rider_id = ?';
            params = [req.user.id];
        }
        
        db.query(query, params, (err, results) => {
            if (err) {
                console.error('Fetch parcels error:', err);
                return res.status(500).json({ message: 'Error fetching parcels' });
            }
            res.json(results);
        });
    } catch (error) {
        console.error('Fetch parcels error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// User management routes for admin
app.get('/api/users', auth, (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ message: 'Access denied' });
        }
        
        db.query('SELECT id, name, email, role, is_approved, created_at FROM users ORDER BY created_at DESC', (err, results) => {
            if (err) {
                console.error('Fetch users error:', err);
                return res.status(500).json({ message: 'Error fetching users' });
            }
            res.json(results);
        });
    } catch (error) {
        console.error('Fetch users error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.put('/api/users/:id/approve', auth, (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ message: 'Access denied' });
        }
        
        db.query('UPDATE users SET is_approved = 1 WHERE id = ? AND role IN ("vendor", "rider")', [req.params.id], (err, result) => {
            if (err) {
                console.error('Approve user error:', err);
                return res.status(500).json({ message: 'Error approving user: ' + err.message });
            }
            if (result.affectedRows === 0) {
                return res.status(404).json({ message: 'User not found or not eligible for approval' });
            }
            res.json({ message: 'User approved successfully' });
        });
    } catch (error) {
        console.error('Approve user error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.delete('/api/users/:id', auth, (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ message: 'Access denied' });
        }
        
        db.query('DELETE FROM users WHERE id = ? AND role IN ("vendor", "rider")', [req.params.id], (err, result) => {
            if (err) {
                console.error('Delete user error:', err);
                return res.status(500).json({ message: 'Error deleting user' });
            }
            res.json({ message: 'User deleted successfully' });
        });
    } catch (error) {
        console.error('Delete user error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

module.exports = app;