const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

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

// Database connection - Using Supabase Session Pooler for IPv4 compatibility
const db = new Pool({
    connectionString: process.env.DATABASE_URL || 'postgresql://postgres:NirojTamang@aws-0-ap-southeast-1.pooler.supabase.com:6543/postgres?pgbouncer=true',
    ssl: { rejectUnauthorized: false }
});

// Auth middleware
const auth = (req, res, next) => {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ message: 'No token provided' });
    try {
        const decoded = jwt.verify(token, 'logistic_delivery_management_system_secret_key_2024');
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

// Register
app.post('/api/register', async (req, res) => {
    try {
        const { name, email, password, role } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        const isApproved = role === 'admin' ? true : false;
        
        const result = await db.query('INSERT INTO users (name, email, password, role, is_approved) VALUES ($1, $2, $3, $4, $5) RETURNING id', 
            [name, email, hashedPassword, role, isApproved]);
        
        const message = role === 'admin' ? 'Admin registered successfully' : 'Registration successful. Please wait for admin approval to login.';
        res.json({ message });
    } catch (error) {
        console.error('Register error:', error.message);
        res.status(400).json({ message: 'Register error: ' + error.message });
    }
});

// Login
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({ message: 'Email and password required' });
        }
        
        console.log('Attempting login for:', email);
        const results = await db.query('SELECT * FROM users WHERE email = $1', [email]);
        console.log('Query result:', results.rows.length);
        
        if (results.rows.length === 0) {
            return res.status(400).json({ message: 'User not found' });
        }
        
        const user = results.rows[0];
        const isMatch = await bcrypt.compare(password, user.password);
        
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid password' });
        }
        
        if (!user.is_approved && user.role !== 'admin') {
            return res.status(403).json({ message: 'Account pending admin approval' });
        }
        
        const token = jwt.sign({ id: user.id, role: user.role }, 'logistic_delivery_management_system_secret_key_2024');
        res.json({ token, user: { id: user.id, name: user.name, role: user.role } });
    } catch (error) {
        console.error('Login error:', error.message);
        res.status(500).json({ message: 'Login error: ' + error.message });
    }
});

// Get parcels
app.get('/api/parcels', auth, async (req, res) => {
    try {
        let query = 'SELECT p.*, u.name as vendor_name, r.name as rider_name FROM parcels p LEFT JOIN users u ON p.vendor_id = u.id LEFT JOIN users r ON p.assigned_rider_id = r.id';
        let params = [];
        
        if (req.user.role === 'vendor') {
            query += ' WHERE p.vendor_id = $1';
            params = [req.user.id];
        }
        
        const results = await db.query(query, params);
        res.json(results.rows);
    } catch (error) {
        console.error('Parcels error:', error);
        res.status(500).json({ message: 'Error fetching parcels' });
    }
});

// Create parcel
app.post('/api/parcels', auth, async (req, res) => {
    try {
        const { recipient_name, recipient_address, recipient_phone, cod_amount } = req.body;
        const result = await db.query('INSERT INTO parcels (vendor_id, recipient_name, address, recipient_phone, cod_amount, status) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id',
            [req.user.id, recipient_name, recipient_address, recipient_phone, cod_amount || 0, 'pending']);
        
        res.json({ message: 'Parcel placed successfully', id: result.rows[0].id });
    } catch (error) {
        console.error('Create parcel error:', error);
        res.status(500).json({ message: 'Error creating parcel' });
    }
});

// Get riders
app.get('/api/riders', auth, async (req, res) => {
    try {
        const results = await db.query('SELECT id, name FROM users WHERE role = $1 AND is_approved = $2', ['rider', true]);
        res.json(results.rows);
    } catch (error) {
        res.status(500).json({ message: 'Error fetching riders' });
    }
});

// Assign rider
app.put('/api/parcels/:id/assign', auth, async (req, res) => {
    try {
        const { rider_id } = req.body;
        const status = rider_id ? 'assigned' : 'pending';
        await db.query('UPDATE parcels SET assigned_rider_id = $1, status = $2 WHERE id = $3',
            [rider_id || null, status, req.params.id]);
        res.json({ message: 'Parcel updated successfully' });
    } catch (error) {
        res.status(500).json({ message: 'Error assigning parcel' });
    }
});

// Update delivery status
app.put('/api/parcels/:id/delivery', auth, async (req, res) => {
    try {
        const { status, delivery_comment } = req.body;
        await db.query('UPDATE parcels SET status = $1, rider_comment = $2 WHERE id = $3',
            [status, delivery_comment || null, req.params.id]);
        res.json({ message: 'Delivery status updated successfully' });
    } catch (error) {
        res.status(500).json({ message: 'Error updating delivery status' });
    }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

module.exports = app;