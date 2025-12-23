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

// Database connection
const db = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
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
    res.json({ message: 'API WORKING - DEPLOYMENT SUCCESS 2025' });
});

// Test endpoint
app.get('/test', (req, res) => {
    res.json({ message: 'Test endpoint working', timestamp: new Date().toISOString() });
});

// Debug endpoint
app.get('/debug', async (req, res) => {
    try {
        const parcels = await db.query('SELECT COUNT(*) as total FROM parcels');
        const users = await db.query('SELECT COUNT(*) as total FROM users');
        const statuses = await db.query('SELECT status, COUNT(*) as count FROM parcels GROUP BY status');
        const sampleDates = await db.query('SELECT id, created_at, DATE(created_at) as date_only FROM parcels ORDER BY created_at DESC LIMIT 5');
        
        res.json({
            total_parcels: parcels.rows[0].total,
            total_users: users.rows[0].total,
            parcel_statuses: statuses.rows,
            sample_dates: sampleDates.rows,
            current_server_time: new Date().toISOString(),
            current_server_date: new Date().toDateString()
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Register
app.post('/api/register', async (req, res) => {
    try {
        const { name, email, password, role } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        const isApproved = role === 'admin';
        
        await db.query('INSERT INTO users (name, email, password, role, is_approved) VALUES ($1, $2, $3, $4, $5)', 
            [name, email, hashedPassword, role, isApproved]);
        
        const message = role === 'admin' ? 'Admin registered successfully' : 'Registration successful. Please wait for admin approval to login.';
        res.json({ message });
    } catch (error) {
        console.error('Register error:', error.message);
        res.status(400).json({ message: 'Registration failed' });
    }
});

// Login
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({ message: 'Email and password required' });
        }
        
        const results = await db.query('SELECT * FROM users WHERE email = $1', [email]);
        
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
        
        const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET);
        res.json({ token, user: { id: user.id, name: user.name, role: user.role } });
    } catch (error) {
        console.error('Login error:', error.message);
        res.status(500).json({ message: 'Login failed' });
    }
});

// Get parcels
app.get('/api/parcels', auth, async (req, res) => {
    try {
        const { search } = req.query;
        let query = 'SELECT p.*, u.name as vendor_name, r.name as rider_name FROM parcels p LEFT JOIN users u ON p.vendor_id = u.id LEFT JOIN users r ON p.assigned_rider_id = r.id';
        let params = [];
        let whereConditions = [];
        
        // Role-based filtering
        if (req.user.role === 'vendor') {
            whereConditions.push('p.vendor_id = $' + (params.length + 1));
            params.push(req.user.id);
        } else if (req.user.role === 'rider') {
            whereConditions.push('p.assigned_rider_id = $' + (params.length + 1));
            params.push(req.user.id);
        }
        
        // Search functionality
        if (search) {
            whereConditions.push('(p.recipient_name ILIKE $' + (params.length + 1) + ' OR p.address ILIKE $' + (params.length + 2) + ' OR p.recipient_phone ILIKE $' + (params.length + 3) + ')');
            params.push(`%${search}%`, `%${search}%`, `%${search}%`);
        }
        
        if (whereConditions.length > 0) {
            query += ' WHERE ' + whereConditions.join(' AND ');
        }
        
        query += ' ORDER BY p.created_at DESC';
        
        const results = await db.query(query, params);
        
        // Group parcels by Nepal date (UTC+5:45)
        const groupedParcels = {};
        results.rows.forEach(parcel => {
            // Convert UTC to Nepal time (UTC+5:45)
            const utcDate = new Date(parcel.created_at);
            const nepalTime = new Date(utcDate.getTime() + (5 * 60 + 45) * 60 * 1000);
            const dateKey = nepalTime.toISOString().split('T')[0]; // YYYY-MM-DD format
            
            if (!groupedParcels[dateKey]) {
                groupedParcels[dateKey] = [];
            }
            groupedParcels[dateKey].push(parcel);
        });
        
        res.json(groupedParcels);
    } catch (error) {
        console.error('Parcels error:', error.message);
        res.status(500).json({ message: 'Error fetching parcels' });
    }
});

// Create parcel
app.post('/api/parcels', auth, async (req, res) => {
    try {
        const { recipient_name, recipient_address, recipient_phone, cod_amount } = req.body;
        
        // Create timestamp in Nepal timezone
        const now = new Date();
        const nepalTime = new Date(now.getTime() + (5 * 60 + 45) * 60 * 1000);
        
        const result = await db.query('INSERT INTO parcels (vendor_id, recipient_name, address, recipient_phone, cod_amount, status, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id',
            [req.user.id, recipient_name, recipient_address, recipient_phone, cod_amount || 0, 'pending', nepalTime]);
        
        res.json({ message: 'Parcel placed successfully', id: result.rows[0].id });
    } catch (error) {
        console.error('Create parcel error:', error.message);
        res.status(500).json({ message: 'Error creating parcel' });
    }
});

// Get riders
app.get('/api/riders', auth, async (req, res) => {
    try {
        const results = await db.query('SELECT id, name FROM users WHERE role = $1 AND is_approved = $2', ['rider', true]);
        res.json(results.rows);
    } catch (error) {
        console.error('Riders error:', error.message);
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
        console.error('Assign error:', error.message);
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
        console.error('Delivery error:', error.message);
        res.status(500).json({ message: 'Error updating delivery status' });
    }
});

// Fix existing parcel dates (admin only)
app.put('/api/fix-dates', auth, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ message: 'Admin access required' });
        }
        
        // Update all existing parcels created before today to Nepal timezone
        const result = await db.query(`
            UPDATE parcels 
            SET created_at = created_at + INTERVAL '5 hours 45 minutes'
            WHERE created_at < (NOW() AT TIME ZONE 'UTC') - INTERVAL '1 hour'
            AND created_at < '2025-12-23 00:00:00'
        `);
        
        res.json({ 
            message: 'Old dates updated to Nepal timezone', 
            updated_count: result.rowCount 
        });
    } catch (error) {
        console.error('Fix dates error:', error.message);
        res.status(500).json({ message: 'Error fixing dates' });
    }
});

// Get stats
app.get('/api/stats', auth, async (req, res) => {
    try {
        let query = 'SELECT status, COUNT(*) as count FROM parcels';
        let params = [];
        
        if (req.user.role === 'vendor') {
            query += ' WHERE vendor_id = $1';
            params = [req.user.id];
        } else if (req.user.role === 'rider') {
            query += ' WHERE assigned_rider_id = $1';
            params = [req.user.id];
        }
        // Admin sees all parcels - no WHERE clause
        
        query += ' GROUP BY status';
        
        const results = await db.query(query, params);
        
        // Return array format that frontend expects
        const statsArray = results.rows.map(row => ({
            status: row.status,
            count: parseInt(row.count)
        }));
        
        res.json(statsArray);
    } catch (error) {
        console.error('Stats error:', error.message);
        res.status(500).json({ message: 'Error fetching stats' });
    }
});

// Get users
app.get('/api/users', auth, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ message: 'Access denied' });
        }
        
        const results = await db.query('SELECT id, name, email, role, is_approved, created_at FROM users ORDER BY created_at DESC');
        res.json(results.rows);
    } catch (error) {
        console.error('Users error:', error.message);
        res.status(500).json({ message: 'Error fetching users' });
    }
});

// Approve user
app.put('/api/users/:id/approve', auth, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ message: 'Access denied' });
        }
        
        await db.query('UPDATE users SET is_approved = true WHERE id = $1', [req.params.id]);
        res.json({ message: 'User approved successfully' });
    } catch (error) {
        console.error('Approve error:', error.message);
        res.status(500).json({ message: 'Error approving user' });
    }
});

// Delete user
app.delete('/api/users/:id', auth, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ message: 'Access denied' });
        }
        
        await db.query('DELETE FROM users WHERE id = $1', [req.params.id]);
        res.json({ message: 'User deleted successfully' });
    } catch (error) {
        console.error('Delete error:', error.message);
        res.status(500).json({ message: 'Error deleting user' });
    }
});

// Vendor report
app.get('/api/vendor-report', auth, async (req, res) => {
    try {
        const results = await db.query(`
            SELECT 
                u.name as vendor_name,
                DATE(p.created_at) as date,
                COUNT(p.id) as total_parcels,
                SUM(p.cod_amount) as total_cod
            FROM parcels p 
            JOIN users u ON p.vendor_id = u.id 
            GROUP BY u.name, DATE(p.created_at)
            ORDER BY DATE(p.created_at) DESC
        `);
        res.json(results.rows);
    } catch (error) {
        console.error('Vendor report error:', error.message);
        res.status(500).json({ message: 'Error fetching vendor report' });
    }
});

// Rider reports
app.get('/api/rider-reports', auth, async (req, res) => {
    try {
        const results = await db.query(`
            SELECT DISTINCT
                u.id,
                u.name as rider_name,
                u.email,
                '' as citizenship_no,
                '' as bike_no,
                '' as license_no,
                COUNT(p.id) as total_parcels_delivered,
                0 as total_km,
                1 as working_days
            FROM users u 
            INNER JOIN parcels p ON u.id = p.assigned_rider_id
            WHERE u.role = 'rider' AND u.is_approved = true
            GROUP BY u.id, u.name, u.email
        `);
        res.json(results.rows);
    } catch (error) {
        console.error('Rider reports error:', error.message);
        res.status(500).json({ message: 'Error fetching rider reports' });
    }
});

// Financial report
app.get('/api/financial-report', auth, async (req, res) => {
    try {
        let query = 'SELECT status, COUNT(*) as count, SUM(cod_amount) as total_cod FROM parcels';
        let params = [];
        
        if (req.user.role === 'vendor') {
            query += ' WHERE vendor_id = $1';
            params = [req.user.id];
        }
        
        query += ' GROUP BY status';
        
        const results = await db.query(query, params);
        res.json(results.rows);
    } catch (error) {
        console.error('Financial report error:', error.message);
        res.status(500).json({ message: 'Error fetching financial report' });
    }
});

// Daily financial report
app.get('/api/financial-report-daily', auth, async (req, res) => {
    try {
        let query = 'SELECT DATE(created_at) as date, status, COUNT(*) as count, SUM(cod_amount) as total_cod FROM parcels';
        let params = [];
        
        if (req.user.role === 'vendor') {
            query += ' WHERE vendor_id = $1';
            params = [req.user.id];
        }
        
        query += ' GROUP BY DATE(created_at), status ORDER BY DATE(created_at) DESC';
        
        const results = await db.query(query, params);
        res.json(results.rows);
    } catch (error) {
        console.error('Daily financial report error:', error.message);
        res.status(500).json({ message: 'Error fetching daily financial report' });
    }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

module.exports = app;