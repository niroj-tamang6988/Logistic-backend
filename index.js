const express = require('express');
const { Pool } = require('pg');
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
const db = new Pool({
    connectionString: process.env.DATABASE_URL || 'postgresql://postgres:NirojTamang@db.mydygbnplhusevdmuloe.supabase.co:5432/postgres',
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
    res.json({ message: 'API is running' });
});

// Register
app.post('/api/register', async (req, res) => {
    try {
        const { name, email, password, role } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        const isApproved = role === 'admin' ? true : false;
        
        db.query('INSERT INTO users (name, email, password, role, is_approved) VALUES ($1, $2, $3, $4, $5) RETURNING id', 
            [name, email, hashedPassword, role, isApproved], (err, result) => {
            if (err) {
                console.error('Register error:', err);
                return res.status(400).json({ message: 'Email already exists' });
            }
            const message = role === 'admin' ? 'Admin registered successfully' : 'Registration successful. Please wait for admin approval to login.';
            res.json({ message });
        });
    } catch (error) {
        console.error('Register error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Login
app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    db.query('SELECT * FROM users WHERE email = $1', [email], async (err, results) => {
        if (err) return res.status(500).json({ message: 'Server error' });
        if (results.rows.length === 0) return res.status(400).json({ message: 'User not found' });
        
        const user = results.rows[0];
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ message: 'Invalid password' });
        
        if (!user.is_approved && user.role !== 'admin') {
            return res.status(403).json({ message: 'Account pending admin approval' });
        }
        
        const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET);
        res.json({ token, user: { id: user.id, name: user.name, role: user.role } });
    });
});

// Get parcels
app.get('/api/parcels', auth, (req, res) => {
    let query = 'SELECT p.*, u.name as vendor_name, r.name as rider_name FROM parcels p LEFT JOIN users u ON p.vendor_id = u.id LEFT JOIN users r ON p.assigned_rider_id = r.id';
    let params = [];
    
    if (req.user.role === 'vendor') {
        query += ' WHERE p.vendor_id = $1';
        params = [req.user.id];
    }
    
    db.query(query, params, (err, results) => {
        if (err) {
            console.error('Parcels error:', err);
            return res.status(500).json({ message: 'Error fetching parcels' });
        }
        res.json(results.rows);
    });
});

// Create parcel
app.post('/api/parcels', auth, (req, res) => {
    const { recipient_name, recipient_address, recipient_phone, cod_amount } = req.body;
    db.query('INSERT INTO parcels (vendor_id, recipient_name, address, recipient_phone, cod_amount, status) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id',
        [req.user.id, recipient_name, recipient_address, recipient_phone, cod_amount || 0, 'pending'], (err, result) => {
        if (err) {
            console.error('Create parcel error:', err);
            return res.status(500).json({ message: 'Error creating parcel' });
        }
        res.json({ message: 'Parcel placed successfully', id: result.rows[0].id });
    });
});

// Get riders
app.get('/api/riders', auth, (req, res) => {
    db.query('SELECT id, name FROM users WHERE role = $1 AND is_approved = $2', ['rider', true], (err, results) => {
        if (err) return res.status(500).json({ message: 'Error fetching riders' });
        res.json(results.rows);
    });
});

// Get stats
app.get('/api/stats', auth, (req, res) => {
    let query = 'SELECT status, COUNT(*) as count FROM parcels';
    let params = [];
    
    if (req.user.role === 'vendor') {
        query += ' WHERE vendor_id = $1';
        params = [req.user.id];
    }
    
    query += ' GROUP BY status';
    
    db.query(query, params, (err, results) => {
        if (err) return res.status(500).json({ message: 'Error fetching stats' });
        res.json(results.rows);
    });
});

// Financial reports
app.get('/api/financial-report', auth, (req, res) => {
    let query = 'SELECT status, COUNT(*) as count, SUM(COALESCE(cod_amount, 0)) as total_cod FROM parcels';
    let params = [];
    
    if (req.user.role === 'vendor') {
        query += ' WHERE vendor_id = $1';
        params = [req.user.id];
    }
    
    query += ' GROUP BY status';
    
    db.query(query, params, (err, results) => {
        if (err) {
            console.error('Financial report error:', err);
            return res.status(500).json({ message: 'Error fetching financial report' });
        }
        res.json(results.rows);
    });
});

// Daily financial reports
app.get('/api/financial-report-daily', auth, (req, res) => {
    let query = 'SELECT DATE(created_at) as date, status, COUNT(*) as count, SUM(COALESCE(cod_amount, 0)) as total_cod FROM parcels';
    let params = [];
    
    if (req.user.role === 'vendor') {
        query += ' WHERE vendor_id = $1';
        params = [req.user.id];
    }
    
    query += ' GROUP BY DATE(created_at), status ORDER BY date DESC';
    
    db.query(query, params, (err, results) => {
        if (err) {
            console.error('Daily financial report error:', err);
            return res.status(500).json({ message: 'Error fetching daily financial report' });
        }
        res.json(results.rows);
    });
});

// Assign rider
app.put('/api/parcels/:id/assign', auth, (req, res) => {
    const { rider_id } = req.body;
    const status = rider_id ? 'assigned' : 'pending';
    db.query('UPDATE parcels SET assigned_rider_id = $1, status = $2 WHERE id = $3',
        [rider_id || null, status, req.params.id], (err, result) => {
        if (err) return res.status(500).json({ message: 'Error assigning parcel' });
        res.json({ message: 'Parcel updated successfully' });
    });
});

// Staff activities
app.get('/api/staff-activities', auth, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Access denied' });
    }
    
    const query = `
        SELECT sa.*, u.name as staff_name 
        FROM staff_activities sa 
        LEFT JOIN users u ON sa.staff_id = u.id 
        ORDER BY sa.created_at DESC
    `;
    
    db.query(query, (err, results) => {
        if (err) {
            console.error('Fetch staff activities error:', err);
            return res.status(500).json({ message: 'Error fetching staff activities' });
        }
        res.json(results.rows);
    });
});

app.post('/api/staff-activities', auth, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Access denied' });
    }
    
    const { staff_id, activity_type, amount, reason, notes } = req.body;
    
    db.query('INSERT INTO staff_activities (staff_id, activity_type, amount, reason, notes) VALUES ($1, $2, $3, $4, $5) RETURNING id',
        [staff_id, activity_type, amount || 0, reason, notes || null], (err, result) => {
        if (err) {
            console.error('Create staff activity error:', err);
            return res.status(500).json({ message: 'Error creating staff activity' });
        }
        res.json({ message: 'Staff activity recorded successfully', id: result.rows[0].id });
    });
});

// Update delivery status
app.put('/api/parcels/:id/delivery', auth, (req, res) => {
    const { status, delivery_comment } = req.body;
    const validStatuses = ['delivered', 'not_delivered', 'assigned'];
    
    if (!validStatuses.includes(status)) {
        return res.status(400).json({ message: 'Invalid status' });
    }
    
    let query = 'UPDATE parcels SET status = $1, rider_comment = $2 WHERE id = $3';
    let params = [status, delivery_comment || null, req.params.id];
    
    db.query(query, params, (err, result) => {
        if (err) {
            console.error('Update delivery error:', err);
            return res.status(500).json({ message: 'Error updating delivery status' });
        }
        res.json({ message: 'Delivery status updated successfully' });
    });
});

// Get users (for admin)
app.get('/api/users', auth, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Access denied' });
    }
    
    db.query('SELECT id, name, email, role, is_approved FROM users ORDER BY created_at DESC', (err, results) => {
        if (err) {
            console.error('Fetch users error:', err);
            return res.status(500).json({ message: 'Error fetching users' });
        }
        res.json(results.rows);
    });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});s = [status, delivery_comment || null, req.params.id];
    
    if (req.user.role === 'rider') {
        query = 'UPDATE parcels SET status = $1, rider_comment = $2 WHERE id = $3 AND assigned_rider_id = $4';
        params = [status, delivery_comment || null, req.params.id, req.user.id];
    }
    
    db.query(query, params, (err, result) => {
        if (err) {
            console.error('Update delivery error:', err);
            return res.status(500).json({ message: 'Error updating delivery status' });
        }
        if (result.rowCount === 0) {
            return res.status(403).json({ message: 'Not authorized to update this parcel' });
        }
        res.json({ message: 'Delivery status updated successfully' });
    });
});

// Get users (admin only)
app.get('/api/users', auth, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Access denied' });
    }
    
    db.query('SELECT id, name, email, role, is_approved, created_at FROM users', (err, results) => {
        if (err) {
            console.error('Fetch users error:', err);
            return res.status(500).json({ message: 'Error fetching users' });
        }
        res.json(results.rows);
    });
});

// Vendor report
app.get('/api/vendor-report', auth, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Access denied' });
    }
    
    const query = `
        SELECT 
            CURRENT_DATE as date,
            u.name as vendor_name,
            COUNT(p.id) as total_parcels,
            SUM(COALESCE(p.cod_amount, 0)) as total_cod
        FROM parcels p
        JOIN users u ON p.vendor_id = u.id
        WHERE u.role = 'vendor'
        GROUP BY u.id, u.name
        ORDER BY u.name
    `;
    
    db.query(query, (err, results) => {
        if (err) {
            console.error('Vendor report error:', err);
            return res.status(500).json({ message: 'Error fetching vendor report' });
        }
        res.json(results.rows);
    });
});

// Rider reports
app.get('/api/rider-reports', auth, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Access denied' });
    }
    
    const query = `
        SELECT 
            u.id,
            u.name as rider_name,
            u.email,
            u.created_at,
            COALESCE(rp.citizenship_no, '') as citizenship_no,
            COALESCE(rp.bike_no, '') as bike_no,
            COALESCE(rp.license_no, '') as license_no,
            COALESCE(rp.photo_url, '') as photo_url,
            COALESCE(SUM(rd.total_km), 0) as total_km,
            COUNT(p.id) as total_parcels_delivered,
            COUNT(DISTINCT rd.date) as working_days
        FROM users u
        LEFT JOIN rider_profiles rp ON u.id = rp.rider_id
        LEFT JOIN rider_daybook rd ON u.id = rd.rider_id
        LEFT JOIN parcels p ON u.id = p.assigned_rider_id AND p.status = 'delivered'
        WHERE u.role = 'rider'
        GROUP BY u.id, u.name, u.email, u.created_at, rp.citizenship_no, rp.bike_no, rp.license_no, rp.photo_url
        ORDER BY u.name
    `;
    
    db.query(query, (err, results) => {
        if (err) {
            console.error('Fetch rider reports error:', err);
            return res.status(500).json({ message: 'Error fetching rider reports' });
        }
        res.json(results.rows);
    });
});

// Delete user
app.delete('/api/users/:id', auth, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Access denied' });
    }
    
    db.query('DELETE FROM users WHERE id = $1 AND role IN ($2, $3)', [req.params.id, 'vendor', 'rider'], (err, result) => {
        if (err) {
            console.error('Delete user error:', err);
            return res.status(500).json({ message: 'Error deleting user' });
        }
        res.json({ message: 'User deleted successfully' });
    });
});

// Approve user
app.put('/api/users/:id/approve', auth, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Access denied' });
    }
    
    db.query('UPDATE users SET is_approved = $1 WHERE id = $2 AND role IN ($3, $4)', [true, req.params.id, 'vendor', 'rider'], (err, result) => {
        if (err) {
            console.error('Approve user error:', err);
            return res.status(500).json({ message: 'Error approving user' });
        }
        if (result.rowCount === 0) {
            return res.status(404).json({ message: 'User not found' });
        }
        res.json({ message: 'User approved successfully' });
    });
});

app.get('/api/rider-daybook-details/:riderId', auth, (req, res) => res.json([]));

module.exports = app;s = [status, delivery_comment || null, req.params.id];
    
    if (req.user.role === 'rider') {
        query = 'UPDATE parcels SET status = $1, rider_comment = $2 WHERE id = $3 AND assigned_rider_id = $4';
        params = [status, delivery_comment || null, req.params.id, req.user.id];
    }
    
    db.query(query, params, (err, result) => {
        if (err) {
            console.error('Update delivery error:', err);
            return res.status(500).json({ message: 'Error updating delivery status' });
        }
        if (result.rowCount === 0) {
            return res.status(403).json({ message: 'Not authorized to update this parcel' });
        }
        res.json({ message: 'Delivery status updated successfully' });
    });
});

module.exports = app;atus, delivery_comment || null, req.params.id];
    
    if (req.user.role === 'rider') {
        query = 'UPDATE parcels SET status = ?, rider_comment = ? WHERE id = ? AND assigned_rider_id = ?';
        params = [status, delivery_comment || null, req.params.id, req.user.id];
    }
    
    db.query(query, params, (err, result) => {
        if (err) {
            console.error('Update delivery error:', err);
            return res.status(500).json({ message: 'Error updating delivery status' });
        }
        if (result.affectedRows === 0) {
            return res.status(403).json({ message: 'Not authorized to update this parcel' });
        }
        res.json({ message: 'Delivery status updated successfully' });
    });
});

// Get users (admin only)
app.get('/api/users', auth, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Access denied' });
    }
    
    db.query('SELECT id, name, email, role, is_approved, created_at FROM users', (err, results) => {
        if (err) {
            console.error('Fetch users error:', err);
            return res.status(500).json({ message: 'Error fetching users' });
        }
        res.json(results);
    });
});

// Vendor report
app.get('/api/vendor-report', auth, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Access denied' });
    }
    
    const query = `
        SELECT 
            CURDATE() as date,
            u.name as vendor_name,
            COUNT(p.id) as total_parcels,
            SUM(COALESCE(p.cod_amount, 0)) as total_cod
        FROM parcels p
        JOIN users u ON p.vendor_id = u.id
        WHERE u.role = 'vendor'
        GROUP BY u.id, u.name
        ORDER BY u.name
    `;
    
    db.query(query, (err, results) => {
        if (err) {
            console.error('Vendor report error:', err);
            return res.status(500).json({ message: 'Error fetching vendor report' });
        }
        res.json(results);
    });
});

// Rider reports
app.get('/api/rider-reports', auth, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Access denied' });
    }
    
    const query = `
        SELECT 
            u.id,
            u.name as rider_name,
            u.email,
            u.created_at,
            '' as citizenship_no,
            '' as bike_no,
            '' as license_no,
            '' as photo_url,
            0 as total_km,
            COUNT(p.id) as total_parcels_delivered,
            0 as working_days
        FROM users u
        LEFT JOIN parcels p ON u.id = p.assigned_rider_id AND p.status = 'delivered'
        WHERE u.role = 'rider'
        GROUP BY u.id, u.name, u.email, u.created_at
        ORDER BY u.name
    `;
    
    db.query(query, (err, results) => {
        if (err) {
            console.error('Fetch rider reports error:', err);
            return res.status(500).json({ message: 'Error fetching rider reports' });
        }
        res.json(results);
    });
});

// Delete user
app.delete('/api/users/:id', auth, (req, res) => {
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
});

// Approve user
app.put('/api/users/:id/approve', auth, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Access denied' });
    }
    
    db.query('UPDATE users SET is_approved = 1 WHERE id = ? AND role IN ("vendor", "rider")', [req.params.id], (err, result) => {
        if (err) {
            console.error('Approve user error:', err);
            return res.status(500).json({ message: 'Error approving user' });
        }
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'User not found' });
        }
        res.json({ message: 'User approved successfully' });
    });
});

// Get users (admin only)
app.get('/api/users', auth, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Access denied' });
    }
    
    db.query('SELECT id, name, email, role, is_approved, created_at FROM users', (err, results) => {
        if (err) {
            console.error('Fetch users error:', err);
            return res.status(500).json({ message: 'Error fetching users' });
        }
        res.json(results.rows);
    });
});

// Vendor report
app.get('/api/vendor-report', auth, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Access denied' });
    }
    
    const query = `
        SELECT 
            CURRENT_DATE as date,
            u.name as vendor_name,
            COUNT(p.id) as total_parcels,
            SUM(COALESCE(p.cod_amount, 0)) as total_cod
        FROM parcels p
        JOIN users u ON p.vendor_id = u.id
        WHERE u.role = 'vendor'
        GROUP BY u.id, u.name
        ORDER BY u.name
    `;
    
    db.query(query, (err, results) => {
        if (err) {
            console.error('Vendor report error:', err);
            return res.status(500).json({ message: 'Error fetching vendor report' });
        }
        res.json(results.rows);
    });
});

// Rider reports
app.get('/api/rider-reports', auth, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Access denied' });
    }
    
    const query = `
        SELECT 
            u.id,
            u.name as rider_name,
            u.email,
            u.created_at,
            COALESCE(rp.citizenship_no, '') as citizenship_no,
            COALESCE(rp.bike_no, '') as bike_no,
            COALESCE(rp.license_no, '') as license_no,
            COALESCE(rp.photo_url, '') as photo_url,
            COALESCE(SUM(rd.total_km), 0) as total_km,
            COUNT(p.id) as total_parcels_delivered,
            COUNT(DISTINCT rd.date) as working_days
        FROM users u
        LEFT JOIN rider_profiles rp ON u.id = rp.rider_id
        LEFT JOIN rider_daybook rd ON u.id = rd.rider_id
        LEFT JOIN parcels p ON u.id = p.assigned_rider_id AND p.status = 'delivered'
        WHERE u.role = 'rider'
        GROUP BY u.id, u.name, u.email, u.created_at, rp.citizenship_no, rp.bike_no, rp.license_no, rp.photo_url
        ORDER BY u.name
    `;
    
    db.query(query, (err, results) => {
        if (err) {
            console.error('Fetch rider reports error:', err);
            return res.status(500).json({ message: 'Error fetching rider reports' });
        }
        res.json(results.rows);
    });
});

// Delete user
app.delete('/api/users/:id', auth, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Access denied' });
    }
    
    db.query('DELETE FROM users WHERE id = $1 AND role IN ($2, $3)', [req.params.id, 'vendor', 'rider'], (err, result) => {
        if (err) {
            console.error('Delete user error:', err);
            return res.status(500).json({ message: 'Error deleting user' });
        }
        res.json({ message: 'User deleted successfully' });
    });
});

// Approve user
app.put('/api/users/:id/approve', auth, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Access denied' });
    }
    
    db.query('UPDATE users SET is_approved = $1 WHERE id = $2 AND role IN ($3, $4)', [true, req.params.id, 'vendor', 'rider'], (err, result) => {
        if (err) {
            console.error('Approve user error:', err);
            return res.status(500).json({ message: 'Error approving user' });
        }
        if (result.rowCount === 0) {
            return res.status(404).json({ message: 'User not found' });
        }
        res.json({ message: 'User approved successfully' });
    });
});

app.get('/api/rider-daybook-details/:riderId', auth, (req, res) => res.json([]));

module.exports = app;