const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

const app = express();

// CORS middleware - must be first
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
    res.header('Access-Control-Allow-Credentials', 'true');
    
    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }
    next();
});

app.use(express.json());

// Health check route
app.get('/', (req, res) => {
    res.json({ message: 'Delivery Management System API is running', status: 'OK' });
});

app.get('/api/health', (req, res) => {
    res.json({ message: 'API is healthy', timestamp: new Date().toISOString() });
});

// Debug endpoint to show table structure
app.get('/api/debug/parcels-structure', (req, res) => {
    db.query('DESCRIBE parcels', (err, results) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json(results);
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

// Login route
app.post('/api/login', (req, res) => {
    try {
        const { email, password } = req.body;
        
        db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
            if (err) {
                console.error('Login query error:', err);
                return res.status(500).json({ message: 'Server error' });
            }
            if (results.length === 0) return res.status(400).json({ message: 'User is not registered. Please register first.' });
            
            const user = results[0];
            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) return res.status(400).json({ message: 'Invalid password. Please check your password.' });
            
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

// Get riders
app.get('/api/riders', auth, (req, res) => {
    try {
        const query = 'SELECT id, name FROM users WHERE role = "rider" AND is_approved = 1';
        db.query(query, (err, results) => {
            if (err) {
                console.error('Fetch riders error:', err);
                return res.status(500).json({ message: 'Error fetching riders' });
            }
            res.json(results);
        });
    } catch (error) {
        console.error('Fetch riders error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Get stats
app.get('/api/stats', auth, (req, res) => {
    try {
        let query = 'SELECT status, COUNT(*) as count FROM parcels';
        let params = [];
        
        if (req.user.role === 'vendor') {
            query += ' WHERE vendor_id = ?';
            params = [req.user.id];
        }
        
        query += ' GROUP BY status';
        
        db.query(query, params, (err, results) => {
            if (err) {
                console.error('Fetch stats error:', err);
                return res.status(500).json({ message: 'Error fetching stats' });
            }
            res.json(results);
        });
    } catch (error) {
        console.error('Fetch stats error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Get users (admin only)
app.get('/api/users', auth, (req, res) => {
    try {
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
    } catch (error) {
        console.error('Fetch users error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Financial reports
app.get('/api/financial-report', auth, (req, res) => {
    try {
        let query = `
            SELECT 
                status,
                COUNT(*) as count,
                SUM(COALESCE(cod_amount, 0)) as total_cod
            FROM parcels 
        `;
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
    } catch (error) {
        console.error('Financial report error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Daily financial reports
app.get('/api/financial-report-daily', auth, (req, res) => {
    try {
        let query = `
            SELECT 
                DATE(created_at) as date,
                status,
                COUNT(*) as count,
                SUM(COALESCE(cod_amount, 0)) as total_cod
            FROM parcels 
        `;
        let params = [];
        
        if (req.user.role === 'vendor') {
            query += ' WHERE vendor_id = ?';
            params = [req.user.id];
        }
        
        query += ' GROUP BY DATE(created_at), status ORDER BY date DESC, status';
        
        db.query(query, params, (err, results) => {
            if (err) {
                console.error('Daily financial report error:', err);
                return res.status(500).json({ message: 'Error fetching daily financial report' });
            }
            res.json(results);
        });
    } catch (error) {
        console.error('Daily financial report error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Vendor report
app.get('/api/vendor-report', auth, (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ message: 'Access denied' });
        }
        
        const query = `
            SELECT 
                DATE(p.created_at) as date,
                u.name as vendor_name,
                COUNT(p.id) as total_parcels,
                SUM(COALESCE(p.cod_amount, 0)) as total_cod
            FROM parcels p
            JOIN users u ON p.vendor_id = u.id
            WHERE u.role = 'vendor'
            GROUP BY DATE(p.created_at), u.id, u.name
            ORDER BY DATE(p.created_at) DESC, u.name
        `;
        
        db.query(query, (err, results) => {
            if (err) {
                console.error('Vendor report error:', err);
                return res.status(500).json({ message: 'Error fetching vendor report' });
            }
            res.json(results);
        });
    } catch (error) {
        console.error('Vendor report error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Rider reports
app.get('/api/rider-reports', auth, (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ message: 'Access denied' });
        }
        
        const query = `
            SELECT 
                u.id,
                u.name as rider_name,
                u.email,
                u.created_at,
                rp.citizenship_no,
                rp.bike_no,
                rp.license_no,
                rp.photo_url,
                COALESCE(SUM(rd.total_km), 0) as total_km,
                COALESCE(SUM(rd.parcels_delivered), 0) as total_parcels_delivered,
                COUNT(rd.id) as working_days
            FROM users u
            LEFT JOIN rider_profiles rp ON u.id = rp.user_id
            LEFT JOIN rider_daybook rd ON u.id = rd.rider_id
            WHERE u.role = 'rider'
            GROUP BY u.id, u.name, u.email, u.created_at, rp.citizenship_no, rp.bike_no, rp.license_no, rp.photo_url
            ORDER BY total_km DESC
        `;
        
        db.query(query, (err, results) => {
            if (err) {
                console.error('Fetch rider reports error:', err);
                return res.status(500).json({ message: 'Error fetching rider reports' });
            }
            res.json(results);
        });
    } catch (error) {
        console.error('Fetch rider reports error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Assign rider to parcel
app.put('/api/parcels/:id/assign', auth, (req, res) => {
    try {
        const { rider_id } = req.body;
        
        db.query('UPDATE parcels SET assigned_rider_id = ?, status = "assigned" WHERE id = ?',
            [rider_id, req.params.id], (err, result) => {
            if (err) {
                console.error('Assign parcel error:', err);
                return res.status(500).json({ message: 'Error assigning parcel' });
            }
            
            // Log the assignment action
            db.query('INSERT INTO parcel_logs (parcel_id, by_user, action, comment) VALUES (?, ?, ?, ?)',
                [req.params.id, req.user.id, 'assigned', `Parcel assigned to rider ID: ${rider_id}`], (logErr) => {
                if (logErr) console.error('Log assignment error:', logErr);
            });
            
            res.json({ message: 'Parcel assigned successfully' });
        });
    } catch (error) {
        console.error('Assign parcel error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Update delivery status
app.put('/api/parcels/:id/delivery', auth, (req, res) => {
    try {
        const { status, delivery_comment } = req.body;
        
        const validStatuses = ['delivered', 'not_delivered', 'assigned', 'pending'];
        if (!validStatuses.includes(status)) {
            return res.status(400).json({ message: 'Invalid status value' });
        }
        
        let query = 'UPDATE parcels SET status = ?, rider_comment = ? WHERE id = ?';
        let params = [status, delivery_comment || null, req.params.id];
        
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
            
            // Log the delivery status update
            db.query('INSERT INTO parcel_logs (parcel_id, by_user, action, comment) VALUES (?, ?, ?, ?)',
                [req.params.id, req.user.id, status, delivery_comment || `Status updated to ${status}`], (logErr) => {
                if (logErr) console.error('Log delivery error:', logErr);
            });
            
            res.json({ message: 'Delivery status updated successfully' });
        });
    } catch (error) {
        console.error('Update delivery error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Rider profile endpoints
app.get('/api/rider-profile', auth, (req, res) => {
    try {
        if (req.user.role !== 'rider') {
            return res.status(403).json({ message: 'Access denied' });
        }
        
        db.query('SELECT * FROM rider_profiles WHERE user_id = ?', [req.user.id], (err, results) => {
            if (err) {
                console.error('Fetch rider profile error:', err);
                return res.status(500).json({ message: 'Error fetching rider profile' });
            }
            res.json(results[0] || {});
        });
    } catch (error) {
        console.error('Fetch rider profile error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/rider-profile', auth, (req, res) => {
    try {
        if (req.user.role !== 'rider') {
            return res.status(403).json({ message: 'Access denied' });
        }
        
        const { citizenship_no, bike_no, license_no, photo_url } = req.body;
        
        db.query('SELECT id FROM rider_profiles WHERE user_id = ?', [req.user.id], (err, results) => {
            if (err) {
                console.error('Check rider profile error:', err);
                return res.status(500).json({ message: 'Error checking rider profile' });
            }
            
            if (results.length > 0) {
                db.query('UPDATE rider_profiles SET citizenship_no = ?, bike_no = ?, license_no = ?, photo_url = ? WHERE user_id = ?',
                    [citizenship_no, bike_no, license_no, photo_url, req.user.id], (err, result) => {
                    if (err) {
                        console.error('Update rider profile error:', err);
                        return res.status(500).json({ message: 'Error updating rider profile' });
                    }
                    res.json({ message: 'Rider profile updated successfully' });
                });
            } else {
                db.query('INSERT INTO rider_profiles (user_id, citizenship_no, bike_no, license_no, photo_url) VALUES (?, ?, ?, ?, ?)',
                    [req.user.id, citizenship_no, bike_no, license_no, photo_url], (err, result) => {
                    if (err) {
                        console.error('Create rider profile error:', err);
                        return res.status(500).json({ message: 'Error creating rider profile' });
                    }
                    res.json({ message: 'Rider profile created successfully' });
                });
            }
        });
    } catch (error) {
        console.error('Rider profile error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Create parcel endpoint
app.post('/api/parcels', auth, (req, res) => {
    try {
        const { recipient_name, recipient_address, recipient_phone, cod_amount } = req.body;
        
        db.query('INSERT INTO parcels (vendor_id, recipent_name, address, recipent_phone, cod_amound, status) VALUES (?, ?, ?, ?, ?, ?)',
            [req.user.id, recipient_name, recipient_address, recipient_phone, cod_amount || 0, 'pending'], (err, result) => {
            if (err) {
                console.error('Create parcel error:', err);
                return res.status(500).json({ message: 'Error creating parcel' });
            }
            res.json({ message: 'Parcel placed successfully', id: result.insertId });
        });
    } catch (error) {
        console.error('Create parcel error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Register endpoint
app.post('/api/register', async (req, res) => {
    try {
        const { name, email, password, role } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        const isApproved = role === 'admin' ? true : false;
        
        db.query('INSERT INTO users (name, email, password, role, is_approved) VALUES (?, ?, ?, ?, ?)', 
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

// Delete user endpoint
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

// Approve user endpoint
app.put('/api/users/:id/approve', auth, (req, res) => {
    try {
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
    } catch (error) {
        console.error('Approve user error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

const PORT = process.env.PORT || 5001;

// Export for Vercel serverless
module.exports = app;