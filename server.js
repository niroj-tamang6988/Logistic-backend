const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

const app = express();

app.use(cors());
app.use(express.json());
app.use('/uploads', express.static('uploads'));

// Create uploads directory if it doesn't exist
if (!fs.existsSync('uploads')) {
    fs.mkdirSync('uploads');
}

// Configure multer for file uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, 'rider-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({ 
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith('image/')) {
            cb(null, true);
        } else {
            cb(new Error('Only image files are allowed'));
        }
    }
});

// Database connection
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
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

// Auth routes
// Password validation function
const validatePassword = (password) => {
    const minLength = 8;
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumbers = /\d/.test(password);
    const hasSpecialChar = /[@#$%^&*!]/.test(password);
    
    if (password.length < minLength) {
        return 'Password must be at least 8 characters long';
    }
    if (!hasUpperCase) {
        return 'Password must contain at least one uppercase letter';
    }
    if (!hasLowerCase) {
        return 'Password must contain at least one lowercase letter';
    }
    if (!hasNumbers) {
        return 'Password must contain at least one number';
    }
    if (!hasSpecialChar) {
        return 'Password must contain at least one special character (@, #, $, %, ^, &, *, !)';
    }
    return null;
};

app.post('/api/register', async (req, res) => {
    try {
        const { name, email, password, role } = req.body;
        
        // Validate password
        const passwordError = validatePassword(password);
        if (passwordError) {
            return res.status(400).json({ message: passwordError });
        }
        
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

// Parcel routes
app.post('/api/parcels', auth, (req, res) => {
    try {
        const { recipient_name, recipient_address, recipient_phone, cod_amount } = req.body;
        
        db.query('INSERT INTO parcels (vendor_id, recipient_name, address, recipient_phone, cod_amount) VALUES (?, ?, ?, ?, ?)',
            [req.user.id, recipient_name, recipient_address, recipient_phone, cod_amount || 0], (err, result) => {
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

app.put('/api/parcels/:id/assign', auth, (req, res) => {
    try {
        const { rider_id } = req.body;
        
        db.query('UPDATE parcels SET assigned_rider_id = ?, status = "assigned" WHERE id = ?',
            [rider_id, req.params.id], (err, result) => {
            if (err) {
                console.error('Assign parcel error:', err);
                return res.status(500).json({ message: 'Error assigning parcel' });
            }
            res.json({ message: 'Parcel assigned successfully' });
        });
    } catch (error) {
        console.error('Assign parcel error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.put('/api/parcels/:id/delivery', auth, (req, res) => {
    try {
        const { status, delivery_comment } = req.body;
        console.log('Update delivery request:', { parcelId: req.params.id, status, delivery_comment, userId: req.user.id, userRole: req.user.role });
        
        // Validate status value
        const validStatuses = ['delivered', 'not_delivered', 'assigned', 'pending', 'placed'];
        if (!validStatuses.includes(status)) {
            console.error('Invalid status value:', status);
            return res.status(400).json({ message: 'Invalid status value' });
        }
        
        let query = 'UPDATE parcels SET status = ?, rider_comment = ? WHERE id = ?';
        let params = [status, delivery_comment || null, req.params.id];
        
        if (req.user.role === 'rider') {
            query = 'UPDATE parcels SET status = ?, rider_comment = ? WHERE id = ? AND assigned_rider_id = ?';
            params = [status, delivery_comment || null, req.params.id, req.user.id];
        }
        
        console.log('Executing query:', query, 'with params:', params);
        console.log('Status being set:', status, 'Type:', typeof status);
        
        db.query(query, params, (err, result) => {
            if (err) {
                console.error('Update delivery SQL error:', err);
                return res.status(500).json({ message: 'Database error: ' + err.message });
            }
            console.log('Update result:', result);
            if (result.affectedRows === 0) {
                return res.status(403).json({ message: 'Not authorized to update this parcel or parcel not found' });
            }
            res.json({ message: 'Delivery status updated successfully' });
        });
    } catch (error) {
        console.error('Update delivery catch error:', error);
        res.status(500).json({ message: 'Server error: ' + error.message });
    }
});

app.get('/api/riders', auth, (req, res) => {
    try {
        const query = 'SELECT id, name FROM users WHERE role = "rider"';
        console.log('Executing riders query:', query);
        db.query(query, (err, results) => {
            if (err) {
                console.error('Fetch riders error:', err);
                return res.status(500).json({ message: 'Error fetching riders' });
            }
            console.log('Riders results:', results);
            res.json(results);
        });
    } catch (error) {
        console.error('Fetch riders error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

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

// User management routes for admin
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

// Date-wise financial reports
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

// Rider profile routes
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

// Photo upload endpoint
app.post('/api/upload-photo', auth, upload.single('photo'), (req, res) => {
    try {
        if (req.user.role !== 'rider' && req.user.role !== 'vendor') {
            return res.status(403).json({ message: 'Access denied' });
        }
        
        if (!req.file) {
            return res.status(400).json({ message: 'No file uploaded' });
        }
        
        const photoUrl = `/uploads/${req.file.filename}`;
        res.json({ photo_url: photoUrl });
    } catch (error) {
        console.error('Photo upload error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/rider-profile', auth, (req, res) => {
    try {
        if (req.user.role !== 'rider') {
            return res.status(403).json({ message: 'Access denied' });
        }
        
        const { citizenship_no, bike_no, license_no, photo_url } = req.body;
        
        // Check if profile exists
        db.query('SELECT id FROM rider_profiles WHERE user_id = ?', [req.user.id], (err, results) => {
            if (err) {
                console.error('Check rider profile error:', err);
                return res.status(500).json({ message: 'Error checking rider profile' });
            }
            
            if (results.length > 0) {
                // Update existing profile
                db.query('UPDATE rider_profiles SET citizenship_no = ?, bike_no = ?, license_no = ?, photo_url = ? WHERE user_id = ?',
                    [citizenship_no, bike_no, license_no, photo_url, req.user.id], (err, result) => {
                    if (err) {
                        console.error('Update rider profile error:', err);
                        return res.status(500).json({ message: 'Error updating rider profile' });
                    }
                    res.json({ message: 'Rider profile updated successfully' });
                });
            } else {
                // Create new profile
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

// Get all rider profiles for admin
app.get('/api/rider-profiles', auth, (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ message: 'Access denied' });
        }
        
        const query = `
            SELECT u.id, u.name, u.email, u.created_at,
                   rp.citizenship_no, rp.bike_no, rp.license_no, rp.photo_url
            FROM users u
            LEFT JOIN rider_profiles rp ON u.id = rp.user_id
            WHERE u.role = 'rider'
            ORDER BY u.name
        `;
        
        db.query(query, (err, results) => {
            if (err) {
                console.error('Fetch rider profiles error:', err);
                return res.status(500).json({ message: 'Error fetching rider profiles' });
            }
            res.json(results);
        });
    } catch (error) {
        console.error('Fetch rider profiles error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Get rider reports for admin
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
        
        console.log('Executing rider reports query:', query);
        db.query(query, (err, results) => {
            if (err) {
                console.error('Fetch rider reports error:', err);
                return res.status(500).json({ message: 'Error fetching rider reports' });
            }
            console.log('Rider reports results:', results);
            res.json(results);
        });
    } catch (error) {
        console.error('Fetch rider reports error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Get rider daybook details for admin
app.get('/api/rider-daybook-details/:riderId', auth, (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ message: 'Access denied' });
        }
        
        const query = `
            SELECT *
            FROM rider_daybook
            WHERE rider_id = ?
            ORDER BY date DESC
        `;
        
        db.query(query, [req.params.riderId], (err, results) => {
            if (err) {
                console.error('Fetch rider daybook details error:', err);
                return res.status(500).json({ message: 'Error fetching rider daybook details' });
            }
            res.json(results);
        });
    } catch (error) {
        console.error('Fetch rider daybook details error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Vendor profile routes
app.get('/api/vendor-profile', auth, (req, res) => {
    try {
        if (req.user.role !== 'vendor') {
            return res.status(403).json({ message: 'Access denied' });
        }
        
        db.query('SELECT * FROM vendor_profiles WHERE user_id = ?', [req.user.id], (err, results) => {
            if (err) {
                console.error('Fetch vendor profile error:', err);
                return res.status(500).json({ message: 'Error fetching vendor profile' });
            }
            res.json(results[0] || {});
        });
    } catch (error) {
        console.error('Fetch vendor profile error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Vendor daybook route
app.get('/api/vendor-daybook', auth, (req, res) => {
    try {
        if (req.user.role !== 'vendor') {
            return res.status(403).json({ message: 'Access denied' });
        }
        
        const query = `
            SELECT 
                DATE(created_at) as date,
                COUNT(*) as total_parcels,
                COUNT(CASE WHEN status = 'delivered' THEN 1 END) as delivered_parcels,
                COUNT(CASE WHEN status = 'not_delivered' THEN 1 END) as not_delivered_parcels,
                COUNT(CASE WHEN status NOT IN ('delivered', 'not_delivered') THEN 1 END) as in_progress_parcels,
                COALESCE(SUM(cod_amount), 0) as total_cod,
                COALESCE(SUM(CASE WHEN status = 'delivered' THEN cod_amount ELSE 0 END), 0) as delivered_cod
            FROM parcels 
            WHERE vendor_id = ?
            GROUP BY DATE(created_at)
            ORDER BY DATE(created_at) DESC
        `;
        
        db.query(query, [req.user.id], (err, results) => {
            if (err) {
                console.error('Fetch vendor daybook error:', err);
                return res.status(500).json({ message: 'Error fetching vendor daybook' });
            }
            res.json(results);
        });
    } catch (error) {
        console.error('Fetch vendor daybook error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/vendor-profile', auth, (req, res) => {
    try {
        if (req.user.role !== 'vendor') {
            return res.status(403).json({ message: 'Access denied' });
        }
        
        const { name, about, photo_url } = req.body;
        
        // Check if profile exists
        db.query('SELECT id FROM vendor_profiles WHERE user_id = ?', [req.user.id], (err, results) => {
            if (err) {
                console.error('Check vendor profile error:', err);
                return res.status(500).json({ message: 'Error checking vendor profile' });
            }
            
            if (results.length > 0) {
                // Update existing profile
                db.query('UPDATE vendor_profiles SET name = ?, about = ?, photo_url = ? WHERE user_id = ?',
                    [name, about, photo_url, req.user.id], (err, result) => {
                    if (err) {
                        console.error('Update vendor profile error:', err);
                        return res.status(500).json({ message: 'Error updating vendor profile' });
                    }
                    res.json({ message: 'Vendor profile updated successfully' });
                });
            } else {
                // Create new profile
                db.query('INSERT INTO vendor_profiles (user_id, name, about, photo_url) VALUES (?, ?, ?, ?)',
                    [req.user.id, name, about, photo_url], (err, result) => {
                    if (err) {
                        console.error('Create vendor profile error:', err);
                        return res.status(500).json({ message: 'Error creating vendor profile' });
                    }
                    res.json({ message: 'Vendor profile created successfully' });
                });
            }
        });
    } catch (error) {
        console.error('Vendor profile error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Vendor-wise report
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
        
        console.log('Vendor report query:', query);
        db.query(query, (err, results) => {
            if (err) {
                console.error('Vendor report error:', err);
                return res.status(500).json({ message: 'Error fetching vendor report' });
            }
            console.log('Vendor report results:', results);
            res.json(results);
        });
    } catch (error) {
        console.error('Vendor report error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Rider daybook routes
app.get('/api/rider-daybook', auth, (req, res) => {
    try {
        if (req.user.role !== 'rider') {
            return res.status(403).json({ message: 'Access denied' });
        }
        
        db.query('SELECT * FROM rider_daybook WHERE rider_id = ? ORDER BY date DESC', [req.user.id], (err, results) => {
            if (err) {
                console.error('Fetch daybook error:', err);
                return res.status(500).json({ message: 'Error fetching daybook' });
            }
            res.json(results);
        });
    } catch (error) {
        console.error('Fetch daybook error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/rider-daybook', auth, (req, res) => {
    try {
        if (req.user.role !== 'rider') {
            return res.status(403).json({ message: 'Access denied' });
        }
        
        const { date, total_km, parcels_delivered, fuel_cost, notes } = req.body;
        
        db.query('INSERT INTO rider_daybook (rider_id, date, total_km, parcels_delivered, fuel_cost, notes) VALUES (?, ?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE total_km = VALUES(total_km), parcels_delivered = VALUES(parcels_delivered), fuel_cost = VALUES(fuel_cost), notes = VALUES(notes)',
            [req.user.id, date, total_km || 0, parcels_delivered || 0, fuel_cost || 0, notes || ''], (err, result) => {
            if (err) {
                console.error('Save daybook error:', err);
                return res.status(500).json({ message: 'Error saving daybook entry' });
            }
            res.json({ message: 'Daybook entry saved successfully' });
        });
    } catch (error) {
        console.error('Save daybook error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/api/rider-daybook-summary', auth, (req, res) => {
    try {
        if (req.user.role !== 'rider') {
            return res.status(403).json({ message: 'Access denied' });
        }
        
        const query = `
            SELECT 
                SUM(total_km) as total_km,
                SUM(parcels_delivered) as total_parcels,
                SUM(fuel_cost) as total_fuel_cost,
                COUNT(*) as total_days
            FROM rider_daybook 
            WHERE rider_id = ?
        `;
        
        db.query(query, [req.user.id], (err, results) => {
            if (err) {
                console.error('Fetch daybook summary error:', err);
                return res.status(500).json({ message: 'Error fetching daybook summary' });
            }
            res.json(results[0] || {});
        });
    } catch (error) {
        console.error('Fetch daybook summary error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/api/rider-daybook-monthly', auth, (req, res) => {
    try {
        if (req.user.role !== 'rider') {
            return res.status(403).json({ message: 'Access denied' });
        }
        
        const query = `
            SELECT 
                YEAR(date) as year,
                MONTH(date) as month,
                SUM(total_km) as total_km,
                SUM(parcels_delivered) as total_parcels,
                SUM(fuel_cost) as total_fuel_cost,
                COUNT(*) as working_days
            FROM rider_daybook 
            WHERE rider_id = ?
            GROUP BY YEAR(date), MONTH(date)
            ORDER BY YEAR(date) DESC, MONTH(date) DESC
        `;
        
        db.query(query, [req.user.id], (err, results) => {
            if (err) {
                console.error('Fetch monthly daybook error:', err);
                return res.status(500).json({ message: 'Error fetching monthly daybook' });
            }
            res.json(results);
        });
    } catch (error) {
        console.error('Fetch monthly daybook error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

const PORT = process.env.PORT || 5001;

// Test database connection on startup
db.query('SELECT 1', (err) => {
    if (err) {
        console.error('Database connection failed:', err.message);
        process.exit(1);
    }
    console.log('Database connected successfully');
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));