const mysql = require('mysql2');
require('dotenv').config();

const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});

db.connect((err) => {
    if (err) {
        console.error('Database connection failed:', err.message);
        process.exit(1);
    }
    
    // Check current parcels
    db.query('SELECT id, status, cod_amount FROM parcels', (err, results) => {
        if (err) {
            console.error('Error checking parcels:', err.message);
        } else {
            console.log('Current parcels:');
            console.table(results);
        }
        db.end();
    });
});