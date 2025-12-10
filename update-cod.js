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
    
    // Update existing parcels with sample COD amounts
    const updateQuery = `
        UPDATE parcels 
        SET cod_amount = CASE 
            WHEN status = 'delivered' THEN 500 
            WHEN status = 'pending' THEN 300 
            WHEN status = 'assigned' THEN 400 
            ELSE 200 
        END 
        WHERE cod_amount = 0 OR cod_amount IS NULL
    `;
    
    db.query(updateQuery, (err, result) => {
        if (err) {
            console.error('Error updating COD amounts:', err.message);
        } else {
            console.log('Updated', result.affectedRows, 'parcels with COD amounts');
        }
        db.end();
    });
});