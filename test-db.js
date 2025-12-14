const { Pool } = require('pg');

const db = new Pool({
    connectionString: 'postgresql://postgres:NirojTamang@db.mydygbnplhusevdmuloe.supabase.co:5432/postgres',
    ssl: { rejectUnauthorized: false }
});

async function testConnection() {
    try {
        const result = await db.query('SELECT NOW()');
        console.log('Database connected:', result.rows[0]);
        
        // Check if admin exists
        const adminCheck = await db.query('SELECT * FROM users WHERE email = $1', ['admin@dms.com']);
        console.log('Admin exists:', adminCheck.rows.length > 0);
        
        if (adminCheck.rows.length === 0) {
            console.log('Creating admin user...');
            const bcrypt = require('bcryptjs');
            const hashedPassword = await bcrypt.hash('password', 10);
            await db.query('INSERT INTO users (name, email, password, role, is_approved) VALUES ($1, $2, $3, $4, $5)', 
                ['Admin', 'admin@dms.com', hashedPassword, 'admin', true]);
            console.log('Admin user created');
        }
        
        process.exit(0);
    } catch (error) {
        console.error('Database error:', error);
        process.exit(1);
    }
}

testConnection();