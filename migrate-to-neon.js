const { Pool } = require('pg');
const bcrypt = require('bcryptjs');

// Neon database connection
const neonDb = new Pool({
    connectionString: 'postgresql://neondb_owner:npg_MiFC8yadsf2x@ep-empty-shape-ah6kyix1-pooler.c-3.us-east-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require',
    ssl: { rejectUnauthorized: false }
});

async function migrateToNeon() {
    try {
        console.log('Creating tables in Neon...');
        
        // Create users table
        await neonDb.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                role VARCHAR(50) NOT NULL,
                is_approved BOOLEAN DEFAULT false,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        
        // Create parcels table
        await neonDb.query(`
            CREATE TABLE IF NOT EXISTS parcels (
                id SERIAL PRIMARY KEY,
                vendor_id INTEGER REFERENCES users(id),
                recipient_name VARCHAR(255) NOT NULL,
                address TEXT NOT NULL,
                recipient_phone VARCHAR(20),
                cod_amount DECIMAL(10,2) DEFAULT 0,
                status VARCHAR(50) DEFAULT 'pending',
                assigned_rider_id INTEGER REFERENCES users(id),
                rider_comment TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        
        // Create admin user
        const hashedPassword = await bcrypt.hash('password', 10);
        await neonDb.query(`
            INSERT INTO users (name, email, password, role, is_approved) 
            VALUES ('Admin', 'admin@dms.com', $1, 'admin', true)
            ON CONFLICT (email) DO NOTHING
        `, [hashedPassword]);
        
        console.log('✅ Neon migration complete!');
        console.log('✅ Admin login: admin@dms.com / password');
        
        process.exit(0);
    } catch (error) {
        console.error('❌ Migration error:', error);
        process.exit(1);
    }
}

migrateToNeon();