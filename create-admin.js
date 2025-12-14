const { Pool } = require('pg');
const bcrypt = require('bcryptjs');

const db = new Pool({
    connectionString: 'postgresql://neondb_owner:npg_MiFC8yadsf2x@ep-empty-shape-ah6kyix1-pooler.c-3.us-east-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require',
    ssl: { rejectUnauthorized: false }
});

async function createAdmin() {
    try {
        console.log('Creating new admin user...');
        
        const hashedPassword = await bcrypt.hash('Nepal@123', 10);
        
        await db.query(`
            INSERT INTO users (name, email, password, role, is_approved) 
            VALUES ('Admin User', 'rnj41752@gmail.com', $1, 'admin', true)
            ON CONFLICT (email) DO UPDATE SET 
            password = $1, 
            role = 'admin', 
            is_approved = true
        `, [hashedPassword]);
        
        console.log('✅ Admin user created successfully!');
        console.log('✅ Login: rnj41752@gmail.com / Nepal@123');
        
        process.exit(0);
    } catch (error) {
        console.error('❌ Error creating admin:', error);
        process.exit(1);
    }
}

createAdmin();