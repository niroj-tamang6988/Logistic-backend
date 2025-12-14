const { Pool } = require('pg');

const db = new Pool({
    connectionString: 'postgresql://neondb_owner:npg_MiFC8yadsf2x@ep-empty-shape-ah6kyix1-pooler.c-3.us-east-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require',
    ssl: { rejectUnauthorized: false }
});

async function updateAdminName() {
    try {
        console.log('Updating admin name...');
        
        const result = await db.query(
            'UPDATE users SET name = $1 WHERE email = $2', 
            ['Nityaraj Joshi', 'rnj41752@gmail.com']
        );
        
        console.log('✅ Admin name updated successfully!');
        console.log(`✅ Updated ${result.rowCount} user(s)`);
        
        // Show updated user
        const user = await db.query('SELECT id, name, email, role, created_at FROM users WHERE email = $1', ['rnj41752@gmail.com']);
        console.log('\n📋 Updated admin user:');
        console.log(`- ${user.rows[0].name} (${user.rows[0].email}) - ${user.rows[0].role}`);
        
        process.exit(0);
    } catch (error) {
        console.error('❌ Error updating admin name:', error);
        process.exit(1);
    }
}

updateAdminName();