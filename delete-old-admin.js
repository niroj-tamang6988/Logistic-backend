const { Pool } = require('pg');

const db = new Pool({
    connectionString: 'postgresql://neondb_owner:npg_MiFC8yadsf2x@ep-empty-shape-ah6kyix1-pooler.c-3.us-east-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require',
    ssl: { rejectUnauthorized: false }
});

async function deleteOldAdmin() {
    try {
        console.log('Deleting old admin user...');
        
        const result = await db.query('DELETE FROM users WHERE email = $1', ['admin@dms.com']);
        
        console.log('✅ Old admin user deleted successfully!');
        console.log(`✅ Deleted ${result.rowCount} user(s)`);
        
        // Show remaining users
        const users = await db.query('SELECT id, name, email, role, created_at FROM users ORDER BY created_at DESC');
        console.log('\n📋 Remaining users:');
        users.rows.forEach(user => {
            console.log(`- ${user.name} (${user.email}) - ${user.role} - Created: ${user.created_at}`);
        });
        
        process.exit(0);
    } catch (error) {
        console.error('❌ Error deleting admin:', error);
        process.exit(1);
    }
}

deleteOldAdmin();