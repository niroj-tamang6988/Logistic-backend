const { Pool } = require('pg');

const db = new Pool({
    connectionString: 'postgresql://neondb_owner:npg_MiFC8yadsf2x@ep-empty-shape-ah6kyix1-pooler.c-3.us-east-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require',
    ssl: { rejectUnauthorized: false }
});

async function createStaffActivitiesTable() {
    try {
        console.log('Creating staff_activities table...');
        
        await db.query(`
            CREATE TABLE IF NOT EXISTS staff_activities (
                id SERIAL PRIMARY KEY,
                staff_id INTEGER REFERENCES users(id),
                activity_type VARCHAR(50) NOT NULL,
                amount DECIMAL(10,2) DEFAULT 0,
                notes TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        
        console.log('✅ Staff activities table created successfully!');
        
        process.exit(0);
    } catch (error) {
        console.error('❌ Error creating table:', error);
        process.exit(1);
    }
}

createStaffActivitiesTable();