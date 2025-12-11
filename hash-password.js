const bcrypt = require('bcryptjs');

async function hashPassword() {
    // Test both passwords
    const passwords = ['Nepal@123', 'password'];
    
    for (const password of passwords) {
        const hashedPassword = await bcrypt.hash(password, 10);
        console.log(`\nPassword: ${password}`);
        console.log(`Hashed: ${hashedPassword}`);
        
        // Test the hash
        const isValid = await bcrypt.compare(password, hashedPassword);
        console.log(`Validation: ${isValid}`);
    }
}

hashPassword();