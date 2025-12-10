const bcrypt = require('bcryptjs');

async function hashPassword() {
    const password = 'Nepal@123';
    const hashedPassword = await bcrypt.hash(password, 10);
    console.log('Password:', password);
    console.log('New Hashed:', hashedPassword);
    
    // Test the hash
    const isValid = await bcrypt.compare(password, hashedPassword);
    console.log('Hash validation:', isValid);
}

hashPassword();