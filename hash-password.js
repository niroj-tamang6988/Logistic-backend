const bcrypt = require('bcryptjs');

async function hashPassword() {
    const password = 'Nepal@123';
    const hashedPassword = await bcrypt.hash(password, 10);
    console.log('Password:', password);
    console.log('Hashed:', hashedPassword);
}

hashPassword();