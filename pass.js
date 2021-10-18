import bcrypt from 'bcrypt';

export default async function checkPass (passwordInput, passwordHash) {
    
    return await bcrypt.compare(passwordInput, passwordHash);
}