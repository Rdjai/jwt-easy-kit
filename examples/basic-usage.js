import { JWTManager } from 'jwt-easy-kit';

// Initialize with your secret
const jwtManager = new JWTManager({
    secret: process.env.JWT_SECRET || 'your-secret-key',
    expiresIn: '1h',
    issuer: 'your-app'
});

// Create a token
const token = jwtManager.createToken({
    userId: 'Rdj_kashyap123',
    email: 'Rdj@rdjkashyap.cv',
    role: 'admin'
});

console.log('Token created:', token);

// Verify the token
try {
    const decoded = jwtManager.verifyToken(token);
    console.log('Decoded token:', decoded);
} catch (error) {
    console.error('Token verification failed:', error.message);
}

// Create token pair (access + refresh)
const tokens = jwtManager.createTokenPair({
    userId: 'rdj_kashyap123',
    email: 'rdj@rdjkashyap.cv'
}, {
    expiresIn: '15m' // Access token expires in 15 minutes
}, {
    expiresIn: '7d' // Refresh token expires in 7 days
});

console.log('Access Token:', tokens.accessToken);
console.log('Access expires:', tokens.accessExpires);
console.log('Refresh Token:', tokens.refreshToken);
console.log('Refresh expires:', tokens.refreshExpires);

// Password hashing
async function handlePassword() {
    const password = 'mySecurePassword';

    // Hash password
    const hash = await jwtManager.hashPassword(password);
    console.log('Password hash:', hash);

    // Verify password
    const isValid = await jwtManager.comparePassword(password, hash);
    console.log('Password valid:', isValid);
}