import express from 'express';
import { JWTManager, authMiddleware, roleMiddleware } from 'jwt-easy-kit';
import cookieParser from 'cookie-parser';

const app = express();
app.use(express.json());
app.use(cookieParser());

// Initialize JWT Manager
const jwtManager = new JWTManager({
    secret: process.env.JWT_SECRET || 'your-secret-key'
});

// Public route
app.get('/api/public', (req, res) => {
    res.json({ message: 'Public endpoint - no auth required' });
});

// Protected route with auth middleware
app.get('/api/protected',
    authMiddleware(jwtManager),
    (req, res) => {
        res.json({
            message: 'Protected endpoint',
            user: req.user
        });
    }
);

// Protected route with role-based access
app.get('/api/admin',
    authMiddleware(jwtManager),
    roleMiddleware(['admin', 'superadmin']),
    (req, res) => {
        res.json({
            message: 'Admin endpoint',
            user: req.user
        });
    }
);

// Login endpoint
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;

    // Validate credentials (simplified)
    if (username === 'admin' && password === 'password123') {
        // Create tokens
        const tokens = jwtManager.createTokenPair({
            userId: '1',
            username: 'admin',
            role: 'admin'
        });

        // Set cookies
        res.cookie('access_token', tokens.accessToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            maxAge: 15 * 60 * 1000 // 15 minutes
        });

        res.cookie('refresh_token', tokens.refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
        });

        res.json({
            message: 'Login successful',
            accessToken: tokens.accessToken,
            refreshToken: tokens.refreshToken,
            expiresIn: tokens.accessExpires
        });
    } else {
        res.status(401).json({ error: 'Invalid credentials' });
    }
});

// Refresh token endpoint
app.post('/api/refresh', async (req, res) => {
    const { refreshToken } = req.body;

    if (!refreshToken) {
        return res.status(400).json({ error: 'Refresh token required' });
    }

    try {
        const newTokens = jwtManager.refreshAccessToken(refreshToken);

        res.json({
            message: 'Token refreshed',
            ...newTokens
        });
    } catch (error) {
        res.status(401).json({ error: 'Invalid refresh token' });
    }
});

// Logout endpoint
app.post('/api/logout',
    authMiddleware(jwtManager),
    (req, res) => {
        // Blacklist the token
        jwtManager.blacklistToken(req.token);

        // Clear cookies
        res.clearCookie('access_token');
        res.clearCookie('refresh_token');

        res.json({ message: 'Logged out successfully' });
    }
);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});