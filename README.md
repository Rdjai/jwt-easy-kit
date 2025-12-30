# JWT Easy Kit 🔐

[![npm version](https://img.shields.io/npm/v/jwt-easy-kit.svg)](https://www.npmjs.com/package/jwt-easy-kit)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Test Coverage](https://img.shields.io/badge/coverage-85%25-brightgreen)](https://github.com/yourusername/jwt-easy-kit)
[![npm downloads](https://img.shields.io/npm/dm/jwt-easy-kit.svg)](https://www.npmjs.com/package/jwt-easy-kit)
[![Node.js Version](https://img.shields.io/node/v/jwt-easy-kit)](https://nodejs.org)

A comprehensive, production-ready JWT authentication toolkit for Node.js applications. Streamline your authentication implementation with minimal code and maximum security.

## ✨ Features

- 🔒 **Complete JWT Management** - Token creation, verification, decoding
- 🔄 **Token Pair System** - Access & refresh tokens with automatic management
- 🛡️ **Express Middleware** - Ready-to-use authentication, role, and permission middlewares
- 👥 **RBAC & PBAC** - Role-Based and Permission-Based Access Control
- 🔑 **Password Utilities** - Secure password hashing and comparison
- 🚫 **Token Blacklisting** - Simple token revocation system
- 📦 **Zero Configuration** - Sensible defaults with easy customization
- 🧪 **Fully Tested** - 85%+ test coverage with 74+ passing tests
- ⚡ **High Performance** - Optimized for production use
- 🔧 **Minimal Dependencies** - Only depends on `jsonwebtoken` and `bcryptjs`

## 📦 Installation

```bash
npm install jwt-easy-kit

or

bash
yarn add jwt-easy-kit
🚀 Quick Start
Basic Usage
javascript
const { JWTManager } = require('jwt-easy-kit');

// Initialize with your secret
const jwtManager = new JWTManager({
  secret: process.env.JWT_SECRET || 'your-secret-key',
  expiresIn: '1h',
  issuer: 'your-app'
});

// Create a JWT token
const token = jwtManager.createToken({
  userId: 'user123',
  email: 'user@example.com',
  role: 'admin'
});

console.log('Token created:', token);

// Verify the token
try {
  const decoded = jwtManager.verifyToken(token);
  console.log('Decoded:', decoded);
} catch (error) {
  console.error('Verification failed:', error.message);
}
Express Middleware
javascript
const express = require('express');
const { JWTManager, authMiddleware, roleMiddleware } = require('jwt-easy-kit');

const app = express();
const jwtManager = new JWTManager({
  secret: process.env.JWT_SECRET
});

// Protected route
app.get('/api/profile', 
  authMiddleware(jwtManager),
  (req, res) => {
    res.json({ user: req.user });
  }
);

// Admin-only route
app.get('/api/admin', 
  authMiddleware(jwtManager),
  roleMiddleware(['admin']),
  (req, res) => {
    res.json({ message: 'Welcome admin!' });
  }
);

app.listen(3000, () => console.log('Server running on port 3000'));
📖 API Documentation
JWTManager Class
Constructor
javascript
new JWTManager(options)
Options:

secret (required) - JWT signing secret

expiresIn - Token expiration (default: '1h')

algorithm - Signing algorithm (default: 'HS256')

issuer - Token issuer (default: 'jwt-easy-kit')

audience - Token audience (default: 'user')

Methods
Method	Description	Returns
createToken(payload, options)	Create JWT token	string
verifyToken(token, options)	Verify and decode token	object
decodeToken(token)	Decode token without verification	object
createTokenPair(payload, accessOptions, refreshOptions)	Create access/refresh token pair	{accessToken, refreshToken, accessExpires, refreshExpires}
refreshAccessToken(refreshToken, additionalPayload)	Refresh access token using refresh token	Token pair object
blacklistToken(token)	Add token to blacklist	void
isTokenBlacklisted(token)	Check if token is blacklisted	boolean
hashPassword(password, saltRounds)	Hash password (async)	Promise<string>
comparePassword(password, hash)	Verify password (async)	Promise<boolean>
getTokenExpiration(token)	Get token expiration date	Date or null
isTokenExpired(token)	Check if token is expired	boolean
revokeRefreshToken(refreshToken)	Revoke refresh token	void
cleanup()	Cleanup expired tokens	void
Middlewares
Authentication Middleware
javascript
authMiddleware(jwtManager, options)
Options:

tokenSource - 'header', 'cookie', or 'query' (default: 'header')

tokenKey - Header key for token (default: 'authorization')

cookieName - Cookie name for token (default: 'token')

queryParam - Query parameter for token (default: 'token')

allowUnauthenticated - Allow unauthenticated requests (default: false)

onError - Custom error handler function

Role Middleware
javascript
roleMiddleware(allowedRoles)
Restricts access to users with specified roles.

Permission Middleware
javascript
permissionMiddleware(requiredPermissions)
Restricts access to users with all specified permissions.

Utility Functions
javascript
const {
  validateOptions,
  sanitizePayload,
  generateTokenId,
  isTokenExpired,
  delay
} = require('jwt-easy-kit');
🔧 Advanced Examples
Token Pair with Refresh Flow
javascript
const { JWTManager } = require('jwt-easy-kit');

const jwtManager = new JWTManager({ secret: process.env.JWT_SECRET });

// Login - create token pair
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  
  // Validate user credentials (pseudo-code)
  const user = await User.findOne({ email });
  if (!user || !await jwtManager.comparePassword(password, user.password)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  
  // Create token pair
  const tokens = jwtManager.createTokenPair(
    { userId: user.id, role: user.role },
    { expiresIn: '15m' }, // Short-lived access token
    { expiresIn: '7d' }   // Long-lived refresh token
  );
  
  // Set refresh token as HTTP-only cookie
  res.cookie('refresh_token', tokens.refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
  });
  
  res.json({
    accessToken: tokens.accessToken,
    expiresIn: tokens.accessExpires
  });
});

// Refresh token endpoint
app.post('/api/refresh', (req, res) => {
  const refreshToken = req.cookies.refresh_token;
  
  if (!refreshToken) {
    return res.status(401).json({ error: 'Refresh token required' });
  }
  
  try {
    const newTokens = jwtManager.refreshAccessToken(refreshToken);
    
    // Set new refresh token
    res.cookie('refresh_token', newTokens.refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });
    
    res.json({
      accessToken: newTokens.accessToken,
      expiresIn: newTokens.accessExpires
    });
  } catch (error) {
    res.status(401).json({ error: 'Invalid refresh token' });
  }
});

// Logout
app.post('/api/logout', authMiddleware(jwtManager), (req, res) => {
  // Blacklist the current token
  jwtManager.blacklistToken(req.token);
  
  // Clear refresh token cookie
  res.clearCookie('refresh_token');
  
  res.json({ message: 'Logged out successfully' });
});
Password Management
javascript
const { JWTManager } = require('jwt-easy-kit');
const jwtManager = new JWTManager({ secret: process.env.JWT_SECRET });

// User registration
app.post('/api/register', async (req, res) => {
  const { email, password } = req.body;
  
  // Hash password
  const hashedPassword = await jwtManager.hashPassword(password);
  
  // Save user to database
  const user = await User.create({
    email,
    password: hashedPassword
  });
  
  // Create token for new user
  const token = jwtManager.createToken({
    userId: user.id,
    email: user.email
  });
  
  res.status(201).json({ token, user: { id: user.id, email: user.email } });
});

// Change password
app.post('/api/change-password', 
  authMiddleware(jwtManager),
  async (req, res) => {
    const { currentPassword, newPassword } = req.body;
    const userId = req.user.userId;
    
    // Get user from database
    const user = await User.findById(userId);
    
    // Verify current password
    const isValid = await jwtManager.comparePassword(currentPassword, user.password);
    if (!isValid) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }
    
    // Hash new password
    const newHashedPassword = await jwtManager.hashPassword(newPassword);
    
    // Update user password
    user.password = newHashedPassword;
    await user.save();
    
    // Blacklist all existing tokens for this user (optional)
    // Implement your own logic based on your token store
    
    res.json({ message: 'Password changed successfully' });
  }
);
Custom Error Handling
javascript
const { authMiddleware } = require('jwt-easy-kit');

const customErrorHandler = (error, req, res, next) => {
  // Custom error responses
  const errorMap = {
    'TokenExpiredError': {
      status: 419,
      code: 'TOKEN_EXPIRED',
      message: 'Your session has expired. Please log in again.'
    },
    'JsonWebTokenError': {
      status: 401,
      code: 'INVALID_TOKEN',
      message: 'Invalid authentication token.'
    },
    'default': {
      status: 401,
      code: 'AUTH_ERROR',
      message: 'Authentication failed.'
    }
  };
  
  const errorConfig = errorMap[error.name] || errorMap.default;
  
  res.status(errorConfig.status).json({
    error: errorConfig.code,
    message: errorConfig.message,
    details: process.env.NODE_ENV === 'development' ? error.message : undefined
  });
};

// Use custom error handler
app.get('/api/protected',
  authMiddleware(jwtManager, { onError: customErrorHandler }),
  (req, res) => {
    res.json({ message: 'Access granted' });
  }
);
🏗️ Project Structure
text
jwt-easy-kit/
├── src/
│   ├── index.js          # Main entry point
│   ├── JWTManager.js     # Core JWT management class
│   ├── middlewares.js    # Express middlewares
│   └── utils.js          # Utility functions
├── tests/
│   ├── JWTManager.test.js
│   ├── middlewares.test.js
│   └── utils.test.js
├── examples/
│   ├── basic-usage.js
│   ├── express-app.js
│   └── refresh-token-flow.js
├── package.json
├── README.md
├── LICENSE
└── .gitignore
🧪 Testing
Run the test suite:

bash
# Run all tests
npm test

# Run tests with watch mode
npm run test:watch

# Run tests with coverage report
npm run test:coverage

# Run specific test file
npx jest tests/JWTManager.test.js
🔒 Security Best Practices
Use Environment Variables for Secrets

javascript
new JWTManager({
  secret: process.env.JWT_SECRET
});
Set Appropriate Token Expirations

javascript
// Short-lived access tokens, longer-lived refresh tokens
createTokenPair(payload, 
  { expiresIn: '15m' }, // Access: 15 minutes
  { expiresIn: '7d' }    // Refresh: 7 days
);
Use HTTPS in Production
Always deploy with HTTPS enabled.

Implement Token Refresh
Use refresh tokens to avoid frequent logins.

Store Refresh Tokens Securely
Use HTTP-only cookies for refresh tokens.

Implement Rate Limiting
Protect authentication endpoints from brute force attacks.

Regular Token Cleanup

javascript
// Periodically cleanup expired tokens
setInterval(() => {
  jwtManager.cleanup();
}, 24 * 60 * 60 * 1000); // Daily
📚 Migration Guide
From v0.x to v1.0
The secret parameter is now required in constructor

Added TypeScript definitions

Improved error messages

Added token cleanup functionality

🤝 Contributing
Contributions are welcome! Please feel free to submit a Pull Request.

Fork the repository

Create your feature branch (git checkout -b feature/AmazingFeature)

Commit your changes (git commit -m 'Add some AmazingFeature')

Push to the branch (git push origin feature/AmazingFeature)

Open a Pull Request

📄 License
This project is licensed under the MIT License - see the LICENSE file for details.

🆘 Support
🐛 Report Bugs

💡 Request Features

❓ Ask Questions

📊 Changelog
v1.0.0
Initial release

Complete JWT management system

Express middleware support

Password utilities

Comprehensive test suite (85%+ coverage)

Production-ready features

Made with ❤️ by [Your Name]

⭐ Show Your Support
If you find this package useful, please consider giving it a star on GitHub!

🔗 Related Projects
express-jwt - JWT middleware for Express

jsonwebtoken - JSON Web Token implementation

passport-jwt - Passport strategy for JWT

🚀 Ready to Use?
Install now and streamline your authentication:

bash
npm install jwt-easy-kit