const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const {
    validateOptions,
    sanitizePayload,
    generateTokenId,
    isTokenExpired
} = require('./utils.js');

class JWTManager {
    constructor(options = {}) {
        const validatedOptions = validateOptions(options);

        this.secret = validatedOptions.secret;

        // Extract and remove secret from options for jwt.sign calls
        const { secret, ...jwtOptions } = validatedOptions;
        this.options = jwtOptions;

        this.blacklist = new Set();
        this.tokenStore = new Map();
    }

    createToken(payload, customOptions = {}) {
        try {
            const sanitizedPayload = sanitizePayload(payload);

            // Merge options without including secret
            const options = { ...this.options, ...customOptions };

            // Remove undefined values from options
            Object.keys(options).forEach(key => {
                if (options[key] === undefined) {
                    delete options[key];
                }
            });

            const finalPayload = {
                ...sanitizedPayload,
                jti: generateTokenId(),
                iat: Math.floor(Date.now() / 1000)
            };

            // Secret is passed separately, not in options
            return jwt.sign(finalPayload, this.secret, options);
        } catch (error) {
            throw new Error(`Failed to create token: ${error.message}`);
        }
    }

    verifyToken(token, customOptions = {}) {
        try {
            if (this.isTokenBlacklisted(token)) {
                throw new Error('Token has been blacklisted');
            }

            const options = { ...this.options, ...customOptions };

            // Secret is passed separately, not in options
            return jwt.verify(token, this.secret, options);
        } catch (error) {
            if (error.message === 'Token has been blacklisted') {
                throw error;
            }
            throw new Error(`Token verification failed: ${error.message}`);
        }
    }

    decodeToken(token) {
        try {
            return jwt.decode(token, { complete: true });
        } catch (error) {
            throw new Error(`Failed to decode token: ${error.message}`);
        }
    }

    createTokenPair(payload, accessOptions = {}, refreshOptions = {}) {
        try {
            const accessToken = this.createToken(payload, {
                expiresIn: accessOptions.expiresIn || '15m',
                ...accessOptions
            });

            const refreshToken = this.createToken(payload, {
                expiresIn: refreshOptions.expiresIn || '7d',
                ...refreshOptions
            });

            const accessDecoded = this.decodeToken(accessToken);
            const refreshDecoded = this.decodeToken(refreshToken);

            this.tokenStore.set(refreshToken, {
                userId: payload.userId || payload.sub,
                createdAt: new Date(),
                expiresAt: new Date(refreshDecoded.payload.exp * 1000)
            });

            return {
                accessToken,
                refreshToken,
                accessExpires: new Date(accessDecoded.payload.exp * 1000),
                refreshExpires: new Date(refreshDecoded.payload.exp * 1000)
            };
        } catch (error) {
            throw new Error(`Failed to create token pair: ${error.message}`);
        }
    }

    refreshAccessToken(refreshToken, additionalPayload = {}) {
        try {
            const decoded = this.verifyToken(refreshToken);

            if (!this.tokenStore.has(refreshToken)) {
                throw new Error('Refresh token not found or invalid');
            }

            const tokenInfo = this.tokenStore.get(refreshToken);

            this.tokenStore.delete(refreshToken);

            // Create new payload without JWT reserved claims
            const newPayload = { ...decoded };

            // Remove JWT reserved claims
            delete newPayload.iat;
            delete newPayload.exp;
            delete newPayload.jti;
            delete newPayload.aud; // Remove audience if present
            delete newPayload.iss; // Remove issuer if present
            delete newPayload.sub; // Remove subject if present

            // Merge with additional payload
            Object.assign(newPayload, additionalPayload);

            return this.createTokenPair(newPayload);
        } catch (error) {
            throw new Error(`Failed to refresh token: ${error.message}`);
        }
    }

    blacklistToken(token) {
        try {
            const decoded = this.decodeToken(token);
            if (decoded && decoded.payload.jti) {
                this.blacklist.add(decoded.payload.jti);
            }
        } catch (error) {
            this.blacklist.add(token);
        }
    }

    isTokenBlacklisted(token) {
        try {
            const decoded = this.decodeToken(token);
            if (decoded && decoded.payload.jti) {
                return this.blacklist.has(decoded.payload.jti);
            }
            // Also check if the token string itself is blacklisted
            return this.blacklist.has(token);
        } catch (error) {
            // If decode throws error, check if token string is blacklisted
            return this.blacklist.has(token);
        }
    }

    // In the hashPassword method, add try-catch:
    async hashPassword(password, saltRounds = 10) {
        try {
            if (!password || typeof password !== 'string') {
                throw new Error('Password must be a non-empty string');
            }
            return await bcrypt.hash(password, saltRounds);
        } catch (error) {
            throw new Error(`Password hashing failed: ${error.message}`);
        }
    }

    // In the comparePassword method, add try-catch:
    async comparePassword(password, hash) {
        try {
            if (!password || typeof password !== 'string') {
                throw new Error('Password must be a non-empty string');
            }
            if (!hash || typeof hash !== 'string') {
                throw new Error('Hash must be a non-empty string');
            }
            return await bcrypt.compare(password, hash);
        } catch (error) {
            throw new Error(`Password comparison failed: ${error.message}`);
        }
    }

    // In the getTokenExpiration method, add try-catch:
    getTokenExpiration(token) {
        try {
            const decoded = this.decodeToken(token);
            if (decoded && decoded.payload.exp) {
                return new Date(decoded.payload.exp * 1000);
            }
            return null;
        } catch (error) {
            throw new Error(`Failed to get token expiration: ${error.message}`);
        }
    }

    async comparePassword(password, hash) {
        try {
            if (!password || typeof password !== 'string') {
                throw new Error('Password must be a non-empty string');
            }
            if (!hash || typeof hash !== 'string') {
                throw new Error('Hash must be a non-empty string');
            }
            return await bcrypt.compare(password, hash);
        } catch (error) {
            throw new Error(`Password comparison failed: ${error.message}`);
        }
    }

    getTokenExpiration(token) {
        try {
            const decoded = this.decodeToken(token);
            if (decoded && decoded.payload.exp) {
                return new Date(decoded.payload.exp * 1000);
            }
            return null;
        } catch (error) {
            throw new Error(`Failed to get token expiration: ${error.message}`);
        }
    }

    isTokenExpired(token) {
        try {
            const decoded = this.decodeToken(token);
            if (decoded && decoded.payload.exp) {
                return isTokenExpired(decoded.payload.exp);
            }
            return true; // If no expiration, consider it invalid/expired
        } catch (error) {
            return true; // If we can't decode, consider it expired/invalid
        }
    }

    revokeRefreshToken(refreshToken) {
        this.tokenStore.delete(refreshToken);
        this.blacklistToken(refreshToken);
    }

    cleanup() {
        const now = new Date();

        for (const [token, info] of this.tokenStore.entries()) {
            if (info.expiresAt < now) {
                this.tokenStore.delete(token);
            }
        }
    }
}

module.exports = { JWTManager };