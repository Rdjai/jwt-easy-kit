/**
 * Utility functions for JWT Easy Kit
 */
const validateOptions = (options) => {
    const defaults = {
        expiresIn: '1h',
        algorithm: 'HS256',
        issuer: 'jwt-easy-kit',
        audience: 'user'
    };

    // Merge options with defaults, but don't override with undefined
    const validated = { ...defaults };
    for (const [key, value] of Object.entries(options)) {
        if (value !== undefined) {
            validated[key] = value;
        }
    }

    if (!validated.secret) {
        throw new Error('JWT secret is required');
    }

    if (validated.expiresIn !== undefined &&
        typeof validated.expiresIn !== 'string' &&
        typeof validated.expiresIn !== 'number') {
        throw new Error('expiresIn must be a string or number');
    }

    return validated;
};

const sanitizePayload = (payload) => {
    if (typeof payload !== 'object' || payload === null) {
        throw new Error('Payload must be an object');
    }

    // Handle arrays by converting them to objects
    if (Array.isArray(payload)) {
        const result = {};
        payload.forEach((item, index) => {
            if (item !== undefined) {
                result[index] = item;
            }
        });
        return result;
    }

    // Handle regular objects
    const sanitized = {};
    for (const [key, value] of Object.entries(payload)) {
        if (value !== undefined) {
            sanitized[key] = value;
        }
    }

    return sanitized;
};

const generateTokenId = () => {
    return require('crypto').randomBytes(16).toString('hex');
};

const isTokenExpired = (exp) => {
    if (exp === undefined || exp === null) {
        return false;
    }

    const currentTime = Math.floor(Date.now() / 1000);
    return exp < currentTime;
};

const delay = (ms) => new Promise(resolve => setTimeout(resolve, ms));

module.exports = {
    validateOptions,
    sanitizePayload,
    generateTokenId,
    isTokenExpired,
    delay
};