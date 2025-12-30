const { JWTManager } = require('./JWTManager.js');
const {
    authMiddleware,
    roleMiddleware,
    permissionMiddleware,
    rateLimitMiddleware
} = require('./middlewares.js');

const {
    validateOptions,
    sanitizePayload,
    generateTokenId,
    isTokenExpired,
    delay
} = require('./utils.js');

const JWTKit = {
    JWTManager,
    authMiddleware,
    roleMiddleware,
    permissionMiddleware,
    rateLimitMiddleware,
    utils: {
        validateOptions,
        sanitizePayload,
        generateTokenId,
        isTokenExpired,
        delay
    }
};

module.exports = JWTKit;
module.exports.JWTManager = JWTManager;
module.exports.authMiddleware = authMiddleware;
module.exports.roleMiddleware = roleMiddleware;
module.exports.permissionMiddleware = permissionMiddleware;
module.exports.rateLimitMiddleware = rateLimitMiddleware;
module.exports.validateOptions = validateOptions;
module.exports.sanitizePayload = sanitizePayload;
module.exports.generateTokenId = generateTokenId;
module.exports.isTokenExpired = isTokenExpired;
module.exports.delay = delay;