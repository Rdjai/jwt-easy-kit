const { JWTManager } = require('./JWTManager.js');

const authMiddleware = (jwtManager, options = {}) => {
    const {
        tokenSource = 'header',
        tokenKey = 'authorization',
        cookieName = 'token',
        queryParam = 'token',
        allowUnauthenticated = false,
        onError = null
    } = options;

    return async (req, res, next) => {
        let token;

        switch (tokenSource) {
            case 'header':
                const authHeader = req.headers[tokenKey] || req.headers[tokenKey.toLowerCase()];
                if (authHeader && authHeader.startsWith('Bearer ')) {
                    token = authHeader.substring(7);
                }
                break;

            case 'cookie':
                token = req.cookies ? req.cookies[cookieName] : null;
                break;

            case 'query':
                token = req.query[queryParam];
                break;

            default:
                token = req.headers['authorization']?.replace('Bearer ', '');
        }

        if (!token) {
            if (allowUnauthenticated) {
                req.user = null;
                return next();
            }

            const error = new Error('No authentication token provided');
            error.status = 401;

            if (onError) {
                return onError(error, req, res, next);
            }

            return res.status(401).json({
                error: 'Authentication required',
                message: 'No token provided'
            });
        }

        try {
            const decoded = jwtManager.verifyToken(token);

            req.user = decoded;
            req.token = token;

            next();
        } catch (error) {
            error.status = 401;

            if (onError) {
                return onError(error, req, res, next);
            }

            const response = {
                error: 'Authentication failed',
                message: error.message
            };

            if (error.name === 'TokenExpiredError') {
                response.message = 'Token has expired';
            } else if (error.name === 'JsonWebTokenError') {
                response.message = 'Invalid token';
            }

            return res.status(401).json(response);
        }
    };
};

const roleMiddleware = (allowedRoles) => {
    const roles = Array.isArray(allowedRoles) ? allowedRoles : [allowedRoles];

    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({ error: 'Authentication required' });
        }

        const userRole = req.user.role || req.user.roles;

        if (!userRole) {
            return res.status(403).json({ error: 'User role not found' });
        }

        const hasRole = roles.some(role => {
            if (Array.isArray(userRole)) {
                return userRole.includes(role);
            }
            return userRole === role;
        });

        if (!hasRole) {
            return res.status(403).json({
                error: 'Insufficient permissions',
                message: `Required roles: ${roles.join(', ')}`
            });
        }

        next();
    };
};

const permissionMiddleware = (requiredPermissions) => {
    const permissions = Array.isArray(requiredPermissions)
        ? requiredPermissions
        : [requiredPermissions];

    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({ error: 'Authentication required' });
        }

        const userPermissions = req.user.permissions || [];

        const hasAllPermissions = permissions.every(permission =>
            userPermissions.includes(permission)
        );

        if (!hasAllPermissions) {
            return res.status(403).json({
                error: 'Insufficient permissions',
                message: `Required permissions: ${permissions.join(', ')}`
            });
        }

        next();
    };
};

const rateLimitMiddleware = (limiter) => {
    return (req, res, next) => {
        limiter(req, res, next);
    };
};

module.exports = {
    authMiddleware,
    roleMiddleware,
    permissionMiddleware,
    rateLimitMiddleware
};