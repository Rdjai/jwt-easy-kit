const { authMiddleware, roleMiddleware, permissionMiddleware } = require('../src/middlewares.js');
const { JWTManager } = require('../src/JWTManager.js');

describe('Middlewares', () => {
    let jwtManager;
    const secret = 'test-secret-key-123';

    beforeEach(() => {
        jwtManager = new JWTManager({ secret });
    });

    describe('authMiddleware', () => {
        const mockReq = (headers = {}, cookies = {}, query = {}) => ({
            headers,
            cookies,
            query,
            user: null,
            token: null
        });

        const mockRes = () => ({
            status: jest.fn().mockReturnThis(),
            json: jest.fn()
        });

        const mockNext = jest.fn();

        test('should extract token from header', async () => {
            const token = jwtManager.createToken({ userId: '123' });
            const req = mockReq({ authorization: `Bearer ${token}` });
            const res = mockRes();

            const middleware = authMiddleware(jwtManager);

            await middleware(req, res, mockNext);

            expect(req.user).toBeDefined();
            expect(req.user.userId).toBe('123');
            expect(mockNext).toHaveBeenCalled();
        });

        test('should handle missing token', async () => {
            const req = mockReq();
            const res = mockRes();

            const middleware = authMiddleware(jwtManager);

            await middleware(req, res, mockNext);

            expect(res.status).toHaveBeenCalledWith(401);
            expect(res.json).toHaveBeenCalledWith(
                expect.objectContaining({ error: 'Authentication required' })
            );
        });

        test('should handle invalid token', async () => {
            const req = mockReq({ authorization: 'Bearer invalid-token' });
            const res = mockRes();

            const middleware = authMiddleware(jwtManager);

            await middleware(req, res, mockNext);

            expect(res.status).toHaveBeenCalledWith(401);
            expect(res.json).toHaveBeenCalledWith(
                expect.objectContaining({ error: 'Authentication failed' })
            );
        });

        test('should handle expired token', async () => {
            // Create token that expires in 1 second
            const token = jwtManager.createToken({ userId: '123' }, { expiresIn: '1s' });

            // Wait for token to expire
            await new Promise(resolve => setTimeout(resolve, 2000));

            const req = mockReq({ authorization: `Bearer ${token}` });
            const res = mockRes();

            const middleware = authMiddleware(jwtManager);

            await middleware(req, res, mockNext);

            expect(res.status).toHaveBeenCalledWith(401);
            expect(res.json).toHaveBeenCalledWith(
                expect.objectContaining({
                    error: 'Authentication failed',
                    message: expect.stringContaining('expired') // Check for any message containing 'expired'
                })
            );
        }, 10000);

        test('should allow unauthenticated when configured', async () => {
            const req = mockReq();
            const res = mockRes();

            const middleware = authMiddleware(jwtManager, { allowUnauthenticated: true });

            await middleware(req, res, mockNext);

            expect(req.user).toBeNull();
            expect(mockNext).toHaveBeenCalled();
        });

        test('should extract token from cookies', async () => {
            const token = jwtManager.createToken({ userId: '123' });
            const req = mockReq({}, { token });
            const res = mockRes();

            const middleware = authMiddleware(jwtManager, { tokenSource: 'cookie' });

            await middleware(req, res, mockNext);

            expect(req.user).toBeDefined();
            expect(req.user.userId).toBe('123');
        });

        test('should extract token from query parameters', async () => {
            const token = jwtManager.createToken({ userId: '123' });
            const req = mockReq({}, {}, { token });
            const res = mockRes();

            const middleware = authMiddleware(jwtManager, {
                tokenSource: 'query',
                queryParam: 'token'
            });

            await middleware(req, res, mockNext);

            expect(req.user).toBeDefined();
            expect(req.user.userId).toBe('123');
        });

        test('should use custom header key', async () => {
            const token = jwtManager.createToken({ userId: '123' });
            const req = mockReq({ 'x-auth-token': `Bearer ${token}` });
            const res = mockRes();

            const middleware = authMiddleware(jwtManager, { tokenKey: 'x-auth-token' });

            await middleware(req, res, mockNext);

            expect(req.user).toBeDefined();
            expect(req.user.userId).toBe('123');
        });

        test('should use custom error handler', async () => {
            const req = mockReq();
            const res = mockRes();
            const customErrorHandler = jest.fn();

            const middleware = authMiddleware(jwtManager, { onError: customErrorHandler });

            await middleware(req, res, mockNext);

            expect(customErrorHandler).toHaveBeenCalled();
            expect(res.status).not.toHaveBeenCalled();
        });

        test('should handle blacklisted token', async () => {
            const token = jwtManager.createToken({ userId: '123' });
            jwtManager.blacklistToken(token);

            const req = mockReq({ authorization: `Bearer ${token}` });
            const res = mockRes();

            const middleware = authMiddleware(jwtManager);

            await middleware(req, res, mockNext);

            expect(res.status).toHaveBeenCalledWith(401);
            expect(res.json).toHaveBeenCalledWith(
                expect.objectContaining({ error: 'Authentication failed' })
            );
        });
    });

    describe('roleMiddleware', () => {
        const mockReq = (user) => ({
            user,
            token: 'test-token'
        });

        const mockRes = () => ({
            status: jest.fn().mockReturnThis(),
            json: jest.fn()
        });

        const mockNext = jest.fn();

        test('should allow access for user with required role', () => {
            const req = mockReq({ role: 'admin' });
            const res = mockRes();

            const middleware = roleMiddleware('admin');
            middleware(req, res, mockNext);

            expect(mockNext).toHaveBeenCalled();
        });

        test('should allow access for user with one of required roles', () => {
            const req = mockReq({ role: 'editor' });
            const res = mockRes();

            const middleware = roleMiddleware(['admin', 'editor', 'viewer']);
            middleware(req, res, mockNext);

            expect(mockNext).toHaveBeenCalled();
        });

        test('should deny access for user without required role', () => {
            const req = mockReq({ role: 'viewer' });
            const res = mockRes();

            const middleware = roleMiddleware('admin');
            middleware(req, res, mockNext);

            expect(res.status).toHaveBeenCalledWith(403);
            expect(res.json).toHaveBeenCalledWith(
                expect.objectContaining({ error: 'Insufficient permissions' })
            );
        });

        test('should handle user with array of roles', () => {
            const req = mockReq({ roles: ['admin', 'editor'] });
            const res = mockRes();

            const middleware = roleMiddleware('admin');
            middleware(req, res, mockNext);

            expect(mockNext).toHaveBeenCalled();
        });

        test('should require authentication', () => {
            const req = mockReq(null); // No user
            const res = mockRes();

            const middleware = roleMiddleware('admin');
            middleware(req, res, mockNext);

            expect(res.status).toHaveBeenCalledWith(401);
            expect(res.json).toHaveBeenCalledWith(
                expect.objectContaining({ error: 'Authentication required' })
            );
        });

        test('should handle user without role property', () => {
            const req = mockReq({ userId: '123' }); // No role
            const res = mockRes();

            const middleware = roleMiddleware('admin');
            middleware(req, res, mockNext);

            expect(res.status).toHaveBeenCalledWith(403);
            expect(res.json).toHaveBeenCalledWith(
                expect.objectContaining({ error: 'User role not found' })
            );
        });
    });

    describe('permissionMiddleware', () => {
        const mockReq = (user) => ({
            user,
            token: 'test-token'
        });

        const mockRes = () => ({
            status: jest.fn().mockReturnThis(),
            json: jest.fn()
        });

        const mockNext = jest.fn();

        test('should allow access for user with required permissions', () => {
            const req = mockReq({ permissions: ['read:users', 'write:users'] });
            const res = mockRes();

            const middleware = permissionMiddleware('read:users');
            middleware(req, res, mockNext);

            expect(mockNext).toHaveBeenCalled();
        });

        test('should allow access for user with all required permissions', () => {
            const req = mockReq({ permissions: ['read:users', 'write:users', 'delete:users'] });
            const res = mockRes();

            const middleware = permissionMiddleware(['read:users', 'write:users']);
            middleware(req, res, mockNext);

            expect(mockNext).toHaveBeenCalled();
        });

        test('should deny access for user missing some permissions', () => {
            const req = mockReq({ permissions: ['read:users'] });
            const res = mockRes();

            const middleware = permissionMiddleware(['read:users', 'write:users']);
            middleware(req, res, mockNext);

            expect(res.status).toHaveBeenCalledWith(403);
            expect(res.json).toHaveBeenCalledWith(
                expect.objectContaining({ error: 'Insufficient permissions' })
            );
        });

        test('should require authentication', () => {
            const req = mockReq(null);
            const res = mockRes();

            const middleware = permissionMiddleware('read:users');
            middleware(req, res, mockNext);

            expect(res.status).toHaveBeenCalledWith(401);
            expect(res.json).toHaveBeenCalledWith(
                expect.objectContaining({ error: 'Authentication required' })
            );
        });

        test('should handle user without permissions property', () => {
            const req = mockReq({ userId: '123' });
            const res = mockRes();

            const middleware = permissionMiddleware('read:users');
            middleware(req, res, mockNext);

            expect(res.status).toHaveBeenCalledWith(403);
            expect(res.json).toHaveBeenCalledWith(
                expect.objectContaining({ error: 'Insufficient permissions' })
            );
        });

        test('should handle empty permissions array', () => {
            const req = mockReq({ permissions: [] });
            const res = mockRes();

            const middleware = permissionMiddleware('read:users');
            middleware(req, res, mockNext);

            expect(res.status).toHaveBeenCalledWith(403);
            expect(res.json).toHaveBeenCalledWith(
                expect.objectContaining({ error: 'Insufficient permissions' })
            );
        });
    });
});