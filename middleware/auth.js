const jwtManager = require('../utils/jwtManager');
const logger = require('../utils/logger');
const { findUserById } = require('../models/users');

/**
 * Enhanced authentication middleware with comprehensive JWT validation
 */
function authenticateToken(req, res, next) {
    const authHeader = (req.headers && req.headers['authorization']) || null;
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN
    const clientIp = req.ip || req.connection.remoteAddress;
    const userAgent = (req.headers && req.headers['user-agent']) || 'Unknown';

    if (!token) {
        logger.warnLogger('Access token missing', {
            ip: clientIp,
            path: req.path,
            userAgent: userAgent
        });
        return res.status(401).json({
            error: 'Access token required',
            code: 'TOKEN_MISSING'
        });
    }

    // Verify token with comprehensive validation
    const validation = jwtManager.verifyAccessToken(token, {
        ipAddress: clientIp,
        userAgent: userAgent
    });

    if (!validation.valid) {
        logger.warnLogger('Access token verification failed', {
            ip: clientIp,
            path: req.path,
            userAgent: userAgent,
            error: validation.error
        });

        // Provide specific error messages based on failure reason
        if (validation.error.includes('expired')) {
            return res.status(401).json({
                error: 'Token expired',
                code: 'TOKEN_EXPIRED',
                message: 'Please refresh your token'
            });
        }

        if (validation.error.includes('blacklisted')) {
            return res.status(401).json({
                error: 'Token has been revoked',
                code: 'TOKEN_BLACKLISTED',
                message: 'Please login again'
            });
        }

        return res.status(403).json({
            error: 'Invalid token',
            code: 'TOKEN_INVALID',
            message: validation.error
        });
    }

    // Add user information to request
    req.user = validation.user;
    req.tokenData = validation.decoded;
    req.clientInfo = {
        ipAddress: clientIp,
        userAgent: userAgent
    };

    logger.infoLogger('Token authenticated successfully', {
        userId: req.user.id,
        email: req.user.email,
        role: req.user.role,
        sessionId: validation.decoded.sessionId,
        jti: validation.decoded.jti,
        ip: clientIp,
        path: req.path
    });

    next();
}

/**
 * Enhanced role-based authorization middleware
 * @param {string|Array} requiredRoles - Required role(s)
 * @param {Array} requiredScopes - Required scopes (optional)
 */
function requireRole(requiredRoles, requiredScopes = []) {
    return (req, res, next) => {
        if (!req.user || !req.tokenData) {
            return res.status(401).json({
                error: 'Authentication required',
                code: 'AUTH_REQUIRED'
            });
        }

        const userRoles = Array.isArray(req.user.role) ? req.user.role : [req.user.role];
        const roles = Array.isArray(requiredRoles) ? requiredRoles : [requiredRoles];

        // Check roles
        const hasRole = roles.some(role => userRoles.includes(role));
        
        if (!hasRole) {
            logger.warnLogger('Access denied - insufficient role', {
                userId: req.user.id,
                userRoles: userRoles,
                requiredRoles: roles,
                path: req.path,
                sessionId: req.tokenData.sessionId
            });
            return res.status(403).json({
                error: 'Insufficient permissions',
                code: 'INSUFFICIENT_ROLE',
                message: `Required role: ${roles.join(' or ')}, your role: ${userRoles.join(', ')}`
            });
        }

        // Check scopes if provided
        if (requiredScopes.length > 0) {
            const userScopes = req.tokenData.scopes || [];
            const hasRequiredScopes = requiredScopes.every(scope => userScopes.includes(scope));
            
            if (!hasRequiredScopes) {
                logger.warnLogger('Access denied - insufficient scopes', {
                    userId: req.user.id,
                    userScopes: userScopes,
                    requiredScopes: requiredScopes,
                    path: req.path,
                    sessionId: req.tokenData.sessionId
                });
                return res.status(403).json({
                    error: 'Insufficient permissions',
                    code: 'INSUFFICIENT_SCOPES',
                    message: `Required scopes: ${requiredScopes.join(', ')}, your scopes: ${userScopes.join(', ')}`
                });
            }
        }

        logger.infoLogger('Role authorization successful', {
            userId: req.user.id,
            role: req.user.role,
            scopes: req.tokenData.scopes,
            path: req.path,
            sessionId: req.tokenData.sessionId
        });

        next();
    };
}

/**
 * Scope-based authorization middleware
 * @param {Array} requiredScopes - Array of required scopes
 */
function requireScopes(requiredScopes) {
    return (req, res, next) => {
        if (!req.user || !req.tokenData) {
            return res.status(401).json({
                error: 'Authentication required',
                code: 'AUTH_REQUIRED'
            });
        }

        const userScopes = req.tokenData.scopes || [];
        const hasAllScopes = requiredScopes.every(scope => userScopes.includes(scope));

        if (!hasAllScopes) {
            logger.warnLogger('Access denied - missing required scopes', {
                userId: req.user.id,
                userScopes: userScopes,
                requiredScopes: requiredScopes,
                path: req.path,
                sessionId: req.tokenData.sessionId
            });
            return res.status(403).json({
                error: 'Insufficient permissions',
                code: 'MISSING_SCOPES',
                message: `Required scopes: ${requiredScopes.join(', ')}`
            });
        }

        logger.infoLogger('Scope authorization successful', {
            userId: req.user.id,
            scopes: userScopes,
            requiredScopes: requiredScopes,
            path: req.path,
            sessionId: req.tokenData.sessionId
        });

        next();
    };
}

/**
 * Client validation middleware
 * @param {Array} allowedClients - Array of allowed client IDs
 */
function requireClient(allowedClients) {
    return (req, res, next) => {
        if (!req.tokenData) {
            return res.status(401).json({
                error: 'Token required',
                code: 'TOKEN_REQUIRED'
            });
        }

        const clientId = req.tokenData.clientId;
        if (!allowedClients.includes(clientId)) {
            logger.warnLogger('Access denied - unauthorized client', {
                clientId: clientId,
                allowedClients: allowedClients,
                path: req.path,
                userId: req.user?.id
            });
            return res.status(403).json({
                error: 'Unauthorized client',
                code: 'UNAUTHORIZED_CLIENT'
            });
        }

        next();
    };
}

/**
 * Rate limiting middleware based on user and endpoint
 */
function userRateLimit(maxRequests = 60, windowMs = 15 * 60 * 1000) {
    const userRequests = new Map();

    return (req, res, next) => {
        if (!req.user) {
            return next();
        }

        const userId = req.user.id.toString();
        const now = Date.now();
        const windowStart = now - windowMs;

        // Clean old entries
        if (userRequests.has(userId)) {
            userRequests.set(userId, userRequests.get(userId).filter(timestamp => timestamp > windowStart));
        }

        // Check current requests
        const requests = userRequests.get(userId) || [];
        if (requests.length >= maxRequests) {
            logger.warnLogger('User rate limit exceeded', {
                userId: req.user.id,
                email: req.user.email,
                path: req.path,
                requestsCount: requests.length,
                limit: maxRequests
            });
            return res.status(429).json({
                error: 'Rate limit exceeded',
                code: 'RATE_LIMIT_EXCEEDED',
                message: `Maximum ${maxRequests} requests per ${Math.ceil(windowMs / 1000 / 60)} minutes`
            });
        }

        // Add current request
        requests.push(now);
        userRequests.set(userId, requests);

        // Add rate limit headers
        res.set({
            'X-RateLimit-Limit': maxRequests,
            'X-RateLimit-Remaining': maxRequests - requests.length,
            'X-RateLimit-Reset': new Date(windowStart + windowMs).toISOString()
        });

        next();
    };
}

/**
 * Session validation middleware
 */
function validateSession(req, res, next) {
    if (!req.user || !req.tokenData) {
        return res.status(401).json({
            error: 'Session validation failed',
            code: 'SESSION_INVALID'
        });
    }

    // Additional session validation can be added here
    // For example, checking session IP address, user agent, etc.
    
    logger.debugLogger('Session validation passed', {
        userId: req.user.id,
        sessionId: req.tokenData.sessionId,
        path: req.path
    });

    next();
}

module.exports = {
    authenticateToken,
    requireRole,
    requireScopes,
    requireClient,
    userRateLimit,
    validateSession,
    jwtManager
};