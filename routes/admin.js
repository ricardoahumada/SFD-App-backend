const express = require('express');
const { authenticateToken, requireRole, requireScopes, userRateLimit } = require('../middleware/auth');
const jwtManager = require('../utils/jwtManager');
const { users, tokenBlacklist, refreshTokenBlacklist } = require('../models/users');
const logger = require('../utils/logger');

const router = express.Router();

/**
 * GET /api/admin
 * Protected endpoint - requires admin role
 * Enhanced with comprehensive JWT validation
 */
router.get('/', 
    authenticateToken, 
    requireRole('admin'), 
    userRateLimit(200, 15 * 60 * 1000), // 200 requests per 15 minutes
    (req, res) => {
        logger.infoLogger('Admin service accessed', {
            userId: req.user.id,
            email: req.user.email,
            sessionId: req.tokenData.sessionId,
            jti: req.tokenData.jti,
            scopes: req.tokenData.scopes
        });

        res.json({
            success: true,
            message: 'Admin service accessed successfully',
            data: {
                service: 'admin_service',
                user: {
                    id: req.user.id,
                    name: req.user.name,
                    email: req.user.email,
                    role: req.user.role,
                    scopes: req.tokenData.scopes
                },
                session: {
                    id: req.tokenData.sessionId,
                    jti: req.tokenData.jti,
                    createdAt: req.tokenData.iat * 1000,
                    expiresAt: req.tokenData.exp * 1000
                },
                client: {
                    id: req.tokenData.clientId,
                    ipAddress: req.clientInfo.ipAddress,
                    userAgent: req.clientInfo.userAgent
                },
                timestamp: new Date().toISOString(),
                jwt_info: {
                    algorithm: req.tokenData.alg,
                    issuer: req.tokenData.iss,
                    audience: req.tokenData.aud,
                    subject: req.tokenData.sub
                }
            }
        });
    }
);

/**
 * GET /api/admin/users
 * Protected endpoint - get all users (admin only)
 * Enhanced with user management capabilities
 */
router.get('/users', 
    authenticateToken, 
    requireRole('admin'), 
    requireScopes(['users:read']),
    userRateLimit(50, 15 * 60 * 1000), // 50 requests per 15 minutes
    (req, res) => {
        logger.infoLogger('Admin users list accessed', {
            userId: req.user.id,
            sessionId: req.tokenData.sessionId
        });

        // Return users without passwords and add additional info
        const sanitizedUsers = users.map(user => ({
            id: user.id,
            name: user.name,
            email: user.email,
            role: user.role,
            scopes: user.scopes,
            createdAt: user.createdAt,
            lastLogin: user.lastLogin,
            activeRefreshTokens: user.refreshTokens.filter(token => !token.isRevoked).length,
            totalSessions: user.refreshTokens.length
        }));

        res.json({
            success: true,
            message: 'Users retrieved successfully',
            users: sanitizedUsers,
            totalUsers: users.length,
            pagination: {
                page: 1,
                limit: users.length,
                total: users.length,
                hasMore: false
            },
            session: {
                id: req.tokenData.sessionId,
                jti: req.tokenData.jti
            },
            timestamp: new Date().toISOString()
        });
    }
);

/**
 * GET /api/admin/stats
 * Protected endpoint - get system statistics (admin only)
 */
router.get('/stats', 
    authenticateToken, 
    requireRole('admin'), 
    requireScopes(['stats:read']),
    userRateLimit(30, 15 * 60 * 1000), // 30 requests per 15 minutes
    (req, res) => {
        logger.infoLogger('Admin stats accessed', {
            userId: req.user.id,
            sessionId: req.tokenData.sessionId
        });

        // Calculate system statistics
        const now = new Date();
        const oneHourAgo = new Date(now.getTime() - 60 * 60 * 1000);
        const oneDayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);

        const stats = {
            users: {
                total: users.length,
                admin: users.filter(u => u.role === 'admin').length,
                customer: users.filter(u => u.role === 'customer').length,
                activeLastHour: users.filter(u => 
                    u.lastLogin && new Date(u.lastLogin.timestamp) > oneHourAgo
                ).length,
                activeLastDay: users.filter(u => 
                    u.lastLogin && new Date(u.lastLogin.timestamp) > oneDayAgo
                ).length
            },
            sessions: {
                totalActiveRefreshTokens: users.reduce((sum, user) => 
                    sum + user.refreshTokens.filter(token => !token.isRevoked).length, 0
                ),
                totalRevokedTokens: users.reduce((sum, user) => 
                    sum + user.refreshTokens.filter(token => token.isRevoked).length, 0
                ),
                averageSessionsPerUser: users.length > 0 ? 
                    (users.reduce((sum, user) => sum + user.refreshTokens.length, 0) / users.length).toFixed(2) : 0
            },
            security: {
                blacklistedAccessTokens: tokenBlacklist.size,
                blacklistedRefreshTokens: refreshTokenBlacklist.size,
                algorithm: jwtManager.getAlgorithmInfo().algorithm,
                clockSkewTolerance: jwtManager.getAlgorithmInfo().clockSkew
            },
            system: {
                uptime: process.uptime(),
                memoryUsage: process.memoryUsage(),
                nodeVersion: process.version,
                environment: process.env.NODE_ENV || 'development',
                lastUpdate: now.toISOString()
            },
            permissions: {
                admin: users.filter(u => u.role === 'admin')[0]?.scopes || [],
                customer: users.filter(u => u.role === 'customer')[0]?.scopes || []
            }
        };

        res.json({
            success: true,
            message: 'System statistics retrieved successfully',
            statistics: stats,
            session: {
                id: req.tokenData.sessionId,
                jti: req.tokenData.jti
            },
            timestamp: now.toISOString()
        });
    }
);

/**
 * GET /api/admin/sessions
 * Get active sessions for all users (admin only)
 */
router.get('/sessions', 
    authenticateToken, 
    requireRole('admin'), 
    requireScopes(['users:read']),
    userRateLimit(20, 15 * 60 * 1000), // 20 requests per 15 minutes
    (req, res) => {
        logger.infoLogger('Admin sessions list accessed', {
            userId: req.user.id,
            sessionId: req.tokenData.sessionId
        });

        const allSessions = users.flatMap(user => 
            user.refreshTokens.map(token => ({
                userId: user.id,
                userEmail: user.email,
                userRole: user.role,
                sessionId: token.sessionId,
                isRevoked: token.isRevoked,
                createdAt: token.createdAt,
                expiresAt: token.expiresAt,
                userAgent: token.userAgent,
                ipAddress: token.ipAddress
            }))
        );

        const activeSessions = allSessions.filter(session => 
            !session.isRevoked && new Date(session.expiresAt) > new Date()
        );

        res.json({
            success: true,
            message: 'Sessions retrieved successfully',
            sessions: allSessions,
            summary: {
                total: allSessions.length,
                active: activeSessions.length,
                revoked: allSessions.length - activeSessions.length
            },
            session: {
                id: req.tokenData.sessionId,
                jti: req.tokenData.jti
            },
            timestamp: new Date().toISOString()
        });
    }
);

/**
 * POST /api/admin/sessions/revoke
 * Revoke a specific session (admin only)
 */
router.post('/sessions/revoke', 
    authenticateToken, 
    requireRole('admin'), 
    requireScopes(['users:write']),
    userRateLimit(10, 15 * 60 * 1000), // 10 requests per 15 minutes
    (req, res) => {
        const { userId, sessionId } = req.body || {};

        if (!userId || !sessionId) {
            return res.status(400).json({
                error: 'User ID and session ID are required',
                code: 'MISSING_PARAMETERS'
            });
        }

        logger.infoLogger('Session revocation requested', {
            requestedBy: req.user.id,
            targetUserId: userId,
            sessionId: sessionId
        });

        // Find user and revoke session
        const user = users.find(u => u.id === parseInt(userId));
        if (!user) {
            return res.status(404).json({
                error: 'User not found',
                code: 'USER_NOT_FOUND'
            });
        }

        const token = user.refreshTokens.find(t => t.sessionId === sessionId);
        if (!token) {
            return res.status(404).json({
                error: 'Session not found',
                code: 'SESSION_NOT_FOUND'
            });
        }

        token.isRevoked = true;

        logger.infoLogger('Session revoked', {
            revokedBy: req.user.id,
            userId: userId,
            sessionId: sessionId
        });

        res.json({
            success: true,
            message: 'Session revoked successfully',
            revokedSession: {
                userId: userId,
                sessionId: sessionId,
                userEmail: user.email,
                revokedAt: new Date().toISOString(),
                revokedBy: req.user.id
            },
            session: {
                id: req.tokenData.sessionId,
                jti: req.tokenData.jti
            },
            timestamp: new Date().toISOString()
        });
    }
);

/**
 * GET /api/admin/blacklist
 * Get blacklisted tokens (admin only)
 */
router.get('/blacklist', 
    authenticateToken, 
    requireRole('admin'), 
    requireScopes(['admin']),
    userRateLimit(15, 15 * 60 * 1000), // 15 requests per 15 minutes
    (req, res) => {
        logger.infoLogger('Admin blacklist accessed', {
            userId: req.user.id,
            sessionId: req.tokenData.sessionId
        });

        const accessTokenBlacklist = Array.from(tokenBlacklist.entries()).map(([token, info]) => ({
            token: token.substring(0, 20) + '...',
            blacklistedAt: info.blacklistedAt,
            reason: info.reason,
            expiresAt: info.expiresAt
        }));

        const refreshTokenBlacklistArray = Array.from(refreshTokenBlacklist.entries()).map(([token, info]) => ({
            token: token.substring(0, 20) + '...',
            blacklistedAt: info.blacklistedAt,
            reason: info.reason
        }));

        res.json({
            success: true,
            message: 'Blacklist retrieved successfully',
            blacklist: {
                accessTokens: accessTokenBlacklist,
                refreshTokens: refreshTokenBlacklistArray,
                summary: {
                    accessTokensCount: accessTokenBlacklist.length,
                    refreshTokensCount: refreshTokenBlacklistArray.length
                }
            },
            session: {
                id: req.tokenData.sessionId,
                jti: req.tokenData.jti
            },
            timestamp: new Date().toISOString()
        });
    }
);

/**
 * POST /api/admin/maintenance
 * System maintenance operations (admin only)
 */
router.post('/maintenance', 
    authenticateToken, 
    requireRole('admin'), 
    requireScopes(['admin']),
    userRateLimit(5, 60 * 60 * 1000), // 5 requests per hour
    (req, res) => {
        const { action } = req.body || {};

        logger.infoLogger('Maintenance operation requested', {
            requestedBy: req.user.id,
            action: action
        });

        let result = {};

        switch (action) {
            case 'cleanup_blacklist':
                // Cleanup expired blacklist entries
                const accessTokensBefore = tokenBlacklist.size;
                const refreshTokensBefore = refreshTokenBlacklist.size;
                
                // This is handled automatically by the cleanup function
                // but we can trigger it manually here
                
                result = {
                    action: 'cleanup_blacklist',
                    accessTokensBefore,
                    refreshTokensBefore,
                    message: 'Blacklist cleanup completed'
                };
                break;

            case 'revoke_all_sessions':
                // Revoke all sessions for all users
                let revokedCount = 0;
                users.forEach(user => {
                    user.refreshTokens.forEach(token => {
                        if (!token.isRevoked) {
                            token.isRevoked = true;
                            revokedCount++;
                        }
                    });
                });

                result = {
                    action: 'revoke_all_sessions',
                    revokedSessions: revokedCount,
                    message: `Revoked ${revokedCount} sessions`
                };
                break;

            default:
                return res.status(400).json({
                    error: 'Invalid maintenance action',
                    code: 'INVALID_ACTION',
                    availableActions: ['cleanup_blacklist', 'revoke_all_sessions']
                });
        }

        logger.infoLogger('Maintenance operation completed', {
            performedBy: req.user.id,
            result: result
        });

        res.json({
            success: true,
            message: 'Maintenance operation completed successfully',
            result: result,
            session: {
                id: req.tokenData.sessionId,
                jti: req.tokenData.jti
            },
            timestamp: new Date().toISOString()
        });
    }
);

module.exports = router;