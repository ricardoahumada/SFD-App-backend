const express = require('express');
const jwtManager = require('../utils/jwtManager');
const { findUserByEmail, findUserById, addRefreshToken, revokeRefreshToken, revokeAllRefreshTokens, updateLastLogin } = require('../models/users');
const { generateSessionId } = require('../models/users');
const { authLogger, tokenLogger, sessionLogger, auditLogger } = require('../utils/logger');

const router = express.Router();

/**
 * POST /api/auth/login
 * Enhanced login with comprehensive JWT token generation
 */
router.post('/login', async (req, res) => {
    const startTime = Date.now();
    const { email, password, clientId = 'web-client' } = req.body || {};
    const clientIp = req.ip || req.connection.remoteAddress;
    const userAgent = (req.headers && req.headers['user-agent']) || 'Unknown';

    try {
        // Input validation
        if (!email || !password) {
            authLogger(false, email || 'missing', clientIp, { 
                event: 'LOGIN_ATTEMPT', 
                reason: 'missing_credentials' 
            });
            return res.status(400).json({ 
                error: 'Email and password are required',
                code: 'MISSING_CREDENTIALS'
            });
        }

        // Find user
        const user = findUserByEmail(email);
        
        if (!user || user.password !== password) {
            authLogger(false, email, clientIp, { 
                event: 'LOGIN_ATTEMPT', 
                reason: 'invalid_credentials',
                userAgent: userAgent
            });
            return res.status(401).json({ 
                error: 'Invalid email or password',
                code: 'INVALID_CREDENTIALS'
            });
        }

        // Generate session ID
        const sessionId = generateSessionId();

        // Create tokens
        const accessTokenData = jwtManager.createAccessToken(user, sessionId, {
            clientId: clientId,
            ipAddress: clientIp,
            userAgent: userAgent
        });

        const refreshTokenData = jwtManager.createRefreshToken(user, sessionId, {
            clientId: clientId
        });

        // Store refresh token
        addRefreshToken(user.id, {
            token: refreshTokenData.token,
            sessionId: sessionId,
            createdAt: new Date().toISOString(),
            expiresAt: new Date(refreshTokenData.claims.exp * 1000).toISOString(),
            userAgent: userAgent,
            ipAddress: clientIp
        });

        // Update last login
        updateLastLogin(user.id, userAgent, clientIp);

        // Log successful authentication
        authLogger(true, email, clientIp, {
            event: 'LOGIN_SUCCESS',
            userId: user.id,
            sessionId: sessionId,
            userAgent: userAgent,
            clientId: clientId
        });

        sessionLogger('CREATED', user.id, sessionId, {
            userAgent: userAgent,
            ipAddress: clientIp,
            clientId: clientId
        });

        const duration = Date.now() - startTime;
        authLogger(true, email, clientIp, {
            event: 'LOGIN_COMPLETED',
            duration: duration
        });

        // Return tokens and user info
        res.json({
            success: true,
            message: 'Login successful',
            access_token: accessTokenData.token,
            refresh_token: refreshTokenData.token,
            token_type: 'Bearer',
            expires_in: 15 * 60, // 15 minutes in seconds
            scope: user.scopes.join(' '),
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                role: user.role,
                scopes: user.scopes
            },
            session: {
                id: sessionId,
                createdAt: accessTokenData.claims.iat * 1000,
                expiresAt: accessTokenData.claims.exp * 1000
            },
            jwt_info: {
                algorithm: jwtManager.getAlgorithmInfo().algorithm,
                issuer: accessTokenData.claims.iss,
                audience: accessTokenData.claims.aud,
                jti: accessTokenData.claims.jti
            }
        });

    } catch (error) {
        authLogger(false, email, clientIp, {
            event: 'LOGIN_ERROR',
            error: error.message
        });
        
        res.status(500).json({
            error: 'Internal server error during login',
            code: 'LOGIN_ERROR'
        });
    }
});

/**
 * POST /api/auth/refresh
 * Enhanced refresh token endpoint with rotation
 */
router.post('/refresh', async (req, res) => {
    const startTime = Date.now();
    const { refresh_token, clientId = 'web-client' } = req.body || {};
    const clientIp = req.ip || req.connection.remoteAddress;
    const userAgent = (req.headers && req.headers['user-agent']) || 'Unknown';

    try {
        if (!refresh_token) {
            return res.status(400).json({
                error: 'Refresh token is required',
                code: 'MISSING_REFRESH_TOKEN'
            });
        }

        // Verify refresh token
        const validation = jwtManager.verifyRefreshToken(refresh_token);
        if (!validation.valid) {
            tokenLogger('REFRESH_VERIFICATION_FAILED', refresh_token, {
                reason: validation.error,
                ip: clientIp
            });
            return res.status(401).json({
                error: 'Invalid refresh token',
                code: 'INVALID_REFRESH_TOKEN'
            });
        }

        // Get user
        const user = findUserById(parseInt(validation.decoded.sub));
        if (!user) {
            return res.status(401).json({
                error: 'User not found',
                code: 'USER_NOT_FOUND'
            });
        }

        const sessionId = validation.decoded.sessionId;

        // Rotate refresh token (invalidate old, create new)
        const newRefreshTokenData = jwtManager.rotateRefreshToken(refresh_token, user, sessionId, {
            clientId: clientId,
            ipAddress: clientIp,
            userAgent: userAgent
        });

        // Create new access token
        const newAccessTokenData = jwtManager.createAccessToken(user, sessionId, {
            clientId: clientId,
            ipAddress: clientIp,
            userAgent: userAgent
        });

        // Store new refresh token
        addRefreshToken(user.id, {
            token: newRefreshTokenData.token,
            sessionId: sessionId,
            createdAt: new Date().toISOString(),
            expiresAt: new Date(newRefreshTokenData.claims.exp * 1000).toISOString(),
            userAgent: userAgent,
            ipAddress: clientIp
        });

        tokenLogger('REFRESH_SUCCESS', refresh_token, {
            userId: user.id,
            sessionId: sessionId,
            oldJti: validation.decoded.jti,
            newJti: newAccessTokenData.claims.jti,
            ip: clientIp
        });

        const duration = Date.now() - startTime;

        res.json({
            success: true,
            message: 'Token refreshed successfully',
            access_token: newAccessTokenData.token,
            refresh_token: newRefreshTokenData.token,
            token_type: 'Bearer',
            expires_in: 15 * 60, // 15 minutes
            scope: user.scopes.join(' '),
            session: {
                id: sessionId,
                refreshedAt: new Date().toISOString()
            }
        });

    } catch (error) {
        tokenLogger('REFRESH_ERROR', refresh_token, {
            error: error.message,
            ip: clientIp
        });

        res.status(500).json({
            error: 'Internal server error during token refresh',
            code: 'REFRESH_ERROR'
        });
    }
});

/**
 * POST /api/auth/logout
 * Enhanced logout with token blacklisting
 */
router.post('/logout', async (req, res) => {
    const { access_token, refresh_token } = req.body;
    const clientIp = req.ip || req.connection.remoteAddress;

    try {
        // Blacklist access token if provided
        if (access_token) {
            jwtManager.blacklistToken(access_token, 'user_logout');
            tokenLogger('BLACKLISTED', access_token, {
                reason: 'user_logout',
                ip: clientIp
            });
        }

        // Revoke refresh token if provided
        if (refresh_token) {
            const validation = jwtManager.verifyRefreshToken(refresh_token);
            if (validation.valid) {
                revokeRefreshToken(parseInt(validation.decoded.sub), validation.decoded.sessionId);
                tokenLogger('REVOKED', refresh_token, {
                    reason: 'user_logout',
                    userId: validation.decoded.sub,
                    sessionId: validation.decoded.sessionId,
                    ip: clientIp
                });
            }
        }

        authLogger(true, 'logout', clientIp, {
            event: 'LOGOUT_SUCCESS',
            tokensBlacklisted: !!access_token,
            refreshTokensRevoked: !!refresh_token
        });

        res.json({
            success: true,
            message: 'Logged out successfully',
            logged_out_at: new Date().toISOString()
        });

    } catch (error) {
        authLogger(false, 'logout', clientIp, {
            event: 'LOGOUT_ERROR',
            error: error.message
        });

        res.status(500).json({
            error: 'Internal server error during logout',
            code: 'LOGOUT_ERROR'
        });
    }
});

/**
 * POST /api/auth/logout-all
 * Logout from all devices/sessions
 */
router.post('/logout-all', async (req, res) => {
    const { access_token } = req.body;
    const clientIp = req.ip || req.connection.remoteAddress;

    try {
        if (!access_token) {
            return res.status(400).json({
                error: 'Access token is required',
                code: 'MISSING_ACCESS_TOKEN'
            });
        }

        // Verify access token to get user ID
        const validation = jwtManager.verifyAccessToken(access_token);
        if (!validation.valid) {
            return res.status(401).json({
                error: 'Invalid access token',
                code: 'INVALID_ACCESS_TOKEN'
            });
        }

        const userId = parseInt(validation.decoded.sub);

        // Blacklist current access token
        jwtManager.blacklistToken(access_token, 'user_logout_all');

        // Revoke all refresh tokens for user
        revokeAllRefreshTokens(userId);

        authLogger(true, 'logout-all', clientIp, {
            event: 'LOGOUT_ALL_SUCCESS',
            userId: userId,
            sessionId: validation.decoded.sessionId
        });

        auditLogger('LOGOUT_ALL', userId, 'all_sessions', 'SUCCESS', {
            sessionId: validation.decoded.sessionId,
            ip: clientIp
        });

        res.json({
            success: true,
            message: 'Logged out from all devices successfully',
            logged_out_at: new Date().toISOString(),
            sessions_terminated: 'all'
        });

    } catch (error) {
        authLogger(false, 'logout-all', clientIp, {
            event: 'LOGOUT_ALL_ERROR',
            error: error.message
        });

        res.status(500).json({
            error: 'Internal server error during logout all',
            code: 'LOGOUT_ALL_ERROR'
        });
    }
});

/**
 * GET /api/auth/profile
 * Get current user profile
 */
router.get('/profile', async (req, res) => {
    try {
        if (!req.user) {
            return res.status(401).json({
                error: 'Authentication required',
                code: 'AUTH_REQUIRED'
            });
        }

        res.json({
            success: true,
            user: {
                id: req.user.id,
                name: req.user.name,
                email: req.user.email,
                role: req.user.role,
                scopes: req.user.scopes,
                createdAt: req.user.createdAt,
                lastLogin: req.user.lastLogin
            },
            session: {
                id: req.tokenData.sessionId,
                createdAt: req.tokenData.iat * 1000,
                expiresAt: req.tokenData.exp * 1000,
                jti: req.tokenData.jti
            }
        });

    } catch (error) {
        res.status(500).json({
            error: 'Internal server error',
            code: 'PROFILE_ERROR'
        });
    }
});

/**
 * GET /api/auth/introspect
 * Token introspection endpoint (RFC 7662 style)
 */
router.post('/introspect', async (req, res) => {
    const { token, token_type_hint } = req.body;
    const clientIp = req.ip || req.connection.remoteAddress;

    try {
        if (!token) {
            return res.status(400).json({
                error: 'Token is required',
                code: 'MISSING_TOKEN'
            });
        }

        const introspection = jwtManager.introspectToken(token);

        // Log introspection attempt
        if (introspection.active) {
            tokenLogger('INTROSPECTION_ACTIVE', token, {
                userId: introspection.sub,
                clientId: introspection.client_id,
                ip: clientIp
            });
        } else {
            tokenLogger('INTROSPECTION_INACTIVE', token, {
                reason: introspection.reason,
                ip: clientIp
            });
        }

        res.json(introspection);

    } catch (error) {
        tokenLogger('INTROSPECTION_ERROR', token, {
            error: error.message,
            ip: clientIp
        });

        res.status(500).json({
            error: 'Internal server error during introspection',
            code: 'INTROSPECTION_ERROR'
        });
    }
});

module.exports = router;