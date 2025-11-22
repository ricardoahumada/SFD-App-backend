const express = require('express');
const jwtManager = require('../utils/jwtManager');
const { authenticateToken } = require('../middleware/auth');
const { tokenLogger, blacklistLogger } = require('../utils/logger');

const router = express.Router();

/**
 * POST /api/tokens/introspect
 * Token introspection endpoint (RFC 7662 compliance)
 */
router.post('/introspect', authenticateToken, (req, res) => {
    const { token } = req.body || {};
    const clientIp = req.ip || req.connection.remoteAddress;

    try {
        if (!token) {
            return res.status(400).json({
                error: 'Token is required',
                code: 'MISSING_TOKEN'
            });
        }

        const introspection = jwtManager.introspectToken(token);

        tokenLogger('INTROSPECTION', token, {
            active: introspection.active,
            userId: introspection.sub,
            clientId: introspection.client_id,
            ip: clientIp,
            requestedBy: req.user?.id
        });

        res.json({
            active: introspection.active,
            ...(introspection.active && {
                scope: introspection.scope,
                client_id: introspection.client_id,
                username: introspection.username,
                token_type: introspection.token_type,
                exp: introspection.exp,
                iat: introspection.iat,
                sub: introspection.sub,
                aud: introspection.aud,
                iss: introspection.iss,
                jti: introspection.jti
            }),
            ...(!introspection.active && {
                error: 'token not active',
                error_description: introspection.reason || 'Token is not active'
            })
        });

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

/**
 * GET /api/tokens/blacklist
 * Check if token is blacklisted
 */
router.get('/blacklist', authenticateToken, (req, res) => {
    const { token } = req.query;
    const clientIp = req.ip || req.connection.remoteAddress;

    try {
        if (!token) {
            return res.status(400).json({
                error: 'Token parameter is required',
                code: 'MISSING_TOKEN'
            });
        }

        const isBlacklisted = jwtManager.verifyAccessToken(token).error?.includes('blacklisted') || false;

        tokenLogger('BLACKLIST_CHECK', token, {
            blacklisted: isBlacklisted,
            ip: clientIp,
            checkedBy: req.user?.id
        });

        res.json({
            token: token.substring(0, 20) + '...',
            blacklisted: isBlacklisted,
            checked_at: new Date().toISOString()
        });

    } catch (error) {
        tokenLogger('BLACKLIST_CHECK_ERROR', token, {
            error: error.message,
            ip: clientIp
        });

        res.status(500).json({
            error: 'Internal server error during blacklist check',
            code: 'BLACKLIST_CHECK_ERROR'
        });
    }
});

/**
 * POST /api/tokens/blacklist
 * Manually blacklist a token (admin only)
 */
router.post('/blacklist', authenticateToken, (req, res) => {
    const { token, reason = 'manual_blacklist' } = req.body || {};
    const clientIp = req.ip || req.connection.remoteAddress;

    try {
        if (!token) {
            return res.status(400).json({
                error: 'Token is required',
                code: 'MISSING_TOKEN'
            });
        }

        // Only admins can manually blacklist tokens
        if (req.user.role !== 'admin') {
            return res.status(403).json({
                error: 'Admin privileges required',
                code: 'ADMIN_REQUIRED'
            });
        }

        const success = jwtManager.blacklistToken(token, reason);
        const tokenPreview = token.substring(0, 20) + '...';

        blacklistLogger('MANUAL_BLACKLIST', tokenPreview, reason, {
            blacklistedBy: req.user.id,
            ip: clientIp,
            success: success
        });

        res.json({
            success: success,
            message: success ? 'Token blacklisted successfully' : 'Failed to blacklist token',
            token: tokenPreview,
            reason: reason,
            blacklisted_at: new Date().toISOString(),
            blacklisted_by: req.user.id
        });

    } catch (error) {
        blacklistLogger('BLACKLIST_ERROR', token, {
            error: error.message,
            ip: clientIp
        });

        res.status(500).json({
            error: 'Internal server error during token blacklisting',
            code: 'BLACKLIST_ERROR'
        });
    }
});

/**
 * GET /api/tokens/algorithm
 * Get current JWT algorithm information
 */
router.get('/algorithm', (req, res) => {
    const algorithmInfo = jwtManager.getAlgorithmInfo();

    res.json({
        algorithm: algorithmInfo.algorithm,
        key_length: algorithmInfo.keyLength,
        production_ready: algorithmInfo.productionReady,
        clock_skew_tolerance: algorithmInfo.clockSkew,
        supported_algorithms: ['HS256', 'RS256'],
        current_environment: process.env.NODE_ENV || 'development'
    });
});

/**
 * GET /api/tokens/health
 * Token service health check
 */
router.get('/health', (req, res) => {
    const algorithmInfo = jwtManager.getAlgorithmInfo();

    res.json({
        status: 'healthy',
        service: 'token-service',
        version: '2.0.0',
        algorithm: algorithmInfo.algorithm,
        timestamp: new Date().toISOString(),
        features: {
            refresh_token_rotation: true,
            token_blacklisting: true,
            comprehensive_claims: true,
            clock_skew_tolerance: true,
            rfc7662_introspection: true
        }
    });
});

module.exports = router;