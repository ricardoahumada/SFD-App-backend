const googleOAuth2 = require('../utils/googleOAuth2');
const { pkceStateManager } = require('../utils/pkceHelper');
const { OAuth2Logger } = require('../utils/logger');

/**
 * OAuth2 Token Validation Middleware
 * Validates Google OAuth2 tokens and extracts user information
 */

/**
 * Middleware to validate OAuth2 access token
 */
async function validateOAuth2Token(req, res, next) {
    try {
        const startTime = Date.now();
        const clientIp = req.ip || req.connection.remoteAddress;
        const userAgent = req.headers['user-agent'] || 'Unknown';

        // Extract token from Authorization header
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            OAuth2Logger('TOKEN_MISSING', clientIp, userAgent, { error: 'No access token provided' });
            return res.status(401).json({
                error: 'Access token required',
                code: 'TOKEN_MISSING',
                message: 'Bearer token must be provided in Authorization header'
            });
        }

        const accessToken = authHeader.substring(7); // Remove 'Bearer ' prefix

        // Get user information from the access token
        const tokenData = await googleOAuth2.getUserInfo(accessToken);
        
        if (!tokenData) {
            OAuth2Logger('TOKEN_INVALID', clientIp, userAgent, { error: 'Invalid token format' });
            return res.status(401).json({
                error: 'Invalid access token',
                code: 'TOKEN_INVALID',
                message: 'Token verification failed'
            });
        }

        // Check if email is verified (optional, based on config)
        if (process.env.REQUIRE_EMAIL_VERIFIED === 'true' && !tokenData.email_verified) {
            OAuth2Logger('EMAIL_NOT_VERIFIED', clientIp, userAgent, { userId: tokenData.sub });
            return res.status(403).json({
                error: 'Email verification required',
                code: 'EMAIL_NOT_VERIFIED',
                message: 'Your email address must be verified to access this resource'
            });
        }

        // Check required scopes (basic check)
        if (process.env.REQUIRE_SCOPES === 'true') {
            const requiredScopes = ['openid', 'email', 'profile'];
            const tokenScopes = tokenData.scope?.split(' ') || [];
            const missingScopes = requiredScopes.filter(scope => !tokenScopes.includes(scope));
            
            if (missingScopes.length > 0) {
                OAuth2Logger('INSUFFICIENT_SCOPES', clientIp, userAgent, { 
                    userId: tokenData.sub, 
                    missingScopes 
                });
                return res.status(403).json({
                    error: 'Insufficient permissions',
                    code: 'INSUFFICIENT_SCOPES',
                    message: `Missing required scopes: ${missingScopes.join(', ')}`
                });
            }
        }

        // Attach user information to request
        req.user = {
            id: tokenData.sub,
            email: tokenData.email,
            emailVerified: tokenData.email_verified,
            name: tokenData.name,
            givenName: tokenData.given_name,
            familyName: tokenData.family_name,
            picture: tokenData.picture,
            locale: tokenData.locale,
            provider: 'google',
            accessToken: accessToken,
            tokenData: tokenData
        };

        // Log successful token validation
        OAuth2Logger('TOKEN_VALIDATED', clientIp, userAgent, { 
            userId: req.user.id,
            duration: Date.now() - startTime
        });

        next();
    } catch (error) {
        OAuth2Logger('TOKEN_VALIDATION_ERROR', req.ip, req.headers['user-agent'], { 
            error: error.message,
            stack: error.stack
        });

        if (error.message.includes('expired')) {
            return res.status(401).json({
                error: 'Token expired',
                code: 'TOKEN_EXPIRED',
                message: 'Access token has expired. Please obtain a new token.'
            });
        }

        return res.status(401).json({
            error: 'Token validation failed',
            code: 'TOKEN_VALIDATION_ERROR',
            message: error.message
        });
    }
}

/**
 * Middleware to validate OAuth2 tokens for admin access
 */
async function validateAdminToken(req, res, next) {
    // First validate basic OAuth2 token
    await new Promise((resolve, reject) => {
        validateOAuth2Token(req, res, (err) => {
            if (err) reject(err);
            else resolve();
        });
    });

    // Check if user has admin role (for demo purposes, we'll check email domain)
    const adminEmails = ['admin@gmail.com', 'admin@google.com']; // Demo admin emails
    if (!adminEmails.includes(req.user.email.toLowerCase())) {
        OAuth2Logger('ADMIN_ACCESS_DENIED', req.ip, req.headers['user-agent'], { 
            userId: req.user.id,
            email: req.user.email
        });
        return res.status(403).json({
            error: 'Admin access required',
            code: 'ADMIN_ACCESS_DENIED',
            message: 'You must be an administrator to access this resource'
        });
    }

    next();
}

/**
 * Optional OAuth2 token validation (doesn't fail if no token)
 */
async function optionalOAuth2Token(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        // No token provided, continue without user context
        return next();
    }

    try {
        await validateOAuth2Token(req, res, next);
    } catch (error) {
        // Token validation failed, but continue without user context
        next();
    }
}

/**
 * Middleware to validate OAuth2 state parameter (CSRF protection)
 */
function validateStateParameter(expectedState) {
    return (req, res, next) => {
        const providedState = req.query.state || req.body.state;
        
        if (!providedState) {
            return res.status(400).json({
                error: 'State parameter required',
                code: 'STATE_MISSING',
                message: 'OAuth2 state parameter is required for CSRF protection'
            });
        }

        if (expectedState && providedState !== expectedState) {
            return res.status(400).json({
                error: 'Invalid state parameter',
                code: 'STATE_MISMATCH',
                message: 'State parameter does not match the one sent in authorization request'
            });
        }

        next();
    };
}

/**
 * Middleware to validate PKCE challenge (Educational demonstration)
 */
function validatePKCEChallenge() {
    return (req, res, next) => {
        if (process.env.ENABLE_PKCE_DEMO !== 'true') {
            return next();
        }

        const state = req.query.state || req.body.state;
        const codeVerifier = req.body.code_verifier;

        if (!codeVerifier) {
            // PKCE not required for this demo
            return next();
        }

        const challengeData = pkceStateManager.validateChallenge(state, codeVerifier);
        
        if (!challengeData) {
            OAuth2Logger('PKCE_VALIDATION_FAILED', req.ip, req.headers['user-agent'], { 
                state,
                error: 'Invalid or expired PKCE challenge'
            });
            return res.status(400).json({
                error: 'PKCE verification failed',
                code: 'PKCE_VALIDATION_FAILED',
                message: 'Invalid or expired PKCE challenge. Please restart the authorization flow.'
            });
        }

        OAuth2Logger('PKCE_VALIDATED', req.ip, req.headers['user-agent'], { 
            state,
            method: challengeData.method
        });

        req.pkceData = challengeData;
        next();
    };
}

module.exports = {
    validateOAuth2Token,
    validateAdminToken,
    optionalOAuth2Token,
    validateStateParameter,
    validatePKCEChallenge
};