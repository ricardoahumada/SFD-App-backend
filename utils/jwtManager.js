const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { findUserById, blacklistToken, isTokenBlacklisted } = require('../models/users');
const logger = require('../utils/logger');

class JWTManager {
    constructor() {
        this.clockSkew = 300; // 5 minutes clock skew tolerance
        this.loadKeys();
    }

    /**
     * Generate a UUID, with fallback for older Node.js versions
     */
    generateUUID() {
        if (crypto.randomUUID) {
            return crypto.randomUUID();
        } else {
            // Fallback for older Node.js versions
            return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
                const r = Math.random() * 16 | 0;
                const v = c === 'x' ? r : (r & 0x3 | 0x8);
                return v.toString(16);
            });
        }
    }

    /**
     * Load RSA keys for RS256 signing
     */
    loadKeys() {
        try {
            const keysPath = process.env.KEYS_PATH || path.join(__dirname, '../../keys');
            const privateKeyPath = path.join(keysPath, 'private.pem');
            const publicKeyPath = path.join(keysPath, 'public.pem');

            if (fs.existsSync(privateKeyPath) && fs.existsSync(publicKeyPath)) {
                this.privateKey = fs.readFileSync(privateKeyPath, 'utf8');
                this.publicKey = fs.readFileSync(publicKeyPath, 'utf8');
                this.algorithm = 'RS256';
                logger.infoLogger('RS256 keys loaded successfully');
            } else {
                this.privateKey = process.env.JWT_PRIVATE_KEY || this.generatePrivateKey();
                this.publicKey = process.env.JWT_PUBLIC_KEY || this.generatePublicKey();
                this.algorithm = 'HS256';
                logger.infoLogger('Using HS256 algorithm with generated key');
            }
        } catch (error) {
            logger.warnLogger('Failed to load RSA keys, falling back to HS256', { error: error.message });
            this.privateKey = process.env.JWT_SECRET || this.generatePrivateKey();
            this.algorithm = 'HS256';
        }
    }

    /**
     * Generate private key for HS256
     */
    generatePrivateKey() {
        return crypto.randomBytes(64).toString('hex');
    }

    /**
     * Generate public key (same as private for symmetric algorithm)
     */
    generatePublicKey() {
        return this.privateKey;
    }

    /**
     * Create access token with comprehensive claims
     */
    createAccessToken(user, sessionId, options = {}) {
        const now = Math.floor(Date.now() / 1000);
        const expiresIn = options.expiresIn || '15m'; // 15 minutes for access tokens
        
        const claims = {
            // Standard JWT claims
            iss: process.env.JWT_ISSUER || 'auth-system-v2',
            aud: process.env.JWT_AUDIENCE || 'auth-system-users',
            sub: user.id.toString(),
            iat: now,
            exp: now + this.parseExpiration(expiresIn),
            
            // Custom claims
            jti: this.generateUUID(), // JWT ID
            sessionId: sessionId,
            role: user.role,
            scopes: user.scopes || [],
            userEmail: user.email,
            userName: user.name,
            
            // Security claims
            tokenType: 'access',
            alg: this.algorithm,
            
            // Client claims
            clientId: options.clientId || 'web-client',
            ipAddress: options.ipAddress,
            userAgent: options.userAgent
        };

        try {
            const token = jwt.sign(claims, this.privateKey, {
                algorithm: this.algorithm
            });

            logger.infoLogger('Access token created', {
                userId: user.id,
                sessionId: sessionId,
                jti: claims.jti
            });

            return { token, claims };
        } catch (error) {
            logger.errorLogger(error, null, { userId: user.id, context: 'access_token_creation' });
            throw new Error('Token creation failed');
        }
    }

    /**
     * Create refresh token with comprehensive claims
     */
    createRefreshToken(user, sessionId, options = {}) {
        const now = Math.floor(Date.now() / 1000);
        const expiresIn = options.expiresIn || '7d'; // 7 days for refresh tokens

        const claims = {
            // Standard JWT claims
            iss: process.env.JWT_ISSUER || 'auth-system-v2',
            aud: process.env.JWT_AUDIENCE || 'auth-system-users',
            sub: user.id.toString(),
            iat: now,
            exp: now + this.parseExpiration(expiresIn),
            
            // Custom claims
            jti: this.generateUUID(),
            sessionId: sessionId,
            tokenType: 'refresh',
            alg: this.algorithm,
            
            // Client claims
            clientId: options.clientId || 'web-client'
        };

        try {
            const token = jwt.sign(claims, this.privateKey, {
                algorithm: this.algorithm
            });

            logger.infoLogger('Refresh token created', {
                userId: user.id,
                sessionId: sessionId,
                jti: claims.jti
            });

            return { token, claims };
        } catch (error) {
            logger.errorLogger(error, null, { userId: user.id, context: 'refresh_token_creation' });
            throw new Error('Refresh token creation failed');
        }
    }

    /**
     * Verify access token with comprehensive validation
     */
    verifyAccessToken(token, options = {}) {
        try {
            // Check blacklist first
            if (isTokenBlacklisted(token)) {
                throw new Error('Token is blacklisted');
            }

            const decoded = jwt.verify(token, this.publicKey, {
                algorithms: [this.algorithm],
                issuer: process.env.JWT_ISSUER || 'auth-system-v2',
                audience: process.env.JWT_AUDIENCE || 'auth-system-users',
                clockTolerance: this.clockSkew
            });

            // Additional validation for access token
            if (decoded.tokenType !== 'access') {
                throw new Error('Invalid token type');
            }

            // Verify user still exists
            const user = findUserById(parseInt(decoded.sub));
            if (!user) {
                throw new Error('User not found');
            }

            logger.infoLogger('Access token verified', {
                userId: user.id,
                jti: decoded.jti,
                sessionId: decoded.sessionId
            });

            return { valid: true, decoded, user };
        } catch (error) {
            logger.warnLogger('Access token verification failed', {
                error: error.message,
                token: token.substring(0, 20) + '...'
            });
            return { valid: false, error: error.message };
        }
    }

    /**
     * Verify refresh token
     */
    verifyRefreshToken(token) {
        try {
            const decoded = jwt.verify(token, this.publicKey, {
                algorithms: [this.algorithm],
                issuer: process.env.JWT_ISSUER || 'auth-system-v2',
                audience: process.env.JWT_AUDIENCE || 'auth-system-users',
                clockTolerance: this.clockSkew
            });

            if (decoded.tokenType !== 'refresh') {
                throw new Error('Invalid token type');
            }

            logger.infoLogger('Refresh token verified', {
                userId: decoded.sub,
                jti: decoded.jti,
                sessionId: decoded.sessionId
            });

            return { valid: true, decoded };
        } catch (error) {
            logger.warnLogger('Refresh token verification failed', {
                error: error.message,
                token: token.substring(0, 20) + '...'
            });
            return { valid: false, error: error.message };
        }
    }

    /**
     * Introspect token (RFC 7662 style)
     */
    introspectToken(token) {
        try {
            const accessValidation = this.verifyAccessToken(token);
            if (accessValidation.valid) {
                return {
                    active: true,
                    scope: accessValidation.decoded.scopes.join(' '),
                    client_id: accessValidation.decoded.clientId,
                    username: accessValidation.user.email,
                    token_type: 'access_token',
                    exp: accessValidation.decoded.exp,
                    iat: accessValidation.decoded.iat,
                    sub: accessValidation.decoded.sub,
                    aud: accessValidation.decoded.aud,
                    iss: accessValidation.decoded.iss,
                    jti: accessValidation.decoded.jti
                };
            }

            const refreshValidation = this.verifyRefreshToken(token);
            if (refreshValidation.valid) {
                return {
                    active: true,
                    client_id: refreshValidation.decoded.clientId,
                    token_type: 'refresh_token',
                    exp: refreshValidation.decoded.exp,
                    iat: refreshValidation.decoded.iat,
                    sub: refreshValidation.decoded.sub,
                    aud: refreshValidation.decoded.aud,
                    iss: refreshValidation.decoded.iss,
                    jti: refreshValidation.decoded.jti
                };
            }

            return {
                active: false,
                reason: 'invalid_token'
            };
        } catch (error) {
            return {
                active: false,
                reason: error.message
            };
        }
    }

    /**
     * Blacklist token immediately
     */
    blacklistToken(token, reason = 'manual_logout') {
        try {
            // Try to decode token to get expiration
            const decoded = jwt.decode(token);
            const expiresAt = decoded ? new Date(decoded.exp * 1000).toISOString() : null;
            
            blacklistToken(token, reason, expiresAt);
            
            logger.infoLogger('Token blacklisted', {
                reason,
                expiresAt,
                jti: decoded?.jti
            });
            
            return true;
        } catch (error) {
            logger.errorLogger(error, null, { context: 'token_blacklisting' });
            return false;
        }
    }

    /**
     * Parse expiration string to seconds
     */
    parseExpiration(exp) {
        const timeUnit = exp.slice(-1);
        const timeValue = parseInt(exp.slice(0, -1));
        
        switch (timeUnit) {
            case 's': return timeValue;
            case 'm': return timeValue * 60;
            case 'h': return timeValue * 60 * 60;
            case 'd': return timeValue * 24 * 60 * 60;
            default: return 3600; // default 1 hour
        }
    }

    /**
     * Get algorithm information
     */
    getAlgorithmInfo() {
        return {
            algorithm: this.algorithm,
            keyLength: this.algorithm === 'RS256' ? '2048-bit RSA' : '512-bit HMAC',
            productionReady: this.algorithm === 'RS256',
            clockSkew: this.clockSkew
        };
    }

    /**
     * Rotate refresh token (invalidate old, create new)
     */
    rotateRefreshToken(oldToken, user, sessionId, options = {}) {
        try {
            // Verify old token
            const validation = this.verifyRefreshToken(oldToken);
            if (!validation.valid) {
                throw new Error('Invalid refresh token');
            }

            // Create new refresh token
            const newTokenData = this.createRefreshToken(user, sessionId, options);
            
            logger.infoLogger('Refresh token rotated', {
                userId: user.id,
                oldJti: validation.decoded.jti,
                newJti: newTokenData.claims.jti,
                sessionId: sessionId
            });

            return newTokenData;
        } catch (error) {
            logger.errorLogger(error, null, { context: 'refresh_token_rotation', userId: user.id });
            throw error;
        }
    }
}

// Export singleton instance
const jwtManager = new JWTManager();

module.exports = jwtManager;