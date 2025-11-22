const { v4: uuidv4 } = require('uuid');

// Enhanced user database with refresh tokens
const users = [
    {
        id: 1,
        name: "Admin User",
        email: "admin@example.com",
        password: "admin123", // In production, this would be hashed
        role: "admin",
        scopes: ["read", "write", "admin", "users:read", "users:write", "stats:read"],
        createdAt: new Date('2023-01-01').toISOString(),
        lastLogin: null,
        refreshTokens: []
    },
    {
        id: 2,
        name: "Customer User",
        email: "customer@example.com",
        password: "customer123", // In production, this would be hashed
        role: "customer",
        scopes: ["read", "write", "profile:read", "profile:write"],
        createdAt: new Date('2023-01-01').toISOString(),
        lastLogin: null,
        refreshTokens: []
    }
];

// Token blacklist for immediate invalidation
const tokenBlacklist = new Map();
const refreshTokenBlacklist = new Map();

/**
 * Find user by email
 */
function findUserByEmail(email) {
    return users.find(user => user.email === email);
}

/**
 * Find user by ID
 */
function findUserById(id) {
    return users.find(user => user.id === id);
}

/**
 * Add refresh token to user
 */
function addRefreshToken(userId, refreshToken) {
    const user = findUserById(userId);
    if (user) {
        // Remove any existing refresh tokens for this session
        user.refreshTokens = user.refreshTokens.filter(token => 
            token.sessionId !== refreshToken.sessionId
        );
        
        user.refreshTokens.push({
            token: refreshToken.token,
            sessionId: refreshToken.sessionId,
            createdAt: refreshToken.createdAt,
            expiresAt: refreshToken.expiresAt,
            userAgent: refreshToken.userAgent || 'unknown',
            ipAddress: refreshToken.ipAddress || 'unknown',
            isRevoked: false
        });
        
        // Clean up old tokens (keep only last 10)
        if (user.refreshTokens.length > 10) {
            user.refreshTokens = user.refreshTokens.slice(-10);
        }
        
        return true;
    }
    return false;
}

/**
 * Revoke refresh token
 */
function revokeRefreshToken(userId, sessionId) {
    const user = findUserById(userId);
    if (user) {
        const token = user.refreshTokens.find(t => t.sessionId === sessionId);
        if (token) {
            token.isRevoked = true;
            // Also add to global blacklist
            refreshTokenBlacklist.set(token.token, {
                revokedAt: new Date().toISOString(),
                reason: 'user_logout'
            });
            return true;
        }
    }
    return false;
}

/**
 * Revoke all refresh tokens for user
 */
function revokeAllRefreshTokens(userId) {
    const user = findUserById(userId);
    if (user) {
        user.refreshTokens.forEach(token => {
            token.isRevoked = true;
            refreshTokenBlacklist.set(token.token, {
                revokedAt: new Date().toISOString(),
                reason: 'user_logout_all'
            });
        });
        user.refreshTokens = [];
        return true;
    }
    return false;
}

/**
 * Validate refresh token
 */
function validateRefreshToken(token) {
    // Check global blacklist first
    if (refreshTokenBlacklist.has(token)) {
        return { valid: false, reason: 'blacklisted' };
    }
    
    // Find token in user database
    for (const user of users) {
        const refreshToken = user.refreshTokens.find(t => t.token === token);
        if (refreshToken) {
            if (refreshToken.isRevoked) {
                return { valid: false, reason: 'revoked' };
            }
            
            if (new Date(refreshToken.expiresAt) <= new Date()) {
                return { valid: false, reason: 'expired' };
            }
            
            return { 
                valid: true, 
                userId: user.id, 
                sessionId: refreshToken.sessionId 
            };
        }
    }
    
    return { valid: false, reason: 'not_found' };
}

/**
 * Blacklist access token
 */
function blacklistToken(token, reason = 'manual_logout', expiresAt = null) {
    tokenBlacklist.set(token, {
        blacklistedAt: new Date().toISOString(),
        reason,
        expiresAt: expiresAt || new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString() // 24 hours default
    });
}

/**
 * Check if token is blacklisted
 */
function isTokenBlacklisted(token) {
    const blacklistEntry = tokenBlacklist.get(token);
    if (!blacklistEntry) return false;
    
    // Check if blacklist entry has expired
    if (new Date(blacklistEntry.expiresAt) <= new Date()) {
        tokenBlacklist.delete(token);
        return false;
    }
    
    return true;
}

/**
 * Clean up expired blacklist entries
 */
function cleanupBlacklist() {
    const now = new Date();
    
    // Clean access token blacklist
    for (const [token, entry] of tokenBlacklist.entries()) {
        if (new Date(entry.expiresAt) <= now) {
            tokenBlacklist.delete(token);
        }
    }
    
    // Clean refresh token blacklist
    for (const [token, entry] of refreshTokenBlacklist.entries()) {
        if (new Date(entry.expiresAt) <= now) {
            refreshTokenBlacklist.delete(token);
        }
    }
}

/**
 * Generate session ID for refresh tokens
 */
function generateSessionId() {
    return uuidv4();
}

/**
 * Update user last login timestamp
 */
function updateLastLogin(userId, userAgent = null, ipAddress = null) {
    const user = findUserById(userId);
    if (user) {
        user.lastLogin = {
            timestamp: new Date().toISOString(),
            userAgent,
            ipAddress
        };
        return true;
    }
    return false;
}

// Clean up blacklisted tokens every hour
setInterval(cleanupBlacklist, 60 * 60 * 1000);

module.exports = {
    users,
    tokenBlacklist,
    refreshTokenBlacklist,
    findUserByEmail,
    findUserById,
    addRefreshToken,
    revokeRefreshToken,
    revokeAllRefreshTokens,
    validateRefreshToken,
    blacklistToken,
    isTokenBlacklisted,
    generateSessionId,
    updateLastLogin,
    cleanupBlacklist
};