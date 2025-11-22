const crypto = require('crypto');

/**
 * PKCE (Proof Key for Code Exchange) Utility
 * Educational implementation to demonstrate PKCE concepts
 * 
 * PKCE adds an extra layer of security to OAuth 2.0 Authorization Code Flow
 * by binding the authorization request to the token exchange request.
 */

/**
 * Generate secure code verifier
 * @param {number} length - Length of the code verifier (default: 128)
 * @returns {string} Base64url-encoded random string
 */
function generateCodeVerifier(length = 128) {
    if (length < 43 || length > 128) {
        throw new Error('Code verifier length must be between 43 and 128 characters');
    }

    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
    let result = '';
    const bytes = crypto.randomBytes(length);
    
    for (let i = 0; i < length; i++) {
        result += chars[bytes[i] % chars.length];
    }
    
    return result;
}

/**
 * Generate code challenge from code verifier using S256 method
 * @param {string} codeVerifier - The code verifier string
 * @returns {string} Base64url-encoded SHA256 hash of the code verifier
 */
function generateCodeChallenge(codeVerifier) {
    if (!codeVerifier) {
        throw new Error('Code verifier is required');
    }

    const hash = crypto.createHash('sha256').update(codeVerifier).digest(); // Get Buffer directly
    return base64urlEncode(hash);
}

/**
 * Generate code challenge using plain method (not recommended for production)
 * @param {string} codeVerifier - The code verifier string
 * @returns {string} Same as code verifier (for comparison purposes)
 */
function generateCodeChallengePlain(codeVerifier) {
    if (!codeVerifier) {
        throw new Error('Code verifier is required');
    }

    return codeVerifier;
}

/**
 * Verify code challenge matches code verifier
 * @param {string} codeVerifier - Original code verifier
 * @param {string} codeChallenge - Code challenge to verify
 * @param {string} method - Challenge method ('S256' or 'plain')
 * @returns {boolean} True if verification succeeds
 */
function verifyCodeChallenge(codeVerifier, codeChallenge, method = 'S256') {
    if (!codeVerifier || !codeChallenge) {
        return false;
    }

    let expectedChallenge;
    if (method === 'S256') {
        expectedChallenge = generateCodeChallenge(codeVerifier);
    } else if (method === 'plain') {
        expectedChallenge = generateCodeChallengePlain(codeVerifier);
    } else {
        throw new Error('Invalid challenge method. Use "S256" or "plain"');
    }

    return expectedChallenge === codeChallenge;
}

/**
 * Base64 URL encoding (RFC 7636 compliant)
 * @param {Buffer|string} input - Input to encode
 * @returns {string} Base64url-encoded string
 */
function base64urlEncode(input) {
    const buffer = Buffer.isBuffer(input) ? input : Buffer.from(input);
    return buffer.toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}

/**
 * Base64 URL decoding
 * @param {string} input - Base64url-encoded string
 * @returns {Buffer} Decoded buffer
 */
function base64urlDecode(input) {
    const base64 = input.replace(/-/g, '+').replace(/_/g, '/');
    const padding = base64.length % 4;
    return Buffer.from(base64 + '='.repeat((4 - padding) % 4), 'base64');
}

/**
 * PKCE State Manager for demonstration
 * Tracks PKCE challenges and validates them during token exchange
 */
class PKCEStateManager {
    constructor() {
        this.challenges = new Map();
        this.cleanupInterval = setInterval(() => {
            this.cleanupExpiredChallenges();
        }, 60000); // Clean up every minute
    }

    /**
     * Store PKCE challenge for validation
     * @param {string} state - OAuth2 state parameter
     * @param {string} codeVerifier - Generated code verifier
     * @param {string} codeChallenge - Generated code challenge
     * @param {string} method - Challenge method (default: S256)
     * @param {number} expiryMs - Expiry time in milliseconds (default: 10 minutes)
     */
    storeChallenge(state, codeVerifier, codeChallenge, method = 'S256', expiryMs = 600000) {
        this.challenges.set(state, {
            codeVerifier,
            codeChallenge,
            method,
            timestamp: Date.now(),
            expiry: Date.now() + expiryMs
        });
    }

    /**
     * Validate and retrieve PKCE challenge
     * @param {string} state - OAuth2 state parameter
     * @param {string} providedCodeVerifier - Code verifier provided in token request
     * @returns {Object|null} Challenge data if valid, null otherwise
     */
    validateChallenge(state, providedCodeVerifier) {
        const challengeData = this.challenges.get(state);
        
        if (!challengeData) {
            return null;
        }

        // Check if expired
        if (Date.now() > challengeData.expiry) {
            this.challenges.delete(state);
            return null;
        }

        // Verify the code verifier
        const isValid = verifyCodeChallenge(
            providedCodeVerifier,
            challengeData.codeChallenge,
            challengeData.method
        );

        if (isValid) {
            // Remove used challenge (one-time use)
            this.challenges.delete(state);
            return challengeData;
        }

        return null;
    }

    /**
     * Clean up expired challenges
     */
    cleanupExpiredChallenges() {
        const now = Date.now();
        for (const [state, data] of this.challenges.entries()) {
            if (now > data.expiry) {
                this.challenges.delete(state);
            }
        }
    }

    /**
     * Clear all challenges (for testing)
     */
    clearAllChallenges() {
        this.challenges.clear();
    }

    /**
     * Get challenge count (for monitoring)
     */
    getChallengeCount() {
        return this.challenges.size;
    }
}

// Singleton instance
const pkceStateManager = new PKCEStateManager();

module.exports = {
    generateCodeVerifier,
    generateCodeChallenge,
    generateCodeChallengePlain,
    verifyCodeChallenge,
    base64urlEncode,
    base64urlDecode,
    pkceStateManager
};