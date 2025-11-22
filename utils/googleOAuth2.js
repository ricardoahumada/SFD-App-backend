const { OAuth2Client } = require('google-auth-library');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const qs = require('qs');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');

/**
 * Google OAuth2 Client Configuration
 */
class GoogleOAuth2Client {
    constructor() {
        this.clientId = process.env.GOOGLE_CLIENT_ID;
        this.clientSecret = process.env.GOOGLE_CLIENT_SECRET;
        this.redirectUri = process.env.GOOGLE_REDIRECT_URI;
        this.scopes = process.env.GOOGLE_SCOPES?.split(' ') || [];
        
        this.authEndpoint = process.env.OAUTH2_AUTHORIZATION_ENDPOINT;
        this.tokenEndpoint = process.env.OAUTH2_TOKEN_ENDPOINT;
        this.userInfoEndpoint = process.env.OAUTH2_USERINFO_ENDPOINT;
        
        if (!this.clientId || !this.clientSecret) {
            throw new Error('Google OAuth2 credentials not configured');
        }
    }

    /**
     * Generate Authorization URL with PKCE for demo purposes
     * In a real implementation, this would be handled by the frontend
     */
    generateAuthorizationUrl(options = {}) {
        const state = options.state || uuidv4();
        const nonce = options.nonce || uuidv4();
        
        // Generate PKCE challenge (for educational demonstration)
        const codeVerifier = this.generateCodeVerifier();
        const codeChallenge = this.generateCodeChallenge(codeVerifier);
        
        const params = {
            client_id: this.clientId,
            redirect_uri: this.redirectUri,
            response_type: 'code',
            scope: this.scopes.join(' '),
            state: state,
            nonce: nonce,
            code_challenge: codeChallenge,
            code_challenge_method: 'S256',
            access_type: 'offline',
            prompt: 'consent'
        };

        const authUrl = new URL(this.authEndpoint);
        Object.keys(params).forEach(key => {
            authUrl.searchParams.append(key, params[key]);
        });

        return {
            authorizationUrl: authUrl.toString(),
            state: state,
            nonce: nonce,
            codeVerifier: codeVerifier,
            codeChallenge: codeChallenge
        };
    }

    /**
     * Exchange authorization code for access token
     */
    async exchangeCodeForTokens(code, codeVerifier, options = {}) {
        try {
            const tokenRequest = {
                client_id: this.clientId,
                client_secret: this.clientSecret,
                code: code,
                grant_type: 'authorization_code',
                redirect_uri: this.redirectUri
            };

            // Add PKCE code verifier if provided (for educational demonstration)
            if (codeVerifier && process.env.ENABLE_PKCE_DEMO === 'true') {
                tokenRequest.code_verifier = codeVerifier;
            }

            const response = await axios.post(this.tokenEndpoint, qs.stringify(tokenRequest), {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                }
            });

            return {
                accessToken: response.data.access_token,
                refreshToken: response.data.refresh_token,
                expiresIn: response.data.expires_in,
                tokenType: response.data.token_type,
                idToken: response.data.id_token,
                scope: response.data.scope
            };
        } catch (error) {
            console.error('Token exchange failed:', error.response?.data || error.message);
            throw new Error(`Token exchange failed: ${error.response?.data?.error_description || error.message}`);
        }
    }

    /**
     * Verify and decode ID token
     */
    async verifyIdToken(idToken) {
        try {
            // In production, you should verify the token signature with Google's public keys
            // For this demo, we'll decode and validate the payload
            const decoded = jwt.decode(idToken);
            
            if (!decoded) {
                throw new Error('Invalid token format');
            }

            // Check token expiration
            if (decoded.exp * 1000 < Date.now()) {
                throw new Error('Token has expired');
            }

            // Check issuer
            if (decoded.iss !== 'https://accounts.google.com') {
                throw new Error('Invalid token issuer');
            }

            // Check audience
            if (decoded.aud !== this.clientId) {
                throw new Error('Invalid token audience');
            }

            return decoded;
        } catch (error) {
            console.error('ID token verification failed:', error.message);
            throw new Error(`ID token verification failed: ${error.message}`);
        }
    }

    /**
     * Get user information from token
     */
    async getUserInfo(accessToken) {
        try {
            const response = await axios.get(this.userInfoEndpoint, {
                headers: {
                    'Authorization': `Bearer ${accessToken}`
                }
            });

            return {
                sub: response.data.sub,
                email: response.data.email,
                email_verified: response.data.email_verified,
                name: response.data.name,
                given_name: response.data.given_name,
                family_name: response.data.family_name,
                picture: response.data.picture,
                locale: response.data.locale
            };
        } catch (error) {
            console.error('User info retrieval failed:', error.response?.data || error.message);
            throw new Error(`User info retrieval failed: ${error.message}`);
        }
    }

    /**
     * Refresh access token
     */
    async refreshAccessToken(refreshToken) {
        try {
            const tokenRequest = {
                client_id: this.clientId,
                client_secret: this.clientSecret,
                refresh_token: refreshToken,
                grant_type: 'refresh_token'
            };

            const response = await axios.post(this.tokenEndpoint, qs.stringify(tokenRequest), {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                }
            });

            return {
                accessToken: response.data.access_token,
                expiresIn: response.data.expires_in,
                tokenType: response.data.token_type,
                scope: response.data.scope
            };
        } catch (error) {
            console.error('Token refresh failed:', error.response?.data || error.message);
            throw new Error(`Token refresh failed: ${error.response?.data?.error_description || error.message}`);
        }
    }

    /**
     * Generate PKCE code verifier (cryptographically secure random string)
     */
    generateCodeVerifier(length = 128) {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
        let result = '';
        const randomValues = crypto.randomBytes(length);
        
        for (let i = 0; i < length; i++) {
            result += chars[randomValues[i] % chars.length];
        }
        
        return result;
    }

    /**
     * Generate PKCE code challenge from code verifier
     */
    generateCodeChallenge(codeVerifier) {
        const hash = crypto.createHash('sha256').update(codeVerifier).digest(); // Get Buffer directly
        return this.base64urlEncode(hash);
    }

    /**
     * Base64 URL encode
     */
    base64urlEncode(input) {
        // Convert Buffer to base64 string if needed
        const str = Buffer.isBuffer(input) ? input.toString('base64') : input;
        return str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    }
}

module.exports = new GoogleOAuth2Client();