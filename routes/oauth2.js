const express = require('express');
const googleOAuth2 = require('../utils/googleOAuth2');
const { pkceStateManager } = require('../utils/pkceHelper');
const { OAuth2Logger, pkceLogger } = require('../utils/logger');

const router = express.Router();

/**
 * GET /api/oauth2/authorize
 * Generate authorization URL with PKCE for demo purposes
 * In production, this would redirect to Google's authorization endpoint
 */
router.get('/authorize', (req, res) => {
    try {
        const clientIp = req.ip || req.connection.remoteAddress;
        const userAgent = req.headers['user-agent'] || 'Unknown';
        
        // Generate authorization URL with PKCE
        const authData = googleOAuth2.generateAuthorizationUrl();
        
        // Store PKCE challenge for validation (demo purposes)
        if (process.env.ENABLE_PKCE_DEMO === 'true') {
            pkceStateManager.storeChallenge(
                authData.state,
                authData.codeVerifier,
                authData.codeChallenge,
                'S256'
            );
            
            console.log('PKCE Debug - Challenge stored with state:', authData.state);
            console.log('PKCE Debug - Active challenges after store:', pkceStateManager.getChallengeCount());
            
            pkceLogger('CHALLENGE_GENERATED', authData.state, {
                codeChallenge: authData.codeChallenge.substring(0, 16) + '...',
                method: 'S256'
            });
        }

        OAuth2Logger('AUTHORIZATION_URL_GENERATED', clientIp, userAgent, {
            state: authData.state,
            nonce: authData.nonce
        });

        res.json({
            success: true,
            message: 'Authorization URL generated successfully',
            data: {
                authorizationUrl: authData.authorizationUrl,
                state: authData.state,
                nonce: authData.nonce,
                pkce: {
                    enabled: process.env.ENABLE_PKCE_DEMO === 'true',
                    codeVerifier: process.env.ENABLE_PKCE_DEMO === 'true' ? authData.codeVerifier : null,
                    codeChallenge: process.env.ENABLE_PKCE_DEMO === 'true' ? authData.codeChallenge : null,
                    method: 'S256'
                }
            },
            instructions: {
                step1: 'Copy the authorization URL and open it in a new tab/window',
                step2: 'Complete Google OAuth2 authorization',
                step3: 'Copy the authorization code from the redirect URL',
                step4: 'Use the /token endpoint to exchange the code for tokens'
            },
            demoNote: 'This is a demonstration of PKCE. In production, the frontend would automatically redirect to Google.'
        });
    } catch (error) {
        OAuth2Logger('AUTHORIZATION_URL_ERROR', req.ip, req.headers['user-agent'], {
            error: error.message
        });

        res.status(500).json({
            error: 'Failed to generate authorization URL',
            code: 'AUTHORIZATION_URL_ERROR',
            message: error.message
        });
    }
});

/**
 * POST /api/oauth2/token
 * Exchange authorization code for access token
 * Supports PKCE verification for enhanced security
 */
router.post('/token', async (req, res) => {
    try {
        const startTime = Date.now();
        const clientIp = req.ip || req.connection.remoteAddress;
        const userAgent = req.headers['user-agent'] || 'Unknown';
        const { code, code_verifier, state } = req.body;

        // Input validation
        if (!code) {
            OAuth2Logger('TOKEN_EXCHANGE_FAILED', clientIp, userAgent, {
                error: 'Authorization code missing',
                state
            });
            return res.status(400).json({
                error: 'Authorization code is required',
                code: 'CODE_MISSING',
                message: 'Authorization code must be provided'
            });
        }

        // Validate state parameter for CSRF protection
        if (!state) {
            OAuth2Logger('TOKEN_EXCHANGE_FAILED', clientIp, userAgent, {
                error: 'State parameter missing',
                state
            });
            return res.status(400).json({
                error: 'State parameter is required',
                code: 'STATE_MISSING',
                message: 'State parameter is required for CSRF protection'
            });
        }

        // PKCE validation (if enabled)
        let pkceValidated = false;
        if (process.env.ENABLE_PKCE_DEMO === 'true') {
            console.log('PKCE Debug - State received:', state);
            console.log('PKCE Debug - Code verifier received:', code_verifier);
            console.log('PKCE Debug - Active challenges:', pkceStateManager.getChallengeCount());
            
            const challengeData = pkceStateManager.validateChallenge(state, code_verifier);
            console.log('PKCE Debug - Challenge data found:', !!challengeData);
            
            if (!challengeData) {
                OAuth2Logger('PKCE_VALIDATION_FAILED', clientIp, userAgent, {
                    state,
                    error: 'Invalid or expired PKCE challenge',
                    activeChallenges: pkceStateManager.getChallengeCount()
                });
                return res.status(400).json({
                    error: 'PKCE verification failed',
                    code: 'PKCE_VALIDATION_FAILED',
                    message: 'Invalid or expired PKCE challenge. Please restart the authorization flow.'
                });
            }
            pkceValidated = true;
            pkceLogger('CHALLENGE_VALIDATED', state, {
                method: challengeData.method
            });
        }

        // Exchange code for tokens
        const tokenData = await googleOAuth2.exchangeCodeForTokens(code, code_verifier);
        
        // Verify ID token if present
        let userInfo = null;
        if (tokenData.idToken) {
            const idTokenData = await googleOAuth2.verifyIdToken(tokenData.idToken);
            userInfo = await googleOAuth2.getUserInfo(tokenData.accessToken);
        }

        OAuth2Logger('TOKEN_EXCHANGE_SUCCESS', clientIp, userAgent, {
            userId: userInfo?.sub || 'unknown',
            hasRefreshToken: !!tokenData.refreshToken,
            pkceValidated,
            duration: Date.now() - startTime
        });

        res.json({
            success: true,
            message: 'Tokens generated successfully',
            data: {
                access_token: tokenData.accessToken,
                refresh_token: tokenData.refreshToken,
                expires_in: tokenData.expiresIn,
                token_type: tokenData.tokenType,
                id_token: tokenData.idToken,
                scope: tokenData.scope,
                user_info: userInfo,
                pkce: {
                    validated: pkceValidated,
                    method: pkceValidated ? 'S256' : null
                }
            },
            security: {
                pkce_enabled: process.env.ENABLE_PKCE_DEMO === 'true',
                pkce_validated: pkceValidated,
                state_validated: true,
                token_verified: !!tokenData.idToken
            },
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        OAuth2Logger('TOKEN_EXCHANGE_ERROR', req.ip, req.headers['user-agent'], {
            error: error.message,
            state: req.body.state
        });

        res.status(400).json({
            error: 'Token exchange failed',
            code: 'TOKEN_EXCHANGE_ERROR',
            message: error.message,
            timestamp: new Date().toISOString()
        });
    }
});

/**
 * POST /api/oauth2/refresh
 * Refresh access token using refresh token
 */
router.post('/refresh', async (req, res) => {
    try {
        const startTime = Date.now();
        const clientIp = req.ip || req.connection.remoteAddress;
        const userAgent = req.headers['user-agent'] || 'Unknown';
        const { refresh_token } = req.body;

        if (!refresh_token) {
            return res.status(400).json({
                error: 'Refresh token is required',
                code: 'REFRESH_TOKEN_MISSING'
            });
        }

        const tokenData = await googleOAuth2.refreshAccessToken(refresh_token);
        
        OAuth2Logger('TOKEN_REFRESH_SUCCESS', clientIp, userAgent, {
            duration: Date.now() - startTime
        });

        res.json({
            success: true,
            message: 'Access token refreshed successfully',
            data: {
                access_token: tokenData.accessToken,
                expires_in: tokenData.expiresIn,
                token_type: tokenData.tokenType,
                scope: tokenData.scope
            },
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        OAuth2Logger('TOKEN_REFRESH_ERROR', req.ip, req.headers['user-agent'], {
            error: error.message
        });

        res.status(400).json({
            error: 'Token refresh failed',
            code: 'TOKEN_REFRESH_ERROR',
            message: error.message,
            timestamp: new Date().toISOString()
        });
    }
});

/**
 * GET /api/oauth2/userinfo
 * Get user information from access token
 */
router.get('/userinfo', async (req, res) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({
                error: 'Access token required',
                code: 'TOKEN_MISSING'
            });
        }

        const accessToken = authHeader.substring(7);
        const userInfo = await googleOAuth2.getUserInfo(accessToken);

        res.json({
            success: true,
            data: userInfo,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(401).json({
            error: 'Failed to get user info',
            code: 'USERINFO_ERROR',
            message: error.message
        });
    }
});

/**
 * GET /api/oauth2/demo/pkce-comparison
 * Demo endpoint showing PKCE benefits (for educational purposes)
 */
router.get('/demo/pkce-comparison', (req, res) => {
    try {
        // Generate sample PKCE data for demonstration
        const codeVerifier = googleOAuth2.generateCodeVerifier();
        const codeChallengeS256 = googleOAuth2.generateCodeChallenge(codeVerifier);
        const codeChallengePlain = codeVerifier; // Plain method (insecure)

        res.json({
            success: true,
            message: 'PKCE Security Comparison Demonstration',
            demo: {
                pkce_concept: {
                    description: 'PKCE (Proof Key for Code Exchange) adds an extra layer of security to OAuth 2.0',
                    problem: 'Without PKCE, a malicious app could intercept the authorization code and exchange it for tokens',
                    solution: 'PKCE binds the authorization request to the token exchange request using cryptographic verification'
                },
                methods: {
                    plain: {
                        method: 'plain',
                        description: 'Code challenge = code verifier (insecure, not recommended)',
                        code_challenge: codeChallengePlain,
                        security_level: 'LOW',
                        use_case: 'Only for backwards compatibility'
                    },
                    s256: {
                        method: 'S256',
                        description: 'Code challenge = SHA256(code verifier) encoded as base64url',
                        code_challenge: codeChallengeS256,
                        security_level: 'HIGH',
                        use_case: 'Recommended for all applications'
                    }
                },
                comparison: {
                    without_pkce: {
                        vulnerability: 'Authorization code interception attack',
                        attacker_steps: [
                            'User clicks malicious app authorization link',
                            'User redirected to legitimate OAuth2 provider',
                            'User authenticates and consents',
                            'Attacker intercepts authorization code',
                            'Attacker exchanges code for tokens using their own app',
                            'Attacker gains access to user resources'
                        ],
                        mitigation: 'PKCE prevents this by requiring cryptographic proof'
                    },
                    with_pkce: {
                        security_benefit: 'Binds authorization request to token exchange',
                        attacker_challenge: [
                            'Attacker intercepts authorization code',
                            'Attacker tries to exchange code for tokens',
                            'Provider requires code_verifier',
                            'Attacker cannot compute valid code_verifier without the original',
                            'Attack fails because attacker cannot prove they initiated the request'
                        ]
                    }
                },
                implementation_notes: {
                    code_verifier_generation: 'Cryptographically secure random string (43-128 characters)',
                    code_challenge_generation: 'SHA256 hash of code verifier, base64url encoded',
                    state_validation: 'CSRF protection through state parameter matching',
                    one_time_use: 'Code verifier can only be used once'
                }
            },
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({
            error: 'Failed to generate PKCE demonstration',
            code: 'PKCE_DEMO_ERROR',
            message: error.message
        });
    }
});

/**
 * GET /api/oauth2/demo/status
 * Get current PKCE state manager status
 */
router.get('/demo/status', (req, res) => {
    res.json({
        success: true,
        data: {
            pkce_enabled: process.env.ENABLE_PKCE_DEMO === 'true',
            active_challenges: pkceStateManager.getChallengeCount(),
            configuration: {
                code_verifier_length: process.env.PKCE_CODE_VERIFIER_LENGTH || 128,
                code_challenge_method: process.env.PKCE_CODE_CHALLENGE_METHOD || 'S256'
            },
            timestamp: new Date().toISOString()
        }
    });
});

module.exports = router;