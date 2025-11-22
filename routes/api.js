const express = require('express');
const { validateOAuth2Token, validateAdminToken, optionalOAuth2Token } = require('../middleware/oauth2');
const { OAuth2Logger } = require('../utils/logger');

// User routes router
const userRouter = express.Router();

// Admin routes router
const adminRouter = express.Router();

// Public routes router
const publicRouter = express.Router();

/**
 * GET /api/user/profile
 * Get current user's profile information
 * Protected by OAuth2 token validation
 */
userRouter.get('/profile', validateOAuth2Token, (req, res) => {
    const startTime = Date.now();
    const user = req.user;
    
    OAuth2Logger('USER_PROFILE_ACCESSED', req.ip, req.headers['user-agent'], {
        userId: user.id,
        email: user.email
    });

    res.json({
        success: true,
        message: 'User profile retrieved successfully',
        data: {
            id: user.id,
            email: user.email,
            emailVerified: user.emailVerified,
            name: user.name,
            givenName: user.givenName,
            familyName: user.familyName,
            picture: user.picture,
            locale: user.locale,
            provider: user.provider
        },
        metadata: {
            accessDuration: Date.now() - startTime,
            timestamp: new Date().toISOString()
        }
    });
});

/**
 * GET /api/user/dashboard
 * User dashboard with OAuth2-protected data
 */
userRouter.get('/dashboard', validateOAuth2Token, (req, res) => {
    const user = req.user;
    
    // Mock user-specific data
    const userData = {
        recentActivity: [
            {
                id: 1,
                action: 'Profile Updated',
                timestamp: new Date(Date.now() - 3600000).toISOString(),
                details: 'Updated profile picture and display name'
            },
            {
                id: 2,
                action: 'OAuth2 Login',
                timestamp: new Date(Date.now() - 7200000).toISOString(),
                details: `Logged in via Google OAuth2 with PKCE`
            }
        ],
        preferences: {
            theme: 'light',
            language: user.locale || 'en',
            notifications: true
        },
        security: {
            oauth2Enabled: true,
            lastLogin: new Date().toISOString(),
            loginMethod: 'OAuth2 with PKCE'
        }
    };

    OAuth2Logger('USER_DASHBOARD_ACCESSED', req.ip, req.headers['user-agent'], {
        userId: user.id
    });

    res.json({
        success: true,
        message: 'Dashboard data retrieved successfully',
        data: userData,
        user: {
            id: user.id,
            name: user.name,
            email: user.email,
            picture: user.picture
        },
        timestamp: new Date().toISOString()
    });
});

/**
 * POST /api/user/settings
 * Update user settings (OAuth2 protected)
 */
userRouter.post('/settings', validateOAuth2Token, (req, res) => {
    const user = req.user;
    const { theme, language, notifications } = req.body;
    
    // Mock settings update
    const updatedSettings = {
        theme: theme || 'light',
        language: language || 'en',
        notifications: notifications !== undefined ? notifications : true,
        lastUpdated: new Date().toISOString()
    };

    OAuth2Logger('USER_SETTINGS_UPDATED', req.ip, req.headers['user-agent'], {
        userId: user.id,
        updatedFields: Object.keys(req.body)
    });

    res.json({
        success: true,
        message: 'Settings updated successfully',
        data: updatedSettings,
        timestamp: new Date().toISOString()
    });
});

/**
 * GET /api/admin/dashboard
 * Admin dashboard (OAuth2 + admin role required)
 */
adminRouter.get('/dashboard', validateAdminToken, (req, res) => {
    const user = req.user;
    
    // Mock admin data
    const adminData = {
        systemStats: {
            totalUsers: 1250,
            activeUsers: 892,
            oauth2Users: 1156,
            newUsersToday: 12
        },
        oauth2Metrics: {
            totalLogins: 5420,
            pkceUsage: 98.5, // Percentage
            averageSessionDuration: '24m 30s',
            popularScopes: [
                'openid',
                'email',
                'profile',
                'https://www.googleapis.com/auth/userinfo.email'
            ]
        },
        securityAlerts: [
            {
                id: 1,
                type: 'info',
                message: 'PKCE validation rate is excellent',
                timestamp: new Date(Date.now() - 1800000).toISOString()
            }
        ],
        recentActivity: [
            {
                id: 1,
                user: 'user123@gmail.com',
                action: 'OAuth2 Login with PKCE',
                timestamp: new Date(Date.now() - 300000).toISOString()
            }
        ]
    };

    OAuth2Logger('ADMIN_DASHBOARD_ACCESSED', req.ip, req.headers['user-agent'], {
        adminId: user.id,
        adminEmail: user.email
    });

    res.json({
        success: true,
        message: 'Admin dashboard data retrieved successfully',
        data: adminData,
        admin: {
            id: user.id,
            name: user.name,
            email: user.email
        },
        timestamp: new Date().toISOString()
    });
});

/**
 * GET /api/admin/users
 * List users (OAuth2 + admin role required)
 */
adminRouter.get('/users', validateAdminToken, (req, res) => {
    const user = req.user;
    const { page = 1, limit = 10 } = req.query;
    
    // Mock users data
    const users = [
        {
            id: 'user1',
            email: 'user1@gmail.com',
            name: 'John Doe',
            provider: 'google',
            emailVerified: true,
            lastLogin: new Date(Date.now() - 3600000).toISOString(),
            oauth2Details: {
                loginMethod: 'OAuth2 with PKCE',
                scopes: ['openid', 'email', 'profile'],
                pkceUsed: true
            }
        },
        {
            id: 'user2',
            email: 'user2@gmail.com',
            name: 'Jane Smith',
            provider: 'google',
            emailVerified: true,
            lastLogin: new Date(Date.now() - 7200000).toISOString(),
            oauth2Details: {
                loginMethod: 'OAuth2 with PKCE',
                scopes: ['openid', 'email'],
                pkceUsed: true
            }
        }
    ];

    OAuth2Logger('ADMIN_USERS_LISTED', req.ip, req.headers['user-agent'], {
        adminId: user.id,
        page: parseInt(page),
        limit: parseInt(limit)
    });

    res.json({
        success: true,
        message: 'Users list retrieved successfully',
        data: {
            users: users,
            pagination: {
                page: parseInt(page),
                limit: parseInt(limit),
                total: users.length,
                hasMore: false
            }
        },
        timestamp: new Date().toISOString()
    });
});

/**
 * GET /api/admin/oauth2-stats
 * OAuth2 specific statistics and metrics
 */
adminRouter.get('/oauth2-stats', validateAdminToken, (req, res) => {
    const user = req.user;
    
    // Mock OAuth2 statistics
    const oauth2Stats = {
        authenticationFlow: {
            totalFlows: 1247,
            withPKCE: 1245,
            withoutPKCE: 2,
            pkceAdoptionRate: 99.8
        },
        securityMetrics: {
            csrfProtectionRate: 100, // State parameter validation
            tokenValidationSuccess: 99.9,
            invalidTokenAttempts: 3,
            pkceValidationFailures: 0
        },
        providerMetrics: {
            google: {
                totalLogins: 1247,
                successRate: 99.2,
                averageResponseTime: '245ms'
            }
        },
        tokenUsage: {
            accessTokenRefreshes: 423,
            refreshSuccessRate: 98.6,
            averageAccessTokenLifetime: '54m 20s'
        },
        clientTypes: {
            web: 892,
            mobile: 234,
            desktop: 121
        },
        recentSecurityEvents: [
            {
                timestamp: new Date(Date.now() - 1800000).toISOString(),
                type: 'PKCE_VALIDATION_SUCCESS',
                details: 'User successfully completed OAuth2 flow with PKCE'
            },
            {
                timestamp: new Date(Date.now() - 3600000).toISOString(),
                type: 'STATE_VALIDATION_SUCCESS',
                details: 'CSRF protection validated successfully'
            }
        ]
    };

    OAuth2Logger('ADMIN_OAUTH2_STATS_ACCESSED', req.ip, req.headers['user-agent'], {
        adminId: user.id
    });

    res.json({
        success: true,
        message: 'OAuth2 statistics retrieved successfully',
        data: oauth2Stats,
        timestamp: new Date().toISOString()
    });
});

/**
 * GET /api/public/info
 * Public endpoint (no authentication required)
 */
publicRouter.get('/info', (req, res) => {
    res.json({
        success: true,
        message: 'Public API information',
        data: {
            apiVersion: '3.0.0',
            authentication: 'OAuth 2.0 with PKCE',
            provider: 'Google',
            features: [
                'OAuth2 Authorization Code Flow',
                'PKCE (Proof Key for Code Exchange)',
                'State parameter validation',
                'Token introspection',
                'Secure token refresh'
            ],
            endpoints: {
                oauth2: {
                    'GET /api/oauth2/authorize': 'Generate authorization URL',
                    'POST /api/oauth2/token': 'Exchange code for tokens',
                    'POST /api/oauth2/refresh': 'Refresh access token',
                    'GET /api/oauth2/userinfo': 'Get user information'
                },
                protected: {
                    'GET /api/user/profile': 'Get user profile',
                    'GET /api/user/dashboard': 'User dashboard',
                    'GET /api/admin/dashboard': 'Admin dashboard',
                    'GET /api/admin/users': 'List users',
                    'GET /api/admin/oauth2-stats': 'OAuth2 statistics'
                },
                demo: {
                    'GET /api/oauth2/demo/pkce-comparison': 'PKCE security demonstration',
                    'GET /api/oauth2/demo/status': 'PKCE state status'
                }
            },
            security: {
                oauth2Enabled: true,
                pkceEnabled: true,
                csrfProtection: true,
                tokenValidation: true
            }
        },
        timestamp: new Date().toISOString()
    });
});

/**
 * GET /api/health
 * Health check endpoint
 */
publicRouter.get('/health', (req, res) => {
    res.json({
        status: 'OK',
        service: 'OAuth2 Resource Server v3.0',
        authentication: 'Google OAuth2 + PKCE',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        environment: process.env.NODE_ENV || 'development'
    });
});

// Mount the sub-routers
const mainRouter = express.Router();
mainRouter.use('/user', userRouter);
mainRouter.use('/admin', adminRouter);
mainRouter.use('/public', publicRouter);

module.exports = mainRouter;