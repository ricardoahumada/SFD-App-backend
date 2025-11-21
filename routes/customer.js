const express = require('express');
const { authenticateToken, requireRole, requireScopes, userRateLimit } = require('../middleware/auth');
const logger = require('../utils/logger');

const router = express.Router();

/**
 * GET /api/customer
 * Protected endpoint - requires customer role
 * Enhanced with comprehensive JWT validation
 */
router.get('/', 
    authenticateToken, 
    requireRole('customer'), 
    userRateLimit(100, 15 * 60 * 1000), // 100 requests per 15 minutes
    (req, res) => {
        logger.infoLogger('Customer service accessed', {
            userId: req.user.id,
            email: req.user.email,
            sessionId: req.tokenData.sessionId,
            jti: req.tokenData.jti,
            scopes: req.tokenData.scopes
        });

        res.json({
            success: true,
            message: 'Customer service accessed successfully',
            data: {
                service: 'customer_service',
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
 * GET /api/customer/profile
 * Protected endpoint - get customer profile with enhanced information
 */
router.get('/profile', 
    authenticateToken, 
    requireRole('customer'), 
    userRateLimit(50, 15 * 60 * 1000), // 50 requests per 15 minutes
    (req, res) => {
        logger.infoLogger('Customer profile accessed', {
            userId: req.user.id,
            email: req.user.email,
            sessionId: req.tokenData.sessionId
        });

        res.json({
            success: true,
            message: 'Customer profile retrieved successfully',
            profile: {
                id: req.user.id,
                name: req.user.name,
                email: req.user.email,
                role: req.user.role,
                scopes: req.tokenData.scopes,
                createdAt: req.user.createdAt,
                lastLogin: req.user.lastLogin,
                accountStatus: 'active',
                membershipLevel: 'standard',
                preferences: {
                    language: 'en',
                    timezone: 'UTC',
                    notifications: true
                }
            },
            session: {
                id: req.tokenData.sessionId,
                jti: req.tokenData.jti,
                createdAt: req.tokenData.iat * 1000,
                expiresAt: req.tokenData.exp * 1000,
                clientId: req.tokenData.clientId
            },
            permissions: {
                canRead: req.tokenData.scopes.includes('read'),
                canWrite: req.tokenData.scopes.includes('write'),
                canAccessProfile: req.tokenData.scopes.includes('profile:read'),
                canUpdateProfile: req.tokenData.scopes.includes('profile:write')
            },
            timestamp: new Date().toISOString()
        });
    }
);

/**
 * PUT /api/customer/profile
 * Update customer profile
 */
router.put('/profile', 
    authenticateToken, 
    requireRole('customer'), 
    requireScopes(['profile:write']),
    userRateLimit(20, 15 * 60 * 1000), // 20 requests per 15 minutes
    (req, res) => {
        const { name, preferences } = req.body || {};
        
        logger.infoLogger('Customer profile update requested', {
            userId: req.user.id,
            sessionId: req.tokenData.sessionId,
            fieldsUpdated: req.body ? Object.keys(req.body) : []
        });

        // In a real application, you would update the database here
        // For this demo, we'll just validate and return success
        
        res.json({
            success: true,
            message: 'Profile updated successfully',
            updatedProfile: {
                id: req.user.id,
                name: name || req.user.name,
                email: req.user.email, // Email cannot be changed for security
                role: req.user.role,
                preferences: preferences || { language: 'en', timezone: 'UTC', notifications: true },
                updatedAt: new Date().toISOString()
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
 * GET /api/customer/data
 * Get customer-specific data
 */
router.get('/data', 
    authenticateToken, 
    requireRole('customer'), 
    requireScopes(['read']),
    userRateLimit(30, 15 * 60 * 1000), // 30 requests per 15 minutes
    (req, res) => {
        logger.infoLogger('Customer data accessed', {
            userId: req.user.id,
            email: req.user.email,
            sessionId: req.tokenData.sessionId
        });

        // Sample customer data
        const customerData = {
            id: req.user.id,
            orderHistory: [
                {
                    id: 'ORD-001',
                    date: '2024-01-15',
                    amount: 299.99,
                    status: 'delivered'
                },
                {
                    id: 'ORD-002',
                    date: '2024-02-10',
                    amount: 149.50,
                    status: 'processing'
                }
            ],
            preferences: {
                shippingAddress: '123 Main St, City, State 12345',
                paymentMethod: '****-****-****-1234',
                newsletter: true,
                notifications: true
            },
            statistics: {
                totalOrders: 2,
                totalSpent: 449.49,
                memberSince: req.user.createdAt,
                lastPurchase: '2024-02-10'
            }
        };

        res.json({
            success: true,
            message: 'Customer data retrieved successfully',
            data: customerData,
            session: {
                id: req.tokenData.sessionId,
                jti: req.tokenData.jti,
                expiresAt: req.tokenData.exp * 1000
            },
            timestamp: new Date().toISOString()
        });
    }
);

/**
 * POST /api/customer/feedback
 * Submit customer feedback
 */
router.post('/feedback', 
    authenticateToken, 
    requireRole('customer'), 
    userRateLimit(10, 60 * 60 * 1000), // 10 requests per hour
    (req, res) => {
        const { rating, comment, category = 'general' } = req.body || {};

        if (!rating || rating < 1 || rating > 5) {
            return res.status(400).json({
                error: 'Rating must be between 1 and 5',
                code: 'INVALID_RATING'
            });
        }

        logger.infoLogger('Customer feedback submitted', {
            userId: req.user.id,
            rating: rating,
            category: category,
            sessionId: req.tokenData.sessionId,
            commentLength: comment ? comment.length : 0
        });

        res.json({
            success: true,
            message: 'Feedback submitted successfully',
            feedback: {
                id: `FB-${Date.now()}`,
                userId: req.user.id,
                rating: rating,
                category: category,
                comment: comment,
                submittedAt: new Date().toISOString(),
                status: 'received'
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
 * GET /api/customer/security
 * Get security information for the customer
 */
router.get('/security', 
    authenticateToken, 
    requireRole('customer'), 
    userRateLimit(20, 15 * 60 * 1000), // 20 requests per 15 minutes
    (req, res) => {
        logger.infoLogger('Customer security info accessed', {
            userId: req.user.id,
            sessionId: req.tokenData.sessionId
        });

        res.json({
            success: true,
            message: 'Security information retrieved successfully',
            security: {
                lastLogin: req.user.lastLogin,
                activeSessions: 1, // In a real app, this would come from session storage
                tokenInfo: {
                    algorithm: req.tokenData.alg,
                    issuedAt: req.tokenData.iat * 1000,
                    expiresAt: req.tokenData.exp * 1000,
                    jti: req.tokenData.jti,
                    sessionId: req.tokenData.sessionId
                },
                clientInfo: {
                    ipAddress: req.clientInfo.ipAddress,
                    userAgent: req.clientInfo.userAgent
                },
                permissions: req.tokenData.scopes,
                accountAge: Math.floor((Date.now() - new Date(req.user.createdAt).getTime()) / (1000 * 60 * 60 * 24))
            },
            timestamp: new Date().toISOString()
        });
    }
);

module.exports = router;