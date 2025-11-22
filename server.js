require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const oauth2Routes = require('./routes/oauth2');
const apiRoutes = require('./routes/api');
const { requestLogger, infoLogger, errorLogger } = require('./utils/logger');

const app = express();
const PORT = process.env.PORT || 3000;

// Security middleware
app.use(helmet());

// CORS Configuration - Allow all origins for demo
const allowedOrigins = process.env.ALLOWED_ORIGINS;
let corsOptions = {
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: [
        'Content-Type', 
        'Authorization', 
        'X-Requested-With',
        'Accept',
        'Origin',
        'Access-Control-Request-Method',
        'Access-Control-Request-Headers'
    ],
    exposedHeaders: [
        'Authorization',
        'Content-Type'
    ],
    optionsSuccessStatus: 200,
    maxAge: 86400 // 24 hours
};

// Configure origin based on ALLOWED_ORIGINS environment variable
if (allowedOrigins === '*') {
    // Wildcard - allow all origins
    corsOptions.origin = true;
} else if (allowedOrigins) {
    // Specific origins from .env file
    corsOptions.origin = allowedOrigins.split(',').map(origin => origin.trim());
} else {
    // Default origins if ALLOWED_ORIGINS is not set
    corsOptions.origin = ['http://localhost:3000', 'http://localhost:8000', 'http://localhost:5173', 'http://127.0.0.1:5173', 'http://127.0.0.1:3000'];
}

app.use(cors(corsOptions));

// Rate limiting for general API
const limiter = rateLimit({
    windowMs: parseInt(process.env.OAUTH2_RATE_LIMIT_WINDOW) || 60000, // 1 minute
    max: parseInt(process.env.OAUTH2_RATE_LIMIT_MAX_REQUESTS) || 10, // 10 requests per window
    message: {
        error: 'Too many requests, please try again later.',
        code: 'RATE_LIMITED'
    },
    standardHeaders: true,
    legacyHeaders: false,
});
app.use('/api/', limiter);

// More strict rate limiting for OAuth2 endpoints
const oauth2Limiter = rateLimit({
    windowMs: parseInt(process.env.OAUTH2_RATE_LIMIT_WINDOW) || 60000, // 1 minute
    max: parseInt(process.env.OAUTH2_RATE_LIMIT_MAX_REQUESTS) || 5, // 5 OAuth2 requests per window
    message: {
        error: 'Too many OAuth2 requests, please try again later.',
        code: 'OAUTH2_RATE_LIMITED'
    },
    standardHeaders: true,
    legacyHeaders: false,
});
app.use('/api/oauth2/', oauth2Limiter);

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// Logging middleware
app.use(requestLogger);

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        message: 'OAuth2 Resource Server v3.0 is running',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        environment: process.env.NODE_ENV || 'development',
        features: {
            oauth2: true,
            pkce: process.env.ENABLE_PKCE_DEMO === 'true',
            csrf_protection: process.env.ENABLE_CSRF_PROTECTION === 'true'
        }
    });
});

// API documentation endpoint
app.get('/api', (req, res) => {
    res.json({
        name: 'OAuth2 Resource Server v3.0',
        version: '3.0.0',
        description: 'OAuth 2.0 Authorization Code Flow with PKCE Implementation',
        authentication: {
            type: 'OAuth 2.0',
            provider: 'Google',
            flow: 'Authorization Code Flow with PKCE',
            features: ['PKCE', 'State Validation', 'Token Introspection', 'Secure Refresh']
        },
        endpoints: {
            oauth2: {
                'GET /api/oauth2/authorize': 'Generate authorization URL with PKCE',
                'POST /api/oauth2/token': 'Exchange authorization code for tokens',
                'POST /api/oauth2/refresh': 'Refresh access token',
                'GET /api/oauth2/userinfo': 'Get user information',
                'GET /api/oauth2/demo/pkce-comparison': 'PKCE security demonstration',
                'GET /api/oauth2/demo/status': 'PKCE state manager status'
            },
            protected: {
                'GET /api/user/profile': 'Get user profile (OAuth2 required)',
                'GET /api/user/dashboard': 'User dashboard (OAuth2 required)',
                'POST /api/user/settings': 'Update user settings (OAuth2 required)',
                'GET /api/admin/dashboard': 'Admin dashboard (Admin OAuth2 required)',
                'GET /api/admin/users': 'List users (Admin OAuth2 required)',
                'GET /api/admin/oauth2-stats': 'OAuth2 statistics (Admin OAuth2 required)'
            },
            public: {
                'GET /api/public/info': 'Public API information',
                'GET /api/health': 'Health check'
            }
        },
        security: {
            pkce_enabled: process.env.ENABLE_PKCE_DEMO === 'true',
            csrf_protection: process.env.ENABLE_CSRF_PROTECTION === 'true',
            state_validation: process.env.ENABLE_STATE_VALIDATION === 'true'
        },
        demo: {
            purpose: 'Educational demonstration of OAuth2 with PKCE',
            features: ['PKCE security benefits', 'OAuth2 flow explanation', 'Google OAuth2 integration']
        },
        timestamp: new Date().toISOString()
    });
});

// OAuth2 routes
app.use('/api/oauth2', oauth2Routes);

// Protected API routes
app.use('/api', apiRoutes);

// 404 handler
app.use('*', (req, res) => {
    res.status(404).json({ 
        error: 'API endpoint not found',
        code: 'ENDPOINT_NOT_FOUND',
        path: req.originalUrl,
        method: req.method,
        timestamp: new Date().toISOString()
    });
});

// Global error handling middleware
app.use((err, req, res, next) => {
    errorLogger(err, req);
    
    // OAuth2 specific errors
    if (err.name === 'OAuth2Error') {
        return res.status(400).json({
            error: err.message,
            code: 'OAUTH2_ERROR',
            ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
        });
    }
    
    // Google API errors
    if (err.response && err.response.status === 401) {
        return res.status(401).json({
            error: 'Authentication failed',
            code: 'OAUTH2_AUTH_FAILED',
            message: 'Google OAuth2 authentication failed'
        });
    }
    
    // Default error response
    res.status(err.status || 500).json({
        error: err.message || 'Internal Server Error',
        code: 'INTERNAL_ERROR',
        ...(process.env.NODE_ENV === 'development' && { 
            stack: err.stack,
            details: err.details 
        }),
        timestamp: new Date().toISOString()
    });
});

// Graceful shutdown
process.on('SIGTERM', () => {
    infoLogger('SIGTERM received, shutting down gracefully');
    process.exit(0);
});

process.on('SIGINT', () => {
    infoLogger('SIGINT received, shutting down gracefully');
    process.exit(0);
});

// Start server
app.listen(PORT, () => {
    infoLogger(`OAuth2 Resource Server v3.0 running on port ${PORT}`);
    infoLogger(`Environment: ${process.env.NODE_ENV || 'development'}`);
    infoLogger(`PKCE Demo: ${process.env.ENABLE_PKCE_DEMO === 'true' ? 'Enabled' : 'Disabled'}`);
    infoLogger(`CORS Origins: ${allowedOrigins || 'Default origins'}`);
});

module.exports = app;