require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const authRoutes = require('./routes/auth');
const customerRoutes = require('./routes/customer');
const adminRoutes = require('./routes/admin');
const tokenRoutes = require('./routes/tokens');
const logger = require('./utils/logger');

const app = express();
const PORT = process.env.PORT || 3000;

// Security middleware
app.use(helmet());

// CORS Configuration
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

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: {
        error: 'Too many requests from this IP, please try again later.'
    },
    standardHeaders: true,
    legacyHeaders: false,
});
app.use('/api/', limiter);

// More strict rate limiting for auth endpoints
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // limit each IP to 5 login attempts per windowMs
    message: {
        error: 'Too many login attempts, please try again later.'
    },
    skipSuccessfulRequests: true,
});
app.use('/api/auth/login', authLimiter);

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// Logging middleware
app.use(logger.requestLogger);

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        message: 'Advanced Auth Server v2.0 is running',
        timestamp: new Date().toISOString(),
        uptime: process.uptime()
    });
});

// API routes
app.use('/api/auth', authRoutes);
app.use('/api/customer', customerRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/tokens', tokenRoutes);

// API documentation endpoint
app.get('/api', (req, res) => {
    res.json({
        name: 'Advanced Authentication API v2.0',
        version: '2.0.0',
        endpoints: {
            auth: {
                'POST /api/auth/login': 'Login with email/password',
                'POST /api/auth/refresh': 'Refresh access token',
                'POST /api/auth/logout': 'Logout and blacklist tokens',
                'POST /api/auth/logout-all': 'Logout from all devices'
            },
            protected: {
                'GET /api/customer': 'Customer service (customer role required)',
                'GET /api/customer/profile': 'Customer profile (customer role required)',
                'GET /api/admin': 'Admin service (admin role required)',
                'GET /api/admin/users': 'Users management (admin role required)',
                'GET /api/admin/stats': 'System statistics (admin role required)'
            },
            token: {
                'POST /api/tokens/introspect': 'Introspect and validate token',
                'GET /api/tokens/blacklist': 'Check if token is blacklisted'
            }
        },
        demoCredentials: {
            admin: { email: 'admin@example.com', password: 'admin123' },
            customer: { email: 'customer@example.com', password: 'customer123' }
        }
    });
});

// 404 handler
app.use('*', (req, res) => {
    res.status(404).json({ 
        error: 'API endpoint not found',
        path: req.originalUrl,
        method: req.method
    });
});

// Global error handling middleware
app.use((err, req, res, next) => {
    logger.errorLogger(err, req);
    
    // JWT errors
    if (err.name === 'JsonWebTokenError') {
        return res.status(401).json({
            error: 'Invalid token',
            message: err.message
        });
    }
    
    if (err.name === 'TokenExpiredError') {
        return res.status(401).json({
            error: 'Token expired',
            message: 'Please refresh your token'
        });
    }
    
    // Default error response
    res.status(err.status || 500).json({
        error: err.message || 'Internal Server Error',
        ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
    });
});

// Graceful shutdown
process.on('SIGTERM', () => {
    logger.infoLogger('SIGTERM received, shutting down gracefully');
    process.exit(0);
});

process.on('SIGINT', () => {
    logger.infoLogger('SIGINT received, shutting down gracefully');
    process.exit(0);
});

app.listen(PORT, () => {
    logger.infoLogger(`Advanced Auth Server v2.0 running on port ${PORT}`);
    logger.infoLogger(`Environment: ${process.env.NODE_ENV || 'development'}`);
});

module.exports = app;