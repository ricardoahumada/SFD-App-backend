# Advanced Authentication System v2.0

[![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)](https://github.com/your-repo/auth-system)
[![Node](https://img.shields.io/badge/node-%3E%3D16.0.0-green.svg)](https://nodejs.org/)
[![License](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)

A comprehensive, enterprise-grade JWT authentication system with refresh token rotation, blacklisting, and advanced security features.

## What's New in v2.0

### Major Enhancements
- **🔄 Refresh Token Rotation** - Automatic token refresh with secure rotation mechanism
- **🛡️ Token Blacklisting** - Immediate token invalidation for enhanced security
- **🔍 Token Introspection** - RFC 7662 compliant token validation service
- **⚡ Automatic Refresh** - 5-minute buffer auto-refresh before expiration
- **🎯 Comprehensive Claims** - Issuer, audience, subject, scope, and JTI validation
- **🔐 Enhanced Security** - Clock skew tolerance and production-ready algorithms
- **📊 Advanced Logging** - Comprehensive audit trails and security monitoring

### Technology Stack
- **Backend**: Node.js, Express.js, JWT with RS256/HS256 support
- **Frontend**: Vanilla JavaScript with enhanced token management
- **Security**: Token rotation, blacklisting, rate limiting, comprehensive logging
- **Deployment**: CodeSandbox, Replit, and local development ready

## Project Structure

```
v2/
├── backend/                     # Enhanced Node.js Backend
│   ├── server.js               # Main server with security middleware
│   ├── package.json            # Dependencies and scripts
│   ├── .env.example            # Environment configuration template
│   ├── routes/
│   │   ├── auth.js            # Enhanced authentication endpoints
│   │   ├── customer.js        # Customer service with comprehensive data
│   │   ├── admin.js          # Admin management with session control
│   │   └── tokens.js         # Token introspection and management
│   ├── middleware/
│   │   └── auth.js           # Advanced JWT validation middleware
│   ├── models/
│   │   └── users.js          # Enhanced user model with refresh tokens
│   ├── utils/
│   │   ├── jwtManager.js     # Comprehensive JWT management
│   │   ├── logger.js         # Enhanced logging system
│   │   └── generateKeys.js   # RSA key generation utility
│   └── configuration files   # Deployment and environment configs
├── frontend/                  # Enhanced Frontend SPA
│   ├── index.html            # Enhanced UI with debug capabilities
│   ├── css/style.css         # Responsive design with new components
│   └── js/
│       ├── api.js           # Enhanced API client with auto-refresh
│       ├── jwt-utils.js     # Comprehensive JWT utilities
│       ├── token-manager.js # Automatic token refresh management
│       ├── auth.js          # Enhanced authentication logic
│       ├── router.js        # Advanced client-side routing
│       └── app.js           # Complete application orchestration
├── CHANGES.md               # Detailed feature documentation
└── README.md               # This file
```

## Features

### Backend Features
- ✅ **JWT with Comprehensive Claims** - Standard and custom claims with validation
- ✅ **Refresh Token Rotation** - Automatic rotation with secure session management
- ✅ **Token Blacklisting** - Immediate invalidation for security incidents
- ✅ **Algorithm Selection** - RS256 for production, HS256 for development
- ✅ **Token Introspection** - RFC 7662 compliant validation service
- ✅ **Clock Skew Tolerance** - Handles distributed system time differences
- ✅ **Enhanced Security Middleware** - Role-based access with fine-grained permissions
- ✅ **Comprehensive Logging** - Request tracking, auth events, security monitoring
- ✅ **Rate Limiting** - Global and endpoint-specific limits
- ✅ **Session Management** - Multi-device session tracking and control

### Frontend Features
- ✅ **Automatic Token Refresh** - 5-minute buffer before expiration
- ✅ **JWT Parsing & Validation** - Client-side token analysis and debugging
- ✅ **Secure Token Storage** - Enhanced storage with multi-tab synchronization
- ✅ **Token Payload Inspection** - Development debug tools with detailed information
- ✅ **Enhanced User Interface** - Real-time token status, session information
- ✅ **Advanced Routing** - Role-based access with comprehensive validation
- ✅ **Error Handling** - Graceful error recovery with user notifications
- ✅ **Performance Monitoring** - Real-time token expiration tracking

## Quick Start

### Prerequisites
- Node.js 16+ installed
- Modern web browser (Chrome, Firefox, Safari, Edge)

### 1. Backend Setup

```bash
cd v2/backend

# Install dependencies
npm install

# Generate RSA keys (for production RS256)
npm run generate-keys

# Copy environment template
cp .env.example .env

# Start the server
npm start
```

**Backend will run on**: `http://localhost:3000`

### 2. Frontend Setup

```bash
cd v2/frontend

# Start a local web server
python -m http.server 8000

# Or using Node.js
npx serve .

# Or using VS Code Live Server extension
```

**Frontend will run on**: `http://localhost:8000`

### 3. Access the Application

Open your browser and navigate to `http://localhost:8000`

## Demo Credentials

### Admin User
- **Email**: admin@example.com
- **Password**: admin123
- **Features**: Full system access, user management, token blacklisting

### Customer User
- **Email**: customer@example.com
- **Password**: customer123
- **Features**: Customer services, profile management, feedback system

## API Endpoints

### Authentication
```
POST /api/auth/login         # Enhanced login with token generation
POST /api/auth/refresh       # Refresh token with rotation
POST /api/auth/logout        # Logout with token blacklisting
POST /api/auth/logout-all    # Terminate all user sessions
GET  /api/auth/profile       # Enhanced profile information
POST /api/auth/introspect    # RFC 7662 token introspection
```

### Customer Services
```
GET  /api/customer           # Customer service access
GET  /api/customer/profile   # Enhanced profile with permissions
PUT  /api/customer/profile   # Profile update with validation
GET  /api/customer/data      # Customer-specific data
POST /api/customer/feedback  # Feedback submission
GET  /api/customer/security  # Security information
```

### Admin Services
```
GET  /api/admin              # Admin service access
GET  /api/admin/users        # User management with sessions
GET  /api/admin/stats        # Comprehensive system statistics
GET  /api/admin/sessions     # Active session management
POST /api/admin/sessions/revoke    # Session revocation
GET  /api/admin/blacklist    # Token blacklist management
POST /api/admin/maintenance  # System maintenance operations
```

### Token Management
```
POST /api/tokens/introspect  # Token validation service
GET  /api/tokens/blacklist   # Blacklist status check
POST /api/tokens/blacklist   # Manual token blacklisting
GET  /api/tokens/algorithm   # Algorithm information
GET  /api/tokens/health      # Token service health
```

## Testing and Debugging

### Manual Testing

#### 1. Authentication Flow
1. Visit the application
2. Login with demo credentials
3. Verify automatic token refresh (check console)
4. Test role-based access control
5. Test logout functionality

#### 2. Token Management
1. Open browser developer tools
2. Check localStorage for tokens
3. Monitor network requests for API calls
4. Test token expiration handling

#### 3. Admin Features
1. Login as admin user
2. Access user management
3. Test session monitoring
4. Test token blacklisting
5. View system statistics

### Debug Mode

Enable debug mode by:
1. Running on localhost or development domain
2. Press `Ctrl+D` to toggle debug view
3. Access `/debug` route for detailed information

Debug features include:
- Token payload inspection
- Session information
- API configuration
- Real-time status monitoring

### API Testing with curl

```bash
# Login and get tokens
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"admin123","clientId":"web-client"}'

# Access protected endpoint
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  http://localhost:3000/api/admin

# Refresh token
curl -X POST http://localhost:3000/api/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"YOUR_REFRESH_TOKEN","clientId":"web-client"}'

# Token introspection
curl -X POST http://localhost:3000/api/tokens/introspect \
  -H "Content-Type: application/json" \
  -d '{"token":"YOUR_JWT_TOKEN"}'
```

## Security Features

### Token Security
- **JTI (JWT ID)** for unique token identification
- **Session tracking** with IP and User-Agent binding
- **Clock skew tolerance** for distributed systems
- **Algorithm agility** (HS256/RS256) based on environment

### Refresh Token Security
- **Rotation on use** prevents replay attacks
- **One-time validation** ensures security
- **Session binding** tracks device usage
- **Automatic cleanup** prevents storage bloat

### Access Control
- **Role-based permissions** with granular scopes
- **Endpoint-specific validation** for security
- **Rate limiting** prevents abuse
- **Session management** for multi-device control

### Monitoring and Audit
- **Comprehensive logging** of all security events
- **Token blacklisting** for incident response
- **Session monitoring** for anomaly detection
- **Audit trails** for compliance requirements

## Monitoring and Health Checks

### Health Check Endpoints
- `/health` - Basic server health status
- `/api/tokens/health` - Token service status
- `/api/tokens/algorithm` - Algorithm configuration

### Real-time Monitoring
- Token expiration countdown
- Session activity tracking
- API response monitoring
- Security event logging

### Performance Metrics
- Authentication success rates
- Token refresh statistics
- API response times
- Memory usage monitoring
