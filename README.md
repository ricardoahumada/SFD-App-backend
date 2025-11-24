# OAuth 2.0 Authorization Code Flow + PKCE Implementation (v3)

This is a comprehensive implementation of OAuth 2.0 Authorization Code Flow with PKCE (Proof Key for Code Exchange) security extension, designed for educational purposes to demonstrate modern OAuth2 security practices.

## Project Structure

```
v3/
├── README.md                           # This file
├── OAUTH2_PKCE_IMPLEMENTATION.md       # Complete technical documentation
├── GOOGLE_OAUTH2_SETUP_GUIDE.md        # Step-by-step Google OAuth2 setup
├── SETUP_CHECKLIST.md                  # Progress tracking checklist
├── backend/                            # OAuth2 Resource Server (Node.js + Express)
│   ├── server.js                       # Main OAuth2 server
│   ├── .env                            # Configuration (needs Google credentials)
│   ├── .env.example                    # Environment template
│   ├── utils/
│   │   ├── googleOAuth2.js             # Google OAuth2 client integration
│   │   └── pkceHelper.js               # PKCE validation & demo utilities
│   ├── middleware/
│   │   └── oauth2.js                   # OAuth2 authentication middleware
│   └── routes/
│       ├── oauth2.js                   # OAuth2 flow endpoints
│       └── api.js                      # Protected API routes
└── frontend/                           # OAuth2 Client (HTML + Vanilla JS)
    ├── index.html                      # Main demo interface
    ├── css/
    │   └── oauth2-demo.css             # Modern styling with animations
    └── js/
        ├── oauth2-client.js            # OAuth2 client implementation
        ├── pkce-helper.js              # PKCE generation using Web Crypto API
        └── demo-ui.js                  # Interactive UI handler
```

## Quick Start

### 1. Google OAuth2 Setup
1. Follow the guide in `GOOGLE_OAUTH2_SETUP_GUIDE.md`
2. Get your Google OAuth2 credentials:
   - `GOOGLE_CLIENT_ID`
   - `GOOGLE_CLIENT_SECRET`
3. Update `backend/.env` with your credentials
4. Use the checklist in `SETUP_CHECKLIST.md` to track progress

### 2. Start the Servers

**Backend (Resource Server):**
```bash
cd v3/backend
npm install
npm run dev
```
Server runs on: http://localhost:3000

**Frontend (OAuth2 Client):**
```bash
cd v3/frontend
npm install
npm start
```
App runs on: http://localhost:5173

### 3. Test the OAuth2 Flow
1. Visit http://localhost:5173
2. Click "Sign in with Google"
3. Complete Google authentication
4. Explore the PKCE security demonstrations

## Configuration

### Required Environment Variables
Update `backend/.env` with your Google OAuth2 credentials:

```env
GOOGLE_CLIENT_ID=your_actual_client_id.googleusercontent.com
GOOGLE_CLIENT_SECRET=your_actual_client_secret
GOOGLE_REDIRECT_URI=http://localhost:5173/callback
GOOGLE_SCOPES=openid email profile
```

## Security Features

This implementation demonstrates:

1. **OAuth 2.0 Authorization Code Flow** - Industry standard delegated authentication
2. **PKCE (RFC 7636)** - Proof Key for Code Exchange for public clients
3. **State Parameter Validation** - CSRF protection
4. **Token Introspection** - Secure token validation
5. **Rate Limiting** - Protection against abuse
6. **Educational Demonstrations** - Visual comparisons showing PKCE benefits

## API Endpoints

### OAuth2 Flow
- `GET /oauth2/authorize` - Start OAuth2 authorization
- `POST /oauth2/token` - Exchange authorization code for tokens
- `POST /oauth2/refresh` - Refresh access tokens
- `GET /oauth2/userinfo` - Get user information

### Protected APIs
- `GET /api/profile` - User profile (requires OAuth2)
- `GET /api/dashboard` - Dashboard data (requires OAuth2)
- `GET /api/admin` - Admin endpoints (requires OAuth2 + admin scope)

### PKCE Demonstrations
- `GET /pkce/demo/challenge` - Generate PKCE challenges
- `GET /pkce/demo/compare` - Compare OAuth2 flows
- `GET /pkce/demo/attack-scenarios` - Simulate attack scenarios

## Technology Stack

**Backend:**
- Node.js + Express.js
- Google OAuth2 integration
- JWT token handling
- PKCE cryptographic validation
- Rate limiting & security middleware

**Frontend:**
- Vanilla JavaScript (ES6+)
- Web Crypto API for PKCE
- Modern CSS with animations
- Educational UI demonstrations

