# Google OAuth2 Credentials Setup Guide

This guide will walk you through obtaining the required Google OAuth2 credentials for the v3 implementation.

## Prerequisites
- Google account
- Access to Google Cloud Console

## Step 1: Create a Google Cloud Project

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Click on the project dropdown at the top
3. Click "NEW PROJECT"
4. Enter project name: `oauth2-pkce-demo` (or any name you prefer)
5. Click "CREATE"
6. Wait for the project to be created (may take a few seconds)

## Step 2: Enable Google Identity API

1. In the Google Cloud Console, go to "APIs & Services" > "Library"
2. Search for "Google Identity API"
3. Click on "Google Identity API"
4. Click "ENABLE"

**Note**: You might also need to enable "Google+ API" if available, as it's sometimes used for user information.

## Step 3: Configure OAuth Consent Screen

1. Go to "APIs & Services" > "OAuth consent screen"
2. Choose "External" user type (unless you have a Google Workspace account)
3. Click "CREATE"
4. Fill in the required fields:
   - **App name**: `OAuth2 PKCE Demo App`
   - **User support email**: Your email address
   - **Authorized domains**: Add `localhost` (optional)
   - **Developer contact information**: Your email address
5. Click "SAVE AND CONTINUE"
6. In "Scopes", click "ADD OR REMOVE SCOPES"
7. Search and select these scopes:
   - `.../auth/userinfo.email`
   - `.../auth/userinfo.profile`
   - `openid`
8. Click "UPDATE"
9. Click "SAVE AND CONTINUE"
10. In "Test users", add your email address (optional, only needed if your app is in "Testing" mode)
11. Click "SAVE AND CONTINUE"
12. Review and click "BACK TO DASHBOARD"

## Step 4: Create OAuth 2.0 Credentials

1. Go to "APIs & Services" > "Credentials"
2. Click "CREATE CREDENTIALS" > "OAuth 2.0 Client IDs"
3. Choose application type: "Web application"
4. Enter name: `OAuth2 PKCE Demo Client`
5. Under "Authorized JavaScript origins", add:
   - `http://localhost:5173`
6. Under "Authorized redirect URIs", add:
   - `http://localhost:5173/callback`
7. Click "CREATE"
8. **IMPORTANT**: Copy the **Client ID** and **Client Secret** - these will be your credentials!

## Step 5: Get Your Credentials

After creating the OAuth 2.0 client, you'll see a popup with:
- **Client ID**: This is your `GOOGLE_CLIENT_ID`
- **Client Secret**: This is your `GOOGLE_CLIENT_SECRET`

## Step 6: Update .env File

Update your `v3/backend/.env` file with the actual credentials:

```env
# Google OAuth2 Configuration
GOOGLE_CLIENT_ID=your_actual_client_id_here
GOOGLE_CLIENT_SECRET=your_actual_client_secret_here
GOOGLE_REDIRECT_URI=http://localhost:5173/callback
GOOGLE_SCOPES=openid email profile

# Server Configuration
PORT=3000
NODE_ENV=development

# CORS Configuration
ALLOWED_ORIGINS=http://localhost:5173

# PKCE Demo Configuration
PKCE_DEMO_ENABLED=true

# Rate Limiting
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100

# Logging
LOG_LEVEL=info
```

## Security Notes

1. **Never commit** your `.env` file to version control
2. **Client Secret** should be kept confidential at all times
3. The redirect URI must exactly match what you configured in Google Cloud Console
4. For production, you'll need to:
   - Use `https://` URLs instead of `http://localhost`
   - Add your production domain to authorized origins
   - Update the redirect URI to point to your production callback URL

## Troubleshooting

### "redirect_uri_mismatch" Error
- Ensure the redirect URI in your code matches exactly with Google Cloud Console
- Check for trailing slashes, protocol (http vs https), etc.

### "access_denied" Error
- Make sure you've added your test user in the OAuth consent screen (if app is in testing mode)
- Ensure the requested scopes are properly configured

### "invalid_client" Error
- Double-check your CLIENT_ID and CLIENT_SECRET
- Ensure the Google Identity API is enabled


## Additional Resources

- [Google OAuth2 Documentation](https://developers.google.com/identity/protocols/oauth2)
- [Google Identity API Reference](https://developers.google.com/identity/protocols/oauth2/openid-connect)
- [OAuth 2.0 Security Best Current Practice](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)