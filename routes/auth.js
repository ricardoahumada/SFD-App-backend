const express = require('express');
const jwt = require('jsonwebtoken');
const router = express.Router();
const { findUserByEmail } = require('../models/users');
const { authLogger } = require('../utils/logger');
const { JWT_SECRET } = require('../middleware/auth');

/**
 * POST /api/auth/login
 * Public endpoint for user authentication
 */
router.post('/login', (req, res) => {
  const { email, password } = req.body;
  const clientIp = req.ip;

  // Validate input
  if (!email || !password) {
    authLogger(false, email || 'missing', clientIp, { reason: 'Missing email or password' });
    return res.status(400).json({ error: 'Email and password are required' });
  }

  // Find user
  const user = findUserByEmail(email);
  
  if (!user || user.password !== password) {
    authLogger(false, email, clientIp, { reason: 'Invalid credentials' });
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  // Generate JWT token
  const token = jwt.sign(
    { 
      id: user.id, 
      email: user.email, 
      role: user.role 
    },
    JWT_SECRET,
    { expiresIn: '24h' }
  );

  authLogger(true, email, clientIp, { userId: user.id, role: user.role });

  // Return success response
  res.json({
    success: true,
    message: 'Login successful',
    token,
    user: {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role
    }
  });
});

module.exports = router;