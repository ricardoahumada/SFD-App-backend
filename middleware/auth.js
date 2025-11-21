const jwt = require('jsonwebtoken');
const { findUserById } = require('../models/users');
const logger = require('../utils/logger');

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

/**
 * Middleware to verify JWT token
 */
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    logger.warnLogger('Access token missing', { ip: req.ip, path: req.path });
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      logger.warnLogger('Invalid token', { ip: req.ip, path: req.path, error: err.message });
      return res.status(403).json({ error: 'Invalid or expired token' });
    }

    // Verify user still exists
    const currentUser = findUserById(user.id);
    if (!currentUser) {
      logger.warnLogger('User not found', { userId: user.id, ip: req.ip, path: req.path });
      return res.status(403).json({ error: 'User not found' });
    }

    req.user = currentUser;
    next();
  });
}

/**
 * Middleware to check if user has required role
 * @param {string} requiredRole - Required role (e.g., 'admin', 'customer')
 */
function requireRole(requiredRole) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    if (req.user.role !== requiredRole) {
      logger.warnLogger('Access denied - insufficient role', {
        userId: req.user.id,
        userRole: req.user.role,
        requiredRole,
        path: req.path
      });
      return res.status(403).json({ error: 'Insufficient permissions' });
    }

    next();
  };
}

module.exports = {
  authenticateToken,
  requireRole,
  JWT_SECRET
};