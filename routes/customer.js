const express = require('express');
const router = express.Router();
const { authenticateToken, requireRole } = require('../middleware/auth');
const logger = require('../utils/logger');

/**
 * GET /api/customer
 * Protected endpoint - requires customer role
 */
router.get('/', authenticateToken, requireRole('customer'), (req, res) => {
  logger.infoLogger('Customer service accessed', {
    userId: req.user.id,
    userEmail: req.user.email
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
        role: req.user.role
      },
      timestamp: new Date().toISOString()
    }
  });
});

/**
 * GET /api/customer/profile
 * Protected endpoint - get customer profile
 */
router.get('/profile', authenticateToken, requireRole('customer'), (req, res) => {
  logger.infoLogger('Customer profile accessed', {
    userId: req.user.id,
    userEmail: req.user.email
  });

  res.json({
    success: true,
    message: 'Customer profile retrieved successfully',
    profile: {
      id: req.user.id,
      name: req.user.name,
      email: req.user.email,
      role: req.user.role,
      accountStatus: 'active',
      memberSince: '2023-01-01'
    }
  });
});

module.exports = router;