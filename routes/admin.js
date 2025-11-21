const express = require('express');
const router = express.Router();
const { authenticateToken, requireRole } = require('../middleware/auth');
const logger = require('../utils/logger');
const { users } = require('../models/users');

/**
 * GET /api/admin
 * Protected endpoint - requires admin role
 */
router.get('/', authenticateToken, requireRole('admin'), (req, res) => {
  logger.infoLogger('Admin service accessed', {
    userId: req.user.id,
    userEmail: req.user.email
  });

  res.json({
    success: true,
    message: 'Admin service accessed successfully',
    data: {
      service: 'admin_service',
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
 * GET /api/admin/users
 * Protected endpoint - get all users (admin only)
 */
router.get('/users', authenticateToken, requireRole('admin'), (req, res) => {
  logger.infoLogger('Admin users list accessed', {
    userId: req.user.id,
    userEmail: req.user.email
  });

  // Return users without passwords
  const sanitizedUsers = users.map(user => ({
    id: user.id,
    name: user.name,
    email: user.email,
    role: user.role
  }));

  res.json({
    success: true,
    message: 'Users retrieved successfully',
    users: sanitizedUsers,
    totalUsers: users.length
  });
});

/**
 * GET /api/admin/stats
 * Protected endpoint - get system statistics (admin only)
 */
router.get('/stats', authenticateToken, requireRole('admin'), (req, res) => {
  logger.infoLogger('Admin stats accessed', {
    userId: req.user.id,
    userEmail: req.user.email
  });

  const stats = {
    totalUsers: users.length,
    adminUsers: users.filter(u => u.role === 'admin').length,
    customerUsers: users.filter(u => u.role === 'customer').length,
    systemStatus: 'operational',
    lastUpdate: new Date().toISOString()
  };

  res.json({
    success: true,
    message: 'System statistics retrieved successfully',
    statistics: stats
  });
});

module.exports = router;