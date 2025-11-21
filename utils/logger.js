/**
 * Logger utility for request and error logging
 */

/**
 * Log incoming requests with timestamp, endpoint, and user role
 */
function requestLogger(req, res, next) {
  const timestamp = new Date().toISOString();
  const method = req.method;
  const path = req.path;
  const userRole = req.user?.role || 'anonymous';
  const userId = req.user?.id || 'N/A';

  console.log(`[${timestamp}] ${method} ${path} | User: ${userId} (${userRole})`);
  next();
}

/**
 * Log authentication attempts
 */
function authLogger(success, email, ip, additionalInfo = {}) {
  const timestamp = new Date().toISOString();
  const status = success ? 'SUCCESS' : 'FAILURE';
  console.log(`[${timestamp}] AUTH ${status} | Email: ${email} | IP: ${ip}`, additionalInfo);
}

/**
 * Log general information
 */
function infoLogger(message, additionalInfo = {}) {
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] INFO: ${message}`, additionalInfo);
}

/**
 * Log warnings
 */
function warnLogger(message, additionalInfo = {}) {
  const timestamp = new Date().toISOString();
  console.warn(`[${timestamp}] WARN: ${message}`, additionalInfo);
}

/**
 * Log errors
 */
function errorLogger(error, req = null, additionalInfo = {}) {
  const timestamp = new Date().toISOString();
  const requestInfo = req ? {
    method: req.method,
    path: req.path,
    ip: req.ip,
    userAgent: req.get('User-Agent')
  } : {};
  
  console.error(`[${timestamp}] ERROR: ${error.message}`, {
    ...requestInfo,
    ...additionalInfo,
    stack: error.stack
  });
}

module.exports = {
  requestLogger,
  authLogger,
  infoLogger,
  warnLogger,
  errorLogger
};