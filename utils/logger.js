/**
 * Enhanced logging utility with JWT-specific logging
 */

const LOG_LEVELS = {
    ERROR: 0,
    WARN: 1,
    INFO: 2,
    DEBUG: 3
};

const currentLogLevel = process.env.LOG_LEVEL ? LOG_LEVELS[process.env.LOG_LEVEL.toUpperCase()] : LOG_LEVELS.INFO;

/**
 * Enhanced request logger with JWT context
 */
function requestLogger(req, res, next) {
    const timestamp = new Date().toISOString();
    const method = req.method;
    const path = req.path;
    const userRole = req.user?.role || 'anonymous';
    const userId = req.user?.id || 'N/A';
    const sessionId = req.tokenData?.sessionId || 'N/A';
    const jti = req.tokenData?.jti || 'N/A';
    const clientIp = req.ip || req.connection.remoteAddress;
    const userAgent = (req.headers && req.headers['user-agent'])?.substring(0, 100) || 'unknown';

    // Log all requests with enhanced context
    console.log(`[${timestamp}] ${method} ${path} | User: ${userId} (${userRole}) | Session: ${sessionId} | JTI: ${jti} | IP: ${clientIp} | UA: ${userAgent}`);

    // Add response logging when response finishes
    const originalSend = res.send;
    res.send = function(data) {
        const responseTime = Date.now() - req.startTime;
        const statusCode = res.statusCode;
        const statusEmoji = statusCode >= 400 ? '❌' : statusCode >= 300 ? '⚠️' : '✅';
        
        console.log(`[${timestamp}] ${statusEmoji} ${method} ${path} | ${statusCode} | ${responseTime}ms | User: ${userId} | Session: ${sessionId}`);
        
        originalSend.call(this, data);
    };

    // Record start time for response time calculation
    req.startTime = Date.now();
    
    next();
}

/**
 * Log authentication events
 */
function authLogger(success, email, ip, additionalInfo = {}) {
    const timestamp = new Date().toISOString();
    const status = success ? '✅ SUCCESS' : '❌ FAILURE';
    const event = additionalInfo.event || 'AUTH';
    
    console.log(`[${timestamp}] ${event} ${status} | Email: ${email} | IP: ${ip}`, {
        ...additionalInfo,
        timestamp
    });
}

/**
 * Log token-related events
 */
function tokenLogger(event, token, additionalInfo = {}) {
    const timestamp = new Date().toISOString();
    const tokenPreview = token ? `${token.substring(0, 20)}...` : 'none';
    
    console.log(`[${timestamp}] TOKEN ${event} | Token: ${tokenPreview}`, {
        ...additionalInfo,
        timestamp
    });
}

/**
 * Log security events
 */
function securityLogger(event, severity, details = {}) {
    const timestamp = new Date().toISOString();
    const severityEmoji = severity === 'HIGH' ? '🚨' : severity === 'MEDIUM' ? '⚠️' : 'ℹ️';
    
    console.log(`[${timestamp}] SECURITY ${severityEmoji} ${event} | Severity: ${severity}`, {
        ...details,
        timestamp
    });
}

/**
 * Log authorization events
 */
function authzLogger(success, userId, requiredPermission, actualPermission, additionalInfo = {}) {
    const timestamp = new Date().toISOString();
    const status = success ? '✅' : '❌';
    
    console.log(`[${timestamp}] AUTHZ ${status} | User: ${userId} | Required: ${requiredPermission} | Actual: ${actualPermission}`, {
        ...additionalInfo,
        timestamp
    });
}

/**
 * Enhanced info logger
 */
function infoLogger(message, additionalInfo = {}) {
    if (currentLogLevel >= LOG_LEVELS.INFO) {
        const timestamp = new Date().toISOString();
        console.log(`[${timestamp}] INFO: ${message}`, {
            ...additionalInfo,
            timestamp
        });
    }
}

/**
 * Enhanced warning logger
 */
function warnLogger(message, additionalInfo = {}) {
    if (currentLogLevel >= LOG_LEVELS.WARN) {
        const timestamp = new Date().toISOString();
        console.warn(`[${timestamp}] WARN: ${message}`, {
            ...additionalInfo,
            timestamp
        });
    }
}

/**
 * Enhanced error logger
 */
function errorLogger(error, req = null, additionalInfo = {}) {
    if (currentLogLevel >= LOG_LEVELS.ERROR) {
        const timestamp = new Date().toISOString();
        const requestInfo = req ? {
            method: req.method,
            path: req.path,
            ip: req.ip,
            userAgent: (req.headers && req.headers['user-agent']) || 'unknown',
            user: req.user?.id || 'anonymous',
            sessionId: req.tokenData?.sessionId || 'N/A'
        } : {};
        
        console.error(`[${timestamp}] ERROR: ${error.message}`, {
            ...requestInfo,
            ...additionalInfo,
            stack: error.stack,
            timestamp
        });
    }
}

/**
 * Debug logger
 */
function debugLogger(message, additionalInfo = {}) {
    if (currentLogLevel >= LOG_LEVELS.DEBUG) {
        const timestamp = new Date().toISOString();
        console.debug(`[${timestamp}] DEBUG: ${message}`, {
            ...additionalInfo,
            timestamp
        });
    }
}

/**
 * Performance logger
 */
function performanceLogger(operation, duration, additionalInfo = {}) {
    const timestamp = new Date().toISOString();
    const performanceEmoji = duration > 1000 ? '🐌' : duration > 500 ? '⏱️' : '⚡';
    
    console.log(`[${timestamp}] ${performanceEmoji} PERFORMANCE: ${operation} took ${duration}ms`, {
        ...additionalInfo,
        duration,
        timestamp
    });
}

/**
 * Audit logger for compliance and security
 */
function auditLogger(action, userId, resource, result, additionalInfo = {}) {
    const timestamp = new Date().toISOString();
    const resultEmoji = result === 'SUCCESS' ? '✅' : '❌';
    
    console.log(`[${timestamp}] AUDIT ${resultEmoji} | Action: ${action} | User: ${userId} | Resource: ${resource}`, {
        result,
        ...additionalInfo,
        timestamp
    });
}

/**
 * Rate limit logger
 */
function rateLimitLogger(ip, userId, endpoint, limit, windowMs) {
    const timestamp = new Date().toISOString();
    
    console.log(`[${timestamp}] RATE_LIMIT | IP: ${ip} | User: ${userId || 'anonymous'} | Endpoint: ${endpoint} | Limit: ${limit} | Window: ${windowMs}ms`);
}

/**
 * Blacklist logger
 */
function blacklistLogger(action, tokenPreview, reason, additionalInfo = {}) {
    const timestamp = new Date().toISOString();
    
    console.log(`[${timestamp}] BLACKLIST ${action} | Token: ${tokenPreview} | Reason: ${reason}`, {
        ...additionalInfo,
        timestamp
    });
}

/**
 * Session logger
 */
function sessionLogger(event, userId, sessionId, additionalInfo = {}) {
    const timestamp = new Date().toISOString();
    
    console.log(`[${timestamp}] SESSION ${event} | User: ${userId} | Session: ${sessionId}`, {
        ...additionalInfo,
        timestamp
    });
}

/**
 * Configuration logger
 */
function configLogger(component, setting, value, additionalInfo = {}) {
    const timestamp = new Date().toISOString();
    const sensitiveSettings = ['password', 'secret', 'key', 'token'];
    const isSensitive = sensitiveSettings.some(sensitive => setting.toLowerCase().includes(sensitive));
    
    if (isSensitive && process.env.NODE_ENV !== 'development') {
        value = '***HIDDEN***';
    }
    
    console.log(`[${timestamp}] CONFIG | ${component}: ${setting} = ${value}`, {
        ...additionalInfo,
        timestamp
    });
}

/**
 * OAuth2 specific logger
 */
function OAuth2Logger(event, ip, userAgent, additionalInfo = {}) {
    const timestamp = new Date().toISOString();
    
    console.log(`[${timestamp}] OAUTH2 ${event} | IP: ${ip} | UA: ${userAgent}`, {
        ...additionalInfo,
        timestamp
    });
}

/**
 * PKCE specific logger
 */
function pkceLogger(event, state, additionalInfo = {}) {
    const timestamp = new Date().toISOString();
    
    console.log(`[${timestamp}] PKCE ${event} | State: ${state?.substring(0, 8) || 'none'}...`, {
        ...additionalInfo,
        timestamp
    });
}

/**
 * Authorization flow logger
 */
function authFlowLogger(event, clientId, redirectUri, additionalInfo = {}) {
    const timestamp = new Date().toISOString();
    
    console.log(`[${timestamp}] AUTH_FLOW ${event} | Client: ${clientId} | Redirect: ${redirectUri}`, {
        ...additionalInfo,
        timestamp
    });
}

module.exports = {
    requestLogger,
    authLogger,
    tokenLogger,
    securityLogger,
    authzLogger,
    OAuth2Logger,
    pkceLogger,
    authFlowLogger,
    infoLogger,
    warnLogger,
    errorLogger,
    debugLogger,
    performanceLogger,
    auditLogger,
    rateLimitLogger,
    blacklistLogger,
    sessionLogger,
    configLogger,
    LOG_LEVELS
};