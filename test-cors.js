#!/usr/bin/env node

/**
 * CORS Configuration Test Script
 * 
 * This script demonstrates how to test different CORS configurations
 * by modifying the ALLOWED_ORIGINS environment variable.
 */

const { spawn } = require('child_process');

// Test configurations
const testConfigs = [
    {
        name: 'Wildcard (Allow All)',
        envVar: 'ALLOWED_ORIGINS=*',
        expectedOrigins: ['http://localhost:5173', 'https://example.com', 'http://localhost:8080']
    },
    {
        name: 'Specific Origins',
        envVar: 'ALLOWED_ORIGINS=http://localhost:5173,https://myapp.com',
        expectedOrigins: ['http://localhost:5173', 'https://myapp.com']
    },
    {
        name: 'Default (No ALLOWED_ORIGINS)',
        envVar: '',
        expectedOrigins: ['http://localhost:5173', 'http://localhost:3000']
    }
];

async function testCORS(config) {
    return new Promise((resolve) => {
        console.log(`\n🧪 Testing: ${config.name}`);
        console.log(`   Environment: ${config.envVar || 'ALLOWED_ORIGINS not set'}`);
        
        // Start server with specific config
        const env = { ...process.env };
        if (config.envVar) {
            config.envVar.split(',').forEach(pair => {
                const [key, value] = pair.split('=');
                env[key] = value;
            });
        }
        
        const server = spawn('node', ['server.js'], {
            cwd: __dirname,
            env: env,
            stdio: 'pipe'
        });
        
        // Give server time to start
        setTimeout(async () => {
            try {
                // Test preflight requests
                const results = [];
                for (const origin of config.expectedOrigins) {
                    const testOrigin = origin === 'https://example.com' ? 'https://example.com' : 
                                     origin === 'https://myapp.com' ? 'https://myapp.com' :
                                     origin === 'http://localhost:5173' ? 'http://localhost:5173' :
                                     origin === 'http://localhost:3000' ? 'http://localhost:3000' : 
                                     origin === 'http://localhost:8080' ? 'http://localhost:8080' : origin;
                    
                    // Simulate curl test (simplified)
                    const curl = spawn('curl', [
                        '-s', '-X', 'OPTIONS', 'http://localhost:3000/api/auth/login',
                        '-H', `Origin: ${testOrigin}`,
                        '-H', 'Access-Control-Request-Method: POST'
                    ]);
                    
                    let output = '';
                    curl.stdout.on('data', (data) => {
                        output += data.toString();
                    });
                    
                    curl.on('close', (code) => {
                        if (code === 0) {
                            results.push(`✅ ${testOrigin}: CORS OK`);
                        } else {
                            results.push(`❌ ${testOrigin}: Failed`);
                        }
                        
                        if (results.length === config.expectedOrigins.length) {
                            results.forEach(result => console.log(`   ${result}`));
                            
                            // Kill server
                            server.kill();
                            resolve();
                        }
                    });
                }
            } catch (error) {
                console.log(`   ❌ Error: ${error.message}`);
                server.kill();
                resolve();
            }
        }, 2000); // Wait 2 seconds for server to start
    });
}

async function runTests() {
    console.log('🚀 CORS Configuration Test Suite');
    console.log('=====================================');
    
    for (const config of testConfigs) {
        await testCORS(config);
        await new Promise(resolve => setTimeout(resolve, 1000)); // Wait between tests
    }
    
    console.log('\n✅ All tests completed!');
    console.log('\n📝 Usage:');
    console.log('   # To allow all origins:');
    console.log('   echo "ALLOWED_ORIGINS=*" >> .env');
    console.log('');
    console.log('   # To allow specific origins:');
    console.log('   echo "ALLOWED_ORIGINS=http://localhost:5173,https://myapp.com" >> .env');
    console.log('');
    console.log('   # To use default origins:');
    console.log('   # Just remove ALLOWED_ORIGINS from .env');
    
    process.exit(0);
}

// Run tests
runTests().catch(error => {
    console.error('Test failed:', error);
    process.exit(1);
});