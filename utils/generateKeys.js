const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

/**
 * Generate RSA key pair for RS256 JWT signing
 */
function generateRSAKeyPair() {
    try {
        const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: {
                type: 'spki',
                format: 'pem'
            },
            privateKeyEncoding: {
                type: 'pkcs8',
                format: 'pem'
            }
        });

        return { publicKey, privateKey };
    } catch (error) {
        console.error('Error generating RSA key pair:', error);
        throw error;
    }
}

/**
 * Save keys to file
 */
function saveKeys(keys, directory = './keys') {
    try {
        // Create directory if it doesn't exist
        if (!fs.existsSync(directory)) {
            fs.mkdirSync(directory, { recursive: true });
        }

        const privateKeyPath = path.join(directory, 'private.pem');
        const publicKeyPath = path.join(directory, 'public.pem');

        fs.writeFileSync(privateKeyPath, keys.privateKey, 'utf8');
        fs.writeFileSync(publicKeyPath, keys.publicKey, 'utf8');

        console.log(`✅ RSA keys saved to ${directory}/`);
        console.log(`   - private.pem (${keys.privateKey.length} characters)`);
        console.log(`   - public.pem (${keys.publicKey.length} characters)`);

        return { privateKeyPath, publicKeyPath };
    } catch (error) {
        console.error('Error saving keys:', error);
        throw error;
    }
}

/**
 * Generate HMAC secret
 */
function generateHMACSecret(length = 64) {
    return crypto.randomBytes(length).toString('hex');
}

/**
 * Main execution
 */
function main() {
    console.log('🔐 JWT Key Generator v2.0');
    console.log('==============================\n');

    const keysDir = process.argv[2] || './keys';
    const algorithm = process.argv[3] || 'RS256'; // RS256 or HS256

    console.log(`Generating ${algorithm} keys...`);
    console.log(`Output directory: ${keysDir}\n`);

    if (algorithm === 'RS256') {
        try {
            const keys = generateRSAKeyPair();
            saveKeys(keys, keysDir);
            
            console.log('\n✅ RSA key pair generated successfully!');
            console.log('\n📋 Next steps:');
            console.log('1. Set environment variables:');
            console.log('   export JWT_ALGORITHM=RS256');
            console.log('2. Update your server configuration to use the keys');
            console.log('3. For production, store keys securely (e.g., environment variables, key vault)');
            
        } catch (error) {
            console.error('❌ Failed to generate RSA keys:', error.message);
            process.exit(1);
        }
    } else if (algorithm === 'HS256') {
        try {
            const secret = generateHMACSecret();
            
            // Create .env file with the secret
            const envContent = `# JWT Configuration for HS256
JWT_ALGORITHM=HS256
JWT_SECRET=${secret}
JWT_ISSUER=auth-system-v2
JWT_AUDIENCE=auth-system-users
NODE_ENV=development
`;

            if (!fs.existsSync(keysDir)) {
                fs.mkdirSync(keysDir, { recursive: true });
            }

            const envPath = path.join(keysDir, '.env');
            fs.writeFileSync(envPath, envContent, 'utf8');

            console.log('✅ HS256 secret generated successfully!');
            console.log(`📄 Configuration saved to: ${envPath}`);
            console.log(`🔑 Secret: ${secret.substring(0, 20)}...`);
            console.log('\n📋 Next steps:');
            console.log('1. Load the environment variables from the .env file');
            console.log('2. For production, use a longer, more secure secret');
            console.log('3. Consider using RS256 for production deployments');
            
        } catch (error) {
            console.error('❌ Failed to generate HS256 secret:', error.message);
            process.exit(1);
        }
    } else {
        console.error('❌ Invalid algorithm. Use "RS256" or "HS256"');
        process.exit(1);
    }
}

// Run if called directly
if (require.main === module) {
    main();
}

module.exports = {
    generateRSAKeyPair,
    saveKeys,
    generateHMACSecret
};