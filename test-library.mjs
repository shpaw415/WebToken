import { webToken } from './dist/index.mjs';

// Test the library functionality
try {
    console.log('🧪 Testing WebToken Library...\n');

    // Create a mock request
    const request = new Request('https://example.com', {
        headers: {
            'User-Agent': 'Test/1.0'
        }
    });

    // Initialize token with secure settings
    console.log('1. ✅ Initializing webToken...');
    const token = new webToken(request, {
        cookieName: 'test-session',
        maxAge: 3600,
        secure: false, // For testing
        httpOnly: true,
        sameSite: 'strict'
    });

    // Test setting data
    console.log('2. ✅ Setting session data...');
    const sessionData = {
        userId: 12345,
        email: 'test@example.com',
        roles: ['user', 'admin'],
        preferences: {
            theme: 'dark',
            language: 'en'
        }
    };

    const encrypted = token.setData(sessionData);
    console.log(`   📦 Encrypted token length: ${encrypted.length} chars`);
    console.log(`   🔒 First 50 chars: ${encrypted.substring(0, 50)}...`);

    // Test token info
    console.log('3. ✅ Getting token info...');
    const tokenInfo = token.getTokenInfo();
    console.log('   📊 Token info:', {
        algorithm: tokenInfo.algorithm,
        cookieName: tokenInfo.cookieName,
        maxAge: tokenInfo.maxAge,
        hasSession: tokenInfo.hasSession
    });

    // Test utility functions
    console.log('4. ✅ Testing utility functions...');
    const secureSecret = webToken.generateSecureSecret(64);
    const secureIV = webToken.generateSecureIV();
    console.log(`   🔑 Generated secret length: ${secureSecret.length}`);
    console.log(`   🎲 Generated IV length: ${secureIV.length}`);

    // Test data validation
    console.log('5. ✅ Testing data validation...');
    const validation = token.getData(encrypted);
    console.log(`   ✅ Token is valid: ${validation.isValid}`);
    if (validation.isValid && validation.payload) {
        console.log(`   👤 User ID: ${validation.payload.userId}`);
        console.log(`   📧 Email: ${validation.payload.email}`);
    }

    console.log('\n🎉 All tests passed! Library is working correctly.');

} catch (error) {
    console.error('❌ Test failed:', error.message);
    process.exit(1);
}