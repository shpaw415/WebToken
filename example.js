import { webToken } from './index.js';

// Example usage of the WebToken library
async function example() {
    // Mock request object (in real app, this would come from your framework)
    const mockRequest = new Request('https://example.com', {
        headers: {
            'cookie': 'session=someexistingtoken'
        }
    });

    // Initialize webToken with secure settings
    const token = new webToken(mockRequest, {
        cookieName: 'session',
        maxAge: 3600, // 1 hour
        secure: true,
        httpOnly: true,
        sameSite: 'strict'
    });

    // Set session data
    console.log('Setting session data...');
    const encrypted = token.setData({
        userId: 123,
        email: 'user@example.com',
        roles: ['user', 'admin'],
        preferences: {
            theme: 'dark',
            language: 'en'
        }
    });

    console.log('Encrypted token:', encrypted.substring(0, 50) + '...');

    // Check if session is valid
    if (token.isValid()) {
        const session = token.session();
        console.log('Session data:', session);
    }

    // Get token info
    const tokenInfo = token.getTokenInfo();
    console.log('Token info:', tokenInfo);

    // Generate secure secret (utility function)
    const secureSecret = webToken.generateSecureSecret(64);
    console.log('Generated secure secret length:', secureSecret.length);

    // Generate secure IV
    const secureIV = webToken.generateSecureIV();
    console.log('Generated IV length:', secureIV.length);
}

// Only run if this file is executed directly
if (import.meta.main) {
    example().catch(console.error);
}