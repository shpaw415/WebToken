# WebToken 🔐

A secure, lightweight, and feature-rich session management library for modern web applications. WebToken provides AES-256-CBC encryption with HMAC integrity verification, JWT-like payload structure, and comprehensive security features.

## Features ✨

- **🔒 Military-grade Security**: AES-256-CBC encryption with random IV per encryption and HMAC integrity verification
- **⏰ JWT-like Structure**: Includes expiration, issuer validation, and unique identifiers
- **🛡️ Timing Attack Protection**: Constant-time comparison prevents timing attacks
- **🍪 Secure Cookies**: Configurable HttpOnly, Secure, SameSite attributes
- **🔄 Token Rotation**: Built-in token rotation for enhanced security
- **📊 Plain Cookie Support**: Manage both encrypted and plain cookies with same security options
- **🔍 Weak Secret Detection**: Validates and prevents weak encryption secrets
- **📏 Size Limits**: Enforces 4KB cookie size limits with validation
- **⚡ TypeScript First**: Full TypeScript support with comprehensive type definitions

## Installation 📦

```bash
npm install webtoken
# or
yarn add webtoken
# or
pnpm add webtoken
# or
bun add webtoken
```

## Quick Start 🚀

### Basic Usage

```typescript
import { webToken } from "webtoken";

// Initialize with secure defaults
const token = new webToken<UserSession>(request, {
  cookieName: "session",
  maxAge: 3600, // 1 hour
  secure: true,
  httpOnly: true,
  sameSite: "strict",
});

// Set encrypted session data
const encrypted = token.setData({
  userId: 123,
  email: "user@example.com",
  roles: ["user", "admin"],
});

// Send cookie to client
token.setCookie(response);

// Check if session is valid
if (token.isValid()) {
  const session = token.session();
  console.log("User ID:", session?.userId);
}
```

### Environment Variables

Set up your environment variables for security:

```bash
# Required: Strong secret (minimum 32 characters)
WEB_TOKEN_SECRET=your-super-secure-random-secret-here-minimum-32-chars

# Optional: Token issuer
TOKEN_ISSUER=myApp
```

## API Reference 📚

### Constructor

```typescript
new webToken<T>(request: Request, options?: WebTokenOptions)
```

#### Options

```typescript
interface WebTokenOptions {
  secret?: string; // Encryption secret (min 32 chars)
  cookieName?: string; // Cookie name (default: 'WebToken')
  algorithm?: string; // Encryption algorithm (default: 'aes-256-cbc')
  maxAge?: number; // Cookie max age in seconds (default: 3600)
  secure?: boolean; // HTTPS only (default: production mode)
  httpOnly?: boolean; // Prevent XSS (default: true)
  sameSite?: "strict" | "lax" | "none"; // CSRF protection (default: 'strict')
  domain?: string; // Cookie domain
  path?: string; // Cookie path (default: '/')
}
```

### Session Management

#### `setData(data, options?)`

Create or replace session data with encryption.

```typescript
const encrypted = token.setData(
  {
    userId: 123,
    preferences: { theme: "dark" },
  },
  {
    expiresInSeconds: 7200, // Custom expiration
    notBefore: new Date(), // Not valid before this date
    preserveExpiration: false, // Keep existing expiration
    jti: "custom-id", // Custom JWT ID
  }
);
```

#### `updateData(data)`

Update existing session data while preserving metadata.

```typescript
token.updateData({
  lastActivity: Date.now(),
  newField: "value",
});
```

#### `session()`

Get current session data.

```typescript
const sessionData = token.session();
if (sessionData) {
  console.log("User:", sessionData.userId);
}
```

#### `isValid()`

Check if session exists and is valid.

```typescript
if (token.isValid()) {
  // Session is valid and not expired
}
```

### Cookie Management

#### `setCookie(response, options?)`

Set encrypted session cookie.

```typescript
token.setCookie(response, {
  maxAge: 7200,
  secure: true,
});
```

#### `clearCookie(response)`

Clear the encrypted session cookie.

```typescript
token.clearCookie(response);
```

### Plain Cookie Support

#### `setPlainCookie(response, name, value, options?)`

Set unencrypted cookie with same security options.

```typescript
token.setPlainCookie(response, "theme", "dark", {
  maxAge: 86400, // 24 hours
  secure: true,
});
```

#### `setPlainJsonCookie(response, name, data, options?)`

Set JSON data as plain cookie.

```typescript
token.setPlainJsonCookie(response, "preferences", {
  language: "en",
  notifications: true,
});
```

#### `getPlainCookie(name)`

Get plain cookie value.

```typescript
const theme = token.getPlainCookie("theme");
```

#### `getPlainJsonCookie<T>(name)`

Get and parse JSON cookie.

```typescript
interface Preferences {
  language: string;
  notifications: boolean;
}

const prefs = token.getPlainJsonCookie<Preferences>("preferences");
```

#### `clearPlainCookie(response, name)`

Clear specific plain cookie.

```typescript
token.clearPlainCookie(response, "theme");
```

### Security & Validation

#### `rotateToken(data?)`

Create new token with fresh expiration for security.

```typescript
if (token.isExpiringSoon()) {
  token.rotateToken();
  token.setCookie(response);
}
```

#### `isExpiringSoon(thresholdSeconds?)`

Check if token expires within threshold (default: 5 minutes).

```typescript
if (token.isExpiringSoon(600)) {
  // 10 minutes
  // Consider rotating token
}
```

#### `getExpirationTime()`

Get token expiration timestamp.

```typescript
const expTime = token.getExpirationTime();
if (expTime) {
  console.log("Expires at:", new Date(expTime));
}
```

#### `getTokenInfo()`

Get token information for debugging (no sensitive data).

```typescript
const info = token.getTokenInfo();
console.log("Token info:", info);
```

### Static Utility Methods

#### `generateSecureSecret(length?)`

Generate cryptographically secure secret.

```typescript
const secret = webToken.generateSecureSecret(64);
console.log("Generated secret:", secret);
```

## Examples 📝

### Express.js Integration

```typescript
import express from "express";
import { webToken } from "webtoken";

const app = express();

// Login endpoint
app.post("/login", async (req, res) => {
  // Authenticate user...
  const user = await authenticateUser(req.body.email, req.body.password);

  if (user) {
    const token = new webToken(req, {
      cookieName: "session",
      maxAge: 3600,
      secure: process.env.NODE_ENV === "production",
    });

    token.setData({
      userId: user.id,
      email: user.email,
      roles: user.roles,
    });

    token.setCookie(res);
    res.json({ success: true });
  } else {
    res.status(401).json({ error: "Invalid credentials" });
  }
});

// Protected route middleware
app.use("/api", (req, res, next) => {
  const token = new webToken(req);

  if (token.isValid()) {
    req.user = token.session();
    next();
  } else {
    res.status(401).json({ error: "Unauthorized" });
  }
});
```

### Next.js API Route

```typescript
// pages/api/login.ts
import { NextApiRequest, NextApiResponse } from "next";
import { webToken } from "webtoken";

export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse
) {
  if (req.method === "POST") {
    const user = await authenticateUser(req.body.email, req.body.password);

    if (user) {
      const token = new webToken(
        new Request(req.url!, {
          headers: req.headers as any,
        }),
        {
          cookieName: "session",
          maxAge: 86400, // 24 hours
        }
      );

      token.setData({
        userId: user.id,
        email: user.email,
      });

      token.setCookie(new Response() as any);
      res.status(200).json({ success: true });
    }
  }
}
```

### Bun Server

```typescript
import { webToken } from "webtoken";

const server = Bun.serve({
  port: 3000,
  async fetch(req) {
    const url = new URL(req.url);

    if (url.pathname === "/login" && req.method === "POST") {
      // Handle login
      const token = new webToken(req, {
        cookieName: "session",
        maxAge: 3600,
      });

      token.setData({ userId: 123, email: "user@example.com" });

      const response = new Response(JSON.stringify({ success: true }));
      token.setCookie(response);
      return response;
    }

    if (url.pathname === "/profile") {
      const token = new webToken(req);

      if (token.isValid()) {
        const user = token.session();
        return new Response(JSON.stringify({ user }));
      } else {
        return new Response("Unauthorized", { status: 401 });
      }
    }

    return new Response("Not Found", { status: 404 });
  },
});
```

## Security Best Practices 🔐

### 1. Strong Secrets

- Use at least 32-character random secrets
- Never hardcode secrets in your code
- Use environment variables or secure key management

```typescript
// ✅ Good
const secret = process.env.WEB_TOKEN_SECRET; // Strong random secret

// ❌ Bad
const secret = "password123"; // Weak secret
```

### 2. Cookie Security

- Always use `secure: true` in production
- Set `httpOnly: true` to prevent XSS
- Use `sameSite: 'strict'` for CSRF protection

```typescript
const token = new webToken(request, {
  secure: process.env.NODE_ENV === "production",
  httpOnly: true,
  sameSite: "strict",
});
```

### 3. Token Rotation

- Rotate tokens periodically for enhanced security
- Check for expiring tokens and rotate proactively

```typescript
if (token.isExpiringSoon(300)) {
  // 5 minutes
  token.rotateToken();
  token.setCookie(response);
}
```

### 4. Input Validation

- Validate all data before storing in tokens
- Implement size limits for token data

```typescript
if (JSON.stringify(userData).length > 1000) {
  throw new Error("User data too large for token");
}
```

## Error Handling 🚨

The library throws descriptive errors for various scenarios:

```typescript
try {
  const token = new webToken(request, {
    secret: "too-short", // Will throw error
  });
} catch (error) {
  console.error("Token initialization failed:", error.message);
}

// Handle specific validation errors
const validation = token.getData(encryptedData);
if (!validation.isValid) {
  switch (validation.error) {
    case "expired":
      // Token has expired
      break;
    case "tampered":
      // Token has been modified
      break;
    case "invalid":
      // Invalid token structure
      break;
  }
}
```

## TypeScript Support 📘

Full TypeScript support with generic session types:

```typescript
interface UserSession {
  userId: number;
  email: string;
  roles: string[];
  preferences: {
    theme: "light" | "dark";
    language: string;
  };
}

const token = new webToken<UserSession>(request);
const session = token.session(); // TypeScript knows this is UserSession | undefined
```

## Development 🛠️

### Building

```bash
bun run build
```

### Testing

```bash
bun test
```

### Linting

```bash
bun run lint
```

## Contributing 🤝

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## License 📄

MIT License - see the [LICENSE](LICENSE) file for details.

## Changelog 📋

See [CHANGELOG.md](CHANGELOG.md) for a detailed list of changes and versions.

## Support 💬

- 📖 [Documentation](https://github.com/your-org/webtoken#readme)
- 🐛 [Issue Tracker](https://github.com/your-org/webtoken/issues)
- 💬 [Discussions](https://github.com/your-org/webtoken/discussions)

---

Made with ❤️ for secure web applications
