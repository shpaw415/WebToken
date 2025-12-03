import { describe, test, expect, beforeAll } from "bun:test";
import { webToken } from "./index";

// Test secret that meets minimum requirements (32+ chars, not weak)
const TEST_SECRET = "test-secure-secret-key-1234567890-abcdef!@#$";

// Helper to create a mock request
function createMockRequest(cookie?: string): Request {
  const headers = new Headers();
  if (cookie) {
    headers.set("cookie", cookie);
  }
  return new Request("http://localhost/test", { headers });
}

describe("WebToken Encryption/Decryption", () => {
  describe("Basic Encryption & Decryption", () => {
    test("should encrypt and decrypt data correctly", () => {
      const request = createMockRequest();
      const token = new webToken(request, { secret: TEST_SECRET });

      const testData = { userId: 123, email: "test@example.com" };
      const encrypted = token.setData(testData);

      expect(encrypted).toBeDefined();
      expect(typeof encrypted).toBe("string");

      // Verify the encrypted token format: ivHex:encrypted.hmac
      const parts = encrypted.split(".");
      expect(parts.length).toBe(2);

      const [encryptedWithIV, hmac] = parts;
      const ivAndData = encryptedWithIV.split(":");
      expect(ivAndData.length).toBe(2);

      // IV should be 32 hex characters (16 bytes)
      expect(ivAndData[0].length).toBe(32);

      // HMAC should be 64 hex characters (SHA-256)
      expect(hmac.length).toBe(64);
    });

    test("should decrypt data and return valid payload", () => {
      const request = createMockRequest();
      const token = new webToken(request, { secret: TEST_SECRET });

      const testData = { userId: 456, role: "admin" };
      const encrypted = token.setData(testData);

      const result = token.getData(encrypted);
      expect(result.isValid).toBe(true);
      expect(result.payload).toEqual(testData);
    });

    test("should handle complex nested data structures", () => {
      const request = createMockRequest();
      const token = new webToken(request, { secret: TEST_SECRET });

      const complexData = {
        user: {
          id: 1,
          profile: {
            name: "John Doe",
            settings: {
              theme: "dark",
              notifications: true,
            },
          },
        },
        permissions: ["read", "write", "delete"],
        metadata: {
          createdAt: Date.now(),
          version: "1.0.0",
        },
      };

      const encrypted = token.setData(complexData);
      const result = token.getData(encrypted);

      expect(result.isValid).toBe(true);
      expect(result.payload).toEqual(complexData);
    });

    test("should handle special characters in data", () => {
      const request = createMockRequest();
      const token = new webToken(request, { secret: TEST_SECRET });

      const specialData = {
        message: "Hello! @#$%^&*()_+-=[]{}|;':\",./<>?`~",
        unicode: "日本語テスト 🔐🎉",
        newlines: "line1\nline2\r\nline3",
        quotes: "He said \"Hello\" and 'Goodbye'",
      };

      const encrypted = token.setData(specialData);
      const result = token.getData(encrypted);

      expect(result.isValid).toBe(true);
      expect(result.payload).toEqual(specialData);
    });

    test("should handle empty object", () => {
      const request = createMockRequest();
      const token = new webToken(request, { secret: TEST_SECRET });

      const encrypted = token.setData({});
      const result = token.getData(encrypted);

      expect(result.isValid).toBe(true);
      expect(result.payload).toEqual({});
    });
  });

  describe("Random IV Generation (Security)", () => {
    test("should generate different ciphertext for same plaintext (random IV)", () => {
      const request = createMockRequest();
      const token = new webToken(request, { secret: TEST_SECRET });

      const testData = { userId: 123, email: "test@example.com" };

      // Encrypt the same data multiple times
      const encrypted1 = token.setData(testData);
      const encrypted2 = token.setData(testData);
      const encrypted3 = token.setData(testData);

      // Each encryption should produce different ciphertext due to random IV
      expect(encrypted1).not.toBe(encrypted2);
      expect(encrypted2).not.toBe(encrypted3);
      expect(encrypted1).not.toBe(encrypted3);

      // But all should decrypt to the same data
      const result1 = token.getData(encrypted1);
      const result2 = token.getData(encrypted2);
      const result3 = token.getData(encrypted3);

      expect(result1.payload).toEqual(testData);
      expect(result2.payload).toEqual(testData);
      expect(result3.payload).toEqual(testData);
    });

    test("should have unique IV in each encrypted token", () => {
      const request = createMockRequest();
      const token = new webToken(request, { secret: TEST_SECRET });

      const testData = { test: "data" };
      const ivs: string[] = [];

      // Generate multiple tokens and extract IVs
      for (let i = 0; i < 10; i++) {
        const encrypted = token.setData(testData);
        const iv = encrypted.split(".")[0].split(":")[0];
        ivs.push(iv);
      }

      // All IVs should be unique
      const uniqueIVs = new Set(ivs);
      expect(uniqueIVs.size).toBe(10);
    });
  });

  describe("HMAC Integrity Verification", () => {
    test("should detect tampered ciphertext", () => {
      const request = createMockRequest();
      const token = new webToken(request, { secret: TEST_SECRET });

      const encrypted = token.setData({ userId: 123 });

      // Tamper with the encrypted data
      const [encryptedWithIV, hmac] = encrypted.split(".");
      const tamperedEncrypted = encryptedWithIV.slice(0, -2) + "00";
      const tamperedToken = `${tamperedEncrypted}.${hmac}`;

      const result = token.getData(tamperedToken);
      expect(result.isValid).toBe(false);
      expect(result.error).toBe("tampered");
    });

    test("should detect tampered HMAC", () => {
      const request = createMockRequest();
      const token = new webToken(request, { secret: TEST_SECRET });

      const encrypted = token.setData({ userId: 123 });

      // Tamper with the HMAC
      const [encryptedWithIV, hmac] = encrypted.split(".");
      const tamperedHmac = hmac.slice(0, -2) + "00";
      const tamperedToken = `${encryptedWithIV}.${tamperedHmac}`;

      const result = token.getData(tamperedToken);
      expect(result.isValid).toBe(false);
      expect(result.error).toBe("tampered");
    });

    test("should detect tampered IV", () => {
      const request = createMockRequest();
      const token = new webToken(request, { secret: TEST_SECRET });

      const encrypted = token.setData({ userId: 123 });

      // Tamper with the IV
      const [encryptedWithIV, hmac] = encrypted.split(".");
      const [iv, encData] = encryptedWithIV.split(":");
      const tamperedIV = iv.slice(0, -2) + "00";
      const tamperedToken = `${tamperedIV}:${encData}.${hmac}`;

      const result = token.getData(tamperedToken);
      expect(result.isValid).toBe(false);
      expect(result.error).toBe("tampered");
    });
  });

  describe("Token Format Validation", () => {
    test("should reject token without HMAC separator", () => {
      const request = createMockRequest();
      const token = new webToken(request, { secret: TEST_SECRET });

      const result = token.getData("invalidtokenwithoutdot");
      expect(result.isValid).toBe(false);
      expect(result.error).toBe("tampered");
    });

    test("should reject token without IV separator", () => {
      const request = createMockRequest();
      const token = new webToken(request, { secret: TEST_SECRET });

      const result = token.getData("nocolonseparator.abcdef1234567890");
      expect(result.isValid).toBe(false);
      expect(result.error).toBe("tampered");
    });

    test("should reject token with invalid IV length", () => {
      const request = createMockRequest();
      const token = new webToken(request, { secret: TEST_SECRET });

      // IV should be 32 hex chars, this is too short
      const result = token.getData("shortiv:encrypteddata.hmacvalue");
      expect(result.isValid).toBe(false);
      expect(result.error).toBe("tampered");
    });

    test("should reject empty token", () => {
      const request = createMockRequest();
      const token = new webToken(request, { secret: TEST_SECRET });

      const result = token.getData("");
      expect(result.isValid).toBe(false);
      expect(result.error).toBe("tampered");
    });
  });

  describe("Cross-Instance Decryption", () => {
    test("should decrypt token from another instance with same secret", () => {
      const request1 = createMockRequest();
      const token1 = new webToken(request1, { secret: TEST_SECRET });

      const testData = { userId: 789, session: "abc123" };
      const encrypted = token1.setData(testData);

      // Create a new instance with the same secret
      const request2 = createMockRequest();
      const token2 = new webToken(request2, { secret: TEST_SECRET });

      const result = token2.getData(encrypted);
      expect(result.isValid).toBe(true);
      expect(result.payload).toEqual(testData);
    });

    test("should fail to decrypt token with different secret", () => {
      const request1 = createMockRequest();
      const token1 = new webToken(request1, { secret: TEST_SECRET });

      const testData = { userId: 789 };
      const encrypted = token1.setData(testData);

      // Create a new instance with a different secret
      const differentSecret = "different-secure-secret-key-1234567890-xyz!@#";
      const request2 = createMockRequest();
      const token2 = new webToken(request2, { secret: differentSecret });

      const result = token2.getData(encrypted);
      expect(result.isValid).toBe(false);
      expect(result.error).toBe("tampered");
    });
  });

  describe("Token Expiration", () => {
    test("should validate non-expired token", () => {
      const request = createMockRequest();
      const token = new webToken(request, {
        secret: TEST_SECRET,
        maxAge: 3600, // 1 hour
      });

      const encrypted = token.setData({ userId: 123 });
      const result = token.getData(encrypted);

      expect(result.isValid).toBe(true);
    });

    test("should reject expired token", async () => {
      const request = createMockRequest();
      const token = new webToken(request, {
        secret: TEST_SECRET,
        maxAge: 1, // 1 second
      });

      const encrypted = token.setData({ userId: 123 }, { expiresInSeconds: 1 });

      // Wait for token to expire (2 seconds to ensure expiration)
      await new Promise((resolve) => setTimeout(resolve, 2100));

      const result = token.getData(encrypted);
      expect(result.isValid).toBe(false);
      expect(result.error).toBe("expired");
    });

    test("should reject token not yet active (notBefore)", () => {
      const request = createMockRequest();
      const token = new webToken(request, { secret: TEST_SECRET });

      // Set notBefore to 1 hour in the future
      const futureDate = new Date(Date.now() + 3600000);
      const encrypted = token.setData(
        { userId: 123 },
        { notBefore: futureDate }
      );

      const result = token.getData(encrypted);
      expect(result.isValid).toBe(false);
      expect(result.error).toBe("not_active");
    });
  });

  describe("Issuer Validation", () => {
    test("should validate token with matching issuer", () => {
      process.env.TOKEN_ISSUER = "testApp";

      const request = createMockRequest();
      const token = new webToken(request, { secret: TEST_SECRET });

      const encrypted = token.setData({ userId: 123 });
      const result = token.getData(encrypted);

      expect(result.isValid).toBe(true);

      delete process.env.TOKEN_ISSUER;
    });

    test("should reject token with mismatched issuer", () => {
      process.env.TOKEN_ISSUER = "app1";

      const request1 = createMockRequest();
      const token1 = new webToken(request1, { secret: TEST_SECRET });
      const encrypted = token1.setData({ userId: 123 });

      // Change issuer
      process.env.TOKEN_ISSUER = "app2";

      const request2 = createMockRequest();
      const token2 = new webToken(request2, { secret: TEST_SECRET });
      const result = token2.getData(encrypted);

      expect(result.isValid).toBe(false);
      expect(result.error).toBe("invalid");

      delete process.env.TOKEN_ISSUER;
    });
  });

  describe("Secret Validation", () => {
    test("should throw error for missing secret", () => {
      const originalSecret = process.env.WEB_TOKEN_SECRET;
      delete process.env.WEB_TOKEN_SECRET;

      const request = createMockRequest();
      expect(() => new webToken(request)).toThrow(
        "WEB_TOKEN_SECRET environment variable is required"
      );

      if (originalSecret) {
        process.env.WEB_TOKEN_SECRET = originalSecret;
      }
    });

    test("should throw error for secret shorter than 32 characters", () => {
      const request = createMockRequest();
      expect(() => new webToken(request, { secret: "short-secret" })).toThrow(
        "Secret must be at least 32 characters"
      );
    });

    test("should throw error for weak secrets (only letters)", () => {
      const request = createMockRequest();
      expect(
        () =>
          new webToken(request, {
            secret: "abcdefghijklmnopqrstuvwxyzabcdef",
          })
      ).toThrow("Secret appears to be weak");
    });

    test("should throw error for weak secrets (only numbers)", () => {
      const request = createMockRequest();
      expect(
        () =>
          new webToken(request, { secret: "12345678901234567890123456789012" })
      ).toThrow("Secret appears to be weak");
    });

    test("should accept strong secret from environment variable", () => {
      const originalSecret = process.env.WEB_TOKEN_SECRET;
      process.env.WEB_TOKEN_SECRET = TEST_SECRET;

      const request = createMockRequest();
      const token = new webToken(request);

      expect(token).toBeDefined();

      if (originalSecret) {
        process.env.WEB_TOKEN_SECRET = originalSecret;
      } else {
        delete process.env.WEB_TOKEN_SECRET;
      }
    });
  });

  describe("Cookie Integration", () => {
    test("should set and retrieve session from cookie", () => {
      // First, create a token and get the encrypted data
      const request1 = createMockRequest();
      const token1 = new webToken(request1, {
        secret: TEST_SECRET,
        cookieName: "session",
      });

      const testData = { userId: 123, role: "user" };
      const encrypted = token1.setData(testData);

      // Create a new request with the cookie
      const request2 = createMockRequest(`session=${encrypted}`);
      const token2 = new webToken(request2, {
        secret: TEST_SECRET,
        cookieName: "session",
      });

      expect(token2.isValid()).toBe(true);
      expect(token2.session()).toEqual(testData);
    });

    test("should return undefined for invalid cookie", () => {
      const request = createMockRequest("session=invalid-token-data");
      const token = new webToken(request, {
        secret: TEST_SECRET,
        cookieName: "session",
      });

      expect(token.isValid()).toBe(false);
      expect(token.session()).toBeUndefined();
    });
  });

  describe("Static Methods", () => {
    test("generateSecureSecret should create secret of specified length", () => {
      const secret64 = webToken.generateSecureSecret(64);
      const secret32 = webToken.generateSecureSecret(32);

      // hex encoding doubles the byte length
      expect(secret64.length).toBe(128);
      expect(secret32.length).toBe(64);
    });

    test("generateSecureSecret should create unique secrets", () => {
      const secrets = new Set<string>();
      for (let i = 0; i < 100; i++) {
        secrets.add(webToken.generateSecureSecret());
      }
      expect(secrets.size).toBe(100);
    });
  });
});
