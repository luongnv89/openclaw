import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { decryptAuthStore, encryptAuthStore, resolveAuthStoreKeyPath } from "./crypto.js";

describe("auth-profiles crypto", () => {
  let tmpDir: string;
  let authStorePath: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "auth-crypto-test-"));
    authStorePath = path.join(tmpDir, "auth-profiles.json");
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("resolves key path relative to auth store", () => {
    const keyPath = resolveAuthStoreKeyPath("/some/dir/auth-profiles.json");
    expect(keyPath).toBe("/some/dir/.auth-key");
  });

  it("encrypt/decrypt round-trip produces original data", () => {
    const original = JSON.stringify({
      version: 1,
      profiles: { "provider:default": { type: "oauth", provider: "test", access: "token123" } },
    });

    const encrypted = encryptAuthStore(original, authStorePath);
    expect(encrypted).toMatch(/^enc:v1:/);
    expect(encrypted).not.toContain("token123");

    const decrypted = decryptAuthStore(encrypted, authStorePath);
    expect(decrypted).toBe(original);
  });

  it("unencrypted input returned as-is (migration)", () => {
    const plaintext = '{"version":1,"profiles":{}}';
    const result = decryptAuthStore(plaintext, authStorePath);
    expect(result).toBe(plaintext);
  });

  it("handles empty string", () => {
    const encrypted = encryptAuthStore("", authStorePath);
    const decrypted = decryptAuthStore(encrypted, authStorePath);
    expect(decrypted).toBe("");
  });

  it("handles large JSON payloads", () => {
    const large = JSON.stringify({
      version: 1,
      profiles: Object.fromEntries(
        Array.from({ length: 100 }, (_, i) => [
          `provider-${i}:default`,
          {
            type: "oauth",
            provider: `provider-${i}`,
            access: `token-${i}`,
            refresh: `refresh-${i}`,
          },
        ]),
      ),
    });

    const encrypted = encryptAuthStore(large, authStorePath);
    const decrypted = decryptAuthStore(encrypted, authStorePath);
    expect(decrypted).toBe(large);
  });

  it("corrupted encrypted data returns empty string", () => {
    const encrypted = "enc:v1:" + Buffer.from("corrupted-garbage-data").toString("base64");
    const result = decryptAuthStore(encrypted, authStorePath);
    expect(result).toBe("");
  });

  it("truncated encrypted data returns empty string", () => {
    // Too short to contain iv + authTag
    const encrypted = "enc:v1:" + Buffer.from("short").toString("base64");
    const result = decryptAuthStore(encrypted, authStorePath);
    expect(result).toBe("");
  });

  it("key file is created with restrictive permissions on first encrypt", () => {
    encryptAuthStore("test", authStorePath);
    const keyPath = resolveAuthStoreKeyPath(authStorePath);
    expect(fs.existsSync(keyPath)).toBe(true);
    const stats = fs.statSync(keyPath);
    // 0o600 = owner read/write only
    expect(stats.mode & 0o777).toBe(0o600);
  });

  it("reuses existing key file on subsequent calls", () => {
    const data1 = "first";
    const data2 = "second";

    encryptAuthStore(data1, authStorePath);
    const keyPath = resolveAuthStoreKeyPath(authStorePath);
    const keyBefore = fs.readFileSync(keyPath, "utf8");

    encryptAuthStore(data2, authStorePath);
    const keyAfter = fs.readFileSync(keyPath, "utf8");

    expect(keyBefore).toBe(keyAfter);
  });

  it("different plaintexts produce different ciphertexts", () => {
    const enc1 = encryptAuthStore("data-one", authStorePath);
    const enc2 = encryptAuthStore("data-two", authStorePath);
    expect(enc1).not.toBe(enc2);
  });
});
