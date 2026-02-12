/**
 * Encryption/decryption for auth profile store at rest.
 *
 * Uses AES-256-GCM with a master key stored in:
 * - macOS Keychain (via `security` command)
 * - File-based key at `<stateDir>/.auth-key` on other platforms
 *
 * Encrypted format: "enc:v1:" + base64(iv + authTag + ciphertext)
 * Unencrypted data is returned as-is for transparent migration.
 */

import { execSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { log } from "./constants.js";

const ENC_PREFIX = "enc:v1:";
const ALGORITHM = "aes-256-gcm";
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;
const KEY_LENGTH = 32;

const KEYCHAIN_SERVICE = "openclaw-auth-store";
const KEYCHAIN_ACCOUNT = "master-key";
const KEY_FILENAME = ".auth-key";

/**
 * Resolve the file-based key path relative to the auth store path.
 */
export function resolveAuthStoreKeyPath(authStorePath: string): string {
  return path.join(path.dirname(authStorePath), KEY_FILENAME);
}

/**
 * Read the master key from macOS Keychain.
 */
function readKeychainKey(): Buffer | null {
  if (process.platform !== "darwin") {
    return null;
  }
  try {
    const result = execSync(
      `security find-generic-password -s "${KEYCHAIN_SERVICE}" -a "${KEYCHAIN_ACCOUNT}" -w`,
      { encoding: "utf8", timeout: 5000, stdio: ["pipe", "pipe", "pipe"] },
    );
    const hex = result.trim();
    if (hex.length !== KEY_LENGTH * 2) {
      return null;
    }
    return Buffer.from(hex, "hex");
  } catch {
    return null;
  }
}

/**
 * Write a master key to macOS Keychain.
 */
function writeKeychainKey(key: Buffer): boolean {
  if (process.platform !== "darwin") {
    return false;
  }
  try {
    const hex = key.toString("hex");
    // Try to delete existing entry first (ignore errors if it doesn't exist)
    try {
      execSync(
        `security delete-generic-password -s "${KEYCHAIN_SERVICE}" -a "${KEYCHAIN_ACCOUNT}"`,
        { timeout: 5000, stdio: ["pipe", "pipe", "pipe"] },
      );
    } catch {
      // ignore - may not exist
    }
    execSync(
      `security add-generic-password -s "${KEYCHAIN_SERVICE}" -a "${KEYCHAIN_ACCOUNT}" -w "${hex}"`,
      { timeout: 5000, stdio: ["pipe", "pipe", "pipe"] },
    );
    return true;
  } catch {
    return false;
  }
}

/**
 * Read or generate the master key for file-based storage.
 */
function readOrCreateFileKey(keyPath: string): Buffer {
  try {
    if (fs.existsSync(keyPath)) {
      const hex = fs.readFileSync(keyPath, "utf8").trim();
      if (hex.length === KEY_LENGTH * 2) {
        return Buffer.from(hex, "hex");
      }
    }
  } catch {
    // fall through to generate
  }

  const key = crypto.randomBytes(KEY_LENGTH);
  const dir = path.dirname(keyPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  }
  fs.writeFileSync(keyPath, key.toString("hex") + "\n", { encoding: "utf8", mode: 0o600 });
  return key;
}

/**
 * Resolve the master encryption key.
 * On macOS, uses Keychain. Falls back to file-based key.
 */
export function resolveMasterKey(authStorePath: string): Buffer {
  // Try macOS Keychain first
  if (process.platform === "darwin") {
    const keychainKey = readKeychainKey();
    if (keychainKey) {
      return keychainKey;
    }
    // Generate and store in Keychain
    const newKey = crypto.randomBytes(KEY_LENGTH);
    if (writeKeychainKey(newKey)) {
      return newKey;
    }
    // Fall through to file-based if Keychain fails
  }

  // File-based key
  const keyPath = resolveAuthStoreKeyPath(authStorePath);
  return readOrCreateFileKey(keyPath);
}

/**
 * Encrypt plaintext auth store data.
 * Returns "enc:v1:" + base64(iv + authTag + ciphertext).
 * On failure, logs warning and returns plaintext (never breaks auth).
 */
export function encryptAuthStore(plaintext: string, authStorePath: string): string {
  try {
    const key = resolveMasterKey(authStorePath);
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
    const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
    const authTag = cipher.getAuthTag();
    const combined = Buffer.concat([iv, authTag, encrypted]);
    return ENC_PREFIX + combined.toString("base64");
  } catch (err) {
    log.warn(`auth store encryption failed, storing unencrypted: ${String(err)}`);
    return plaintext;
  }
}

/**
 * Decrypt auth store data.
 * If input has no "enc:v1:" prefix, returns as-is (transparent migration).
 * On failure, logs warning and returns empty string.
 */
export function decryptAuthStore(data: string, authStorePath: string): string {
  if (!data.startsWith(ENC_PREFIX)) {
    return data;
  }

  try {
    const key = resolveMasterKey(authStorePath);
    const combined = Buffer.from(data.slice(ENC_PREFIX.length), "base64");

    if (combined.length < IV_LENGTH + AUTH_TAG_LENGTH) {
      log.warn("auth store encrypted data too short, returning empty");
      return "";
    }

    const iv = combined.subarray(0, IV_LENGTH);
    const authTag = combined.subarray(IV_LENGTH, IV_LENGTH + AUTH_TAG_LENGTH);
    const ciphertext = combined.subarray(IV_LENGTH + AUTH_TAG_LENGTH);

    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
    decipher.setAuthTag(authTag);
    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return decrypted.toString("utf8");
  } catch (err) {
    log.warn(`auth store decryption failed: ${String(err)}`);
    return "";
  }
}
