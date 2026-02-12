import { describe, expect, it, vi } from "vitest";
import type { LookupFn } from "./ssrf.js";
import { fetchWithSsrFGuard } from "./fetch-guard.js";
import { SsrFBlockedError } from "./ssrf.js";

type MockResponse = {
  ok: boolean;
  status: number;
  headers: { get: (key: string) => string | null };
  body?: { cancel: () => void };
  text?: () => Promise<string>;
};

function makeHeaders(map: Record<string, string>): MockResponse["headers"] {
  return { get: (key) => map[key.toLowerCase()] ?? null };
}

function redirectResponse(location: string, status = 302): MockResponse {
  return {
    ok: false,
    status,
    headers: makeHeaders({ location }),
    body: { cancel: vi.fn() },
  };
}

function okResponse(body = "ok"): MockResponse {
  return {
    ok: true,
    status: 200,
    headers: makeHeaders({ "content-type": "text/plain" }),
    text: async () => body,
  };
}

// A lookup function that resolves any hostname to a public IP
const publicLookup: LookupFn = async (_hostname, _opts) => {
  return [{ address: "93.184.216.34", family: 4 }];
};

describe("fetchWithSsrFGuard redirect SSRF validation", () => {
  it("blocks redirect to 127.0.0.1", async () => {
    const fetchImpl = vi.fn().mockResolvedValueOnce(redirectResponse("http://127.0.0.1/steal"));

    await expect(
      fetchWithSsrFGuard({
        url: "https://example.com",
        fetchImpl: fetchImpl as never,
        lookupFn: publicLookup,
        pinDns: false,
      }),
    ).rejects.toThrow(SsrFBlockedError);
  });

  it("blocks redirect to private IP 192.168.1.1", async () => {
    const fetchImpl = vi.fn().mockResolvedValueOnce(redirectResponse("http://192.168.1.1/admin"));

    await expect(
      fetchWithSsrFGuard({
        url: "https://example.com",
        fetchImpl: fetchImpl as never,
        lookupFn: publicLookup,
        pinDns: false,
      }),
    ).rejects.toThrow(SsrFBlockedError);
  });

  it("blocks redirect to 10.0.0.1", async () => {
    const fetchImpl = vi.fn().mockResolvedValueOnce(redirectResponse("http://10.0.0.1/metadata"));

    await expect(
      fetchWithSsrFGuard({
        url: "https://example.com",
        fetchImpl: fetchImpl as never,
        lookupFn: publicLookup,
        pinDns: false,
      }),
    ).rejects.toThrow(SsrFBlockedError);
  });

  it("blocks redirect to metadata.google.internal", async () => {
    const fetchImpl = vi
      .fn()
      .mockResolvedValueOnce(
        redirectResponse("http://metadata.google.internal/computeMetadata/v1/"),
      );

    await expect(
      fetchWithSsrFGuard({
        url: "https://example.com",
        fetchImpl: fetchImpl as never,
        lookupFn: publicLookup,
        pinDns: false,
      }),
    ).rejects.toThrow(SsrFBlockedError);
  });

  it("blocks redirect to localhost", async () => {
    const fetchImpl = vi.fn().mockResolvedValueOnce(redirectResponse("http://localhost/admin"));

    await expect(
      fetchWithSsrFGuard({
        url: "https://example.com",
        fetchImpl: fetchImpl as never,
        lookupFn: publicLookup,
        pinDns: false,
      }),
    ).rejects.toThrow(SsrFBlockedError);
  });

  it("blocks redirect to non-HTTP protocol (ftp)", async () => {
    const fetchImpl = vi.fn().mockResolvedValueOnce(redirectResponse("ftp://evil.com/malware"));

    await expect(
      fetchWithSsrFGuard({
        url: "https://example.com",
        fetchImpl: fetchImpl as never,
        lookupFn: publicLookup,
        pinDns: false,
      }),
    ).rejects.toThrow(SsrFBlockedError);
  });

  it("blocks redirect to file:// protocol", async () => {
    const fetchImpl = vi.fn().mockResolvedValueOnce(redirectResponse("file:///etc/passwd"));

    await expect(
      fetchWithSsrFGuard({
        url: "https://example.com",
        fetchImpl: fetchImpl as never,
        lookupFn: publicLookup,
        pinDns: false,
      }),
    ).rejects.toThrow(SsrFBlockedError);
  });

  it("allows redirect to public IP", async () => {
    const fetchImpl = vi
      .fn()
      .mockResolvedValueOnce(redirectResponse("https://93.184.216.34/page"))
      .mockResolvedValueOnce(okResponse("public"));

    const result = await fetchWithSsrFGuard({
      url: "https://example.com",
      fetchImpl: fetchImpl as never,
      lookupFn: publicLookup,
      pinDns: false,
    });

    expect(result.response.status).toBe(200);
    await result.release();
  });

  it("allows redirect to private IP when policy.allowPrivateNetwork is true", async () => {
    const fetchImpl = vi
      .fn()
      .mockResolvedValueOnce(redirectResponse("http://192.168.1.1/api"))
      .mockResolvedValueOnce(okResponse("private-ok"));

    // Need a lookup that also resolves private hostnames
    const privateLookup: LookupFn = async (_hostname, _opts) => {
      return [{ address: "192.168.1.1", family: 4 }];
    };

    const result = await fetchWithSsrFGuard({
      url: "https://example.com",
      fetchImpl: fetchImpl as never,
      lookupFn: privateLookup,
      pinDns: false,
      policy: { allowPrivateNetwork: true },
    });

    expect(result.response.status).toBe(200);
    await result.release();
  });

  it("allows redirect to allowed hostname even if it looks private", async () => {
    const fetchImpl = vi
      .fn()
      .mockResolvedValueOnce(redirectResponse("http://localhost:8080/api"))
      .mockResolvedValueOnce(okResponse("allowed"));

    // Return public IP for initial host, private for localhost
    const smartLookup: LookupFn = async (hostname, _opts) => {
      if (hostname === "localhost") {
        return [{ address: "127.0.0.1", family: 4 }];
      }
      return [{ address: "93.184.216.34", family: 4 }];
    };

    const result = await fetchWithSsrFGuard({
      url: "https://example.com",
      fetchImpl: fetchImpl as never,
      lookupFn: smartLookup,
      pinDns: false,
      policy: { allowedHostnames: ["localhost"] },
    });

    expect(result.response.status).toBe(200);
    await result.release();
  });
});
