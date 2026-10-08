import { afterEach, expect, test } from "bun:test";
import { createHash, randomBytes } from "node:crypto";
import { createEmulator } from "../src/emulator.js";

const running = [];
afterEach(() => { while (running.length) running.pop().stop(); });
const start = () => { const emulator = createEmulator({ port: 0 }); running.push(emulator); return emulator; };
const id = () => randomBytes(32).toString("base64url");
const request = (baseURL, path, { token, method = "GET", body, headers = {} } = {}) => fetch(`${baseURL}${path}`, {
  method,
  headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(body ? { "Content-Type": "application/json" } : {}), ...headers },
  ...(body ? { body: JSON.stringify(body) } : {}),
});

async function login(emulator, account = "engineer") {
  const verifier = id(), state = id();
  const redirectURI = "http://127.0.0.1:49217/callback";
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  const begin = await request(emulator.baseURL, "/oauth/requests", { method: "POST", body: { challenge, state, redirectURI } });
  expect(begin.status).toBe(200);
  const { authorizationURL } = await begin.json();
  const page = await (await fetch(authorizationURL)).text();
  const requestID = page.match(/name="requestID" value="([^"]+)"/)?.[1];
  const csrf = page.match(/name="csrf" value="([^"]+)"/)?.[1];
  expect(requestID).toBeTruthy();
  expect(csrf).toBeTruthy();
  const approved = await fetch(`${emulator.baseURL}/oauth/approve`, {
    method: "POST", redirect: "manual",
    headers: { "Content-Type": "application/x-www-form-urlencoded", Origin: emulator.baseURL },
    body: new URLSearchParams({ requestID, csrf, account }),
  });
  expect(approved.status).toBe(303);
  const callback = new URL(approved.headers.get("Location"));
  expect(callback.searchParams.get("state")).toBe(state);
  const code = callback.searchParams.get("code");
  const exchanged = await request(emulator.baseURL, "/oauth/token", { method: "POST", body: { code, verifier, redirectURI } });
  expect(exchanged.status).toBe(200);
  const session = await exchanged.json();
  expect(session.accessToken).toBeTruthy();
  expect(session.configuration.config.providers.corporate.settings.baseURL).toBe(`${emulator.baseURL}/v1`);
  return { ...session, code, verifier, redirectURI };
}

test("browser login, configuration revision and ETag", async () => {
  const emulator = start();
  expect((await request(emulator.baseURL, "/health")).status).toBe(200);
  expect((await request(emulator.baseURL, "/api/config")).status).toBe(401);
  const { accessToken, code, verifier, redirectURI } = await login(emulator);
  expect((await request(emulator.baseURL, "/oauth/token", { method: "POST", body: { code, verifier, redirectURI } })).status).toBe(400);
  const initial = await request(emulator.baseURL, "/api/config", { token: accessToken });
  expect(initial.headers.get("ETag")).toBe('"config-1"');
  expect((await request(emulator.baseURL, "/api/config", { token: accessToken, headers: { "If-None-Match": '"config-1"' } })).status).toBe(304);
  const published = await request(emulator.baseURL, "/admin/state", { method: "POST", body: { publish: true, modelName: "Updated demo", context: 64000 }, headers: { "x-demo-admin": emulator.adminToken } });
  expect(published.status).toBe(200);
  const current = await (await request(emulator.baseURL, "/api/config", { token: accessToken })).json();
  expect(current.revision).toBe(2);
  expect(current.config.providers.corporate.models["demo-code"].name).toBe("Updated demo");
});

test("account-specific skills, load signal and fixed inference response", async () => {
  const emulator = start();
  const { accessToken } = await login(emulator, "analyst");
  const catalogue = await (await request(emulator.baseURL, "/api/skills", { token: accessToken })).json();
  expect(catalogue.skills.map(({ id }) => id)).toEqual(["corp-data-quality"]);
  expect((await request(emulator.baseURL, "/api/skills/corp-code-review", { token: accessToken })).status).toBe(403);
  const skill = await (await request(emulator.baseURL, "/api/skills/corp-data-quality", { token: accessToken })).json();
  expect(createHash("sha256").update(skill.content).digest("hex")).toBe(catalogue.skills[0].sha256);
  expect((await request(emulator.baseURL, "/admin/state", { method: "POST", body: { level: "red" }, headers: { "x-demo-admin": emulator.adminToken } })).status).toBe(200);
  expect((await (await request(emulator.baseURL, "/api/load", { token: accessToken })).json()).level).toBe("red");
  const completion = await (await request(emulator.baseURL, "/v1/chat/completions", { token: accessToken, method: "POST", body: { model: "demo-code", messages: [{ role: "user", content: "hello" }] } })).json();
  expect(completion.choices[0].message.content).toContain("локальный эмулятор");
});

test("role-scoped MCP catalog and demo personal-token connection", async () => {
  const emulator = start();
  const analyst = await login(emulator, "analyst");
  const catalog = await (await request(emulator.baseURL, "/api/mcps", { token: analyst.accessToken })).json();
  expect(catalog.servers.map(({ id }) => id)).toEqual(["confluence"]);
  expect(catalog.servers[0].url).toBe(`${emulator.baseURL}/mcp/confluence`);
  expect((await request(emulator.baseURL, "/mcp/confluence", { method: "POST", body: { jsonrpc: "2.0", id: 1, method: "tools/list" } })).status).toBe(401);
  const connected = await request(emulator.baseURL, "/mcp/confluence", { token: "demo-confluence-token", method: "POST", body: { jsonrpc: "2.0", id: 1, method: "tools/list" } });
  expect(connected.status).toBe(200);
  expect((await connected.json()).result.tools[0].name).toBe("find_pages");
});

test("loopback and admin protection, outage, expiration and revocation", async () => {
  const emulator = start();
  expect((await request(emulator.baseURL, "/admin/state")).status).toBe(403);
  expect((await request(emulator.baseURL, "/health", { headers: { Origin: "https://example.invalid" } })).status).toBe(403);
  const invalidCallback = await request(emulator.baseURL, "/oauth/requests", { method: "POST", body: { challenge: id(), state: id(), redirectURI: "https://example.invalid/callback" } });
  expect(invalidCallback.status).toBe(400);
  const { accessToken } = await login(emulator);
  const admin = (body) => request(emulator.baseURL, "/admin/state", { method: "POST", body, headers: { "x-demo-admin": emulator.adminToken } });
  expect((await admin({ offline: true })).status).toBe(200);
  expect((await request(emulator.baseURL, "/api/config", { token: accessToken })).status).toBe(503);
  expect((await admin({ offline: false, expire: true })).status).toBe(200);
  expect((await request(emulator.baseURL, "/api/config", { token: accessToken })).status).toBe(401);
  const next = await login(emulator);
  expect((await request(emulator.baseURL, "/oauth/revoke", { token: next.accessToken, method: "POST", body: {} })).status).toBe(200);
  expect((await request(emulator.baseURL, "/api/skills", { token: next.accessToken })).status).toBe(401);
});
