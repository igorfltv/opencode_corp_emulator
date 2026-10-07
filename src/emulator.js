import { createHash, timingSafeEqual } from "node:crypto";
import { random, digest } from "./io.js";
import { loginPage, adminPage } from "./pages.js";

const users = [
  { id: "engineer", name: "Анна · Engineering", role: "engineering" },
  { id: "analyst", name: "Михаил · Analytics", role: "analytics" },
];
const skills = [
  { id: "corp-code-review", name: "Code review", description: "Проверка корректности, тестов и рисков изменения.", roles: ["engineering"], content: "Проверь diff. Найди конкретные ошибки и риски регрессии. Ссылайся на файлы и строки. Не выдумывай требования. Заверши перечнем проверок и ограничений." },
  { id: "corp-incident-triage", name: "Incident triage", description: "Сбор фактов при инциденте без опасных команд.", roles: ["engineering"], content: "Сначала уточни симптомы, временной интервал и затронутые системы. Собери доступные read-only метрики и логи. Отдели факты от гипотез. Не перезапускай сервисы без явного запроса." },
  { id: "corp-data-quality", name: "Data quality", description: "Проверка схемы, пропусков, дублей и качества данных.", roles: ["engineering", "analytics"], content: "Проверь схему, долю пропусков, дубликаты и ограничения данных. Не изменяй исходные данные. Приведи воспроизводимые проверки и явно укажи ограничения выборки." },
].map((skill) => { const content = `---\nname: ${skill.id}\ndescription: ${skill.description}\n---\n\n${skill.content}\n`; return { ...skill, content, version: "1.0.0", sha256: digest(content) }; });
class HTTPError extends Error { constructor(status, message) { super(message); this.status = status; } }
const fail = (condition, message, status = 400) => { if (condition) throw new HTTPError(status, message); };
const json = (data, status = 200, headers = {}) => Response.json(data, { status, headers: { "Cache-Control": "no-store", ...headers } });
const html = (text, nonce = "", callbackOrigin = "") => new Response(text, { headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "Content-Security-Policy": `default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-${nonce}'; connect-src 'self'; form-action 'self' ${callbackOrigin}; frame-ancestors 'none'; base-uri 'none'` } });
async function body(request) { fail(!request.headers.get("content-type")?.includes("application/json"), "Expected JSON"); const text = await request.text(); fail(text.length > 65536, "Body too large"); try { return JSON.parse(text); } catch { throw new HTTPError(400, "Invalid JSON"); } }

export function createEmulator({ port = 4310 } = {}) {
  const requests = new Map(), codes = new Map(), tokens = new Map();
  const adminToken = random();
  const state = { revision: 1, modelName: "Company Code Demo", context: 128000, level: "green", offline: false, audit: [] };
  const audit = (action, detail = "") => { state.audit.push({ at: new Date().toISOString(), action, detail }); if (state.audit.length > 200) state.audit.shift(); };
  const configuration = () => ({ revision: state.revision, config: { providers: { corporate: {
    name: "Company Inference", settings: { baseURL: `${baseURL}/v1` }, models: { "demo-code": { name: state.modelName, limit: { context: state.context, output: 8192 } } },
  } } } });
  const authorize = (request) => {
    const raw = request.headers.get("authorization")?.replace(/^Bearer /, "") ?? "";
    const credential = tokens.get(digest(raw));
    fail(!credential || credential.expiresAt <= Date.now(), "Unauthorized", 401);
    return { ...credential, hash: digest(raw) };
  };
  const server = Bun.serve({ hostname: "127.0.0.1", port, maxRequestBodySize: 1048576,
    async fetch(request) {
      try {
        const url = new URL(request.url);
        fail(url.origin !== baseURL, "Invalid Host", 403);
        const origin = request.headers.get("origin");
        fail(origin && origin !== baseURL, "Cross-origin request rejected", 403);
        const path = url.pathname;
        if (path === "/health" && request.method === "GET") return json({ ok: true, emulator: true });
        if ((path === "/" || path === "/admin") && request.method === "GET") { const nonce = random(); return html(adminPage(adminToken, nonce), nonce); }
        if (path === "/admin/state") {
          fail(request.headers.get("x-demo-admin") !== adminToken, "Forbidden", 403);
          if (request.method === "POST") {
            const patch = await body(request);
            fail(Object.keys(patch).some((key) => !["level", "offline", "expire", "publish", "modelName", "context"].includes(key)), "Unknown property");
            if (patch.level !== undefined) { fail(!["green", "yellow", "red"].includes(patch.level), "Invalid level"); state.level = patch.level; audit("load.changed", patch.level); }
            if (patch.offline !== undefined) { fail(typeof patch.offline !== "boolean", "Invalid offline flag"); state.offline = patch.offline; audit("availability.changed", String(!patch.offline)); }
            if (patch.publish) {
              fail(typeof patch.modelName !== "string" || !patch.modelName.trim() || patch.modelName.length > 100 || !Number.isInteger(patch.context) || patch.context < 8192 || patch.context > 2000000, "Invalid configuration");
              state.modelName = patch.modelName; state.context = patch.context; state.revision++; audit("config.published", `v${state.revision}`);
            }
            if (patch.expire) { for (const token of tokens.values()) token.expiresAt = 0; audit("tokens.expired"); }
          } else fail(request.method !== "GET", "Method not allowed", 405);
          return json({ ...state, queue: { green: 2, yellow: 24, red: 130 }[state.level], activeTokens: [...tokens.values()].filter((token) => token.expiresAt > Date.now()).length });
        }
        if (path === "/oauth/requests" && request.method === "POST") {
          const input = await body(request);
          let callback; try { callback = new URL(input.redirectURI); } catch { throw new HTTPError(400, "Invalid redirect URI"); }
          fail(callback.protocol !== "http:" || callback.hostname !== "127.0.0.1" || !callback.port || callback.pathname !== "/callback" || callback.search || callback.hash || callback.username || callback.password, "Only a loopback callback is allowed");
          fail(!/^[A-Za-z0-9_-]{43}$/.test(input.challenge) || !/^[A-Za-z0-9_-]{43}$/.test(input.state), "Invalid PKCE/state");
          for (const [id, value] of requests) if (value.expiresAt < Date.now()) requests.delete(id);
          fail(requests.size > 100, "Too many pending requests", 429);
          const id = random(); requests.set(id, { ...input, id, csrf: random(), expiresAt: Date.now() + 300000 });
          return json({ authorizationURL: `${baseURL}/oauth/authorize?request=${id}` });
        }
        if (path === "/oauth/authorize" && request.method === "GET") {
          const entry = requests.get(url.searchParams.get("request"));
          fail(!entry || entry.expiresAt < Date.now(), "Login link expired", 410);
          const nonce = random();
          return html(loginPage(entry, users, nonce), nonce, new URL(entry.redirectURI).origin);
        }
        if (path === "/oauth/approve" && request.method === "POST") {
          const form = await request.formData(); const entry = requests.get(form.get("requestID"));
          fail(!entry || entry.expiresAt < Date.now() || form.get("csrf") !== entry.csrf, "Invalid login request");
          const user = users.find((user) => user.id === form.get("account")); fail(!user, "Invalid account");
          requests.delete(entry.id);
          const code = random(); codes.set(code, { ...entry, user, expiresAt: Date.now() + 60000 });
          const redirect = new URL(entry.redirectURI); redirect.searchParams.set("code", code); redirect.searchParams.set("state", entry.state);
          if (request.headers.get("accept")?.includes("application/json")) return json({ redirect: redirect.href });
          return new Response(null, { status: 303, headers: { Location: redirect.href, "Cache-Control": "no-store", "Referrer-Policy": "no-referrer" } });
        }
        if (path === "/oauth/token" && request.method === "POST") {
          const input = await body(request); const entry = codes.get(input.code);
          fail(!entry || entry.expiresAt < Date.now() || entry.redirectURI !== input.redirectURI || !/^[A-Za-z0-9_-]{43}$/.test(input.verifier), "Invalid authorization code");
          const challenge = createHash("sha256").update(input.verifier).digest("base64url");
          fail(!timingSafeEqual(Buffer.from(entry.challenge), Buffer.from(challenge)), "Invalid PKCE verifier");
          codes.delete(input.code);
          const accessToken = random(); const expiresAt = Date.now() + 8 * 3600000;
          tokens.set(digest(accessToken), { user: entry.user, expiresAt }); audit("login", entry.user.id);
          return json({ accessToken, expiresAt, user: entry.user, configuration: configuration() });
        }
        if (path === "/oauth/revoke" && request.method === "POST") { const identity = authorize(request); tokens.delete(identity.hash); audit("logout", identity.user.id); return json({ revoked: true }); }
        if (path.startsWith("/api/") || path.startsWith("/v1/")) {
          const identity = authorize(request); fail(state.offline, "Simulated API outage", 503);
          if (path === "/api/config" && request.method === "GET") {
            const etag = `"config-${state.revision}"`; audit("config.read", `v${state.revision}`);
            if (request.headers.get("if-none-match") === etag) return new Response(null, { status: 304, headers: { ETag: etag, "Cache-Control": "no-store" } });
            return json(configuration(), 200, { ETag: etag });
          }
          if (path === "/api/load" && request.method === "GET") return json({ level: state.level, queue: { green: 2, yellow: 24, red: 130 }[state.level], observedAt: Date.now(), message: { green: "Нормальная нагрузка", yellow: "Высокая нагрузка; ответы могут идти медленнее", red: "Инференс перегружен; по возможности отложите тяжёлые задачи" }[state.level] });
          if (path === "/api/skills" && request.method === "GET") return json({ skills: skills.filter((skill) => skill.roles.includes(identity.user.role)).map(({ roles, content, ...skill }) => skill) });
          if (path.startsWith("/api/skills/") && request.method === "GET") {
            const skill = skills.find((skill) => skill.id === decodeURIComponent(path.slice("/api/skills/".length)));
            fail(!skill || !skill.roles.includes(identity.user.role), "Skill not available", 403); audit("skill.download", skill.id); return json({ content: skill.content });
          }
          if (path === "/v1/models" && request.method === "GET") return json({ object: "list", data: [{ id: "demo-code", object: "model", owned_by: "company-demo" }] });
          if (path === "/v1/chat/completions" && request.method === "POST") {
            const input = await body(request);
            const content = "Это локальный эмулятор, а не настоящая модель. Используйте /login, /refresh_config, /skills_load и /corp_status для проверки корпоративного плагина.";
            const id = `chatcmpl-${random()}`;
            const common = { id, created: Math.floor(Date.now() / 1000), model: "demo-code" };
            if (input.stream) {
              const chunks = [{ ...common, object: "chat.completion.chunk", choices: [{ index: 0, delta: { role: "assistant", content }, finish_reason: null }] }, { ...common, object: "chat.completion.chunk", choices: [{ index: 0, delta: {}, finish_reason: "stop" }] }];
              return new Response(chunks.map((chunk) => `data: ${JSON.stringify(chunk)}\n\n`).join("") + "data: [DONE]\n\n", { headers: { "Content-Type": "text/event-stream", "Cache-Control": "no-store" } });
            }
            return json({ ...common, object: "chat.completion", choices: [{ index: 0, message: { role: "assistant", content }, finish_reason: "stop" }], usage: { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 } });
          }
        }
        return json({ error: "Not found" }, 404);
      } catch (error) { return json({ error: error instanceof HTTPError ? error.message : "Request failed" }, error instanceof HTTPError ? error.status : 500); }
    },
  });
  const baseURL = `http://127.0.0.1:${server.port}`;
  return { server, baseURL, state, adminToken, stop: () => server.stop(true) };
}
