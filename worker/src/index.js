const GITHUB_API_VERSION = "2022-11-28";
const COOKIE_SESSION = "svb_session";
const COOKIE_OAUTH_STATE = "svb_oauth_state";
const OAUTH_STATE_TTL_SECONDS = 10 * 60;
const DEFAULT_SESSION_TTL_SECONDS = 8 * 60 * 60;
const REPO_PAGE_SIZE = 100;

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);
      const path = url.pathname;

      if (request.method === "OPTIONS") {
        return handleOptions(request, env);
      }

      if (path === "/auth/login" && request.method === "GET") {
        return handleAuthLogin(env);
      }

      if (path === "/auth/callback" && request.method === "GET") {
        return handleAuthCallback(request, env);
      }

      if (path === "/auth/logout" && request.method === "POST") {
        return handleLogout(request, env);
      }

      if (path === "/api/session" && request.method === "GET") {
        return handleSession(request, env);
      }

      if (path === "/api/repos" && request.method === "GET") {
        return handleRepos(request, env);
      }

      return jsonResponse(request, env, { error: "Not found" }, 404);
    } catch (error) {
      console.error("Unhandled worker error:", error);
      return jsonResponse(request, env, { error: "Internal server error" }, 500);
    }
  }
};

function handleOptions(request, env) {
  const origin = request.headers.get("Origin");
  if (!isAllowedOrigin(origin, env)) {
    return new Response(null, { status: 403 });
  }

  const headers = new Headers();
  headers.set("Access-Control-Allow-Origin", origin);
  headers.set("Access-Control-Allow-Credentials", "true");
  headers.set("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  headers.set("Access-Control-Allow-Headers", "Content-Type");
  headers.set("Access-Control-Max-Age", "86400");
  headers.set("Vary", "Origin");
  return new Response(null, { status: 204, headers });
}

function handleAuthLogin(env) {
  const clientId = requiredEnv(env, "CLIENT_ID");
  const redirectUri = requiredEnv(env, "REDIRECT_URI");

  const state = randomToken(24);
  const authUrl = new URL("https://github.com/login/oauth/authorize");
  authUrl.searchParams.set("client_id", clientId);
  authUrl.searchParams.set("redirect_uri", redirectUri);
  authUrl.searchParams.set("scope", "repo read:org");
  authUrl.searchParams.set("state", state);
  authUrl.searchParams.set("allow_signup", "false");

  const headers = new Headers();
  headers.set("Location", authUrl.toString());
  headers.append(
    "Set-Cookie",
    serializeCookie(COOKIE_OAUTH_STATE, state, {
      maxAge: OAUTH_STATE_TTL_SECONDS,
      path: "/",
      sameSite: "Lax",
      secure: true,
      httpOnly: true
    })
  );

  return new Response(null, { status: 302, headers });
}

async function handleAuthCallback(request, env) {
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const cookies = parseCookies(request.headers.get("Cookie"));
  const expectedState = cookies[COOKIE_OAUTH_STATE];

  if (!code || !state || !expectedState || state !== expectedState) {
    return redirectToFrontend(env, "state_mismatch", [
      clearCookie(COOKIE_OAUTH_STATE, "Lax"),
      clearCookie(COOKIE_SESSION, "None")
    ]);
  }

  try {
    const accessToken = await exchangeGithubToken(code, env);
    const user = await fetchGithubUser(accessToken);
    const org = getAllowedOrg(env);
    const membership = await fetchOrgMembership(accessToken, org);

    if (membership?.state !== "active") {
      return redirectToFrontend(env, "org_access_denied", [
        clearCookie(COOKIE_OAUTH_STATE, "Lax"),
        clearCookie(COOKIE_SESSION, "None")
      ]);
    }

    const ttlSeconds = getSessionTtlSeconds(env);
    const expiresAt = Math.floor(Date.now() / 1000) + ttlSeconds;
    const sessionPayload = {
      accessToken,
      user: {
        login: user.login,
        name: user.name || user.login,
        avatar_url: user.avatar_url || ""
      },
      exp: expiresAt
    };

    const sealedSession = await encryptPayload(sessionPayload, requiredEnv(env, "COOKIE_SECRET"));
    return redirectToFrontend(env, null, [
      clearCookie(COOKIE_OAUTH_STATE, "Lax"),
      serializeCookie(COOKIE_SESSION, sealedSession, {
        maxAge: ttlSeconds,
        path: "/",
        sameSite: "None",
        secure: true,
        httpOnly: true
      })
    ]);
  } catch (error) {
    console.error("OAuth callback failed:", error);
    return redirectToFrontend(env, "auth_failed", [
      clearCookie(COOKIE_OAUTH_STATE, "Lax"),
      clearCookie(COOKIE_SESSION, "None")
    ]);
  }
}

function handleLogout(request, env) {
  const headers = new Headers();
  headers.append("Set-Cookie", clearCookie(COOKIE_SESSION, "None"));
  headers.append("Set-Cookie", clearCookie(COOKIE_OAUTH_STATE, "Lax"));
  return jsonResponse(request, env, { ok: true }, 200, headers);
}

async function handleSession(request, env) {
  const session = await readSessionFromRequest(request, env);
  if (!session) {
    return jsonResponse(request, env, { authenticated: false }, 200);
  }

  return jsonResponse(request, env, {
    authenticated: true,
    user: session.user,
    expires_at: session.exp
  });
}

async function handleRepos(request, env) {
  const session = await readSessionFromRequest(request, env);
  if (!session) {
    return jsonResponse(request, env, { error: "Unauthorized" }, 401);
  }

  const url = new URL(request.url);
  const requestedOrg = (url.searchParams.get("org") || "").trim();
  const allowedOrg = getAllowedOrg(env);
  const normalizedRequestedOrg = requestedOrg || allowedOrg;

  if (normalizedRequestedOrg.toLowerCase() !== allowedOrg.toLowerCase()) {
    return jsonResponse(request, env, { error: "Invalid org." }, 400);
  }

  try {
    const repos = await listReposForOrg(session.accessToken, allowedOrg);
    return jsonResponse(request, env, {
      org: allowedOrg,
      count: repos.length,
      repos
    });
  } catch (error) {
    console.error("Failed to fetch repositories:", error);
    return jsonResponse(request, env, { error: "Failed to fetch repositories from GitHub." }, 502);
  }
}

async function exchangeGithubToken(code, env) {
  const tokenResponse = await fetch("https://github.com/login/oauth/access_token", {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      "User-Agent": "studiovibi-links-worker"
    },
    body: JSON.stringify({
      client_id: requiredEnv(env, "CLIENT_ID"),
      client_secret: requiredEnv(env, "CLIENT_SECRET"),
      redirect_uri: requiredEnv(env, "REDIRECT_URI"),
      code
    })
  });

  const tokenData = await tokenResponse.json();
  if (!tokenResponse.ok || !tokenData.access_token) {
    const details = tokenData.error_description || tokenData.error || "oauth_exchange_failed";
    throw new Error(`GitHub token exchange failed: ${details}`);
  }
  return tokenData.access_token;
}

async function fetchGithubUser(accessToken) {
  const response = await fetch("https://api.github.com/user", {
    headers: githubHeaders(accessToken)
  });
  if (!response.ok) {
    throw new Error(`GitHub user request failed with status ${response.status}`);
  }
  return response.json();
}

async function fetchOrgMembership(accessToken, org) {
  const response = await fetch(`https://api.github.com/user/memberships/orgs/${encodeURIComponent(org)}`, {
    headers: githubHeaders(accessToken)
  });

  if (response.status === 404) {
    return { state: "inactive" };
  }

  if (!response.ok) {
    throw new Error(`Org membership check failed with status ${response.status}`);
  }

  return response.json();
}

async function listReposForOrg(accessToken, org) {
  const collected = [];
  let page = 1;

  while (page <= 100) {
    const endpoint = new URL("https://api.github.com/user/repos");
    endpoint.searchParams.set("per_page", String(REPO_PAGE_SIZE));
    endpoint.searchParams.set("page", String(page));
    endpoint.searchParams.set("sort", "full_name");
    endpoint.searchParams.set("direction", "asc");
    endpoint.searchParams.set("affiliation", "owner,organization_member,collaborator");

    const response = await fetch(endpoint.toString(), {
      headers: githubHeaders(accessToken)
    });

    if (!response.ok) {
      throw new Error(`GitHub repos request failed with status ${response.status}`);
    }

    const repos = await response.json();
    if (!Array.isArray(repos) || repos.length === 0) {
      break;
    }

    for (const repo of repos) {
      if (!repo?.owner?.login || repo.owner.login.toLowerCase() !== org.toLowerCase()) {
        continue;
      }
      if (repo.archived) {
        continue;
      }
      collected.push({
        name: repo.name,
        description: repo.description || "",
        html_url: repo.html_url,
        private: Boolean(repo.private),
        archived: Boolean(repo.archived),
        updated_at: repo.updated_at
      });
    }

    if (repos.length < REPO_PAGE_SIZE) {
      break;
    }

    page += 1;
  }

  collected.sort((a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: "base" }));
  return collected;
}

function githubHeaders(accessToken) {
  return {
    Accept: "application/vnd.github+json",
    Authorization: `Bearer ${accessToken}`,
    "User-Agent": "studiovibi-links-worker",
    "X-GitHub-Api-Version": GITHUB_API_VERSION
  };
}

function getAllowedOrg(env) {
  return String(env.ALLOWED_ORG || "StudioVibi").trim();
}

function getSessionTtlSeconds(env) {
  const raw = Number(env.SESSION_TTL_SECONDS || DEFAULT_SESSION_TTL_SECONDS);
  if (!Number.isFinite(raw) || raw <= 0) {
    return DEFAULT_SESSION_TTL_SECONDS;
  }
  return Math.floor(raw);
}

async function readSessionFromRequest(request, env) {
  const cookies = parseCookies(request.headers.get("Cookie"));
  const sessionCookie = cookies[COOKIE_SESSION];
  if (!sessionCookie) {
    return null;
  }

  try {
    const payload = await decryptPayload(sessionCookie, requiredEnv(env, "COOKIE_SECRET"));
    if (!payload?.exp || payload.exp <= Math.floor(Date.now() / 1000)) {
      return null;
    }
    if (!payload.accessToken || !payload.user?.login) {
      return null;
    }
    return payload;
  } catch (error) {
    console.error("Failed to read session:", error);
    return null;
  }
}

async function encryptPayload(payload, secret) {
  const json = JSON.stringify(payload);
  const key = await deriveAesKey(secret);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    textEncoder.encode(json)
  );
  const cipher = new Uint8Array(encrypted);
  const combined = new Uint8Array(iv.length + cipher.length);
  combined.set(iv, 0);
  combined.set(cipher, iv.length);
  return bytesToBase64Url(combined);
}

async function decryptPayload(encodedValue, secret) {
  const bytes = base64UrlToBytes(encodedValue);
  if (bytes.length <= 12) {
    throw new Error("Malformed encrypted payload.");
  }

  const iv = bytes.slice(0, 12);
  const cipher = bytes.slice(12);
  const key = await deriveAesKey(secret);
  const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, cipher);
  return JSON.parse(textDecoder.decode(decrypted));
}

let cachedKeySecret = null;
let cachedKey = null;

async function deriveAesKey(secret) {
  if (cachedKey && cachedKeySecret === secret) {
    return cachedKey;
  }

  const hashed = await crypto.subtle.digest("SHA-256", textEncoder.encode(secret));
  cachedKey = await crypto.subtle.importKey("raw", hashed, "AES-GCM", false, ["encrypt", "decrypt"]);
  cachedKeySecret = secret;
  return cachedKey;
}

function bytesToBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  const base64 = btoa(binary);
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlToBytes(input) {
  const base64 = input.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - (base64.length % 4 || 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function parseCookies(headerValue) {
  const result = {};
  if (!headerValue) {
    return result;
  }

  const entries = headerValue.split(";");
  for (const entry of entries) {
    const [rawName, ...rawValueParts] = entry.trim().split("=");
    if (!rawName) continue;
    const rawValue = rawValueParts.join("=");
    result[rawName] = decodeURIComponent(rawValue || "");
  }
  return result;
}

function serializeCookie(name, value, options = {}) {
  const parts = [`${name}=${encodeURIComponent(value)}`];
  if (options.maxAge != null) {
    parts.push(`Max-Age=${Math.max(0, Math.floor(options.maxAge))}`);
  }
  if (options.path) {
    parts.push(`Path=${options.path}`);
  }
  if (options.sameSite) {
    parts.push(`SameSite=${options.sameSite}`);
  }
  if (options.secure) {
    parts.push("Secure");
  }
  if (options.httpOnly) {
    parts.push("HttpOnly");
  }
  return parts.join("; ");
}

function clearCookie(name, sameSite = "None") {
  return serializeCookie(name, "", {
    maxAge: 0,
    path: "/",
    sameSite,
    secure: true,
    httpOnly: true
  });
}

function randomToken(byteLength) {
  const bytes = crypto.getRandomValues(new Uint8Array(byteLength));
  return bytesToBase64Url(bytes);
}

function requiredEnv(env, key) {
  const value = env[key];
  if (!value) {
    throw new Error(`Missing required environment variable: ${key}`);
  }
  return value;
}

function isAllowedOrigin(origin, env) {
  if (!origin) return false;
  const allowed = String(env.FRONTEND_ORIGIN || "").trim().replace(/\/+$/, "");
  if (!allowed) return false;
  return origin === allowed;
}

function withCors(response, request, env) {
  const origin = request.headers.get("Origin");
  if (!origin || !isAllowedOrigin(origin, env)) {
    return response;
  }

  const headers = new Headers(response.headers);
  headers.set("Access-Control-Allow-Origin", origin);
  headers.set("Access-Control-Allow-Credentials", "true");
  headers.set("Vary", "Origin");
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers
  });
}

function jsonResponse(request, env, payload, status = 200, extraHeaders = new Headers()) {
  const headers = new Headers(extraHeaders);
  headers.set("Content-Type", "application/json; charset=utf-8");
  const response = new Response(JSON.stringify(payload), { status, headers });
  return withCors(response, request, env);
}

function frontendAllUrl(env, authError = null) {
  const origin = String(requiredEnv(env, "FRONTEND_ORIGIN")).replace(/\/+$/, "");
  const target = new URL(`${origin}/all/`);
  if (authError) {
    target.searchParams.set("auth_error", authError);
  }
  return target.toString();
}

function redirectToFrontend(env, authError, cookies = []) {
  const headers = new Headers();
  headers.set("Location", frontendAllUrl(env, authError));
  for (const cookie of cookies) {
    headers.append("Set-Cookie", cookie);
  }
  return new Response(null, { status: 302, headers });
}
