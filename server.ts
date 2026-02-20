type SessionUser = {
  login: string;
  avatar_url?: string | null;
};

type Session = {
  accessToken: string;
  user: SessionUser;
  expiresAt: number;
};

type OAuthState = {
  expiresAt: number;
};

type RepoSummary = {
  name: string;
  html_url: string;
  description: string | null;
  private: boolean;
  updated_at: string;
};

type CookieOptions = {
  httpOnly?: boolean;
  maxAge?: number;
  path?: string;
  sameSite?: "Lax" | "Strict" | "None";
  secure?: boolean;
};

class HttpError extends Error {
  status: number;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

const DEFAULT_ORG = "StudioVibi";
const PORT = parseNumber(Bun.env.PORT, 3000);
const ORG_NAME = (Bun.env.ORG_NAME || DEFAULT_ORG).trim() || DEFAULT_ORG;
const APP_BASE_URL = normalizeBaseUrl(Bun.env.APP_BASE_URL || "");
const GITHUB_CLIENT_ID = (Bun.env.GITHUB_CLIENT_ID || "").trim();
const GITHUB_CLIENT_SECRET = (Bun.env.GITHUB_CLIENT_SECRET || "").trim();
const SESSION_TTL_HOURS = parseNumber(Bun.env.SESSION_TTL_HOURS, 12);
const SESSION_TTL_MS = SESSION_TTL_HOURS * 60 * 60 * 1000;
const OAUTH_STATE_TTL_MS = 10 * 60 * 1000;
const MAX_REPO_PAGES = 10;
const IS_PROD = Bun.env.NODE_ENV === "production";

const sessions = new Map<string, Session>();
const oauthStates = new Map<string, OAuthState>();

const staticRoutes: Record<string, string> = {
  "/": "index.html",
  "/index.html": "index.html",
  "/app.js": "app.js",
  "/styles.css": "styles.css",
  "/fonts/Minecraftia.ttf": "fonts/Minecraftia.ttf"
};

function parseNumber(value: string | undefined, fallback: number): number {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) return fallback;
  return parsed;
}

function normalizeBaseUrl(value: string): string {
  return value.replace(/\/+$/, "");
}

function isOauthConfigured(): boolean {
  return Boolean(GITHUB_CLIENT_ID && GITHUB_CLIENT_SECRET);
}

function json(data: unknown, status = 200, headers?: HeadersInit): Response {
  const responseHeaders = new Headers(headers);
  responseHeaders.set("content-type", "application/json; charset=utf-8");
  responseHeaders.set("cache-control", "no-store");
  return new Response(JSON.stringify(data), { status, headers: responseHeaders });
}

function parseCookies(request: Request): Map<string, string> {
  const raw = request.headers.get("cookie");
  const cookies = new Map<string, string>();
  if (!raw) return cookies;

  for (const part of raw.split(";")) {
    const [name, ...rest] = part.trim().split("=");
    if (!name) continue;
    const value = rest.join("=");
    cookies.set(name, decodeURIComponent(value || ""));
  }
  return cookies;
}

function serializeCookie(name: string, value: string, options: CookieOptions = {}): string {
  const parts = [`${name}=${encodeURIComponent(value)}`];
  parts.push(`Path=${options.path || "/"}`);

  if (typeof options.maxAge === "number") {
    parts.push(`Max-Age=${Math.max(0, Math.floor(options.maxAge))}`);
  }
  if (options.httpOnly) parts.push("HttpOnly");
  if (options.sameSite) parts.push(`SameSite=${options.sameSite}`);
  if (options.secure) parts.push("Secure");

  return parts.join("; ");
}

function cookieDefaults(maxAgeSeconds: number): CookieOptions {
  return {
    httpOnly: true,
    path: "/",
    sameSite: "Lax",
    secure: IS_PROD,
    maxAge: maxAgeSeconds
  };
}

function pruneExpired(): void {
  const now = Date.now();

  for (const [id, session] of sessions) {
    if (session.expiresAt <= now) sessions.delete(id);
  }

  for (const [state, entry] of oauthStates) {
    if (entry.expiresAt <= now) oauthStates.delete(state);
  }
}

function getSessionFromRequest(request: Request): { sid: string | null; session: Session | null } {
  pruneExpired();
  const cookies = parseCookies(request);
  const sid = cookies.get("sid");
  if (!sid) return { sid: null, session: null };

  const session = sessions.get(sid);
  if (!session) return { sid, session: null };
  return { sid, session };
}

function safeRedirectRoot(errorCode?: string, clearOauthState = false): Response {
  const target = errorCode ? `/?error=${encodeURIComponent(errorCode)}` : "/";
  const headers = new Headers({ location: target });
  if (clearOauthState) {
    headers.append("set-cookie", serializeCookie("oauth_state", "", cookieDefaults(0)));
  }
  return new Response(null, { status: 302, headers });
}

function getRequestOrigin(request: Request): string {
  if (APP_BASE_URL) return APP_BASE_URL;
  const url = new URL(request.url);
  return `${url.protocol}//${url.host}`;
}

async function fetchGithubToken(code: string, redirectUri: string): Promise<string> {
  const body = new URLSearchParams({
    client_id: GITHUB_CLIENT_ID,
    client_secret: GITHUB_CLIENT_SECRET,
    code,
    redirect_uri: redirectUri
  });

  const response = await fetch("https://github.com/login/oauth/access_token", {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body
  });

  const payload = (await response.json()) as {
    access_token?: string;
    error?: string;
    error_description?: string;
  };

  if (!response.ok || !payload.access_token) {
    const message =
      payload.error_description || payload.error || "GitHub OAuth token exchange failed.";
    throw new HttpError(502, message);
  }

  return payload.access_token;
}

async function fetchGithubUser(accessToken: string): Promise<SessionUser> {
  const response = await fetch("https://api.github.com/user", {
    headers: {
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${accessToken}`,
      "X-GitHub-Api-Version": "2022-11-28",
      "User-Agent": "studiovibi-all"
    }
  });

  if (!response.ok) {
    throw new HttpError(502, "Failed to fetch GitHub user profile.");
  }

  const payload = (await response.json()) as { login?: string; avatar_url?: string | null };
  if (!payload.login) {
    throw new HttpError(502, "GitHub profile did not return a valid login.");
  }

  return {
    login: payload.login,
    avatar_url: payload.avatar_url || null
  };
}

function hasNextPage(linkHeader: string | null): boolean {
  if (!linkHeader) return false;
  return linkHeader.includes('rel="next"');
}

async function fetchOrgRepos(org: string, accessToken: string | null): Promise<RepoSummary[]> {
  const repos: RepoSummary[] = [];
  const repoType = accessToken ? "all" : "public";

  for (let page = 1; page <= MAX_REPO_PAGES; page += 1) {
    const url = new URL(`https://api.github.com/orgs/${encodeURIComponent(org)}/repos`);
    url.searchParams.set("per_page", "100");
    url.searchParams.set("page", String(page));
    url.searchParams.set("type", repoType);

    const headers: Record<string, string> = {
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      "User-Agent": "studiovibi-all"
    };

    if (accessToken) {
      headers.Authorization = `Bearer ${accessToken}`;
    }

    const response = await fetch(url, { headers });
    const rateRemaining = response.headers.get("x-ratelimit-remaining");

    if (!response.ok) {
      let message = `GitHub API error (${response.status}).`;
      try {
        const body = (await response.json()) as { message?: string };
        if (body.message) message = body.message;
      } catch {
        // ignore JSON parsing failures
      }

      if (response.status === 403 && rateRemaining === "0") {
        throw new HttpError(429, "GitHub API rate limit exceeded. Try again later.");
      }
      if (response.status === 401) {
        throw new HttpError(401, "GitHub session expired. Please login again.");
      }
      if (response.status === 404) {
        throw new HttpError(404, `Organization "${org}" not found.`);
      }

      throw new HttpError(502, message);
    }

    const pageRepos = (await response.json()) as Array<{
      name?: string;
      html_url?: string;
      description?: string | null;
      private?: boolean;
      updated_at?: string;
    }>;

    for (const repo of pageRepos) {
      if (!repo.name || !repo.html_url || !repo.updated_at) continue;
      repos.push({
        name: repo.name,
        html_url: repo.html_url,
        description: repo.description || null,
        private: Boolean(repo.private),
        updated_at: repo.updated_at
      });
    }

    if (pageRepos.length < 100 || !hasNextPage(response.headers.get("link"))) {
      break;
    }
  }

  repos.sort((a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: "base" }));
  return repos;
}

async function handleApiSession(request: Request): Promise<Response> {
  const { session } = getSessionFromRequest(request);

  if (!session) {
    return json({
      authenticated: false,
      user: null,
      oauth_configured: isOauthConfigured()
    });
  }

  return json({
    authenticated: true,
    user: session.user,
    oauth_configured: isOauthConfigured()
  });
}

async function handleApiRepos(request: Request): Promise<Response> {
  try {
    const { session } = getSessionFromRequest(request);
    const url = new URL(request.url);
    const orgParam = (url.searchParams.get("org") || "").trim();
    const org = orgParam || ORG_NAME;

    const repos = await fetchOrgRepos(org, session?.accessToken || null);
    const visibilityMode = session ? "public_and_private" : "public_only";

    return json({ repos, visibility_mode: visibilityMode });
  } catch (error) {
    if (error instanceof HttpError) {
      if (error.status === 401) {
        const { sid } = getSessionFromRequest(request);
        if (sid) sessions.delete(sid);
      }
      return json({ error: error.message }, error.status);
    }

    return json({ error: "Unexpected error while loading repositories." }, 500);
  }
}

async function handleAuthLogin(request: Request): Promise<Response> {
  if (!isOauthConfigured()) {
    return json(
      {
        error:
          "GitHub OAuth is not configured. Set GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET in .env."
      },
      503
    );
  }

  const state = crypto.randomUUID();
  oauthStates.set(state, { expiresAt: Date.now() + OAUTH_STATE_TTL_MS });

  const redirectUri = `${getRequestOrigin(request)}/auth/callback`;
  const authUrl = new URL("https://github.com/login/oauth/authorize");
  authUrl.searchParams.set("client_id", GITHUB_CLIENT_ID);
  authUrl.searchParams.set("redirect_uri", redirectUri);
  authUrl.searchParams.set("scope", "repo");
  authUrl.searchParams.set("state", state);

  const headers = new Headers();
  headers.append(
    "set-cookie",
    serializeCookie("oauth_state", state, cookieDefaults(Math.floor(OAUTH_STATE_TTL_MS / 1000)))
  );
  headers.set("location", authUrl.toString());

  return new Response(null, { status: 302, headers });
}

async function handleAuthCallback(request: Request): Promise<Response> {
  if (!isOauthConfigured()) {
    return safeRedirectRoot("oauth_not_configured", true);
  }

  const url = new URL(request.url);
  const code = url.searchParams.get("code") || "";
  const state = url.searchParams.get("state") || "";
  const cookies = parseCookies(request);
  const cookieState = cookies.get("oauth_state") || "";
  const knownState = oauthStates.get(state);

  oauthStates.delete(state);

  if (!code) return safeRedirectRoot("oauth_missing_code", true);
  if (!state || !cookieState || cookieState !== state || !knownState) {
    return safeRedirectRoot("oauth_state_invalid", true);
  }
  if (knownState.expiresAt <= Date.now()) {
    return safeRedirectRoot("oauth_state_expired", true);
  }

  try {
    const redirectUri = `${getRequestOrigin(request)}/auth/callback`;
    const accessToken = await fetchGithubToken(code, redirectUri);
    const user = await fetchGithubUser(accessToken);
    const sid = crypto.randomUUID();
    sessions.set(sid, {
      accessToken,
      user,
      expiresAt: Date.now() + SESSION_TTL_MS
    });

    const headers = new Headers();
    headers.append(
      "set-cookie",
      serializeCookie("sid", sid, cookieDefaults(Math.floor(SESSION_TTL_MS / 1000)))
    );
    headers.append("set-cookie", serializeCookie("oauth_state", "", cookieDefaults(0)));
    headers.set("location", "/");
    return new Response(null, { status: 302, headers });
  } catch (error) {
    return safeRedirectRoot("oauth_failed", true);
  }
}

async function handleAuthLogout(request: Request): Promise<Response> {
  if (request.method !== "POST") {
    return json({ error: "Method not allowed." }, 405);
  }

  const { sid } = getSessionFromRequest(request);
  if (sid) sessions.delete(sid);

  const headers = new Headers();
  headers.append("set-cookie", serializeCookie("sid", "", cookieDefaults(0)));
  return json({ ok: true }, 200, headers);
}

function notFound(): Response {
  return new Response("Not found", { status: 404 });
}

function serveStatic(pathname: string): Response {
  const filePath = staticRoutes[pathname];
  if (!filePath) return notFound();
  return new Response(Bun.file(filePath));
}

Bun.serve({
  port: PORT,
  async fetch(request) {
    const url = new URL(request.url);
    const { pathname } = url;
    pruneExpired();

    if (pathname === "/api/session" && request.method === "GET") {
      return handleApiSession(request);
    }

    if (pathname === "/api/repos" && request.method === "GET") {
      return handleApiRepos(request);
    }

    if (pathname === "/auth/login" && request.method === "GET") {
      return handleAuthLogin(request);
    }

    if (pathname === "/auth/callback" && request.method === "GET") {
      return handleAuthCallback(request);
    }

    if (pathname === "/auth/logout") {
      return handleAuthLogout(request);
    }

    if (pathname in staticRoutes) {
      return serveStatic(pathname);
    }

    return notFound();
  }
});

console.log(`all is running at http://localhost:${PORT} (org=${ORG_NAME})`);
