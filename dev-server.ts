import path from "node:path";

import worker from "./worker/src/index.js";

const port = Number(process.env.PORT || 8787);
const host = process.env.HOST || "127.0.0.1";
const rootDir = import.meta.dir;
const allDir = path.join(rootDir, "all");

const workerEnv = {
  ALLOWED_ORG: process.env.ALLOWED_ORG || "StudioVibi",
  FRONTEND_ORIGIN: process.env.FRONTEND_ORIGIN || `http://${host}:${port}`,
  REDIRECT_URI: process.env.REDIRECT_URI || `http://${host}:${port}/auth/callback`,
  SESSION_TTL_SECONDS: process.env.SESSION_TTL_SECONDS || "28800",
  CLIENT_ID: process.env.CLIENT_ID || "",
  CLIENT_SECRET: process.env.CLIENT_SECRET || "",
  COOKIE_SECRET: process.env.COOKIE_SECRET || ""
};

function resolveAllPath(pathname: string): string | null {
  if (!pathname.startsWith("/all")) {
    return null;
  }

  let relative = pathname.slice("/all".length);
  if (!relative || relative === "/") {
    relative = "/index.html";
  }

  const decoded = decodeURIComponent(relative.split("?")[0].split("#")[0]);
  const normalized = path.normalize(decoded).replace(/^(\.\.(\/|\\|$))+/, "");
  return path.join(allDir, normalized);
}

async function serveAllFile(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const filePath = resolveAllPath(url.pathname);
  if (!filePath) {
    return new Response("Not found", { status: 404 });
  }

  const file = Bun.file(filePath);
  if (!(await file.exists())) {
    return new Response("Not found", { status: 404 });
  }

  if (filePath.endsWith("index.html")) {
    let html = await file.text();
    const localBase = `http://${host}:${port}`;
    html = html.replaceAll("https://REPLACE_WITH_WORKER_DOMAIN", localBase);
    return new Response(html, {
      headers: {
        "Content-Type": "text/html; charset=utf-8"
      }
    });
  }

  return new Response(file, {
    headers: file.type ? { "Content-Type": file.type } : undefined
  });
}

function isWorkerRoute(pathname: string): boolean {
  return (
    pathname === "/auth/login" ||
    pathname === "/auth/callback" ||
    pathname === "/auth/logout" ||
    pathname === "/api/session" ||
    pathname === "/api/repos"
  );
}

const server = Bun.serve({
  hostname: host,
  port,
  async fetch(request) {
    const url = new URL(request.url);

    if (url.pathname === "/") {
      return Response.redirect(`http://${host}:${port}/all/`, 302);
    }

    if (isWorkerRoute(url.pathname) || request.method === "OPTIONS") {
      return worker.fetch(request, workerEnv as any);
    }

    if (url.pathname === "/all") {
      return Response.redirect(`http://${host}:${port}/all/`, 302);
    }

    if (url.pathname.startsWith("/all/")) {
      return serveAllFile(request);
    }

    return new Response("Not found", { status: 404 });
  }
});

console.log(`[dev-server] running at http://${host}:${port}`);
console.log(`[dev-server] frontend: http://${host}:${port}/all/`);
console.log("[dev-server] worker routes: /auth/* and /api/*");
console.log("[dev-server] set CLIENT_ID, CLIENT_SECRET and COOKIE_SECRET to test GitHub login.");

process.on("SIGINT", () => {
  server.stop(true);
  process.exit(0);
});
