import http from "node:http";
import { readFile } from "node:fs/promises";
import { extname } from "node:path";

const port = Number(process.env.PORT || 3000);
const mcp = process.env.MCP_API_URL || "http://mcp-server:8718";
const root = new URL("./public/", import.meta.url);
const mime = { ".html": "text/html", ".css": "text/css", ".js": "text/javascript" };

async function proxyJson(path, options = {}) {
  const response = await fetch(mcp + path, { signal: AbortSignal.timeout(30000), ...options });
  const payload = await response.json().catch(() => ({ error: `MCP HTTP ${response.status}` }));
  if (!response.ok) {
    const error = new Error(payload.error ?? `MCP HTTP ${response.status}`);
    error.status = response.status;
    throw error;
  }
  return payload;
}

async function readBody(request) {
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > 256 * 1024) throw new Error("Request body is too large");
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
}

const server = http.createServer(async (request, response) => {
  try {
    const url = new URL(request.url, "http://ui");
    response.setHeader("Cache-Control", "no-store");

    if (url.pathname === "/health") {
      response.setHeader("Content-Type", "application/json");
      return response.end('{"status":"ok"}');
    }
    if (url.pathname === "/api/dashboard" && request.method === "GET") {
      response.setHeader("Content-Type", "application/json");
      return response.end(JSON.stringify(await proxyJson("/api/dashboard")));
    }
    if (url.pathname === "/api/ask" && request.method === "POST") {
      const body = await readBody(request);
      response.setHeader("Content-Type", "application/json");
      return response.end(JSON.stringify(await proxyJson("/api/ask", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      })));
    }
    if (request.method !== "GET") return response.writeHead(405).end("Method not allowed");

    const path = url.pathname === "/" ? "index.html" : url.pathname.slice(1);
    if (path.includes("..")) return response.writeHead(403).end();
    const bytes = await readFile(new URL(path, root));
    response.setHeader("Content-Type", mime[extname(path)] || "application/octet-stream");
    response.end(bytes);
  } catch (error) {
    response.writeHead(error.status ?? (error.code === "ENOENT" ? 404 : 503)).end(String(error.message));
  }
});

server.listen(port, "0.0.0.0", () => console.log("ZimaBrain UI live on " + port));
