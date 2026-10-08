#!/usr/bin/env node
import { createServer } from "node:http";
import { readFile, stat } from "node:fs/promises";
import { extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("./public/", import.meta.url));
const port = Number.parseInt(process.env.PORT ?? "3737", 10);
const host = process.env.HOST ?? "127.0.0.1";
const diagnostics = [];
const mime = new Map([
  [".html", "text/html; charset=utf-8"],
  [".js", "text/javascript; charset=utf-8"],
  [".mjs", "text/javascript; charset=utf-8"],
  [".css", "text/css; charset=utf-8"],
  [".json", "application/json; charset=utf-8"],
  [".syx", "application/octet-stream"],
  [".svg", "image/svg+xml"],
]);

function resolvePath(urlPath) {
  const decoded = decodeURIComponent(urlPath.split("?", 1)[0]);
  const requested = decoded === "/" ? "index.html" : decoded.replace(/^\/+/, "");
  const safe = normalize(requested);
  if (safe.startsWith("..") || safe.includes("\0")) return null;
  return join(root, safe);
}

const server = createServer(async (request, response) => {
  try {
    if (request.url === "/__diagnostics") {
      if (request.method === "GET") {
        const body = Buffer.from(`${JSON.stringify(diagnostics, null, 2)}\n`);
        response.writeHead(200, {
          "Content-Type": "application/json; charset=utf-8",
          "Content-Length": body.length,
          "Cache-Control": "no-store",
        });
        response.end(body);
        return;
      }
      if (request.method === "DELETE") {
        diagnostics.length = 0;
        response.writeHead(204).end();
        return;
      }
      if (request.method === "POST") {
        const chunks = [];
        let length = 0;
        for await (const chunk of request) {
          length += chunk.length;
          if (length > 65536) throw new Error("diagnostic body too large");
          chunks.push(chunk);
        }
        diagnostics.push(JSON.parse(Buffer.concat(chunks).toString("utf8")));
        if (diagnostics.length > 200) diagnostics.splice(0, diagnostics.length - 200);
        response.writeHead(204).end();
        return;
      }
      response.writeHead(405, { Allow: "GET, POST, DELETE" }).end();
      return;
    }
    const path = resolvePath(request.url ?? "/");
    if (!path) {
      response.writeHead(400).end("Bad request");
      return;
    }
    const metadata = await stat(path);
    if (!metadata.isFile()) throw new Error("not a file");
    const body = await readFile(path);
    response.writeHead(200, {
      "Content-Type": mime.get(extname(path)) ?? "application/octet-stream",
      "Content-Length": body.length,
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:",
    });
    response.end(body);
  } catch {
    response.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" }).end("Not found");
  }
});

server.listen(port, host, () => {
  console.log(`SMK-37 Patch Set Editor: http://${host}:${port}`);
});
