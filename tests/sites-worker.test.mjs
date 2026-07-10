import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { extname, resolve, sep } from "node:path";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

const projectRoot = fileURLToPath(new URL("../", import.meta.url));
const clientRoot = resolve(projectRoot, "dist", "client");
const mimeTypes = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".png": "image/png",
  ".svg": "image/svg+xml",
};

async function loadWorker() {
  const workerUrl = pathToFileURL(
    resolve(projectRoot, "dist", "server", "index.js"),
  );
  workerUrl.searchParams.set("test", `${process.pid}-${Date.now()}`);
  return (await import(workerUrl.href)).default;
}

function mockAssets() {
  return {
    async fetch(request) {
      const url = new URL(request.url);
      let pathname = decodeURIComponent(url.pathname);
      if (pathname === "/") {
        pathname = "/index.html";
      }

      const file = resolve(clientRoot, `.${pathname}`);
      if (file !== clientRoot && !file.startsWith(`${clientRoot}${sep}`)) {
        return new Response("Not Found", { status: 404 });
      }

      try {
        const body = await readFile(file);
        return new Response(body, {
          headers: {
            "Content-Type":
              mimeTypes[extname(file).toLowerCase()] ||
              "application/octet-stream",
          },
        });
      } catch (error) {
        if (error?.code === "ENOENT" || error?.code === "EISDIR") {
          return new Response("Not Found", {
            status: 404,
            headers: { "Content-Type": "text/plain; charset=utf-8" },
          });
        }
        throw error;
      }
    },
  };
}

function context() {
  return {
    waitUntil() {},
    passThroughOnException() {},
  };
}

test("serves the product homepage and rewrites share metadata to its Sites origin", async () => {
  const worker = await loadWorker();
  const response = await worker.fetch(
    new Request("https://ai-signal-guard.example/", {
      headers: { accept: "text/html" },
    }),
    { ASSETS: mockAssets() },
    context(),
  );

  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type") || "", /^text\/html/);
  assert.equal(response.headers.get("x-content-type-options"), "nosniff");

  const html = await response.text();
  assert.match(html, /<title>AI Signal Guard/);
  assert.match(html, /https:\/\/ai-signal-guard\.example\/assets\//);
  assert.doesNotMatch(html, /betaer\.github\.io\/AISignalGuard/);
});

test("serves the browser bundle through the assets binding", async () => {
  const worker = await loadWorker();
  const response = await worker.fetch(
    new Request("https://ai-signal-guard.example/app.min.js"),
    { ASSETS: mockAssets() },
    context(),
  );

  assert.equal(response.status, 200);
  assert.match(
    response.headers.get("content-type") || "",
    /^text\/javascript/,
  );
  const javascript = await response.text();
  assert.ok(javascript.length > 50_000);
  assert.match(javascript, /window\.location\.href/);
  assert.doesNotMatch(javascript, /betaer\.github\.io\/AISignalGuard/);
});

test("returns the branded 404 page with an actual 404 status", async () => {
  const worker = await loadWorker();
  const response = await worker.fetch(
    new Request("https://ai-signal-guard.example/missing", {
      headers: { accept: "text/html" },
    }),
    { ASSETS: mockAssets() },
    context(),
  );

  assert.equal(response.status, 404);
  assert.match(await response.text(), /这个页面没有信号/);
});

test("supports HEAD and rejects mutating methods", async () => {
  const worker = await loadWorker();
  const env = { ASSETS: mockAssets() };

  const head = await worker.fetch(
    new Request("https://ai-signal-guard.example/", { method: "HEAD" }),
    env,
    context(),
  );
  assert.equal(head.status, 200);
  assert.equal(await head.text(), "");

  const post = await worker.fetch(
    new Request("https://ai-signal-guard.example/", { method: "POST" }),
    env,
    context(),
  );
  assert.equal(post.status, 405);
  assert.equal(post.headers.get("allow"), "GET, HEAD");
});
