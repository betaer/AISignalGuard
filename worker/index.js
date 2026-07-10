const LEGACY_SITE_BASE = "https://betaer.github.io/AISignalGuard/";

const SECURITY_HEADERS = {
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
};

function acceptsHtml(request) {
  return (request.headers.get("accept") || "").includes("text/html");
}

function assetRequest(request, url) {
  return new Request(url || request.url, {
    method: "GET",
    headers: request.headers,
  });
}

async function withSiteOrigin(response, origin) {
  const contentType = response.headers.get("content-type") || "";
  if (!contentType.startsWith("text/html")) {
    return { body: response.body, isHtml: false };
  }

  const html = await response.text();
  return {
    body: html.replaceAll(LEGACY_SITE_BASE, `${origin}/`),
    isHtml: true,
  };
}

const worker = {
  async fetch(request, env) {
    if (!env?.ASSETS?.fetch) {
      return new Response("Site assets are unavailable.", { status: 503 });
    }

    if (request.method !== "GET" && request.method !== "HEAD") {
      return new Response("Method Not Allowed", {
        status: 405,
        headers: { Allow: "GET, HEAD", ...SECURITY_HEADERS },
      });
    }

    const url = new URL(request.url);
    let response = await env.ASSETS.fetch(assetRequest(request));
    let status = response.status;

    if (status === 404 && acceptsHtml(request)) {
      response = await env.ASSETS.fetch(
        assetRequest(request, new URL("/404.html", url)),
      );
      status = 404;
    }

    const { body, isHtml } = await withSiteOrigin(response, url.origin);
    const headers = new Headers(response.headers);
    Object.entries(SECURITY_HEADERS).forEach(([name, value]) => {
      headers.set(name, value);
    });
    if (isHtml) {
      headers.set("Cache-Control", "no-cache");
      headers.set("Content-Type", "text/html; charset=utf-8");
      headers.delete("Content-Length");
    }

    return new Response(request.method === "HEAD" ? null : body, {
      status,
      headers,
    });
  },
};

export default worker;
