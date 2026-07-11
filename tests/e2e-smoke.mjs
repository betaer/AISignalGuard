// 端到端回归测试：确定性 fixture 路由，覆盖评分正确性与关键竞态。
// 运行：npm run test:e2e
// 首次需要：npx playwright install chromium
//
// 场景相互独立（各自新建 page/context），单场景失败不阻塞其余场景。
// 分数断言使用 delta（同一页面前后差值），不依赖宿主机字体 / Emoji 差异。
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const projectRoot = fileURLToPath(new URL("../", import.meta.url));

const mimeTypes = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".png": "image/png",
  ".svg": "image/svg+xml",
};

const FIXTURE_IPV4 = "203.0.113.10";
const FIXTURE_IPV6 = "2001:db8::1";
// 命中 isHostingOrg 正则 → 出口 IP 扣 22 分，用于验证失败重测后惩罚被撤销
const HOSTING_ORG = "Example Hosting Cloud";

const IP_INTEL_HOSTS = [
  "ipwho.is",
  "api.ip.sb",
  "ipinfo.io",
  "get.geojs.io",
  "api.db-ip.com",
  "api.ipapi.is",
  "api.country.is",
  "api.ipify.org",
  "api64.ipify.org",
  "api6.ipify.org",
  "api.iplocation.net",
];

function ipPayload(overrides = {}) {
  return {
    ip: FIXTURE_IPV4,
    country_code: "US",
    country: "United States",
    city: "Ashburn",
    asn: "AS64500",
    org: HOSTING_ORG,
    ...overrides,
  };
}

function twitterWeightedLength(text) {
  const urlPattern = /https?:\/\/\S+/g;
  let length = 0;
  let cursor = 0;
  for (const match of text.matchAll(urlPattern)) {
    length += Array.from(text.slice(cursor, match.index)).reduce(
      (sum, char) => sum + (char.codePointAt(0) <= 0x10ff ? 1 : 2),
      0,
    ) + 23;
    cursor = match.index + match[0].length;
  }
  return length + Array.from(text.slice(cursor)).reduce(
    (sum, char) => sum + (char.codePointAt(0) <= 0x10ff ? 1 : 2),
    0,
  );
}

async function captureCopiedSummary(page) {
  await page.addInitScript(() => {
    window.__copiedSummary = "";
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: {
        writeText: async (text) => {
          window.__copiedSummary = text;
        },
      },
    });
  });
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Fake RTCPeerConnection：吐出一个不在 fixture 出口列表里的公网 srflx 候选，
// 使 WebRTC 判定为“发现出口外公网候选”（-12），用于验证 reapplyWebrtc()。
const FAKE_WEBRTC_INIT = `
  window.RTCPeerConnection = class {
    constructor() { this.onicecandidate = null; }
    createDataChannel() { return {}; }
    createOffer() { return Promise.resolve({}); }
    setLocalDescription() {
      var self = this;
      setTimeout(function () {
        if (self.onicecandidate) {
          self.onicecandidate({
            candidate: { candidate: "candidate:1 1 udp 2122260223 198.51.100.7 54400 typ srflx generation 0" }
          });
          self.onicecandidate({ candidate: null });
        }
      }, 100);
      return Promise.resolve();
    }
    close() {}
  };
`;

/**
 * 全量确定性路由。所有外部请求都被本地 fixture 接管，杜绝真实网络抖动。
 * opts.flags 是可变对象：{ blockIpSources } 可在场景中途切换。
 * opts.ipDelays: { [hostSubstring]: ms } 指定 IP 情报源的响应延迟。
 * opts.allowedIpHosts: 仅允许指定 IP 情报主机返回，用于验证来源接管。
 * opts.ipPayloadByHost: { [host]: overrides } 为指定来源覆盖标准 fixture 字段。
 * opts.ipv6First: api6.ipify 立即返回 IPv6（配合 ipDelays 模拟双栈切换）。
 * opts.hangOpenaiStatus: status.openai.com 挂 9 秒后 abort（fallback 竞态用例）。
 */
async function routeFixtures(target, baseOrigin, opts = {}) {
  const flags = opts.flags || {};
  await target.route("**/*", async (route) => {
    const url = new URL(route.request().url());
    if (url.origin === baseOrigin) {
      return route.continue();
    }
    const host = url.hostname;
    const json = (body, status = 200) =>
      route.fulfill({ status, contentType: "application/json", body: JSON.stringify(body) }).catch(() => {});
    const text = (body, contentType = "text/plain") =>
      route.fulfill({ status: 200, contentType, body }).catch(() => {});

    const isIpIntel = IP_INTEL_HOSTS.some((h) => host === h || host.endsWith(`.${h}`));
    if (isIpIntel) {
      if (flags.blockIpSources) {
        return route.abort().catch(() => {});
      }
      if (opts.allowedIpHosts && !opts.allowedIpHosts.includes(host)) {
        return route.abort().catch(() => {});
      }
      if (opts.ipv6First && host === "api6.ipify.org") {
        return json({ ip: FIXTURE_IPV6 });
      }
      if (opts.ipv6First && host === "ipwho.is" && url.pathname.startsWith("/2001")) {
        return json(ipPayload({ ip: FIXTURE_IPV6 }));
      }
      const delayEntry = Object.entries(opts.ipDelays || {}).find(([k]) => host.includes(k));
      if (delayEntry) {
        await sleep(delayEntry[1]);
      }
      if (host.includes("ipify")) {
        return json({ ip: FIXTURE_IPV4 });
      }
      if (host === "api.country.is") {
        return json({ ip: FIXTURE_IPV4, country: "US" });
      }
      if (host === "api.iplocation.net") {
        return json({
          ip: url.searchParams.get("ip") || FIXTURE_IPV4,
          country_code2: "US",
          country_name: "United States",
          isp: HOSTING_ORG,
        });
      }
      return json(ipPayload({
        ...opts.ipOverrides,
        ...(opts.ipPayloadByHost?.[host] || {}),
      }));
    }
    if (host === "bash.ws") {
      if (url.pathname === "/id") {
        return text("abc123def");
      }
      if (url.pathname.startsWith("/dnsleak/test/")) {
        return json([
          { type: "ip", ip: FIXTURE_IPV4, country_name: "United States", asn: HOSTING_ORG },
          { type: "dns", ip: "8.8.8.8", country_name: "United States", asn: "Google LLC" },
          { type: "dns", ip: "8.8.4.4", country_name: "United States", asn: "Google LLC" },
          { type: "conclusion", ip: "No DNS leaks" },
        ]);
      }
      return text("");
    }
    if (host.endsWith(".bash.ws")) {
      return route.fulfill({ status: 200, contentType: "image/png", body: "" }).catch(() => {});
    }
    if (url.pathname === "/cdn-cgi/trace") {
      return text(`fl=1\nip=${FIXTURE_IPV4}\nloc=US\n`);
    }
    if (host === "status.openai.com" && opts.hangOpenaiStatus) {
      await sleep(9000);
      return route.abort().catch(() => {});
    }
    if (url.pathname.includes("/api/v2/status.json")) {
      return json({ status: { indicator: "none" } });
    }
    if (host === "api.github.com") {
      return json({ stargazers_count: 42 });
    }
    // 其余外部请求（favicon 探针、generate_204、GA 等）统一返回 204
    return route.fulfill({ status: 204, body: "" }).catch(() => {});
  });
}

async function waitForScore(page, timeout = 60000) {
  await page.waitForFunction(
    () => /^\d+$/.test(document.querySelector("#score-number").textContent.trim()),
    null,
    { timeout },
  );
  return Number(await page.locator("#score-number").innerText());
}

async function scoreNodeSnapshot(page) {
  return page.locator("#score-nodes .score-node").evaluateAll((nodes) =>
    nodes.map((node) => {
      const icon = node.querySelector(".score-node-icon");
      const use = icon?.querySelector("use");
      const href = use?.getAttribute("href") || "";
      const iconRect = icon?.getBoundingClientRect();
      return {
        id: node.dataset.scoreSegment,
        status: node.dataset.status,
        label: node.querySelector(".score-node-label")?.textContent.trim(),
        expanded: node.getAttribute("aria-expanded"),
        controls: node.getAttribute("aria-controls"),
        iconHref: href,
        hasIcon:
          Boolean(href && document.querySelector(href)) &&
          iconRect?.width > 0 &&
          iconRect?.height > 0 &&
          getComputedStyle(icon).visibility !== "hidden",
      };
    }),
  );
}

// ---------- 场景定义 ----------
const scenarios = [
  {
    name: "复制摘要：无中国信号时生成 280 字符内英文宣传文案",
    async run({ browser, base, ok }) {
      const page = await browser.newPage({ locale: "en-US", timezoneId: "America/New_York" });
      await captureCopiedSummary(page);
      await routeFixtures(page, base.origin);
      await page.goto(base.href);
      await waitForScore(page);
      await page.locator("#copy-summary").click();
      const copied = await page.evaluate(() => window.__copiedSummary);
      ok("English share title", copied.startsWith("Claude Account Risk Check"), copied);
      ok("English CTA retained", copied.includes("Check yours: https://betaer.github.io/AiSignalGuard/"), copied);
      ok("repository URL removed", !copied.includes("github.com/betaer"), copied);
      ok("non-core rows hidden", !/^(WebRTC|DNS|Region):/m.test(copied), copied);
      ok("English share within X budget", twitterWeightedLength(copied) <= 280, `length=${twitterWeightedLength(copied)}`);
      await page.close();
    },
  },
  {
    name: "复制摘要：中文语言与香港出口均触发中文宣传文案",
    async run({ browser, base, ok }) {
      const chinesePage = await browser.newPage({ locale: "zh-CN", timezoneId: "America/New_York" });
      await captureCopiedSummary(chinesePage);
      await routeFixtures(chinesePage, base.origin);
      await chinesePage.goto(base.href);
      await waitForScore(chinesePage);
      await chinesePage.locator("#copy-summary").click();
      const chineseCopied = await chinesePage.evaluate(() => window.__copiedSummary);
      ok("Chinese locale selects Chinese summary", chineseCopied.includes("Claude 封号风险检测"), chineseCopied);
      ok("Chinese CTA retained", chineseCopied.includes("立即检测：https://betaer.github.io/AiSignalGuard/"), chineseCopied);
      ok("Chinese share within X budget", twitterWeightedLength(chineseCopied) <= 280, `length=${twitterWeightedLength(chineseCopied)}`);
      await chinesePage.close();

      const hongKongPage = await browser.newPage({ locale: "en-US", timezoneId: "America/New_York" });
      await captureCopiedSummary(hongKongPage);
      await routeFixtures(hongKongPage, base.origin, {
        ipOverrides: { country_code: "HK", country: "Hong Kong" },
      });
      await hongKongPage.goto(base.href);
      await hongKongPage.locator('[data-region="cnhk"]').click();
      await waitForScore(hongKongPage);
      await hongKongPage.locator("#copy-summary").click();
      const hongKongCopied = await hongKongPage.evaluate(() => window.__copiedSummary);
      ok("Hong Kong exit selects Chinese summary", hongKongCopied.includes("Claude 封号风险检测"), hongKongCopied);
      await hongKongPage.close();
    },
  },
  {
    name: "出口 IP 质量：忽略仅 IP 快速响应并由更完整来源自动升级",
    async run({ browser, base, ok }) {
      const page = await browser.newPage();
      await page.addInitScript(() => {
        window.__ipSourceTags = [];
        document.addEventListener("DOMContentLoaded", () => {
          let last = "";
          new MutationObserver(() => {
            const tag = document.querySelector('[data-row="ip"] .row-tag')?.textContent.trim() || "";
            if (tag && tag !== last) {
              last = tag;
              window.__ipSourceTags.push(tag);
            }
          }).observe(document.documentElement, { childList: true, subtree: true, characterData: true });
        });
      });
      await routeFixtures(page, base.origin, {
        allowedIpHosts: ["api.ipify.org", "ipwho.is", "api.ip.sb"],
        ipDelays: { "ipwho.is": 1500, "api.ip.sb": 3500 },
        ipPayloadByHost: {
          "ipwho.is": { asn: "", org: "", city: "" },
          "api.ip.sb": { asn: "AS64501", org: "Premium Residential ISP", city: "New York" },
        },
      });
      await page.goto(base.href);

      await page.waitForFunction(
        () => document.querySelector('[data-row="ip"] .row-tag')?.textContent.trim() === "ipwho.is",
        null,
        { timeout: 5000 },
      );
      const tagsAfterGeo = await page.evaluate(() => window.__ipSourceTags);
      ok(
        "IP-only response stays provisional",
        !tagsAfterGeo.includes("ipify.org"),
        JSON.stringify(tagsAfterGeo),
      );
      ok(
        "first geo-complete source takes over",
        tagsAfterGeo[0] === "ipwho.is",
        JSON.stringify(tagsAfterGeo),
      );

      await page.waitForFunction(
        () => document.querySelector('[data-row="ip"] .row-tag')?.textContent.trim() === "ip.sb",
        null,
        { timeout: 5000 },
      );
      const finalTags = await page.evaluate(() => window.__ipSourceTags);
      ok("later higher-quality source upgrades card", finalTags.at(-1) === "ip.sb", JSON.stringify(finalTags));
      await page.close();
    },
  },
  {
    name: "baseline: fixture 环境评分完成且识别机房出口",
    async run({ browser, base, ok }) {
      const page = await browser.newPage();
      const errors = [];
      page.on("pageerror", (e) => errors.push(String(e)));
      await routeFixtures(page, base.origin);
      await page.goto(base.href);
      const score = await waitForScore(page);
      ok("score resolves", Number.isFinite(score), `score=${score}`);
      ok("no page errors", errors.length === 0, errors.join(" | ").slice(0, 200));
      const insights = await page.locator("#score-insights").innerText();
      ok("hosting exit flagged", insights.includes("机房 / VPN 出口"), insights.replace(/\s+/g, " ").slice(0, 60));
      const nodes = await scoreNodeSnapshot(page);
      ok("six score nodes rendered", nodes.length === 6, JSON.stringify(nodes));
      ok(
        "score node ids are stable",
        nodes.map((node) => node.id).join(",") === "ip,identity,leak,conn,ai,multi",
        JSON.stringify(nodes),
      );
      ok(
        "score node labels match the approved A layout",
        nodes.map((node) => node.label).join(",") === "出口 IP,身份,泄漏,网络连通,AI 出口,多源互证",
        JSON.stringify(nodes),
      );
      ok(
        "score nodes expose SVG, status and collapsed aria state",
        nodes.length === 6 &&
          nodes.every(
            (node) =>
              node.hasIcon &&
              node.iconHref === `#score-icon-${node.id}` &&
              node.status &&
              node.expanded === "false" &&
              node.controls === `score-node-tip-${node.id}`,
          ),
        JSON.stringify(nodes),
      );
      const ipNode = nodes.find((node) => node.id === "ip");
      ok("hosting IP node is amber", ipNode?.status === "amber", JSON.stringify(ipNode));
      const connectors = await page.locator("#score-nodes > svg, #score-nodes > .score-connector").count();
      ok("score nodes have no connector lines", connectors === 0, `count=${connectors}`);
      await page.close();
    },
  },
  {
    name: "A 方案评分节点：单气泡交互与移动端无横向溢出",
    async run({ browser, base, ok }) {
      const page = await browser.newPage({ viewport: { width: 390, height: 844 } });
      await routeFixtures(page, base.origin, {
        ipDelays: { "ipwho.is": 800, "api.ip.sb": 1600, "ipinfo.io": 2400 },
      });
      await page.goto(base.href);
      const identity = page.locator('[data-score-segment="identity"]');
      const ip = page.locator('[data-score-segment="ip"]');
      await identity.waitFor({ state: "visible" });
      await identity.hover();
      await page.waitForTimeout(220);
      await page.evaluate(() => {
        const probe = { renders: 0, frames: 0, hiddenFrames: 0, done: false };
        window.__scoreHoverProbe = probe;
        new MutationObserver(() => {
          probe.renders += 1;
        }).observe(document.querySelector("#section-root"), { childList: true });
        const sample = () => {
          const node = document.querySelector('[data-score-segment="identity"]');
          const tip = node?.querySelector(".score-node-tip");
          const style = tip ? getComputedStyle(tip) : null;
          probe.frames += 1;
          if (
            !node ||
            node.getAttribute("aria-expanded") !== "true" ||
            !style ||
            style.visibility !== "visible" ||
            Number(style.opacity) < 0.9
          ) {
            probe.hiddenFrames += 1;
          }
          if (!probe.done) requestAnimationFrame(sample);
        };
        requestAnimationFrame(sample);
      });
      await page.waitForFunction(() => window.__scoreHoverProbe?.renders >= 1, null, { timeout: 10000 });
      await page.waitForTimeout(250);
      const hoverProbe = await page.evaluate(() => {
        window.__scoreHoverProbe.done = true;
        return window.__scoreHoverProbe;
      });
      ok(
        "hover tooltip stays continuously visible across async score renders",
        hoverProbe.renders >= 1 && hoverProbe.frames > 0 && hoverProbe.hiddenFrames === 0,
        JSON.stringify(hoverProbe),
      );

      await ip.click();
      await identity.hover();
      await page.waitForTimeout(220);
      const rendersBeforePinnedHover = await page.evaluate(() => window.__scoreHoverProbe.renders);
      await page.waitForFunction(
        (before) => window.__scoreHoverProbe?.renders > before,
        rendersBeforePinnedHover,
        { timeout: 10000 },
      );
      const openDuringPinnedHover = await page.locator('.score-node[aria-expanded="true"]').evaluateAll((nodes) =>
        nodes.map((node) => node.dataset.scoreSegment),
      );
      ok(
        "hovered node remains the only open tooltip while another node is pinned and scores update",
        openDuringPinnedHover.join(",") === "identity",
        openDuringPinnedHover.join(",") || "none",
      );
      await page.locator("#score-title").hover();
      await page.waitForTimeout(220);
      const restoredPinned = await page.locator('.score-node[aria-expanded="true"]').evaluateAll((nodes) =>
        nodes.map((node) => ({ id: node.dataset.scoreSegment, pinned: node.classList.contains("is-pinned") })),
      );
      ok(
        "leaving the transient tooltip restores the pinned tooltip",
        restoredPinned.length === 1 && restoredPinned[0].id === "ip" && restoredPinned[0].pinned,
        JSON.stringify(restoredPinned),
      );

      const ai = page.locator('[data-score-segment="ai"]');
      await ai.focus();
      await identity.hover();
      await page.locator("#score-title").hover();
      await page.waitForTimeout(220);
      const restoredFocus = await page.locator('.score-node[aria-expanded="true"]').evaluateAll((nodes) =>
        nodes.map((node) => ({ id: node.dataset.scoreSegment, pinned: node.classList.contains("is-pinned") })),
      );
      ok(
        "leaving a hovered node restores the focused node before the pinned node",
        restoredFocus.length === 1 && restoredFocus[0].id === "ai" && !restoredFocus[0].pinned,
        JSON.stringify(restoredFocus),
      );
      await page.locator("#privacy-toggle").focus();
      await page.waitForTimeout(220);
      const restoredAfterBlur = await page.locator('.score-node[aria-expanded="true"]').evaluateAll((nodes) =>
        nodes.map((node) => ({ id: node.dataset.scoreSegment, pinned: node.classList.contains("is-pinned") })),
      );
      ok(
        "blurring the focused score node falls back to the pinned tooltip",
        restoredAfterBlur.length === 1 && restoredAfterBlur[0].id === "ip" && restoredAfterBlur[0].pinned,
        JSON.stringify(restoredAfterBlur),
      );

      await identity.focus();
      const rendersBeforeFocus = await page.evaluate(() => window.__scoreHoverProbe.renders);
      await page.waitForFunction(
        (before) => window.__scoreHoverProbe?.renders > before,
        rendersBeforeFocus,
        { timeout: 10000 },
      );
      const focusAfterRender = await page.evaluate(() => document.activeElement?.dataset?.scoreSegment || "");
      ok("score-node focus survives an async result re-render", focusAfterRender === "identity", focusAfterRender || "BODY");
      await identity.press("Escape");
      await waitForScore(page);
      const scoreNodes = page.locator("#score-nodes .score-node");
      const count = await scoreNodes.count();
      ok("mobile renders all six nodes", count === 6, `count=${count}`);
      if (count !== 6) {
        await page.close();
        return;
      }
      await ip.click();
      ok("click pins one tooltip", (await ip.getAttribute("aria-expanded")) === "true");
      await page.waitForTimeout(220);
      const ipTip = await ip.locator(".score-node-tip").evaluate((tip) => {
        const rect = tip.getBoundingClientRect();
        const style = getComputedStyle(tip);
        return {
          visible: style.visibility === "visible" && Number(style.opacity) > 0.9,
          inViewport: rect.left >= 0 && rect.right <= innerWidth && rect.top >= 0 && rect.bottom <= innerHeight,
        };
      });
      ok("pinned tooltip is visibly rendered inside the viewport", ipTip.visible && ipTip.inViewport, JSON.stringify(ipTip));
      await identity.focus();
      const openAfterFocus = await page.locator('.score-node[aria-expanded="true"]').count();
      ok(
        "focus keeps only one tooltip open",
        openAfterFocus === 1 && (await identity.getAttribute("aria-expanded")) === "true",
        `open=${openAfterFocus}`,
      );
      await identity.press("Escape");
      await page.waitForTimeout(220);
      const openAfterEscape = await page.locator('.score-node[aria-expanded="true"]').count();
      const visibleAfterEscape = await page.locator(".score-node-tip").evaluateAll((tips) =>
        tips.filter((tip) => {
          const style = getComputedStyle(tip);
          return style.visibility === "visible" || Number(style.opacity) > 0;
        }).length,
      );
      const focusAfterEscape = await page.evaluate(() => document.activeElement?.dataset?.scoreSegment || "");
      ok(
        "Escape closes every tooltip and keeps focus on its trigger",
        openAfterEscape === 0 && visibleAfterEscape === 0 && focusAfterEscape === "identity",
        `open=${openAfterEscape}, visible=${visibleAfterEscape}, focus=${focusAfterEscape || "BODY"}`,
      );

      await page.setViewportSize({ width: 300, height: 700 });
      const narrowAudit = [];
      for (const id of ["ip", "identity", "leak", "conn", "ai", "multi"]) {
        const node = page.locator(`[data-score-segment="${id}"]`);
        await node.click();
        await page.waitForTimeout(220);
        narrowAudit.push(
          await node.locator(".score-node-tip").evaluate((tip, segment) => {
            const rect = tip.getBoundingClientRect();
            const style = getComputedStyle(tip);
            return {
              id: segment,
              visible: style.visibility === "visible" && Number(style.opacity) > 0.9,
              inViewport: rect.left >= 0 && rect.right <= innerWidth && rect.top >= 0 && rect.bottom <= innerHeight,
              overflow: document.documentElement.scrollWidth - innerWidth,
            };
          }, id),
        );
      }
      ok(
        "300px layout keeps every active tooltip visible without horizontal overflow",
        narrowAudit.every((item) => item.visible && item.inViewport && item.overflow <= 0),
        JSON.stringify(narrowAudit),
      );
      await page.close();
    },
  },
  {
    name: "IP 重测失败：旧机房扣分撤销、改按未测出计（delta 恰为 +14）",
    async run({ browser, base, ok }) {
      const flags = {};
      const page = await browser.newPage();
      await routeFixtures(page, base.origin, { flags });
      await page.goto(base.href);
      const before = await waitForScore(page);
      flags.blockIpSources = true;
      await page.click('[data-row="ip"]');
      await page.click('[data-action="run-ip"]');
      await page.waitForFunction(
        () => {
          const el = document.querySelector('[data-row-wrap="ip"] .row-value');
          return el && el.textContent.includes("无法读取");
        },
        null,
        { timeout: 30000 },
      );
      const after = await waitForScore(page, 20000);
      // 机房 -22 撤销、未测出 -8 生效：分数应精确上升 14
      ok("score delta is exactly +14", after - before === 14, `${before} -> ${after}`);
      const insights = await page.locator("#score-insights").innerText();
      ok(
        "no stale hosting/CN chips",
        !insights.includes("机房 / VPN 出口") && !insights.includes("出口 IP 在中国"),
        insights.replace(/\s+/g, " ").slice(0, 80),
      );
      ok("未测出 chip present", insights.includes("出口 IP 未完整测出"));
      await page.close();
    },
  },
  {
    name: "WebRTC 残留：IP 重测失败后重核候选，泄漏扣分撤销（delta 恰为 +26）",
    async run({ browser, base, ok }) {
      const flags = {};
      const page = await browser.newPage();
      await page.addInitScript(FAKE_WEBRTC_INIT);
      await routeFixtures(page, base.origin, { flags });
      await page.goto(base.href);
      const before = await waitForScore(page);
      const webrtcBefore = await page.locator('[data-row="webrtc"] .row-value').innerText();
      ok("baseline flags WebRTC leak", webrtcBefore.includes("发现出口外公网候选"), webrtcBefore);
      const leakNodeBefore = await page.locator('[data-score-segment="leak"]').getAttribute("data-status");
      ok("WebRTC leak marks the leak node red", leakNodeBefore === "red", String(leakNodeBefore));
      flags.blockIpSources = true;
      await page.click('[data-row="ip"]');
      await page.click('[data-action="run-ip"]');
      await page.waitForFunction(
        () => {
          const el = document.querySelector('[data-row-wrap="ip"] .row-value');
          return el && el.textContent.includes("无法读取");
        },
        null,
        { timeout: 30000 },
      );
      const after = await waitForScore(page, 20000);
      // 机房 -22 → 未测出 -8（+14），WebRTC 泄漏 -12 → 待核对 0（+12）：恰 +26
      ok("score delta is exactly +26", after - before === 26, `${before} -> ${after}`);
      const webrtcAfter = await page.locator('[data-row="webrtc"] .row-value').innerText();
      ok("WebRTC re-verified to 待出口 IP 核对", webrtcAfter.includes("待出口 IP 核对"), webrtcAfter);
      await page.close();
    },
  },
  {
    name: "过期展示回写：重测时在途的旧互证响应不得回写已清空的表格",
    async run({ browser, base, ok }) {
      const flags = {};
      const page = await browser.newPage();
      // iplocation.net 只被互证使用（runIP 不用它），延迟 6s 制造在途旧请求
      await routeFixtures(page, base.origin, { flags, ipDelays: { "iplocation.net": 6000 } });
      await page.goto(base.href);
      // 等互证其余 7 个源写入表格（iplocation 仍在途）
      await page.waitForFunction(
        () => document.querySelector("#sec-multi") && document.querySelector("#sec-multi").textContent.includes("United States"),
        null,
        { timeout: 20000 },
      );
      flags.blockIpSources = true;
      await page.click('[data-row="ip"]');
      await page.click('[data-action="run-ip"]');
      await page.waitForFunction(
        () => {
          const el = document.querySelector('[data-row-wrap="ip"] .row-value');
          return el && el.textContent.includes("无法读取");
        },
        null,
        { timeout: 30000 },
      );
      // 等待在途的 iplocation 响应（约 6s 后到达）尝试回写
      await sleep(9000);
      const tableText = await page.locator("#sec-multi").innerText();
      ok(
        "stale self-check response did not repopulate the cleared table",
        !tableText.includes("United States"),
        tableText.replace(/\s+/g, " ").slice(0, 100),
      );
      await page.close();
    },
  },
  {
    name: "IP 重测成功：互证用最新 IP 重跑",
    async run({ browser, base, ok }) {
      const page = await browser.newPage();
      const iplocationUrls = [];
      page.on("request", (r) => {
        if (r.url().includes("api.iplocation.net")) iplocationUrls.push(r.url());
      });
      await routeFixtures(page, base.origin);
      await page.goto(base.href);
      await waitForScore(page);
      const countBefore = iplocationUrls.length;
      await page.click('[data-row="ip"]');
      await page.click('[data-action="run-ip"]');
      // runIP 成功 → idle 2.6s 后互证重跑
      await sleep(9000);
      const fresh = iplocationUrls.slice(countBefore);
      ok("multi self-check re-runs after retest", fresh.length > 0, `${countBefore} -> ${iplocationUrls.length}`);
      ok(
        "re-run targets the latest IP",
        fresh.some((u) => u.includes(FIXTURE_IPV4)),
        fresh[fresh.length - 1] || "no request",
      );
      await page.close();
    },
  },
  {
    name: "双栈切换：首个 IPv6 结果被聚合 IPv4 取代后，互证仍按本机跑、评分不卡死",
    async run({ browser, base, ok }) {
      const page = await browser.newPage();
      const iplocationUrls = [];
      page.on("request", (r) => {
        if (r.url().includes("api.iplocation.net")) iplocationUrls.push(r.url());
      });
      await routeFixtures(page, base.origin, {
        ipv6First: true,
        // 其余 IP 源延迟 3.5s（晚于 2.6s 的互证 idle）：
        // 首个结果 IPv6 → idle 用 IPv6 启动互证 → 聚合把主 IP 切为 IPv4，
        // 必须触发“作废旧互证并用新 IP 重跑”，否则评分卡死或沿用旧 IP。
        ipDelays: {
          "ipwho.is": 3500,
          "ip.sb": 3500,
          "ipinfo.io": 3500,
          "geojs.io": 3500,
          "db-ip.com": 3500,
          "ipapi.is": 3500,
          "country.is": 3500,
          "api.ipify.org": 3500,
          "api64.ipify.org": 3500,
          "iplocation.net": 0,
        },
      });
      await page.goto(base.href);
      let score = NaN;
      try {
        score = await waitForScore(page, 60000);
      } catch {
        /* 卡死则 score 保持 NaN */
      }
      ok("score resolves (not stuck at 检测中)", Number.isFinite(score), `score=${score}`);
      // 顺序必须是：先用首个 IPv6 启动互证，聚合切换后再用 IPv4 重跑
      const v6Index = iplocationUrls.findIndex((u) => u.includes(encodeURIComponent(FIXTURE_IPV6)));
      const v4Index = iplocationUrls.findIndex((u) => u.includes(FIXTURE_IPV4));
      ok(
        "self-check ordered IPv6 first, then re-run with final IPv4",
        v6Index >= 0 && v4Index > v6Index,
        `v6@${v6Index}, v4@${v4Index} of ${iplocationUrls.length}`,
      );
      await page.close();
    },
  },
  {
    name: "任意 IP 查询：仅供参考、不改评分",
    async run({ browser, base, ok }) {
      const page = await browser.newPage();
      await routeFixtures(page, base.origin);
      await page.goto(base.href);
      const before = await waitForScore(page);
      await page.fill("#multi-ip", "9.9.9.9");
      await page.click('[data-action="run-multi"]');
      await sleep(2500);
      const summary = await page.locator("#sec-multi .summary-line").innerText();
      const after = await waitForScore(page);
      ok("reference-only note shown", summary.includes("不参与"), summary.slice(0, 60));
      ok("score unchanged", before === after, `${before} -> ${after}`);
      await page.close();
    },
  },
  {
    name: "输入框焦点：Enter 触发的连续重渲染后焦点与光标保留",
    async run({ browser, base, ok }) {
      const page = await browser.newPage();
      await routeFixtures(page, base.origin);
      await page.goto(base.href);
      await waitForScore(page);
      await page.focus("#multi-ip");
      await page.keyboard.type(FIXTURE_IPV4);
      await page.keyboard.press("Enter"); // runMulti → fixture 秒回 → 多次重渲染
      await sleep(1500);
      const state = await page.evaluate(() => ({
        id: document.activeElement && document.activeElement.id,
        caret: document.activeElement && document.activeElement.selectionStart,
        len: document.activeElement && document.activeElement.value ? document.activeElement.value.length : -1,
      }));
      ok("focus retained", state.id === "multi-ip", `activeElement=${state.id}`);
      ok("caret preserved", state.caret === state.len && state.len > 0, `caret=${state.caret}/${state.len}`);
      await page.close();
    },
  },
  {
    name: "探针 fallback：主请求超时 abort 后的迟到失败不覆盖 fallback 成功",
    async run({ browser, base, ok }) {
      const ctx = await browser.newContext();
      await routeFixtures(ctx, base.origin, { hangOpenaiStatus: true });
      const page = await ctx.newPage();
      await page.goto(base.href);
      const pass = await page
        .waitForFunction(
          () => {
            const card = Array.from(document.querySelectorAll(".conn-card")).find((c) =>
              c.textContent.includes("openai.com"),
            );
            return card && card.textContent.includes("可达");
          },
          null,
          { timeout: 30000 },
        )
        .then(() => true)
        .catch(() => false);
      const cardText = pass
        ? ""
        : (await page.locator(".conn-card").allInnerTexts()).find((c) => c.includes("openai")) || "card missing";
      ok("openai.com resolves via fallback", pass, cardText);
      await ctx.close();
    },
  },
  {
    name: "Windows 模拟：Emoji 中性、评分完成",
    async run({ browser, base, ok }) {
      const ctx = await browser.newContext({
        userAgent:
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36",
      });
      await routeFixtures(ctx, base.origin);
      const page = await ctx.newPage();
      await page.addInitScript(() => {
        Object.defineProperty(navigator, "platform", { get: () => "Win32" });
      });
      await page.goto(base.href);
      let score = NaN;
      try {
        score = await waitForScore(page);
      } catch {
        /* stuck */
      }
      ok("score completes with emoji neutral", Number.isFinite(score), `score=${score}`);
      const emojiRow = await page.locator('[data-row="emoji"] .row-value').innerText();
      ok("emoji row shows 不适用", emojiRow.includes("不适用"), emojiRow);
      await ctx.close();
    },
  },
];

// ---------- 运行器 ----------
async function main() {
  let chromium;
  try {
    ({ chromium } = await import("playwright"));
  } catch {
    console.error("缺少 playwright，请先：npm install && npx playwright install chromium");
    process.exit(2);
  }

  const server = createServer(async (req, res) => {
    let pathname = decodeURIComponent(new URL(req.url, "http://localhost/").pathname);
    if (pathname === "/") pathname = "/index.html";
    const file = resolve(projectRoot, `.${pathname}`);
    if (!file.startsWith(`${projectRoot.replace(/\/$/, "")}${sep}`)) {
      res.writeHead(403).end();
      return;
    }
    try {
      const body = await readFile(file);
      res.writeHead(200, {
        "Content-Type": mimeTypes[extname(file).toLowerCase()] || "application/octet-stream",
      });
      res.end(body);
    } catch {
      res.writeHead(404, { "Content-Type": "text/plain" }).end("Not Found");
    }
  });
  // 动态端口，避免 EADDRINUSE
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const base = new URL(`http://127.0.0.1:${server.address().port}/`);

  let browser;
  const results = [];
  try {
    // 禁用非代理 UDP：真实 STUN 候选会和 fixture 出口 IP 冲突，破坏分数确定性
    browser = await chromium
      .launch({ args: ["--force-webrtc-ip-handling-policy=disable_non_proxied_udp"] })
      .catch((err) => {
        console.error("chromium 启动失败，请先：npx playwright install chromium\n" + err.message);
        process.exit(2);
      });
    for (const scenario of scenarios) {
      console.log(`\n== ${scenario.name}`);
      const ok = (name, pass, extra = "") => {
        results.push({ pass, line: `${pass ? "PASS" : "FAIL"} [${scenario.name}] ${name}${extra ? " — " + extra : ""}` });
        console.log(`  ${pass ? "PASS" : "FAIL"} ${name}${extra ? " — " + extra : ""}`);
      };
      try {
        await scenario.run({ browser, base, ok });
      } catch (err) {
        results.push({ pass: false, line: `FAIL [${scenario.name}] scenario crashed — ${String(err).slice(0, 200)}` });
        console.log(`  FAIL scenario crashed — ${String(err).slice(0, 200)}`);
      }
    }
  } finally {
    await browser?.close().catch(() => {});
    server.close();
  }

  const failed = results.filter((r) => !r.pass);
  console.log(`\n${results.length - failed.length}/${results.length} assertions passed, ${scenarios.length} scenarios`);
  if (failed.length) {
    failed.forEach((f) => console.log(f.line));
    process.exit(1);
  }
}

await main();
