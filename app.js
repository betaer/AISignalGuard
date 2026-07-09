(function () {
  "use strict";

  var RING_CIRCUMFERENCE = 326.726;
  var REPO = "betaer/AISignalGuard";
  var NAV = [
    ["sec-score", "信任分"],
    ["sec-ip", "出口 IP"],
    ["sec-identity", "身份信号"],
    ["sec-leak", "网络泄漏"],
    ["sec-conn", "网络连通"],
    ["sec-multi", "多源交叉"],
    ["sec-aipath", "AI 路径"],
    ["sec-aistatus", "AI 状态"],
    ["sec-fp", "浏览器指纹"],
    ["sec-trace", "路由追踪"]
  ];

  var COLORS = {
    green: "oklch(0.58 0.12 148)",
    amber: "oklch(0.66 0.12 78)",
    red: "oklch(0.58 0.16 25)",
    pending: "#b7b7af"
  };

  var SCORE_SEGMENTS = [
    { id: "ip", label: "IP", name: "出口 IP", weight: 35 },
    { id: "identity", label: "身份", name: "身份信号", weight: 18 },
    { id: "leak", label: "泄漏", name: "网络泄漏", weight: 27 },
    { id: "conn", label: "大陆探针", name: "大陆直连探针", weight: 20 },
    { id: "ai", label: "AI出口", name: "AI 路径出口", weight: 15 },
    { id: "multi", label: "互证", name: "多源交叉", weight: 4 }
  ];

  var state = {
    region: "cnhk",
    privacy: false,
    activeId: "sec-score",
    score: 0,
    displayScore: 0,
    renderPaused: false,
    renderScheduled: false,
    renderToken: 0,
    runId: 0,
    analyticsLoaded: false,
    panels: {
      rules: false,
      privacy: false
    },
    open: {
      ip: false,
      consistency: false,
      lang: false,
      tz: false,
      emoji: false,
      font: false,
      webrtc: false,
      dns: false
    },
    rows: {},
    dns: {
      done: false,
      running: false,
      servers: []
    },
    conn: {
      running: true,
      groups: []
    },
    multiIp: "",
    myIp: "",
    exitIps: [],
    multiSummary: "点「查询」用 8 个数据源交叉核对你的出口 IP，或输入任意 IP。",
    multi: [],
    aipath: [],
    aistatus: [],
    fp: [],
    traceTab: 0,
    copied: ""
  };

  var statusText = {
    green: "可信",
    amber: "一般",
    red: "高危",
    pending: "检测中"
  };

  var advice = {
    ip: "优先使用质量稳定的住宅 / 移动网络出口，避免共享机房、廉价 VPN 和多人复用的代理池。出口地区、账号地区和使用习惯要保持一致。",
    consistency: "让 IP、时区、系统语言和浏览器语言指向同一地区。只改其中一项通常会制造更明显的矛盾。",
    lang: "按出口地区调整浏览器首选语言。例如美国出口可使用 en-US / en，香港出口可使用 zh-HK / en-HK。",
    tz: "把系统时区调整到出口 IP 所在城市附近。浏览器通常直接读取系统时区，网页脚本可以看到。",
    emoji: "这只是弱信号。若其他核心项已经一致，Emoji 差异通常不是决定因素。",
    font: "中文字体只是弱来源信号，不等于风险。它需要和出口 IP、语言、时区、DNS 等信号一起看；需要隔离时，用独立浏览器配置文件或远程浏览器环境。",
    webrtc: "浏览器或代理工具里关闭 WebRTC 非代理 UDP，或开启代理软件的 TUN / 全局模式，避免 STUN 直连暴露真实地址。",
    dns: "让 DNS 与代理走同一隧道，开启远程解析 / DoH / TUN，避免使用运营商本地 DNS；必要时关闭 IPv6 或确保 IPv6 DNS 也走代理。"
  };

  var DETECTION_HINTS = [
    "先校准，再判断；单个信号不是结论，组合信号才有意义。",
    "不确定时先标记为未确认，不把浏览器限制误读成安全。",
    "检测只报告浏览器可观察到的事实，证据不足的部分保持留白。",
    "一致性比单项漂亮指标更重要，矛盾信号才最值得警惕。"
  ];

  var CHINESE_FONT_CANDIDATES = [
    "DengXian",
    "FangSong",
    "Microsoft YaHei UI",
    "Microsoft YaHei",
    "SimHei",
    "SimSun",
    "NSimSun",
    "PingFang SC",
    "Hiragino Sans GB",
    "STHeiti",
    "Heiti SC",
    "Songti SC",
    "STSong",
    "Source Han Sans SC",
    "Source Han Serif SC",
    "Noto Sans CJK SC",
    "Noto Serif CJK SC",
    "方正小标宋简体",
    "小标宋体",
    "仿宋_GB2312",
    "HarmonyOS Sans",
    "Alibaba PuHuiTi",
    "Smiley Sans",
    "WenQuanYi Micro Hei"
  ];

  var connTargets = [
    {
      title: "AI 服务",
      sites: [
        {
          host: "claude.ai",
          probeUrl: "https://claude.ai/favicon.ico",
          softFail: true,
          failStatus: "浏览器受限"
        },
        {
          host: "chatgpt.com",
          probeUrl: "https://chatgpt.com/favicon.ico",
          softFail: true,
          failStatus: "浏览器受限"
        },
        {
          host: "openai.com",
          probeUrl: "https://status.openai.com/api/v2/status.json",
          fallbackUrl: "https://openai.com/favicon.ico",
          mode: "cors",
          softFail: true,
          failStatus: "浏览器受限"
        },
        {
          host: "gemini.google.com",
          probeUrl: "https://www.gstatic.com/generate_204",
          fallbackUrl: "https://gemini.google.com/favicon.ico",
          softFail: true,
          failStatus: "浏览器受限"
        }
      ]
    },
    {
      title: "全球站点 · 常被墙",
      sites: [
        { host: "google.com", probeUrl: "https://www.gstatic.com/generate_204" },
        { host: "youtube.com", probeUrl: "https://www.youtube.com/favicon.ico" },
        { host: "x.com", probeUrl: "https://x.com/favicon.ico" },
        { host: "wikipedia.org", probeUrl: "https://www.wikipedia.org/static/favicon/wikipedia.ico" }
      ]
    },
    {
      title: "中国站点",
      sites: [
        { host: "baidu.com", probeUrl: "https://www.baidu.com/favicon.ico", softFail: true, failStatus: "未确认" },
        { host: "qq.com", probeUrl: "https://www.qq.com/favicon.ico", softFail: true, failStatus: "未确认" },
        { host: "taobao.com", probeUrl: "https://www.taobao.com/favicon.ico", softFail: true, failStatus: "未确认" },
        { host: "bilibili.com", probeUrl: "https://www.bilibili.com/favicon.ico", softFail: true, failStatus: "未确认" }
      ]
    }
  ];

  var aiTargets = [
    { name: "Cloudflare 基准", host: "cloudflare.com" },
    { name: "ChatGPT", host: "chatgpt.com" },
    { name: "OpenAI Platform", host: "platform.openai.com" },
    { name: "Claude", host: "claude.ai" },
    { name: "Anthropic Console", host: "console.anthropic.com" },
    { name: "Perplexity", host: "www.perplexity.ai" }
  ];

  var statusTargets = [
    {
      name: "Anthropic / Claude",
      url: "https://status.claude.com/api/v2/status.json",
      page: "https://status.claude.com"
    },
    {
      name: "OpenAI / ChatGPT",
      url: "https://status.openai.com/api/v2/status.json",
      page: "https://status.openai.com"
    }
  ];

  var traceTabs = [
    {
      name: "🍎 macOS",
      commands: [
        ["① 安装 mtr", "brew install mtr"],
        ["② 运行（推荐）", "sudo mtr -rwzbc 20 claude.ai"]
      ]
    },
    {
      name: "▣ Windows",
      commands: [
        ["① 系统自带", "tracert claude.ai"],
        ["② PowerShell", "Test-NetConnection claude.ai -TraceRoute"]
      ]
    },
    {
      name: "🐧 Ubuntu / Debian",
      commands: [
        ["① 安装", "sudo apt install -y mtr traceroute"],
        ["② 运行（推荐）", "sudo mtr -rwzbc 20 claude.ai"]
      ]
    }
  ];

  var traceFakeIpRanges = [
    ["198.18.0.0/15", "最常见 Fake-IP，代理会把域名映射到这个测试网段"],
    ["198.19.0.0/16", "198.18 扩展，用于更大的 Fake-IP 池"],
    ["240.0.0.0/4", "保留 / 实验地址，部分代理作为 Fake-IP 使用"],
    ["192.0.0.0/24", "特殊用途地址，不应当当作真实公网出口"],
    ["100.64.0.0/10", "CGNAT 共享地址，常见于运营商或中转网络"],
    ["10.0.0.0/8", "私网地址，只代表本地网络、容器、网关或隧道内部"],
    ["172.16.0.0/12", "私网地址，只代表本地网络、容器、网关或隧道内部"],
    ["192.168.0.0/16", "私网地址，只代表本地网络、家庭路由或隧道内部"]
  ];

  function $(selector) {
    return document.querySelector(selector);
  }

  function escapeHtml(value) {
    return String(value == null ? "" : value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  function highlightRiskText(value) {
    var chinaPattern =
      /(中国大陆|中国口径内|中国口径|中国解析器|中国出口|大陆直连|大陆探针|港澳|香港|澳门|大陆|中国|Hong Kong|Hongkong|Macao|Macau|China(?:\s+(?:Telecom|Unicom|Mobile))?|Chinanet|PRC|Asia\/(?:Shanghai|Urumqi|Chongqing|Harbin|Kashgar|Beijing|Hong_Kong|Macau)|\b(?:CN|HK|MO|AS4134|AS4837|AS9808)\b|\bzh(?!-)\b|\bzh-(?:CN|HK|MO|Hans|Hans-CN|Hant-HK|Hant-MO|Yue)\b|电信|联通|移动|广电|教育网)/gi;
    return escapeHtml(value)
      .replace(/(矛盾|异常)/g, '<strong class="risk-emphasis">$1</strong>')
      .replace(chinaPattern, '<strong class="china-emphasis">$1</strong>');
  }

  function highlightSummaryText(value) {
    if (/未发现|未检出|未命中/.test(value || "")) {
      return escapeHtml(value);
    }
    return highlightRiskText(value);
  }

  function statusClass(status) {
    return ["green", "amber", "red"].indexOf(status) >= 0 ? status : "pending";
  }

  function setRow(id, patch) {
    var current = state.rows[id] || {};
    state.rows[id] = Object.assign(
      {
        status: "pending",
        value: "检测中…",
        detail: "",
        tag: "",
        advice: advice[id] || ""
      },
      current,
      patch
    );
    recompute();
    if (!state.renderPaused) {
      render();
    }
  }

  function withBatchedRender(fn, immediate) {
    state.renderPaused = true;
    try {
      fn();
    } finally {
      state.renderPaused = false;
      if (immediate) {
        renderImmediate();
      } else {
        render();
      }
    }
  }

  function setPendingRows() {
    [
      "ip",
      "consistency",
      "lang",
      "tz",
      "emoji",
      "font",
      "webrtc",
      "dns"
    ].forEach(function (id) {
      state.rows[id] = {
        status: "pending",
        value: id === "dns" ? "等待自动检测…" : "检测中…",
        detail:
          id === "dns"
            ? "页面稳定后会自动执行标准检测，也可以手动点击标准检测。"
            : "正在读取信号…",
        tag: "",
        advice: advice[id] || ""
      };
    });
    state.dns = {
      done: false,
      running: false,
      servers: []
    };
  }

  function pendingConnGroups() {
    return connTargets.map(function (group) {
      return {
        title: group.title,
        sites: group.sites.map(function (site) {
          return {
            host: site.host,
            code: "pending",
            status: "等待检测"
          };
        })
      };
    });
  }

  function isCurrentRun(runId) {
    return runId === state.runId;
  }

  function staleRunError() {
    var err = new Error("stale run");
    err.stale = true;
    return err;
  }

  function rowReady(id) {
    return Boolean(state.rows[id] && state.rows[id].status !== "pending");
  }

  function connReady() {
    return Boolean(
      state.conn.groups.length &&
        !state.conn.running &&
        state.conn.groups.every(function (group) {
          return group.sites.every(function (site) {
            return site.code !== "pending";
          });
        })
    );
  }

  function aiPathReady() {
    return Boolean(
      state.aipath.length &&
        state.aipath.every(function (item) {
          return item.status !== "pending";
        })
    );
  }

  function multiReady() {
    if (!state.multi.length) {
      return rowReady("ip") && !state.myIp;
    }
    return state.multi.every(function (item) {
      return item.country !== "…" && item.geo !== "查询中";
    });
  }

  function scoreReady() {
    return (
      ["ip", "consistency", "lang", "tz", "emoji", "font", "webrtc", "dns"].every(rowReady) &&
      connReady() &&
      aiPathReady() &&
      multiReady()
    );
  }

  function isChinaCountry(code) {
    var cc = String(code || "").toUpperCase();
    if (state.region === "cnhk") {
      return ["CN", "HK", "MO"].indexOf(cc) >= 0;
    }
    return cc === "CN";
  }

  function isChinaTimezone(timeZone) {
    var zone = String(timeZone || "");
    var mainland = [
      "Asia/Shanghai",
      "Asia/Urumqi",
      "Asia/Chongqing",
      "Asia/Harbin",
      "Asia/Kashgar",
      "Asia/Beijing",
      "PRC"
    ];
    var cnhk = mainland.concat(["Asia/Hong_Kong", "Asia/Macau", "Asia/Macao", "Hongkong", "Macao"]);
    if (!zone || zone === "未知") {
      return false;
    }
    return (state.region === "cnhk" ? cnhk : mainland).indexOf(zone) >= 0;
  }

  function languageRisk(languages) {
    var joined = languages.join(",").toLowerCase();
    var mainlandChinese = function (lang) {
      return /^zh(-hans)?(-cn)?$/i.test(lang);
    };
    if (state.region === "cnhk" && /(zh-hk|zh-mo|zh-hant-hk|zh-yue)/i.test(joined)) {
      return true;
    }
    return languages.some(mainlandChinese);
  }

  function regionLabel() {
    return state.region === "cnhk" ? "中国大陆 / 香港 / 澳门，不含台湾" : "仅中国大陆，不含台湾";
  }

  function isHostingOrg(text) {
    return /hosting|cloud|datacenter|data center|colo|vps|vpn|proxy|server|amazon|aws|google|microsoft|azure|oracle|digitalocean|linode|akamai|ovh|hetzner|vultr|leaseweb|m247|cogent|alibaba|tencent|huawei cloud|cloudflare/i.test(
      text || ""
    );
  }

  function isPrivateIp(ip) {
    var value = String(ip || "").toLowerCase();
    return (
      /^(10\.|127\.|169\.254\.|192\.168\.|192\.0\.0\.|198\.18\.|198\.19\.|172\.(1[6-9]|2\d|3[0-1])\.|::1|fc|fd|fe80)/i.test(
        value
      ) ||
      /^100\.(6[4-9]|[78]\d|9\d|1[01]\d|12[0-7])\./.test(value) ||
      /^(24[0-9]|25[0-5])\./.test(value)
    );
  }

  function isIpv4Address(value) {
    if (!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(value || "")) {
      return false;
    }
    return String(value)
      .split(".")
      .every(function (part) {
        var n = Number(part);
        return n >= 0 && n <= 255;
      });
  }

  function isIpv6Address(value) {
    return /^[a-f0-9:]+$/i.test(value || "") && String(value).indexOf(":") >= 0;
  }

  function isMdnsAddress(value) {
    return /\.local$/i.test(value || "");
  }

  function isPublicNetworkAddress(value) {
    return (isIpv4Address(value) || isIpv6Address(value)) && !isPrivateIp(value);
  }

  function getJson(url, timeoutMs) {
    return new Promise(function (resolve, reject) {
      var controller = new AbortController();
      var timer = window.setTimeout(function () {
        controller.abort();
      }, timeoutMs || 8000);
      fetch(url, {
        cache: "no-store",
        signal: controller.signal
      })
        .then(function (response) {
          if (!response.ok) {
            throw new Error("HTTP " + response.status);
          }
          return response.json();
        })
        .then(resolve)
        .catch(reject)
        .finally(function () {
          window.clearTimeout(timer);
        });
    });
  }

  function getText(url, timeoutMs) {
    return new Promise(function (resolve, reject) {
      var controller = new AbortController();
      var timer = window.setTimeout(function () {
        controller.abort();
      }, timeoutMs || 8000);
      fetch(url, {
        cache: "no-store",
        signal: controller.signal
      })
        .then(function (response) {
          if (!response.ok) {
            throw new Error("HTTP " + response.status);
          }
          return response.text();
        })
        .then(resolve)
        .catch(reject)
        .finally(function () {
          window.clearTimeout(timer);
        });
    });
  }

  function normalizeIpPayload(payload, source) {
    if (!payload) {
      return null;
    }
    var ip = payload.ip || payload.query || payload.ipAddress || payload.client_ip || "";
    var cc =
      payload.country_code ||
      payload.countryCode ||
      payload.countryCode2 ||
      payload.country ||
      payload.country_code2 ||
      payload.countryCodeIso ||
      (payload.location &&
        (payload.location.country_code ||
          (payload.location.country && payload.location.country.code) ||
          payload.location.country)) ||
      (payload.datacenter && payload.datacenter.country) ||
      "";
    if (payload.country && String(payload.country).length === 2) {
      cc = payload.country;
    }
    var country =
      payload.country_name ||
      payload.countryName ||
      (payload.location &&
        payload.location.country &&
        (payload.location.country.name || payload.location.country.code)) ||
      payload.country ||
      payload.country_code ||
      "";
    if (country && typeof country === "object") {
      country = country.name || country.code || "";
    }
    var city = payload.city || payload.region || payload.regionName || payload.stateProv || "";
    if (payload.location) {
      city = payload.location.city || payload.location.region || city;
    }
    var asn =
      payload.asn ||
      payload.as ||
      (payload.asn && payload.asn.asn) ||
      (payload.connection && payload.connection.asn) ||
      (payload.traits && payload.traits.autonomous_system_number) ||
      "";
    if (payload.asn && typeof payload.asn === "object") {
      asn = payload.asn.asn || payload.asn.route || "";
    }
    var org =
      payload.org ||
      payload.isp ||
      (payload.connection && (payload.connection.org || payload.connection.isp)) ||
      payload.organization ||
      payload.company ||
      "";
    if (payload.company && typeof payload.company === "object") {
      org = payload.company.name || payload.company.domain || org;
    }
    if (payload.asn && typeof payload.asn === "object") {
      org = org || payload.asn.org || payload.asn.descr || "";
    }
    var normalizedCc = String(cc || "").toUpperCase();
    var countryText = country || normalizedCc || "";
    var geoOk = Boolean(normalizedCc || (countryText && countryText !== "未知"));
    return {
      source: source,
      ip: ip,
      cc: normalizedCc,
      country: countryText || "未返回地区",
      geo: [city, normalizedCc].filter(Boolean).join(" · ") || "—",
      asn: asn ? String(asn).replace(/^AS/i, "AS") : "—",
      org: org || "—",
      ok: Boolean(ip || normalizedCc || countryText || asn || org),
      geoOk: geoOk
    };
  }

  function runLocalSignals(immediate) {
    withBatchedRender(function () {
      var languages = Array.from(navigator.languages || [navigator.language || ""]);
      var languageFlag = languageRisk(languages);
      setRow("lang", {
        status: languageFlag ? "amber" : "green",
        value: languages.filter(Boolean).join(" · ") || "未知",
        detail:
          "浏览器会把首选语言发送给大部分网站。当前采用 AI Signal Guard 兼容口径：" +
          regionLabel() +
          "。语言不一定代表真实地区，但它和出口 IP、账号资料不一致时，会成为画像矛盾。"
      });

      var timeZone = "未知";
      try {
        timeZone = Intl.DateTimeFormat().resolvedOptions().timeZone || "未知";
      } catch (err) {
        timeZone = "未知";
      }
      var tzFlag = isChinaTimezone(timeZone);
      setRow("tz", {
        status: tzFlag ? "amber" : "green",
        value: timeZone,
        detail:
          "网页可以读取系统时区。当前风险口径只包含中国大陆、香港、澳门，不包含台湾；Asia/Taipei / ROC 不按风险时区处理。若出口 IP 在境外，但时区仍指向当前中国口径内地区，风控会看到明显矛盾。"
      });

      var emoji = detectEmoji();
      setRow("emoji", {
        status: emoji.flag === true ? "amber" : emoji.flag === null ? "pending" : "green",
        value: emoji.value,
        detail:
          "AI Signal Guard 兼容逻辑会先用 😀 确认彩色 Emoji 可用，再看 🇹🇼 是否被渲染为黑白字母或完全不渲染。Windows 不适用，Canvas 被保护时也不误报。\n" +
          emoji.detail
      });

      var fonts = detectFonts();
      var fontGroups = compactFontHits(fonts.hit);
      setRow("font", {
        status: fonts.hit.length ? "amber" : "green",
        value: fontGroups.labels.length ? "检测到：" + fontGroups.labels.join(" · ") : "未检测到候选中文字体",
        detail:
          fontGroups.detail +
          "\n字体探测通过文字宽度差异判断本机是否存在候选字体，并把同类字体合并显示；未命中的候选字体不会列出。中文字体不是风险本身，但黑体类和宋体类是大陆系统常见弱来源信号。"
      });

      state.fp = collectFingerprint();
    }, immediate);
    updateAudioFingerprint();
  }

  function detectEmoji() {
    if (isWindows()) {
      return {
        flag: null,
        value: "Windows 不适用",
        detail: "Windows 对国旗 Emoji 的支持策略不同，AI Signal Guard 不用此项判断。"
      };
    }
    try {
      var control = getCharColors("😀");
      if (control.opaquePixelCount === 0 || control.isMono) {
        return {
          flag: null,
          value: "无法判断",
          detail: "普通 Emoji 未彩色渲染，可能是系统缺少彩色 Emoji 字体或浏览器开启了指纹保护。"
        };
      }
      var flag = getCharColors("🇹🇼");
      if (flag.opaquePixelCount === 0) {
        return {
          flag: true,
          value: "旗帜未渲染",
          detail: "普通 Emoji 正常，但 🇹🇼 完全不渲染，符合 AI Signal Guard 的大陆设备弱特征。"
        };
      }
      if (flag.isMono) {
        return {
          flag: true,
          value: "旗帜黑白回退",
          detail: "普通 Emoji 正常，但 🇹🇼 渲染为黑白字母回退，符合 AI Signal Guard 的大陆设备弱特征。"
        };
      }
      return {
        flag: false,
        value: "旗帜彩色渲染",
        detail: "普通 Emoji 与 🇹🇼 旗帜均可彩色渲染，未命中大陆设备弱特征。"
      };
    } catch (err) {
      return {
        flag: null,
        value: "Canvas 不可读",
        detail: "Canvas 不可用或读取被浏览器保护拦截，按无法判断处理。"
      };
    }
  }

  function isWindows() {
    if (navigator.platform && navigator.platform.indexOf("Win") === 0) {
      return true;
    }
    return /Windows/i.test(navigator.userAgent || "");
  }

  function getCharColors(char) {
    var canvas = document.createElement("canvas");
    var fontSize = 100;
    canvas.width = fontSize;
    canvas.height = fontSize;
    var ctx = canvas.getContext("2d");
    if (!ctx) {
      throw new Error("Canvas context not supported");
    }
    ctx.textBaseline = "top";
    ctx.font = fontSize + "px sans-serif";
    ctx.fillStyle = "black";
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    ctx.fillText(char, 0, 0);
    var data = ctx.getImageData(0, 0, canvas.width, canvas.height).data;
    var colorSet = {};
    var isMono = true;
    var opaquePixelCount = 0;
    for (var i = 0; i < data.length; i += 4) {
      var r = data[i];
      var g = data[i + 1];
      var b = data[i + 2];
      var a = data[i + 3];
      if (a > 0) {
        opaquePixelCount += 1;
        colorSet[r + "," + g + "," + b] = true;
        if (isMono && !(r === g && g === b)) {
          isMono = false;
        }
      }
    }
    canvas.remove();
    return {
      colors: Object.keys(colorSet),
      isMono: isMono,
      opaquePixelCount: opaquePixelCount
    };
  }

  function detectFonts() {
    var canvas = document.createElement("canvas");
    var ctx = canvas.getContext("2d");
    if (!ctx) {
      return {
        hit: []
      };
    }
    var hit = [];
    CHINESE_FONT_CANDIDATES.forEach(function (font) {
      if (isFontAvailable(ctx, font)) {
        hit.push(font);
      }
    });
    canvas.remove();
    return {
      hit: hit
    };
  }

  function compactFontHits(hit) {
    var groups = [];
    var notes = [];
    var used = {};
    function hasAny(names) {
      var found = false;
      names.forEach(function (name) {
        if (hit.indexOf(name) >= 0) {
          used[name] = true;
          found = true;
        }
      });
      return found;
    }
    if (
      hasAny([
        "Microsoft YaHei",
        "SimHei",
        "PingFang SC",
        "Hiragino Sans GB",
        "STHeiti",
        "Heiti SC",
        "Source Han Sans SC",
        "Noto Sans CJK SC",
        "HarmonyOS Sans",
        "Alibaba PuHuiTi",
        "WenQuanYi Micro Hei"
      ])
    ) {
      groups.push("HeiTi");
      notes.push("HeiTi（黑体 / 苹方 / 微软雅黑等）");
    }
    if (hasAny(["Songti SC", "STSong", "Source Han Serif SC", "Noto Serif CJK SC"])) {
      groups.push("SongTi");
      notes.push("SongTi（宋体类）");
    }
    hit.forEach(function (font) {
      if (!used[font] && groups.indexOf(font) < 0) {
        groups.push(font);
        notes.push(font);
      }
    });
    return {
      labels: groups,
      detail: groups.length ? "命中类别：" + notes.join(" / ") + "。" : "未检测到候选中文字体。"
    };
  }

  function isFontAvailable(ctx, font) {
    var baseFonts = ["monospace", "sans-serif", "serif"];
    var sample = "mmmmmmmmmmlli中文测试";
    return baseFonts.some(function (baseFont) {
      ctx.font = "72px " + baseFont;
      var baseWidth = ctx.measureText(sample).width;
      ctx.font = '72px "' + font + '", ' + baseFont;
      var fontWidth = ctx.measureText(sample).width;
      return fontWidth !== baseWidth;
    });
  }

  function collectFingerprint() {
    var nav = window.navigator;
    var screenInfo = window.screen || {};
    var canvasHash = getCanvasHash();
    var languages = Array.from(nav.languages || [nav.language || ""]).filter(Boolean);
    var dpr = window.devicePixelRatio || 1;
    return [
      { key: "UserAgent", value: nav.userAgent || "未知", sensitive: true, wide: true },
      { key: "平台 Platform", value: nav.platform || "未知" },
      {
        key: "屏幕",
        value:
          (screenInfo.width || "?") +
          "x" +
          (screenInfo.height || "?") +
          " @" +
          dpr +
          "x · " +
          (screenInfo.colorDepth || "?") +
          "bit"
      },
      { key: "CPU 核心", value: nav.hardwareConcurrency ? nav.hardwareConcurrency + " 核" : "未知" },
      { key: "设备内存", value: nav.deviceMemory ? nav.deviceMemory + " GB" : "未知" },
      { key: "语言", value: languages.join(", ") || "未知" },
      { key: "时区", value: Intl.DateTimeFormat().resolvedOptions().timeZone || "未知" },
      { key: "Canvas 指纹", value: canvasHash, sensitive: true },
      { key: "声纹指纹", value: "计算中", sensitive: true, id: "audio" }
    ];
  }

  function updateAudioFingerprint() {
    getAudioHash().then(function (hash) {
      state.fp = state.fp.map(function (item) {
        if (item.id !== "audio") {
          return item;
        }
        return Object.assign({}, item, {
          value: hash
        });
      });
      render();
    });
  }

  function getAudioHash() {
    return new Promise(function (resolve) {
      var OfflineAudio = window.OfflineAudioContext || window.webkitOfflineAudioContext;
      if (!OfflineAudio) {
        resolve("不可用");
        return;
      }
      try {
        var context = new OfflineAudio(1, 5000, 44100);
        var oscillator = context.createOscillator();
        var compressor = context.createDynamicsCompressor();
        oscillator.type = "triangle";
        oscillator.frequency.value = 10000;
        compressor.threshold.value = -50;
        compressor.knee.value = 40;
        compressor.ratio.value = 12;
        compressor.attack.value = 0;
        compressor.release.value = 0.25;
        oscillator.connect(compressor);
        compressor.connect(context.destination);
        oscillator.start(0);
        oscillator.stop(0.12);
        context
          .startRendering()
          .then(function (buffer) {
            var data = buffer.getChannelData(0);
            var samples = [];
            for (var i = 4500; i < data.length; i += 8) {
              samples.push(data[i].toFixed(6));
            }
            resolve(simpleHash(samples.join(",")));
          })
          .catch(function () {
            resolve("读取失败");
          });
      } catch (err) {
        resolve("读取失败");
      }
    });
  }

  function getWebglInfo() {
    try {
      var canvas = document.createElement("canvas");
      var gl = canvas.getContext("webgl") || canvas.getContext("experimental-webgl");
      if (!gl) {
        return "不可用";
      }
      var debug = gl.getExtension("WEBGL_debug_renderer_info");
      if (!debug) {
        return "可用，调试扩展关闭";
      }
      return (
        gl.getParameter(debug.UNMASKED_VENDOR_WEBGL) +
        " · " +
        gl.getParameter(debug.UNMASKED_RENDERER_WEBGL)
      );
    } catch (err) {
      return "读取失败";
    }
  }

  function getCanvasHash() {
    try {
      var canvas = document.createElement("canvas");
      canvas.width = 320;
      canvas.height = 96;
      var ctx = canvas.getContext("2d");
      ctx.fillStyle = "#f7f7f5";
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.fillStyle = "#1a1a18";
      ctx.font = "16px -apple-system, BlinkMacSystemFont, sans-serif";
      ctx.fillText("AI Signal Guard 指纹样本 2026", 18, 24);
      ctx.strokeStyle = "#7aa981";
      ctx.arc(88, 58, 18, 0, Math.PI * 1.72);
      ctx.stroke();
      return simpleHash(canvas.toDataURL());
    } catch (err) {
      return "读取失败";
    }
  }

  function simpleHash(text) {
    var hash = 2166136261;
    for (var i = 0; i < text.length; i += 1) {
      hash ^= text.charCodeAt(i);
      hash += (hash << 1) + (hash << 4) + (hash << 7) + (hash << 8) + (hash << 24);
    }
    return ("00000000" + (hash >>> 0).toString(16)).slice(-8);
  }

  function runIP() {
    var runId = state.runId;
    state.myIp = "";
    state.exitIps = [];
    setRow("ip", {
      status: "pending",
      value: "检测中…",
      detail: "正在读取出口 IP 情报…"
    });
    var sources = [
      function () {
        return getJson("https://ipwho.is/", 7000).then(function (payload) {
          return normalizeIpPayload(payload, "ipwho.is");
        });
      },
      function () {
        return getJson("https://api.ip.sb/geoip", 7000).then(function (payload) {
          return normalizeIpPayload(payload, "ip.sb");
        });
      },
      function () {
        return getJson("https://ipinfo.io/json", 7000).then(function (payload) {
          return normalizeIpPayload(payload, "ipinfo.io");
        });
      },
      function () {
        return getJson("https://get.geojs.io/v1/ip/geo.json", 7000).then(function (payload) {
          return normalizeIpPayload(payload, "geojs.io");
        });
      },
      function () {
        return getJson("https://api.db-ip.com/v2/free/self", 7000).then(function (payload) {
          return normalizeIpPayload(payload, "db-ip.com");
        });
      },
      function () {
        return getJson("https://api.ipapi.is/", 7000).then(function (payload) {
          return normalizeIpPayload(payload, "ipapi.is");
        });
      },
      function () {
        return getJson("https://api.country.is/", 7000).then(function (payload) {
          return normalizeIpPayload(payload, "country.is");
        });
      },
      function () {
        return getJson("https://api.ipify.org?format=json", 7000).then(function (payload) {
          return normalizeIpPayload(payload, "ipify.org");
        });
      },
      function () {
        return getJson("https://api64.ipify.org?format=json", 7000).then(function (payload) {
          return normalizeIpPayload(payload, "ipify64.org");
        });
      },
      function () {
        return getJson("https://api6.ipify.org?format=json", 7000).then(function (payload) {
          return normalizeIpPayload(payload, "ipify6.org");
        });
      }
    ];
    var multiStarted = false;
    var lastAppliedKey = "";

    function maybeRunMulti(ip) {
      if (multiStarted || !ip) {
        return;
      }
      multiStarted = true;
      scheduleIdle(function () {
        if (isCurrentRun(runId) && !state.multi.length) {
          runMulti(ip);
        }
      }, 2600);
    }

    function applyIpResults(results) {
      if (!isCurrentRun(runId)) {
        return false;
      }
      var ipResults = uniqueIpResults(results);
      var result = ipResults[0] || results[0];
      if (!result || !result.ok || !result.ip) {
        return false;
      }
      var appliedKey = ipResults
        .map(function (item) {
          return item.source + ":" + item.ip;
        })
        .join("|");
      if (appliedKey && appliedKey === lastAppliedKey) {
        return true;
      }
      lastAppliedKey = appliedKey;
      state.myIp = result.ip || "";
      state.exitIps = ipResults;
      var orgText = [result.org, result.asn].join(" ");
      var hasGeo = Boolean(result.cc || (result.country && result.country !== "未知"));
      var cn = isChinaCountry(result.cc);
      var host = isHostingOrg(orgText);
      var status = !hasGeo ? "amber" : cn ? "red" : host ? "amber" : "green";
      var value = formatExitIpHeadline(ipResults, result);
      var detail =
        "出口 IP 是平台最先看到的信号。中国大陆 / 港澳口径由上方切换决定；机房、云厂商、VPN 和代理池会被视为中风险。\n出口 IP：\n" +
        formatExitIpHeadline(ipResults, result);
      if (ipResults.length > 1) {
        detail += "\n\n双栈来源明细：\n" + formatExitIpList(ipResults);
      } else {
        detail +=
          "\n地区：" +
          (result.country || result.cc || "未知") +
          "\nASN：" +
          (result.asn || "未知") +
          "\n组织：" +
          (result.org || "未知");
      }
      setRow("ip", {
        status: status,
        value: value,
        tag: result.source,
        country: result.cc,
        isCN: cn,
        host: host,
        ip: result.ip,
        ips: ipResults.map(function (item) {
          return item.ip;
        }),
        org: result.org,
        detail: detail
      });
      recomputeConsistency();
      maybeRunMulti(result.ip || "");
      return true;
    }

    var probes = sources.map(function (task) {
      return task()
        .then(function (result) {
          return result && result.ok ? result : null;
        })
        .catch(function () {
          return null;
        });
    });

    firstResolvedResult(probes).then(function (result) {
      if (!isCurrentRun(runId)) {
        return;
      }
      if (result) {
        applyIpResults([result]);
      }
    });

    Promise.all(probes)
      .then(function (results) {
        if (!isCurrentRun(runId)) {
          return;
        }
        var successful = results.filter(function (result) {
          return result && result.ok;
        });
        if (!successful.length || !applyIpResults(successful)) {
          throw new Error("empty result");
        }
      })
      .catch(function () {
        if (!isCurrentRun(runId)) {
          return;
        }
        state.multiSummary = "出口 IP 未测出，无法自动交叉核对。可手动输入 IP 查询。";
        state.multi = [];
        setRow("ip", {
          status: "amber",
          value: "无法读取出口 IP",
          detail:
            "浏览器无法读取 IP 情报，可能是接口被网络拦截、跨源限制或当前代理阻断。此项失败不代表安全，只代表未测出。"
        });
        recomputeConsistency();
      });
  }

  function firstResolvedResult(promises) {
    return new Promise(function (resolve) {
      var settled = false;
      var remaining = promises.length;
      if (!remaining) {
        resolve(null);
        return;
      }
      promises.forEach(function (promise) {
        promise
          .then(function (result) {
            if (settled) {
              return;
            }
            if (result) {
              settled = true;
              resolve(result);
              return;
            }
            remaining -= 1;
            if (remaining === 0) {
              resolve(null);
            }
          })
          .catch(function () {
            if (settled) {
              return;
            }
            remaining -= 1;
            if (remaining === 0) {
              resolve(null);
            }
          });
      });
    });
  }

  function uniqueIpResults(results) {
    var seen = {};
    return results.filter(function (result) {
      if (!result || !result.ip || seen[result.ip]) {
        return false;
      }
      if (!isIpv4Address(result.ip) && !isIpv6Address(result.ip)) {
        return false;
      }
      seen[result.ip] = true;
      return true;
    });
  }

  function ipVersionLabel(ip) {
    if (isIpv6Address(ip)) {
      return "IPv6";
    }
    if (isIpv4Address(ip)) {
      return "IPv4";
    }
    return "IP";
  }

  function fieldLine(label, value) {
    return label + "：" + (value || "—");
  }

  function uniqueValues(values) {
    var seen = {};
    return (values || []).filter(function (value) {
      if (!value || seen[value]) {
        return false;
      }
      seen[value] = true;
      return true;
    });
  }

  function ipSortWeight(ip) {
    if (isIpv4Address(ip)) {
      return 0;
    }
    if (isIpv6Address(ip)) {
      return 1;
    }
    return 2;
  }

  function sortIpValues(values) {
    return uniqueValues(values).sort(function (left, right) {
      return ipSortWeight(left) - ipSortWeight(right);
    });
  }

  function sortIpResults(results) {
    return (results || []).slice().sort(function (left, right) {
      return ipSortWeight(left && left.ip) - ipSortWeight(right && right.ip);
    });
  }

  function formatIpLines(ips) {
    var list = sortIpValues(ips);
    return (
      list
        .map(function (ip) {
          return fieldLine(ipVersionLabel(ip), ip);
        })
        .join("\n") || "未知"
    );
  }

  function formatWebrtcCandidateLines(ips, exitIps) {
    var exitSet = {};
    uniqueValues(exitIps).forEach(function (ip) {
      exitSet[ip] = true;
    });
    return (
      sortIpValues(ips)
        .map(function (ip) {
          return fieldLine(ipVersionLabel(ip), ip) + (exitSet[ip] ? "（与出口一致）" : "（出口列表外）");
        })
        .join("\n") || "无"
    );
  }

  function formatExitIpHeadline(results, fallback) {
    var list = sortIpResults(results && results.length ? results : fallback ? [fallback] : []);
    if (list.length > 1) {
      return formatIpLines(
        list.map(function (item) {
          return item.ip;
        })
      );
    }
    var item = list[0] || {};
    return [
      fieldLine(ipVersionLabel(item.ip), item.ip),
      item.country || item.cc ? fieldLine("地区", item.country || item.cc) : "",
      item.org ? fieldLine("组织", item.org) : ""
    ]
      .filter(Boolean)
      .join("\n");
  }

  function formatExitIpList(results) {
    return sortIpResults(results)
      .map(function (item) {
        return [
          fieldLine(ipVersionLabel(item.ip), item.ip),
          fieldLine("来源", item.source),
          fieldLine("地区", item.country || item.cc || "未知地区"),
          fieldLine("ASN", item.asn || "未知 ASN"),
          fieldLine("组织", item.org || "未知组织")
        ].join("\n");
      })
      .join("\n\n");
  }

  function formatAiPathValue(ips, locs) {
    var cleanIps = sortIpValues(ips);
    var cleanLocs = uniqueValues(locs);
    var loc = cleanLocs.length > 1 ? cleanLocs.join(" / ") : cleanLocs[0] || "?";
    return formatIpLines(cleanIps) + "\n" + fieldLine("地区", loc);
  }

  function recomputeConsistency() {
    var ip = state.rows.ip || {};
    var lang = state.rows.lang || {};
    var tz = state.rows.tz || {};
    var issues = [];
    if (lang.status === "amber") {
      issues.push("语言含中文");
    }
    if (tz.status === "amber") {
      issues.push("时区指向中国");
    }
    if (!ip.country) {
      setRow("consistency", {
        status: "pending",
        value: "待出口 IP",
        detail: "正在等待出口 IP 结果，之后会核对 IP、时区和语言是否互相冲突。",
        advice: ""
      });
      return;
    }
    if (!ip.isCN && issues.length) {
      setRow("consistency", {
        status: "red",
        value: "信号矛盾",
        flag: true,
        detail:
          "出口 IP 不在当前中国口径内，但 " +
          issues.join(" / ") +
          "。这类前后矛盾比单项信号更容易被模型化识别。",
        advice: advice.consistency
      });
    } else if (ip.isCN) {
      setRow("consistency", {
        status: "amber",
        value: "自洽但暴露",
        flag: false,
        detail: "各信号和出口 IP 未见明显冲突，但整体画像仍指向中国口径内地区。",
        advice: "核心是更换出口 IP，并让语言、时区、DNS、WebRTC 一起跟随出口地区。"
      });
    } else {
      setRow("consistency", {
        status: "green",
        value: "一致 · 未见冲突",
        flag: false,
        detail: "出口 IP、语言和时区未发现明显互相冲突。继续检查 DNS、WebRTC 和 AI 路径。",
        advice: ""
      });
    }
  }

  function runWebRTC() {
    var runId = state.runId;
    setRow("webrtc", {
      status: "pending",
      value: "检测中…",
      detail: "正在通过 STUN 观察候选地址…"
    });
    var RTCPeerConnection =
      window.RTCPeerConnection || window.webkitRTCPeerConnection || window.mozRTCPeerConnection;
    if (!RTCPeerConnection) {
      setRow("webrtc", {
        status: "green",
        value: "浏览器不支持 WebRTC",
        detail: "当前浏览器未暴露 RTCPeerConnection，无法通过 WebRTC STUN 读取候选地址。"
      });
      return;
    }

    var found = [];
    var pc;
    try {
      pc = new RTCPeerConnection({
        iceServers: [{ urls: "stun:stun.l.google.com:19302" }]
      });
      pc.createDataChannel("aisignal");
      pc.onicecandidate = function (event) {
        if (!event || !event.candidate || !event.candidate.candidate) {
          return;
        }
        var address = extractIceAddress(event.candidate.candidate);
        if (address && found.indexOf(address) < 0) {
          found.push(address);
        }
      };
      pc.createOffer()
        .then(function (offer) {
          return pc.setLocalDescription(offer);
        })
        .catch(function () {});
    } catch (err) {
      setRow("webrtc", {
        status: "amber",
        value: "检测失败",
        detail: "WebRTC 初始化失败：" + err.message
      });
      return;
    }

    window.setTimeout(function () {
      if (!isCurrentRun(runId)) {
        try {
          pc.close();
        } catch (err) {}
        return;
      }
      try {
        pc.close();
      } catch (err) {}
      var publicIps = found.filter(function (ip) {
        return isPublicNetworkAddress(ip);
      });
      var privateIps = found.filter(function (ip) {
        return isPrivateIp(ip);
      });
      var hiddenHosts = found.filter(isMdnsAddress);
      var ipRow = state.rows.ip || {};
      var exitIps = (ipRow.ips && ipRow.ips.length ? ipRow.ips : [ipRow.ip]).filter(Boolean);
      var unmatchedPublicIps = publicIps.filter(function (ip) {
        return exitIps.length && exitIps.indexOf(ip) < 0;
      });
      var leak = unmatchedPublicIps.length > 0;
      var hiddenCount = hiddenHosts.length + privateIps.length;
      if (publicIps.length && !exitIps.length) {
        setRow("webrtc", {
          status: "amber",
          value: "待出口 IP 核对",
          flag: false,
          detail:
            "WebRTC 看到了公网候选，但当前出口 IP 还没有完成读取，暂时无法判断它是否为代理外地址。\n公网候选：\n" +
            formatIpLines(publicIps) +
            (hiddenCount ? "\n另有 " + hiddenCount + " 个内网 / 浏览器隐藏候选，单独看不构成泄漏。" : "")
        });
      } else if (leak) {
        setRow("webrtc", {
          status: "red",
          value: "发现出口外公网候选",
          flag: true,
          detail:
            "WebRTC 返回了不在当前出口 IP 列表里的公网候选，网站可能绕过代理看到另一条网络路径。\n出口外公网候选：\n" +
            formatIpLines(unmatchedPublicIps) +
            "\n当前出口 IP：\n" +
            formatIpLines(exitIps) +
            "\n全部公网候选：\n" +
            formatWebrtcCandidateLines(publicIps, exitIps) +
            (hiddenCount ? "\n另有 " + hiddenCount + " 个内网 / 浏览器隐藏候选，单独看不构成泄漏。" : "")
        });
      } else if (publicIps.length || privateIps.length) {
        setRow("webrtc", {
          status: "green",
          value: publicIps.length ? "候选与出口一致" : "仅内网候选",
          flag: false,
          detail:
            (publicIps.length
              ? "WebRTC 看到了公网候选，但它们都能在当前出口 IP 列表中找到，未发现代理外公网地址。\n公网候选：\n" +
                formatWebrtcCandidateLines(publicIps, exitIps) +
                "\n当前出口 IP：\n" +
                formatIpLines(exitIps)
              : "WebRTC 只返回了内网、CGNAT、Fake-IP 或保留地址，未发现可直接定位真实网络的公网候选。") +
            "\n已归类候选：" +
            summarizeWebrtcCandidates(publicIps, privateIps, hiddenHosts)
        });
      } else if (hiddenHosts.length) {
        setRow("webrtc", {
          status: "green",
          value: "浏览器已隐藏地址",
          flag: false,
          detail:
            "浏览器把 WebRTC 候选地址隐藏成 mDNS 主机名，网页看不到真实内网 IP 或公网 IP。这是现代浏览器常见的保护行为。\n已隐藏候选：" +
            hiddenHosts.length +
            " 个"
        });
      } else {
        setRow("webrtc", {
          status: "green",
          value: "未发现可读 IP",
          flag: false,
          detail:
            "没有从 WebRTC 候选信息中读取到 IP。现代浏览器可能使用 mDNS 隐藏内网地址，或当前网络阻断了 STUN。"
        });
      }
    }, 4200);
  }

  function extractIceAddress(candidate) {
    var parts = String(candidate || "").trim().split(/\s+/);
    if (parts.length >= 6 && /^candidate:/i.test(parts[0])) {
      return parts[4];
    }
    var fallback = String(candidate || "").match(
      /([0-9]{1,3}(?:\.[0-9]{1,3}){3}|[a-f0-9.-]+\.local|[a-f0-9:]{4,})/i
    );
    return fallback ? fallback[1] : "";
  }

  function summarizeWebrtcCandidates(publicIps, privateIps, hiddenHosts) {
    var parts = [];
    if (publicIps.length) {
      parts.push("公网候选：\n" + formatIpLines(publicIps));
    }
    if (privateIps.length) {
      parts.push("内网 / 保留：\n" + formatIpLines(privateIps));
    }
    if (hiddenHosts.length) {
      parts.push("浏览器隐藏 mDNS " + hiddenHosts.length + " 个");
    }
    return parts.join("\n") || "无";
  }

  function runDNS(mode) {
    if (state.dns.running) {
      return;
    }
    var runId = state.runId;
    var deep = mode === "deep";
    state.dns = {
      done: false,
      running: true,
      mode: mode,
      servers: []
    };
    setRow("dns", {
      status: "pending",
      value: "检测中…",
      detail: "正在通过 bash.ws 分配的子域名触发 DNS 查询，约 10 到 20 秒。"
    });
    getText("https://bash.ws/id", 8000)
      .then(function (id) {
        if (!isCurrentRun(runId)) {
          throw staleRunError();
        }
        id = String(id || "").trim();
        if (!/^[a-z0-9]{6,}$/i.test(id)) {
          throw new Error("bad id");
        }
        var count = deep ? 30 : 10;
        var probes = [];
        for (var i = 1; i <= count; i += 1) {
          probes.push(loadProbeImage("https://" + i + "." + id + ".bash.ws/logo.png", 5000));
        }
        return Promise.all(probes)
          .then(function () {
            return sleep(1500);
          })
          .then(function () {
            return getJson("https://bash.ws/dnsleak/test/" + id + "?json", 9000);
          });
      })
      .then(function (data) {
        if (!isCurrentRun(runId)) {
          return;
        }
        if (!Array.isArray(data)) {
          throw new Error("bad result");
        }
        var yourIp = data.find(function (item) {
          return item.type === "ip";
        });
        var exitIsChina = yourIp && dnsIsChina(yourIp);
        var servers = data
          .filter(function (item) {
            return item.type === "dns";
          })
          .map(function (server) {
            return {
              ip: server.ip || "—",
              country: server.country_name || server.country || "Unknown",
              asn: server.asn || "",
              cn: dnsIsChina(server)
            };
          });
        var cnResolvers = servers.filter(function (server) {
          return server.cn;
        });
        var status = "green";
        var summary = "";
        if (!servers.length) {
          status = "amber";
          summary = "未取到 DNS 解析器记录，可能是 bash.ws 被当前网络限制或结果尚未生成。";
        } else if (cnResolvers.length && !exitIsChina) {
          status = "red";
          summary =
            "出口 IP 看起来在境外，但有 " +
            cnResolvers.length +
            " 个 DNS 解析器指向中国口径内地区，说明 DNS 可能没有走代理。";
        } else if (exitIsChina && cnResolvers.length) {
          status = "amber";
          summary = "出口 IP 与 DNS 都指向中国口径内地区，画像自洽但仍暴露来源。";
        } else {
          summary = "检测到 " + servers.length + " 个 DNS 解析器，未发现中国口径内解析器。";
        }
        state.dns = {
          done: true,
          running: false,
          mode: mode,
          status: status,
          summary: summary,
          yourIp: yourIp
            ? {
                ip: yourIp.ip || "—",
                sub: (yourIp.country_name || yourIp.country || "Unknown") + (yourIp.asn ? " · " + yourIp.asn : "")
              }
            : null,
          servers: servers,
          cnHit: Boolean(cnResolvers.length && !exitIsChina),
          exitIsChina: Boolean(exitIsChina)
        };
        setRow("dns", {
          status: status,
          value: cnResolvers.length ? "检出中国解析器" : servers.length + " 个解析器",
          detail:
            "真正的 DNS 泄漏检测需要权威 DNS 服务器配合。这里借助 bash.ws 完成，第三方会看到本次解析请求。\n" +
            summary
        });
      })
      .catch(function (err) {
        if ((err && err.stale) || !isCurrentRun(runId)) {
          return;
        }
        state.dns = {
          done: true,
          running: false,
          mode: mode,
          error: true,
          servers: [],
          summary:
            "检测失败：" +
            String((err && err.message) || err) +
            "。这通常是 bash.ws 被墙、限流、跨源失败或代理未放行其子域名。检测失败不代表安全，只代表本项未测出。"
        };
        setRow("dns", {
          status: "amber",
          value: "检测失败",
          detail: state.dns.summary
        });
      });
  }

  function dnsIsChina(item) {
    var text = [item.country, item.country_name, item.asn].join(" ");
    return (
      isChinaCountry(item.country) ||
      /china\b|chinanet|china ?169|cnc group|unicom|china ?mobile|cmnet|tietong|cernet|cngi|dnspod|114dns|电信|联通|移动|广电|教育网/i.test(
        text
      )
    );
  }

  function loadProbeImage(url, timeoutMs) {
    return new Promise(function (resolve) {
      var done = false;
      var controller = new AbortController();
      var timer = window.setTimeout(finish, timeoutMs || 5000);
      function finish() {
        if (done) {
          return;
        }
        done = true;
        controller.abort();
        window.clearTimeout(timer);
        resolve();
      }
      fetch(url + "?_=" + Date.now(), {
        cache: "no-store",
        mode: "no-cors",
        referrerPolicy: "no-referrer",
        signal: controller.signal
      })
        .then(finish)
        .catch(finish);
    });
  }

  function sleep(ms) {
    return new Promise(function (resolve) {
      window.setTimeout(resolve, ms);
    });
  }

  function runConn() {
    var runId = state.runId;
    state.conn = {
      running: true,
      groups: connTargets.map(function (group) {
        return {
          title: group.title,
          sites: group.sites.map(function (site) {
            return {
              host: site.host,
              code: "pending",
              status: "检测中"
            };
          })
        };
      })
    };
    render();
    connTargets.forEach(function (group) {
      group.sites.forEach(function (site) {
        probeHost(site).then(function (result) {
          updateConnHost(site.host, result.code, result.status, runId);
        });
      });
    });
  }

  function probeHost(site) {
    return new Promise(function (resolve) {
      var done = false;
      var startedAt = performance.now();
      var controller = new AbortController();
      var timer = window.setTimeout(function () {
        controller.abort();
        finish(false, false);
      }, 6500);
      function finish(ok, exhausted) {
        if (done) {
          return;
        }
        if (!ok && !exhausted && site.fallbackUrl) {
          probeFetch(site.fallbackUrl, "no-cors", controller.signal).then(function (fallbackOk) {
            finish(fallbackOk, true);
          });
          return;
        }
        done = true;
        window.clearTimeout(timer);
        if (ok) {
          resolve({
            code: "ok",
            status: "可达 " + Math.max(1, Math.round(performance.now() - startedAt)) + "ms"
          });
          return;
        }
        resolve({
          code: site.softFail ? "unknown" : "bad",
          status: site.failStatus || "不可达"
        });
      }
      probeFetch(site.probeUrl || "https://" + site.host + "/favicon.ico", site.mode || "no-cors", controller.signal).then(
        function (ok) {
          finish(ok, false);
        }
      );
    });
  }

  function probeFetch(url, mode, signal) {
    return fetch(addCacheBust(url), {
        cache: "no-store",
        mode: mode || "no-cors",
        referrerPolicy: "no-referrer",
        signal: signal
      })
        .then(function () {
          return true;
        })
        .catch(function () {
          return false;
        });
  }

  function addCacheBust(url) {
    return url + (url.indexOf("?") === -1 ? "?" : "&") + "_=" + Date.now();
  }

  function updateConnHost(host, code, label, runId) {
    if (runId && !isCurrentRun(runId)) {
      return;
    }
    state.conn.groups.forEach(function (group) {
      group.sites.forEach(function (site) {
        if (site.host === host) {
          site.code = code;
          site.status = label;
        }
      });
    });
    var allDone = state.conn.groups.every(function (group) {
      return group.sites.every(function (site) {
        return site.code !== "pending";
      });
    });
    state.conn.running = !allDone;
    recompute();
    render();
  }

  function networkVerdict() {
    if (!state.conn.groups || !state.conn.groups.length) {
      return {
        status: "pending",
        result: null,
        text: "大陆探针判定：等待网络连通结果。"
      };
    }
    var mainland = state.conn.groups.find(function (group) {
      return group.title === "中国站点";
    });
    var globalWall = state.conn.groups.find(function (group) {
      return group.title === "全球站点 · 常被墙";
    });
    var mainlandReachable = Boolean(
      mainland &&
        mainland.sites.some(function (site) {
          return site.code === "ok";
        })
    );
    var globalReachable = Boolean(
      globalWall &&
        globalWall.sites.some(function (site) {
          return site.code === "ok";
        })
    );
    var globalPending = Boolean(
      globalWall &&
        globalWall.sites.some(function (site) {
          return site.code === "pending";
        })
    );
    var mainlandPending = Boolean(
      mainland &&
        mainland.sites.some(function (site) {
          return site.code === "pending";
        })
    );
    var aiPending = state.conn.groups.some(function (group) {
      return group.title === "AI 服务" && group.sites.some(function (site) {
        return site.code === "pending";
      });
    });
    var pending = globalPending || mainlandPending;
    if (globalReachable) {
      return {
        status: "green",
        result: false,
        text: "大陆探针判定：全球站点 · 常被墙可达，当前不像大陆直连，或已走代理 / 分流。"
      };
    }
    if (!pending && mainlandReachable) {
      return {
        status: "red",
        result: true,
        text: "大陆探针判定：全球站点 · 常被墙不可达但中国站点可达，符合大陆直连特征。"
      };
    }
    if (pending) {
      return {
        status: "pending",
        result: null,
        text: "大陆探针判定：全球站点 · 常被墙或中国站点仍在检测中。"
      };
    }
    return {
      status: "amber",
      result: null,
      text:
        "大陆探针判定：全球站点 · 常被墙和中国站点都不可达，可能离线、被扩展拦截或网络限制。" +
        (aiPending ? "AI 服务仍在排障检测，不参与大陆直连扣分。" : "")
    };
  }

  function runMulti(ip) {
    var runId = state.runId;
    var target = String(ip || state.multiIp || state.myIp || "").trim();
    state.multiSummary = "正在从多个数据源交叉查询…";
    state.multi = [
      "db-ip.com",
      "ipwho.is",
      "ip.sb",
      "geojs.io",
      "ipapi.is",
      "ipinfo.io",
      "country.is",
      "iplocation.net"
    ].map(function (source) {
      return {
        source: source,
        country: "…",
        geo: "查询中",
        asn: "—",
        org: "—",
        ok: false
      };
    });
    render();

    var tasks = [
      {
        source: "db-ip.com",
        url: !target || target === state.myIp
          ? "https://api.db-ip.com/v2/free/self"
          : target
          ? "https://api.db-ip.com/v2/free/" + encodeURIComponent(target)
          : "https://api.db-ip.com/v2/free/self"
      },
      {
        source: "ipwho.is",
        url: target ? "https://ipwho.is/" + encodeURIComponent(target) : "https://ipwho.is/"
      },
      {
        source: "ip.sb",
        url: target
          ? "https://api.ip.sb/geoip/" + encodeURIComponent(target)
          : "https://api.ip.sb/geoip"
      },
      {
        source: "geojs.io",
        url: target
          ? "https://get.geojs.io/v1/ip/geo/" + encodeURIComponent(target) + ".json"
          : "https://get.geojs.io/v1/ip/geo.json"
      },
      {
        source: "ipapi.is",
        url: target
          ? "https://api.ipapi.is/?q=" + encodeURIComponent(target)
          : "https://api.ipapi.is/"
      },
      {
        source: "ipinfo.io",
        url: target
          ? "https://ipinfo.io/" + encodeURIComponent(target) + "/json"
          : "https://ipinfo.io/json"
      },
      {
        source: "country.is",
        url: target && target !== state.myIp ? "" : "https://api.country.is/",
        unsupported: Boolean(target && target !== state.myIp)
      },
      {
        source: "iplocation.net",
        url: target
          ? "https://api.iplocation.net/?ip=" + encodeURIComponent(target)
          : "https://api.iplocation.net/"
      }
    ];

    tasks.forEach(function (task, index) {
      if (task.unsupported) {
        state.multi[index] = {
          source: task.source,
          country: "不支持指定 IP",
          geo: "仅支持当前出口",
          asn: "—",
          org: "—",
          ok: false,
          geoOk: false
        };
        summarizeMulti();
        render();
        return;
      }
      getJson(task.url, 8500)
        .then(function (payload) {
          if (!isCurrentRun(runId)) {
            throw staleRunError();
          }
          return normalizeIpPayload(payload, task.source);
        })
        .then(function (result) {
          if (!isCurrentRun(runId)) {
            return;
          }
          state.multi[index] = result || {
            source: task.source,
            country: "无结果",
            geo: "—",
            asn: "—",
            org: "—",
            ok: false
          };
          summarizeMulti();
          render();
        })
        .catch(function () {
          if (!isCurrentRun(runId)) {
            return;
          }
          state.multi[index] = {
            source: task.source,
            country: "无法读取",
            geo: "跨源 / 限流",
            asn: "—",
            org: "—",
            ok: false
          };
          summarizeMulti();
          render();
        });
    });
  }

  function summarizeMulti() {
    var ok = state.multi.filter(function (item) {
      return item.ok;
    });
    if (!ok.length) {
      state.multiSummary = "暂未拿到可用结果，可能是接口限流或跨源限制。";
      recompute();
      return;
    }
    var geoOk = ok.filter(function (item) {
      return item.geoOk;
    });
    if (!geoOk.length) {
      state.multi = state.multi.map(function (item) {
        return Object.assign({}, item, {
          mismatch: false
        });
      });
      state.multiSummary =
        ok.length +
        " 个数据源返回结果，但都没有给出可用于地理交叉的地区字段；ASN / 组织信息仅作参考。";
      recompute();
      return;
    }
    var countries = {};
    geoOk.forEach(function (item) {
      var key = item.cc || item.country || "未知";
      countries[key] = (countries[key] || 0) + 1;
    });
    var sorted = Object.keys(countries).sort(function (a, b) {
      return countries[b] - countries[a];
    });
    var main = sorted[0];
    state.multi = state.multi.map(function (item) {
      if (!item.ok || !item.geoOk) {
        return item;
      }
      return Object.assign({}, item, {
        mismatch: (item.cc || item.country || "未知") !== main
      });
    });
    var mismatch = state.multi.filter(function (item) {
      return item.mismatch;
    }).length;
    state.multiSummary =
      ok.length +
      " 个数据源返回结果，其中 " +
      geoOk.length +
      " 个可用于地理交叉；主流判定为 " +
      main +
      (mismatch ? "，其中 " + mismatch + " 个来源与主流结果不一致。" : "，未发现明显地理冲突。");
    recompute();
  }

  function runAipath() {
    var runId = state.runId;
    state.aipath = aiTargets.map(function (target) {
      return {
        name: target.name,
        host: target.host,
        value: "检测中…",
        status: "pending"
      };
    });
    render();
    aiTargets.forEach(function (target, index) {
      var probes = [0, 1].map(function (probeIndex) {
        return getText("https://" + target.host + "/cdn-cgi/trace?_=" + Date.now() + "-" + probeIndex, 8000)
          .then(function (text) {
            return parseCloudflareTrace(text);
          })
          .catch(function () {
            return null;
          });
      });
      Promise.all(probes).then(function (traces) {
          if (!isCurrentRun(runId)) {
            return;
          }
          traces = traces.filter(function (trace) {
            return trace && (trace.ip || trace.loc);
          });
          if (!traces.length) {
            state.aipath[index] = {
              name: target.name,
              host: target.host,
              value: "无法读取（跨源 / 限流）",
              status: "amber"
            };
            recompute();
            render();
            return;
          }
          var ips = uniqueValues(
            traces
              .map(function (trace) {
                return trace.ip;
              })
              .filter(Boolean)
          );
          var locs = uniqueValues(
            traces
              .map(function (trace) {
                return String(trace.loc || "").toUpperCase();
              })
              .filter(Boolean)
          );
          var cn = locs.some(isChinaCountry);
          state.aipath[index] = {
            name: target.name,
            host: target.host,
            ip: ips[0] || "—",
            ips: ips,
            loc: locs[0] || "—",
            locs: locs,
            value: formatAiPathValue(ips, locs),
            status: cn ? "red" : ips.length ? "green" : "amber"
          };
          recompute();
          render();
        });
    });
  }

  function parseCloudflareTrace(text) {
    return String(text || "")
      .split(/\n+/)
      .reduce(function (acc, line) {
        var index = line.indexOf("=");
        if (index > 0) {
          acc[line.slice(0, index)] = line.slice(index + 1);
        }
        return acc;
      }, {});
  }

  function runAiStatus() {
    var runId = state.runId;
    state.aistatus = statusTargets.map(function (target) {
      return {
        name: target.name,
        page: target.page,
        value: "读取中…",
        status: "pending"
      };
    });
    render();
    var statusMap = {
      none: ["green", "运行正常"],
      minor: ["amber", "轻微异常"],
      major: ["red", "故障"],
      critical: ["red", "严重故障"],
      maintenance: ["amber", "维护中"]
    };
    statusTargets.forEach(function (target, index) {
      getJson(target.url, 8000)
        .then(function (json) {
          if (!isCurrentRun(runId)) {
            return;
          }
          var indicator = json.status && json.status.indicator;
          var mapped = statusMap[indicator] || ["pending", indicator || "未知"];
          state.aistatus[index] = {
            name: target.name,
            page: target.page,
            value: mapped[1],
            status: mapped[0]
          };
          render();
        })
        .catch(function () {
          if (!isCurrentRun(runId)) {
            return;
          }
          state.aistatus[index] = {
            name: target.name,
            page: target.page,
            value: "无法读取（跨源 / 限流）",
            status: "pending"
          };
          render();
        });
    });
  }

  function recompute() {
    var score = 100;
    var ip = state.rows.ip || {};
    var lang = state.rows.lang || {};
    var tz = state.rows.tz || {};
    var emoji = state.rows.emoji || {};
    var font = state.rows.font || {};
    var webrtc = state.rows.webrtc || {};
    var consistency = state.rows.consistency || {};
    var directMainland = networkVerdict().result === true;
    var aipCN = state.aipath.some(function (item) {
      return item.status === "red";
    });
    var multiMismatch = state.multi.some(function (item) {
      return item.mismatch;
    });

    if (ip.isCN) {
      score -= 35;
    } else if (ip.host) {
      score -= 22;
    } else if (ip.status === "amber" && !ip.country) {
      score -= 8;
    }
    if (directMainland) {
      score -= 20;
    }
    if (state.dns.cnHit) {
      score -= 15;
    }
    if (webrtc.flag) {
      score -= 12;
    }
    if (aipCN) {
      score -= 15;
    }
    if (multiMismatch) {
      score -= 4;
    }
    if (consistency.flag) {
      score -= 8;
    }
    if (lang.status === "amber") {
      score -= 4;
    }
    if (tz.status === "amber") {
      score -= 4;
    }
    if (emoji.status === "amber") {
      score -= 1;
    }
    if (font.status === "amber") {
      score -= 1;
    }
    state.score = Math.max(0, Math.min(100, score));
  }

  function scoreKey(score) {
    if (score >= 80) {
      return "green";
    }
    if (score >= 50) {
      return "amber";
    }
    return "red";
  }

  function identityConsistencyLabel(row) {
    if (!row || row.status === "pending") {
      return "检测中";
    }
    if (row.flag) {
      return "信号矛盾";
    }
    if (row.value === "自洽但暴露") {
      return "中国口径内出口暴露";
    }
    return "无暴露";
  }

  function identityScoreDetail(lang, tz, consistency) {
    return [
      "语言：" + ((lang && lang.value) || "检测中"),
      "时区：" + ((tz && tz.value) || "检测中"),
      "一致性：" + identityConsistencyLabel(consistency)
    ].join("\n");
  }

  function scoreSegmentData() {
    var ip = state.rows.ip || {};
    var lang = state.rows.lang || {};
    var tz = state.rows.tz || {};
    var emoji = state.rows.emoji || {};
    var font = state.rows.font || {};
    var webrtc = state.rows.webrtc || {};
    var dns = state.rows.dns || {};
    var consistency = state.rows.consistency || {};
    var verdict = networkVerdict();
    var hasRows = Object.keys(state.rows).length > 0;
    var ipPenalty = ip.isCN ? 35 : ip.host ? 22 : ip.status === "amber" && !ip.country ? 8 : 0;
    var identityPenalty =
      (consistency.flag ? 8 : 0) +
      (lang.status === "amber" ? 4 : 0) +
      (tz.status === "amber" ? 4 : 0) +
      (emoji.status === "amber" ? 1 : 0) +
      (font.status === "amber" ? 1 : 0);
    var leakPenalty = (state.dns.cnHit ? 15 : 0) + (webrtc.flag ? 12 : 0);
    var connPenalty = verdict.result === true ? 20 : 0;
    var aiPenalty = state.aipath.some(function (item) {
      return item.status === "red";
    })
      ? 15
      : 0;
    var multiMismatch = state.multi.some(function (item) {
      return item.mismatch;
    });
    var multiPenalty = multiMismatch ? 4 : 0;
    var multiUnavailable = !state.multi.length && rowReady("ip") && !state.myIp;
    var aiPending =
      !state.aipath.length ||
      state.aipath.some(function (item) {
        return item.status === "pending";
      });
    var aiAmber = state.aipath.some(function (item) {
      return item.status === "amber";
    });
    return [
      {
        id: "ip",
        label: "IP",
        name: "出口 IP",
        max: 35,
        penalty: ipPenalty,
        status: !hasRows || ip.status === "pending" ? "pending" : ipPenalty >= 35 ? "red" : ipPenalty ? "amber" : "green",
        detail: rowShareStatus("ip")
      },
      {
        id: "identity",
        label: "身份",
        name: "身份信号",
        max: 18,
        penalty: identityPenalty,
        status:
          !hasRows || [lang, tz, emoji, font].some(function (row) {
            return row.status === "pending";
          })
            ? "pending"
            : consistency.flag
              ? "red"
              : identityPenalty
                ? "amber"
                : "green",
        detail: identityScoreDetail(lang, tz, consistency)
      },
      {
        id: "leak",
        label: "泄漏",
        name: "网络泄漏",
        max: 27,
        penalty: leakPenalty,
        status:
          dns.status === "pending" || webrtc.status === "pending"
            ? "pending"
            : leakPenalty
              ? "red"
              : "green",
        detail: "DNS：" + rowShareStatus("dns") + "；WebRTC：" + rowShareStatus("webrtc")
      },
      {
        id: "conn",
        label: "大陆探针",
        name: "大陆直连探针",
        max: 20,
        penalty: connPenalty,
        status: verdict.status,
        detail: networkShareStatus() + "。此项只看全球站点 · 常被墙与中国站点的可达性，不使用 AI 平台服务稳定性。"
      },
      {
        id: "ai",
        label: "AI出口",
        name: "AI 路径出口",
        max: 15,
        penalty: aiPenalty,
        status: aiPending ? "pending" : aiPenalty ? "red" : aiAmber ? "amber" : "green",
        detail: aiPathShareStatus()
      },
      {
        id: "multi",
        label: "互证",
        name: "多源交叉",
        max: 4,
        penalty: multiPenalty,
        status: !state.multi.length ? (multiUnavailable ? "amber" : "pending") : multiPenalty ? "amber" : "green",
        detail: state.multiSummary
      }
    ];
  }

  function segmentStatusText(segment) {
    if (segment.status === "red") {
      return "高风险";
    }
    if (segment.status === "amber") {
      return "需留意";
    }
    if (segment.status === "green") {
      return "正常";
    }
    return "检测中";
  }

  function segmentPenaltyText(segment) {
    if (segment.status === "pending") {
      return "待判定 · 上限 " + segment.max + " 分";
    }
    if (segment.penalty > 0) {
      return "已扣 " + segment.penalty + " 分 · 上限 " + segment.max + " 分";
    }
    return "未扣分 · 上限 " + segment.max + " 分";
  }

  function scoreProgressClass(score, hasRows) {
    return hasRows ? scoreKey(score) : "pending";
  }

  function renderScoreRingSegments(segments, score, hasRows) {
    var totalWeight = SCORE_SEGMENTS.reduce(function (sum, item) {
      return sum + item.weight;
    }, 0);
    var gap = 7.2;
    var usable = RING_CIRCUMFERENCE - gap * SCORE_SEGMENTS.length;
    var cursor = 0;
    var tracks = [];
    var normalizedScore = hasRows ? Math.max(0, Math.min(100, score)) : 0;
    var progressLength = RING_CIRCUMFERENCE * (normalizedScore / 100);
    var progressKey = scoreProgressClass(normalizedScore, hasRows);
    SCORE_SEGMENTS.forEach(function (meta, index) {
      var segment = segments[index];
      var length = usable * (meta.weight / totalWeight);
      var dash = Math.max(0, length).toFixed(3) + " " + RING_CIRCUMFERENCE.toFixed(3);
      var offset = (-cursor).toFixed(3);
      tracks.push(
        '<circle class="score-track score-track-segment" cx="60" cy="60" r="52" stroke-dasharray="' +
          dash +
          '" stroke-dashoffset="' +
          offset +
          '"></circle>'
      );
      cursor += length + gap;
    });
    return (
      tracks.join("") +
      '<circle class="score-progress score-progress-' +
      progressKey +
      '" cx="60" cy="60" r="52" stroke-dasharray="' +
      progressLength.toFixed(3) +
      " " +
      RING_CIRCUMFERENCE.toFixed(3) +
      '" stroke-dashoffset="0"><title>' +
      escapeHtml(hasRows ? "综合信任分：" + normalizedScore + "/100" : "综合信任分：检测中") +
      "</title></circle>"
    );
  }

  function scoreTipDetailRows(detail) {
    return String(detail || "等待检测结果")
      .split(/(?:\n+|；|。)\s*/)
      .map(function (row) {
        return row.trim();
      })
      .filter(Boolean);
  }

  function renderScoreTipDetail(detail) {
    return scoreTipDetailRows(detail)
      .map(function (row) {
        return '<span class="score-tip-line">' + highlightRiskText(row) + "</span>";
      })
      .join("");
  }

  function renderScoreSegmentHotspots(segments, ready) {
    var totalWeight = SCORE_SEGMENTS.reduce(function (sum, item) {
      return sum + item.weight;
    }, 0);
    var gap = 7.2;
    var usable = RING_CIRCUMFERENCE - gap * SCORE_SEGMENTS.length;
    var cursor = 0;
    return SCORE_SEGMENTS.map(function (meta, index) {
      var segment = segments[index];
      var length = usable * (meta.weight / totalWeight);
      var midRatio = (cursor + length / 2) / RING_CIRCUMFERENCE;
      var angle = -90 + midRatio * 360;
      var rad = (angle * Math.PI) / 180;
      var radius = 96;
      var x = 90 + Math.cos(rad) * radius;
      var y = 90 + Math.sin(rad) * radius;
      var side = y > 92 ? "is-bottom" : "is-top";
      var horizontal = x > 118 ? "is-right" : x < 62 ? "is-left" : "is-center";
      var displayStatus = ready ? segment.status : "pending";
      cursor += length + gap;
      return (
        '<button class="score-metric score-metric-' +
        statusClass(displayStatus) +
        " " +
        side +
        " " +
        horizontal +
        '" type="button" style="left:' +
        x.toFixed(1) +
        "px;top:" +
        y.toFixed(1) +
        'px" aria-label="' +
        escapeHtml(segment.name + "：" + segmentStatusText(segment) + "，" + segmentPenaltyText(segment)) +
        '">' +
        '<span class="score-metric-label">' +
        escapeHtml(segment.label) +
        "</span>" +
        '<span class="score-metric-tip" role="tooltip"><strong class="score-tip-title">' +
        escapeHtml(segment.name) +
        '</strong><span class="score-tip-meta">状态：' +
        escapeHtml(segmentStatusText(segment)) +
        " · " +
        escapeHtml(segmentPenaltyText(segment)) +
        '</span><span class="score-tip-detail">' +
        renderScoreTipDetail(segment.detail) +
        "</span></span></button>"
      );
    }).join("");
  }

  function collectRiskItems() {
    var items = [];
    var ip = state.rows.ip || {};
    if (ip.isCN) {
      items.push({ label: "出口 IP 在中国口径内", section: "sec-ip", row: "ip", severity: "red" });
    }
    if (ip.host) {
      items.push({ label: "机房 / VPN 出口", section: "sec-ip", row: "ip", severity: "amber" });
    }
    if (ip.status === "amber" && !ip.country) {
      items.push({ label: "出口 IP 未完整测出", section: "sec-ip", row: "ip", severity: "amber" });
    }
    if (state.dns.cnHit) {
      items.push({ label: "DNS 中国解析器", section: "sec-leak", row: "dns", severity: "red" });
    }
    if (networkVerdict().result === true) {
      items.push({ label: "大陆直连", section: "sec-conn", row: "", severity: "red" });
    }
    if ((state.rows.webrtc || {}).flag) {
      items.push({ label: "WebRTC 出口外公网候选", section: "sec-leak", row: "webrtc", severity: "red" });
    }
    if ((state.rows.consistency || {}).flag) {
      items.push({ label: "信号前后矛盾", section: "sec-ip", row: "consistency", severity: "red" });
    }
    if ((state.rows.lang || {}).status === "amber") {
      items.push({ label: "语言含中文", section: "sec-identity", row: "lang", severity: "amber" });
    }
    if ((state.rows.tz || {}).status === "amber") {
      items.push({ label: "时区在中国", section: "sec-identity", row: "tz", severity: "amber" });
    }
    if (
      state.aipath.some(function (item) {
        return item.status === "red";
      })
    ) {
      items.push({ label: "AI 路径出口在中国", section: "sec-aipath", row: "", severity: "red" });
    }
    if (
      state.multi.some(function (item) {
        return item.mismatch;
      })
    ) {
      items.push({ label: "多源 IP 情报冲突", section: "sec-multi", row: "", severity: "amber" });
    }
    return items;
  }

  function collectRiskFlags() {
    return collectRiskItems().map(function (item) {
      return item.label;
    });
  }

  function detectionHint() {
    return DETECTION_HINTS[state.runId % DETECTION_HINTS.length];
  }

  function renderScoreInsights() {
    var items = collectRiskItems();
    if (items.length) {
      return (
        '<div class="score-risk-strip" aria-label="风险项定位">' +
        items
          .map(function (item) {
            return (
              '<button class="score-risk-chip score-risk-chip-' +
              escapeHtml(item.severity || "amber") +
              '" type="button" data-risk-section="' +
              escapeHtml(item.section) +
              '" data-risk-row="' +
              escapeHtml(item.row || "") +
              '"><span class="score-risk-mark">!</span><span>' +
              highlightRiskText(item.label) +
              "</span></button>"
            );
          })
          .join("") +
        "</div>"
      );
    }
    if (!scoreReady()) {
      return '<p class="score-hint">' + escapeHtml(detectionHint()) + "</p>";
    }
    return "";
  }

  function openRiskTarget(sectionId, rowId) {
    if (rowId) {
      state.open[rowId] = true;
    }
    state.activeId = sectionId || state.activeId;
    renderImmediate();
    window.requestAnimationFrame(function () {
      var target =
        (rowId && document.querySelector('[data-row="' + rowId.replace(/"/g, '\\"') + '"]')) ||
        document.getElementById(sectionId);
      if (target) {
        target.scrollIntoView({ behavior: "smooth", block: "start" });
      }
      updateActiveNav();
    });
  }

  function summaryText() {
    var flags = collectRiskFlags();
    if (!Object.keys(state.rows).length) {
      return "正在运行本地与联网检测…";
    }
    if (!scoreReady()) {
      return flags.length
        ? "检测仍在继续，已发现 " + flags.length + " 项风险信号。点击下方标记项可先定位排查。"
        : "正在完成 DNS、WebRTC、网络连通、AI 路径和多源交叉检测。";
    }
    if (!flags.length) {
      return "未发现明显暴露信号，各项信号与出口 IP 基本一致。这是较理想的状态。";
    }
    return "检测完成！\n发现 " + flags.length + " 项需要留意的信号！";
  }

  function shareStatusLabel(status) {
    return statusText[statusClass(status)] || "检测中";
  }

  function rowShareStatus(id) {
    var row = state.rows[id] || {};
    if (!Object.keys(row).length || row.status === "pending") {
      return "检测中";
    }
    if (id === "ip") {
      if (row.isCN) {
        return "高危 · 出口在中国口径内";
      }
      if (row.host) {
        return "一般 · 机房 / VPN / 代理池特征";
      }
      if (row.status === "green") {
        return "可信 · 未见高风险出口";
      }
      return "一般 · 出口 IP 未完整测出";
    }
    if (id === "dns") {
      if (state.dns.cnHit) {
        return "高危 · 命中中国解析器";
      }
      if (row.status === "green") {
        return "可信 · 未见中国解析器";
      }
      return shareStatusLabel(row.status) + " · " + (row.value || "未完整测出");
    }
    if (id === "webrtc") {
      return shareStatusLabel(row.status) + " · " + (row.value || "未完整测出");
    }
    if (id === "consistency") {
      return shareStatusLabel(row.status) + " · " + (row.value || "未完整测出");
    }
    return shareStatusLabel(row.status);
  }

  function networkShareStatus() {
    var verdict = networkVerdict();
    if (verdict.result === true) {
      return "高危 · 疑似大陆直连";
    }
    if (verdict.result === false) {
      return "可信 · 未见大陆直连";
    }
    if (verdict.status === "amber") {
      return "未确认 · 网络探针不可判定";
    }
    return "检测中";
  }

  function aiPathShareStatus() {
    if (!state.aipath.length) {
      return "检测中";
    }
    if (
      state.aipath.some(function (item) {
        return item.status === "red";
      })
    ) {
      return "高危 · AI 路径命中中国出口";
    }
    if (
      state.aipath.some(function (item) {
        return item.status === "pending";
      })
    ) {
      return "检测中";
    }
    if (
      state.aipath.some(function (item) {
        return item.status === "amber";
      })
    ) {
      return "一般 · AI 路径部分无法读取";
    }
    return "可信 · AI 路径未见中国出口";
  }

  function diagnosticSummaryText() {
    var ready = scoreReady();
    var scoreText = ready ? state.score + "/100（" + statusText[scoreKey(state.score)] + "）" : "检测中";
    var flags = collectRiskFlags();
    return [
      "AI Signal Guard 诊断摘要",
      "信任分：" + scoreText,
      "判定口径：" + diagnosticRegionLabel(),
      "风险项：" + (flags.length ? flags.join(" / ") : "未发现明显暴露信号"),
      "出口 IP：" + rowShareStatus("ip"),
      "身份一致性：" + rowShareStatus("consistency"),
      "WebRTC：" + rowShareStatus("webrtc"),
      "DNS：" + rowShareStatus("dns"),
      "网络连通：" + networkShareStatus(),
      "AI 路径：" + aiPathShareStatus(),
      "",
      "在线检测：https://betaer.github.io/AISignalGuard/",
      "开源仓库：https://github.com/betaer/AISignalGuard"
    ].join("\n");
  }

  function diagnosticRegionLabel() {
    return state.region === "cnhk" ? "中国大陆 + 香港 + 澳门，不含台湾" : "仅中国大陆，不含台湾";
  }

  function render() {
    if (state.renderPaused || state.renderScheduled) {
      return;
    }
    state.renderScheduled = true;
    var token = (state.renderToken += 1);
    var schedule = window.requestAnimationFrame || function (callback) {
      window.setTimeout(callback, 0);
    };
    schedule(function () {
      if (token === state.renderToken) {
        renderNow();
      }
    });
  }

  function renderImmediate() {
    state.renderToken += 1;
    renderNow();
  }

  function renderNow() {
    state.renderScheduled = false;
    document.body.classList.toggle("privacy-on", state.privacy);
    renderTopbar();
    renderScore();
    renderSections();
    bindScoreMetricEvents();
    bindDynamicEvents();
  }

  function renderTopbar() {
    $("#privacy-toggle").textContent = state.privacy ? "◉ 隐私模式" : "◎ 隐私模式";
    $("#nav-list").innerHTML = NAV.map(function (item) {
      return (
        '<a class="nav-item ' +
        (state.activeId === item[0] ? "is-active" : "") +
        '" href="#' +
        item[0] +
        '" data-nav="' +
        item[0] +
        '">' +
        escapeHtml(item[1]) +
        "</a>"
      );
    }).join("");
    document.querySelectorAll(".segmented-button").forEach(function (button) {
      button.classList.toggle("is-active", button.dataset.region === state.region);
    });
    $("#rules-panel").hidden = !state.panels.rules;
    $("#privacy-panel").hidden = !state.panels.privacy;
    updateNavScrollHint();
  }

  function renderScore() {
    var ready = scoreReady();
    state.displayScore = state.score;
    var key = scoreKey(state.score);
    var value = ready ? state.displayScore : "··";
    var segments = scoreSegmentData();
    $("#score-number").textContent = value;
    $("#score-status").textContent = ready ? statusText[key] : "检测中";
    $("#score-status").style.color = ready ? COLORS[key] : COLORS.pending;
    $("#score-ring").innerHTML = renderScoreRingSegments(segments, state.score, ready);
    $("#score-segment-hotspots").innerHTML = renderScoreSegmentHotspots(segments, ready);
    $("#score-summary").innerHTML = highlightRiskText(summaryText());
    $("#score-insights").innerHTML = renderScoreInsights();
    var copySummary = $("#copy-summary");
    if (copySummary) {
      var copyLabel = copySummary.querySelector(".floating-share-label");
      var copyTextLabel =
        state.copied === "diagnostic-summary"
          ? "已复制"
          : state.copied === "diagnostic-summary:failed"
            ? "复制失败"
            : "复制摘要";
      copySummary.classList.toggle("is-copied", state.copied === "diagnostic-summary");
      copySummary.classList.toggle("is-failed", state.copied === "diagnostic-summary:failed");
      if (copyLabel) {
        copyLabel.textContent = copyTextLabel;
      }
    }
  }

  function setActiveScoreMetric(button) {
    document.querySelectorAll(".score-metric.is-active").forEach(function (metric) {
      if (metric !== button) {
        metric.classList.remove("is-active");
      }
    });
    if (button) {
      button.classList.add("is-active");
    }
  }

  function bindScoreMetricEvents() {
    document.querySelectorAll(".score-metric").forEach(function (button) {
      button.addEventListener("mouseenter", function () {
        setActiveScoreMetric(button);
      });
      button.addEventListener("focus", function () {
        setActiveScoreMetric(button);
      });
      button.addEventListener("mouseleave", function () {
        button.classList.remove("is-active");
      });
      button.addEventListener("blur", function () {
        button.classList.remove("is-active");
      });
      button.addEventListener("click", function (event) {
        event.stopPropagation();
        setActiveScoreMetric(button);
      });
    });
  }

  function renderSections() {
    var html = "";
    html += renderRowSection("sec-ip", "出口 IP", "风控第一顺位", [
      rowVm("ip", "出口 IP 质量", { sensitive: true, actions: [["↻ 重测", "run-ip"]] }),
      rowVm("consistency", "一致性核对")
    ]);
    html += renderRowSection("sec-identity", "身份信号", "身份画像是否一致", [
      rowVm("lang", "浏览器语言"),
      rowVm("tz", "系统时区"),
      rowVm("emoji", "Emoji 渲染"),
      rowVm("font", "中文字体")
    ]);
    html += renderRowSection("sec-leak", "网络泄漏", "真实出口是否暴露", [
      rowVm("webrtc", "WebRTC 泄漏", { sensitive: true, actions: [["↻ 重测", "run-webrtc"]] }),
      rowVm("dns", "DNS 泄漏", {
        actions: [
          ["标准检测", "run-dns-std"],
          ["深度检测", "run-dns-deep"]
        ],
        extra: renderDnsExtra()
      })
    ]);
    html += renderConnSection();
    html += renderMultiSection();
    html += renderAiPathSection();
    html += renderAiStatusSection();
    html += renderFingerprintSection();
    html += renderTraceSection();
    $("#section-root").innerHTML = html;
  }

  function rowVm(id, name, options) {
    var row = state.rows[id] || {
      status: "pending",
      value: "检测中…",
      detail: "正在读取信号…",
      tag: "",
      advice: advice[id] || ""
    };
    return Object.assign({}, row, {
      id: id,
      name: name,
      open: Boolean(state.open[id]),
      sensitive: options && options.sensitive,
      actions: (options && options.actions) || [],
      extra: (options && options.extra) || ""
    });
  }

  function renderRowSection(id, title, sub, rows) {
    return (
      '<section class="section" id="' +
      id +
      '">' +
      renderSectionHead(title, sub) +
      '<div class="panel">' +
      rows.map(renderRow).join("") +
      "</div></section>"
    );
  }

  function renderSectionHead(title, sub, action) {
    return (
      '<div class="section-head"><div class="section-kicker"><span class="section-title">' +
      escapeHtml(title) +
      '</span><span class="section-sub">' +
      highlightRiskText(sub) +
      "</span></div>" +
      (action || "") +
      "</div>"
    );
  }

  function renderSectionAction(label, action) {
    return (
      '<button class="section-action" type="button" data-action="' +
      escapeHtml(action) +
      '">' +
      escapeHtml(label) +
      "</button>"
    );
  }

  function renderRow(row) {
    var cls = "row" + (row.open ? " is-open" : "");
    var valueCls = "row-value" + (row.sensitive ? " sensitive" : "");
    return (
      '<article class="' +
      cls +
      '" data-row-wrap="' +
      row.id +
      '"><button class="row-head" type="button" data-row="' +
      row.id +
      '" aria-expanded="' +
      row.open +
      '"><span class="dot ' +
      statusClass(row.status) +
      '"></span><span class="row-name">' +
      escapeHtml(row.name) +
      '</span><span class="row-tag">' +
      escapeHtml(row.tag || "") +
      '</span><span></span><span class="' +
      valueCls +
      '" title="' +
      escapeHtml(row.value) +
      '">' +
      highlightRiskText(row.value) +
      '</span><span class="chevron">›</span></button>' +
      (row.open ? renderRowBody(row) : "") +
      "</article>"
    );
  }

  function renderRowBody(row) {
    return (
      '<div class="row-body"><div class="row-result"><span class="dot ' +
      statusClass(row.status) +
      '"></span><span class="row-result-text"><span class="row-result-label">检测结果</span><strong class="row-result-value ' +
      (row.sensitive ? "sensitive" : "") +
      '">' +
      highlightRiskText(row.value || "暂无结果") +
      "</strong></span></div><p class=\"row-detail\">" +
      highlightRiskText(row.detail || "暂无详细信息") +
      "</p>" +
      (row.advice
        ? '<div class="advice"><div class="advice-label">规避建议</div><p>' +
          highlightRiskText(row.advice) +
          "</p></div>"
        : "") +
      (row.actions && row.actions.length
        ? '<div class="row-actions">' +
          row.actions
            .map(function (action) {
              return (
                '<button class="button" type="button" data-action="' +
                action[1] +
                '">' +
                escapeHtml(action[0]) +
                "</button>"
              );
            })
            .join("") +
          "</div>"
        : "") +
      (row.extra || "") +
      "</div>"
    );
  }

  function renderDnsExtra() {
    if (!state.dns.done && !state.dns.running) {
      return "";
    }
    var dns = state.dns;
    var html =
      '<div class="dns-extra"><div class="dns-summary"><div class="advice-label">' +
      (dns.running ? "DNS 检测中" : dns.mode === "deep" ? "深度检测结果" : "标准检测结果") +
      "</div><p>" +
      highlightSummaryText(dns.summary || "正在等待 DNS 解析器返回结果…") +
      "</p></div>";
    if (dns.yourIp || (dns.servers && dns.servers.length)) {
      html +=
        '<div class="dns-table-wrap"><table class="dns-table"><thead><tr><th>地址</th><th>角色</th><th>地区 / ASN</th></tr></thead><tbody>';
      if (dns.yourIp) {
        html +=
          '<tr><td><span class="table-source"><span class="dot ' +
          statusClass(dns.status) +
          '"></span><span class="sensitive">' +
          escapeHtml(dns.yourIp.ip) +
          '</span></span></td><td>出口</td><td>' +
          escapeHtml(dns.yourIp.sub || "—") +
          "</td></tr>";
      }
      (dns.servers || []).forEach(function (server) {
        html +=
          '<tr><td><span class="table-source"><span class="dot ' +
          (server.cn && !dns.exitIsChina ? "red" : "green") +
          '"></span><span class="sensitive">' +
          escapeHtml(server.ip) +
          '</span></span></td><td>' +
          (server.cn ? highlightRiskText("中国解析器") : "DNS 解析器") +
          "</td><td>" +
          highlightRiskText(server.country + (server.asn ? " · " + server.asn : "")) +
          "</td></tr>";
      });
      html += "</tbody></table></div>";
    }
    return html + "</div>";
  }

  function renderConnSection() {
    var groups = state.conn.groups.length
      ? state.conn.groups
      : connTargets.map(function (group) {
          return {
            title: group.title,
            sites: group.sites.map(function (site) {
              return {
                host: site.host,
                code: "pending",
                status: "检测中"
              };
            })
          };
        });
    return (
      '<section class="section" id="sec-conn">' +
      renderSectionHead("网络连通", "是否大陆直连", renderSectionAction("↻ 重测", "run-conn")) +
      '<div class="panel conn-panel">' +
      groups
        .map(function (group) {
          return (
            '<div class="conn-group"><div class="conn-group-title">' +
            escapeHtml(group.title) +
            '</div><div class="conn-grid">' +
            group.sites
              .map(function (site) {
                var tone = site.code === "ok" ? "green" : site.code === "bad" ? "red" : "pending";
                return (
                  '<div class="conn-card"><span class="dot ' +
                  tone +
                  '"></span><span class="conn-card-host">' +
                  escapeHtml(site.host) +
                  '</span><span class="conn-card-status ' +
                  tone +
                  '">' +
                  escapeHtml(site.status) +
                  "</span></div>"
                );
              })
              .join("") +
            "</div></div>"
          );
        })
        .join("") +
      '<p class="conn-note">浏览器探针只判断能否建立跨站请求，不读取内容、不带 referrer。AI 服务和部分中国站点会拦截跨源探针；这类结果显示为“浏览器受限”或“未确认”，不等同于网站不可用。大陆探针只依据全球站点 · 常被墙与中国站点的可达性，AI 服务仅用于排障展示，不参与大陆直连扣分。</p></div></section>'
    );
  }

  function renderMultiSection() {
    var rows = state.multi.length
      ? state.multi
      : [
          "db-ip.com",
          "ipwho.is",
          "ip.sb",
          "geojs.io",
          "ipapi.is",
          "ipinfo.io",
          "country.is",
          "iplocation.net"
        ].map(function (source) {
          return {
            source: source,
            country: "…",
            geo: "查询中",
            asn: "—",
            org: "—",
            ok: false
          };
        });
    return (
      '<section class="section" id="sec-multi">' +
      renderSectionHead("多源交叉", "8 个 IP 情报源互证") +
      '<div class="panel"><div class="table-tools"><input id="multi-ip" value="' +
      escapeHtml(state.multiIp || "") +
      '" placeholder="' +
      escapeHtml(state.myIp ? state.myIp + "（本机当前IP）" : "本机当前IP 读取中，或输入任意 IP") +
      '" autocomplete="off" spellcheck="false"><button class="button" type="button" data-action="run-multi">查询</button></div><div class="summary-line">' +
      highlightRiskText(state.multiSummary) +
      '</div><div class="table-wrap"><table class="data-table"><thead><tr><th>来源</th><th>地区</th><th>Geo</th><th>ASN</th><th>组织</th></tr></thead><tbody>' +
      rows
        .map(function (row) {
          return (
            '<tr><td><span class="table-source"><span class="dot ' +
            (row.ok ? (isChinaCountry(row.cc) ? "red" : "green") : "pending") +
            '"></span>' +
            escapeHtml(row.source) +
            (row.mismatch ? '<span class="mismatch">冲突</span>' : "") +
            "</span></td><td>" +
            highlightRiskText(row.country || "—") +
            "</td><td>" +
            highlightRiskText(row.geo || "—") +
            "</td><td>" +
            highlightRiskText(row.asn || "—") +
            '</td><td class="sensitive">' +
            highlightRiskText(row.org || "—") +
            "</td></tr>"
          );
        })
        .join("") +
      "</tbody></table></div></div></section>"
    );
  }

  function renderAiPathSection() {
    var rows = state.aipath.length
      ? state.aipath
      : aiTargets.map(function (target) {
          return {
            name: target.name,
            host: target.host,
            value: "检测中…",
            status: "pending"
          };
        });
    return (
      '<section class="section" id="sec-aipath">' +
      renderSectionHead(
        "AI 路径",
        "访问 AI 站点时看到的 Cloudflare 出口",
        renderSectionAction("↻ 重测", "run-aipath")
      ) +
      '<div class="panel"><div class="path-list ai-path-list">' +
      rows
        .map(function (row) {
          return (
            '<div class="mini-row path-row"><span class="dot ' +
            statusClass(row.status) +
            '"></span><span class="mini-title path-title"><span class="path-name">' +
            escapeHtml(row.name) +
            '</span><span class="path-sep">·</span><span class="path-host">' +
            escapeHtml(row.host || "") +
            '</span></span><span class="mini-value sensitive" title="' +
            escapeHtml(row.host) +
            '">' +
            highlightRiskText(row.value) +
            "</span></div>"
          );
        })
        .join("") +
      "</div></div></section>"
    );
  }

  function renderAiStatusSection() {
    var rows = state.aistatus.length
      ? state.aistatus
      : statusTargets.map(function (target) {
          return {
            name: target.name,
            page: target.page,
            value: "读取中…",
            status: "pending"
          };
        });
    return (
      '<section class="section" id="sec-aistatus">' +
      renderSectionHead(
        "AI 状态",
        "服务故障排除",
        renderSectionAction("↻ 重测", "run-aistatus")
      ) +
      '<div class="panel"><div class="status-list">' +
      rows
        .map(function (row) {
          var tone = statusClass(row.status);
          return (
            '<div class="mini-row status-row"><span class="dot ' +
            tone +
            '"></span><span class="mini-title">' +
            escapeHtml(row.name) +
            '</span><a class="mini-value status-link ' +
            tone +
            '" href="' +
            escapeHtml(row.page || "#") +
            '" target="_blank" rel="noreferrer">' +
            highlightRiskText(row.value) +
            "</a></div>"
          );
        })
        .join("") +
      "</div></div></section>"
    );
  }

  function renderFingerprintSection() {
    var rows = state.fp.length
      ? state.fp
      : [
          { key: "UserAgent", value: "检测中" },
          { key: "平台 Platform", value: "检测中" },
          { key: "屏幕", value: "检测中" },
          { key: "CPU 核心", value: "检测中" },
          { key: "设备内存", value: "检测中" },
          { key: "语言", value: "检测中" },
          { key: "时区", value: "检测中" },
          { key: "Canvas 指纹", value: "检测中" },
          { key: "声纹指纹", value: "计算中" }
        ];
    return (
      '<section class="section" id="sec-fp">' +
      renderSectionHead("浏览器指纹", "本机可见环境") +
      '<div class="panel"><div class="fingerprint-grid">' +
      rows
        .map(function (row) {
          return (
            '<div class="fingerprint-cell ' +
            (row.wide ? "is-wide" : "") +
            '"><div class="fingerprint-key">' +
            escapeHtml(row.key) +
            '</div><div class="fingerprint-value ' +
            (row.sensitive ? "sensitive" : "") +
            '" title="' +
            escapeHtml(row.value) +
            '">' +
            highlightRiskText(row.value) +
            "</div></div>"
          );
        })
        .join("") +
      "</div></div></section>"
    );
  }

  function renderTraceSection() {
    var active = traceTabs[state.traceTab] || traceTabs[0];
    var fakeIpRows = traceFakeIpRanges
      .map(function (row) {
        return (
          "<tr><td><code>" +
          escapeHtml(row[0]) +
          "</code></td><td>" +
          highlightRiskText(row[1]) +
          "</td></tr>"
        );
      })
      .join("");
    var traceIntro =
      highlightRiskText("浏览器无法执行 traceroute（需 ICMP / 原始套接字，JS 一律被禁）。在本机终端先按需安装，再运行追踪；") +
      "<code>mtr</code>" +
      highlightRiskText(" 需 ") +
      "<code>sudo</code>" +
      highlightRiskText("。看路径中是否出现归属中国（CN）、或 ASN 为电信 AS4134 / 联通 AS4837 / 移动 AS9808 的跳。");
    var traceNote =
      highlightRiskText("若结果全是 ") +
      "<code>* * *</code>" +
      highlightRiskText(
        "，或 claude.ai 解析 / 跳点落在下方网段，通常说明请求走的是代理 Fake-IP、CGNAT、私网网关或本地隧道，本机看不到真实公网路径。此时不要把这些地址当成真实出口；继续关注后续是否出现中国（CN）归属，或电信 AS4134 / 联通 AS4837 / 移动 AS9808。"
      );
    return (
      '<section class="section" id="sec-trace">' +
      renderSectionHead("路由追踪", "本机命令复核") +
      '<div class="panel trace-panel"><p class="trace-intro">' +
      traceIntro +
      '</p><div class="trace-tabs">' +
      traceTabs
        .map(function (tab, index) {
          return (
            '<button class="trace-tab ' +
            (index === state.traceTab ? "is-active" : "") +
            '" type="button" data-trace-tab="' +
            index +
            '">' +
            escapeHtml(tab.name) +
            "</button>"
          );
        })
        .join("") +
      '</div><div class="trace-command-grid">' +
      active.commands
        .map(function (command) {
          var copied = state.copied === command[1];
          return (
            '<div class="trace-command-card"><div class="trace-command-head"><span class="command-label">' +
            escapeHtml(command[0]) +
            '</span></div><div class="command-box"><code class="command-code">' +
            escapeHtml(command[1]) +
            '</code><button class="copy-button ' +
            (copied ? "is-copied" : "") +
            '" type="button" data-copy="' +
            escapeHtml(command[1]) +
            '">' +
            (copied ? "✓ 已复制" : "复制") +
            "</button></div></div>"
          );
        })
        .join("") +
      '</div><div class="trace-note"><strong>Fake-IP / 内网地址兼容判断</strong><p>' +
      traceNote +
      '</p><div class="trace-range-wrap"><table class="trace-range-table"><thead><tr><th>网段</th><th>用途 / 含义</th></tr></thead><tbody>' +
      fakeIpRows +
      "</tbody></table></div></div></div></section>"
    );
  }

  function bindStaticEvents() {
    $("#privacy-toggle").addEventListener("click", function () {
      state.privacy = !state.privacy;
      render();
    });
    $("#run-all").addEventListener("click", runAll);
    $("#copy-summary").addEventListener("click", function () {
      copyText(diagnosticSummaryText(), "diagnostic-summary");
    });
    document.addEventListener("click", function (event) {
      if (!event.target.closest(".score-metric")) {
        setActiveScoreMetric(null);
      }
    });
    document.querySelectorAll("[data-region]").forEach(function (button) {
      button.addEventListener("click", function () {
        state.region = button.dataset.region;
        runAll();
      });
    });
    document.querySelectorAll("[data-panel]").forEach(function (button) {
      button.addEventListener("click", function () {
        var id = button.dataset.panel;
        state.panels.rules = id === "rules" ? !state.panels.rules : false;
        state.panels.privacy = id === "privacy" ? !state.panels.privacy : false;
        render();
      });
    });
    window.addEventListener("hashchange", updateActiveNav);
    window.addEventListener("scroll", throttle(updateActiveNav, 120), { passive: true });
    $("#nav-list").addEventListener("scroll", throttle(updateNavScrollHint, 80), { passive: true });
    window.addEventListener("resize", throttle(updateNavScrollHint, 120), { passive: true });
  }

  function bindDynamicEvents() {
    document.querySelectorAll("[data-row]").forEach(function (button) {
      button.addEventListener("click", function () {
        var id = button.dataset.row;
        state.open[id] = !state.open[id];
        render();
      });
    });
    document.querySelectorAll("[data-action]").forEach(function (button) {
      button.addEventListener("click", function () {
        var action = button.dataset.action;
        if (action === "run-ip") runIP();
        if (action === "run-webrtc") runWebRTC();
        if (action === "run-dns-std") runDNS("std");
        if (action === "run-dns-deep") runDNS("deep");
        if (action === "run-conn") runConn();
        if (action === "run-multi") runMulti(($("#multi-ip") || {}).value || "");
        if (action === "run-aipath") runAipath();
        if (action === "run-aistatus") runAiStatus();
      });
    });
    document.querySelectorAll("[data-risk-section]").forEach(function (button) {
      button.addEventListener("click", function () {
        openRiskTarget(button.dataset.riskSection, button.dataset.riskRow || "");
      });
    });
    var input = $("#multi-ip");
    if (input) {
      input.addEventListener("input", function () {
        state.multiIp = input.value;
      });
      input.addEventListener("keydown", function (event) {
        if (event.key === "Enter") {
          runMulti(input.value);
        }
      });
    }
    document.querySelectorAll("[data-trace-tab]").forEach(function (button) {
      button.addEventListener("click", function () {
        state.traceTab = Number(button.dataset.traceTab) || 0;
        render();
      });
    });
    document.querySelectorAll("[data-copy]").forEach(function (button) {
      button.addEventListener("click", function () {
        copyText(button.dataset.copy);
      });
    });
    document.querySelectorAll("[data-nav]").forEach(function (link) {
      link.addEventListener("click", function () {
        state.activeId = link.dataset.nav;
        renderTopbar();
      });
    });
  }

  function copyText(text, copiedKey) {
    var key = copiedKey || text;
    function done() {
      flashCopiedState(key);
    }
    function failed() {
      flashCopiedState(key + ":failed");
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done).catch(function () {
        if (fallbackCopy(text)) {
          done();
        } else {
          failed();
        }
      });
      return;
    }
    if (fallbackCopy(text)) {
      done();
    } else {
      failed();
    }
  }

  function flashCopiedState(key) {
    state.copied = key;
    render();
    window.setTimeout(function () {
      if (state.copied === key) {
        state.copied = "";
        render();
      }
    }, 1500);
  }

  function fallbackCopy(text) {
    var textarea = document.createElement("textarea");
    textarea.value = text;
    textarea.setAttribute("readonly", "");
    textarea.style.position = "fixed";
    textarea.style.top = "-9999px";
    document.body.appendChild(textarea);
    textarea.select();
    var ok = false;
    try {
      ok = document.execCommand("copy");
    } catch (err) {}
    document.body.removeChild(textarea);
    return ok;
  }

  function updateActiveNav() {
    var doc = document.documentElement;
    var atBottom = window.innerHeight + window.scrollY >= doc.scrollHeight - 2;
    var current = NAV[0][0];
    if (atBottom) {
      current = NAV[NAV.length - 1][0];
    } else {
      var trigger = Math.max(120, window.innerHeight * 0.33);
      for (var i = 0; i < NAV.length; i += 1) {
        var el = document.getElementById(NAV[i][0]);
        if (!el) {
          continue;
        }
        var rect = el.getBoundingClientRect();
        if (rect.top <= trigger && rect.bottom > 80) {
          current = NAV[i][0];
        }
      }
    }
    if (state.activeId !== current) {
      state.activeId = current;
      renderTopbar();
    }
  }

  function updateNavScrollHint() {
    var nav = $("#nav-list");
    var wrap = nav ? nav.closest(".anchor-nav") : null;
    if (!nav || !wrap) {
      return;
    }
    var maxScroll = nav.scrollWidth - nav.clientWidth;
    var isScrollable = maxScroll > 2;
    wrap.classList.toggle("is-scrollable", isScrollable);
    wrap.classList.toggle("is-scroll-end", !isScrollable || nav.scrollLeft >= maxScroll - 2);
  }

  function throttle(fn, wait) {
    var last = 0;
    var timer = null;
    return function () {
      var now = Date.now();
      var remaining = wait - (now - last);
      if (remaining <= 0) {
        last = now;
        fn();
      } else if (!timer) {
        timer = window.setTimeout(function () {
          last = Date.now();
          timer = null;
          fn();
        }, remaining);
      }
    };
  }

  function scheduleAfterPaint(fn, delayMs) {
    var delay = typeof delayMs === "number" ? delayMs : 0;
    function runAfterDelay() {
      window.setTimeout(fn, delay);
    }
    if (window.requestAnimationFrame) {
      window.requestAnimationFrame(function () {
        window.requestAnimationFrame(runAfterDelay);
      });
      return;
    }
    runAfterDelay();
  }

  function scheduleIdle(fn, timeoutMs) {
    if (window.requestIdleCallback) {
      window.requestIdleCallback(fn, {
        timeout: timeoutMs || 1800
      });
      return;
    }
    window.setTimeout(fn, Math.min(timeoutMs || 1400, 1400));
  }

  function loadAnalytics() {
    if (state.analyticsLoaded) {
      return;
    }
    state.analyticsLoaded = true;
    if (typeof window.gtag === "function") {
      window.gtag("js", new Date());
      window.gtag("config", "G-8YCMR5G9CN");
    }
    var script = document.createElement("script");
    script.async = true;
    script.src = "https://www.googletagmanager.com/gtag/js?id=G-8YCMR5G9CN";
    document.head.appendChild(script);
  }

  function loadStars() {
    getJson("https://api.github.com/repos/" + REPO, 8000)
      .then(function (repo) {
        var count = repo.stargazers_count;
        $("#star-count").textContent = typeof count === "number" ? String(count) : "Star";
      })
      .catch(function () {
        $("#star-count").textContent = "GitHub";
      });
  }

  function runAll() {
    state.runId += 1;
    var runId = state.runId;
    setPendingRows();
    state.multi = [];
    state.multiSummary = "等待出口 IP 后自动交叉核对…";
    state.conn = {
      running: true,
      groups: pendingConnGroups()
    };
    state.aipath = aiTargets.map(function (target) {
      return {
        name: target.name,
        host: target.host,
        value: "等待检测…",
        status: "pending"
      };
    });
    state.aistatus = statusTargets.map(function (target) {
      return {
        name: target.name,
        page: target.page,
        value: "等待读取…",
        status: "pending"
      };
    });
    state.fp = [];
    state.myIp = "";
    state.exitIps = [];
    state.score = 0;
    state.displayScore = 0;
    renderImmediate();
    runLocalSignals(true);
    recomputeConsistency();
    runIP();
    scheduleAfterPaint(function () {
      if (runId !== state.runId) {
        return;
      }
      runWebRTC();
      runDNS("std");
    }, 1200);
    scheduleAfterPaint(function () {
      if (runId !== state.runId) {
        return;
      }
      runConn();
      runAipath();
      runAiStatus();
    }, 1800);
  }

  document.addEventListener("DOMContentLoaded", function () {
    bindStaticEvents();
    runAll();
    scheduleAfterPaint(function () {
      scheduleIdle(loadStars, 2200);
      scheduleIdle(loadAnalytics, 4200);
    }, 1200);
  });
})();
