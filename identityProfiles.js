/**
 * AiSignalGuard 数字身份画像配置。
 *
 * 每个画像的 weights 与 checks 使用相同的键，并且权重总和固定为 100。
 * 这里仅描述目标环境，不对访问者的真实身份作判断。
 */

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  Object.freeze(value);
  for (const child of Object.values(value)) deepFreeze(child);
  return value;
}

function check(
  id,
  label,
  description,
  matchText,
  partialText,
  mismatchText,
  pendingText,
  advice,
) {
  return {
    id,
    label,
    description,
    matchText,
    partialText,
    mismatchText,
    pendingText,
    advice,
  };
}

const LOCATION = check(
  "location",
  "地理位置",
  "比较出口位置与目标画像的地域要求。",
  "出口位置与目标画像一致",
  "出口位置与目标画像部分一致",
  "出口位置与目标画像存在明确差异",
  "尚未获得足够的地理位置信号",
  "检查出口地区、浏览器位置授权与目标环境是否保持一致。",
);

const LOCATION_CONSISTENCY = check(
  "location",
  "位置一致性",
  "核对出口位置本身以及它与语言、时区等环境信号是否一致。",
  "位置与其他环境信号保持一致",
  "位置与部分环境信号仍有待核对差异",
  "位置与其他环境信号存在明确差异",
  "尚未获得足够的位置一致性信号",
  "核对出口位置、设备时区和日常使用语言是否保持一致。",
);

const NETWORK = check(
  "network",
  "网络类型",
  "分析 ISP、ASN 与住宅或数据中心等网络特征。",
  "网络类型符合目标画像特征",
  "网络类型仅部分符合目标画像特征",
  "网络类型与目标画像存在差异",
  "尚未确认网络类型",
  "核对当前 ISP、网络类型与目标环境的使用场景。",
);

const REPUTATION = check(
  "reputation",
  "IP 信誉",
  "结合现有风险与网络证据分析出口信誉。",
  "IP 信誉信号稳定",
  "IP 信誉存在少量待核对信号",
  "IP 信誉存在明显风险信号",
  "尚未获得足够的 IP 信誉证据",
  "查看具体风险因子，并优先处理有明确来源支持的异常信号。",
);

const TIMEZONE = check(
  "timezone",
  "时区",
  "比较浏览器时区、出口位置与目标画像。",
  "时区与目标环境一致",
  "时区与目标环境部分一致",
  "时区与目标环境不一致",
  "尚未确认时区一致性",
  "将设备时区设置为实际使用地区，并核对系统与浏览器设置。",
);

const LANGUAGE = check(
  "language",
  "语言",
  "比较浏览器语言与目标画像的常用语言环境。",
  "浏览器语言与目标环境一致",
  "浏览器语言与目标环境部分一致",
  "浏览器语言与目标环境存在差异",
  "尚未确认浏览器语言",
  "核对操作系统和浏览器的首选语言是否与日常使用环境一致。",
);

const BROWSER = check(
  "browser",
  "浏览器环境",
  "检查浏览器、平台和常见客户端信号的内部一致性。",
  "浏览器环境信号一致",
  "浏览器环境存在少量差异",
  "浏览器环境存在明显不一致",
  "尚未获得完整的浏览器环境信号",
  "核对浏览器版本、操作系统与设备平台信号是否相互一致。",
);

const DNS = check(
  "dns",
  "DNS",
  "分析 DNS 解析区域与出口环境的一致性。",
  "DNS 与出口环境一致",
  "DNS 与出口环境部分一致",
  "DNS 与出口环境不一致",
  "尚未确认 DNS 一致性",
  "核对 DNS 解析器所在地区与当前网络出口。",
);

const WEBRTC = check(
  "webrtc",
  "WebRTC",
  "比较 WebRTC 地址与已发现的网络出口。",
  "WebRTC 信号与出口环境一致",
  "WebRTC 信号存在少量待核对差异",
  "WebRTC 信号与出口环境不一致",
  "尚未获得 WebRTC 一致性信号",
  "检查浏览器 WebRTC 地址是否暴露了与当前出口不同的网络路径。",
);

function serviceCheck(id, label, targetLabel) {
  return check(
    id,
    label,
    `分析${targetLabel}相关服务的可达性与访问路径信号。`,
    `${targetLabel}相关服务访问路径符合目标画像`,
    `${targetLabel}相关服务仅部分可达或仍有待确认信号`,
    `${targetLabel}相关服务存在明确的访问差异`,
    `尚未完成${targetLabel}相关服务检测`,
    `查看${targetLabel}相关服务的逐项结果，并区分本地限制、服务状态与网络路径问题。`,
  );
}

function strictUsLocationRule() {
  return {
    id: "target_region_conflict",
    signalId: "location",
    statuses: ["mismatch"],
    minConfidence: 0.75,
    cap: 69,
    reason: "检测到与美国目标地区明确冲突的地理信号",
  };
}

const profiles = [
  {
    id: "generic",
    name: "通用数字身份分析",
    icon: "🌐",
    description: "不预设具体地区或职业，分析各类环境信号之间的一致性。",
    target: {
      label: "通用数字环境",
      summarySubject: "通用数字环境",
      geography: { mode: "any", countryCodes: [], label: "不限定地区" },
      languageTags: [],
      timezonePrefixes: [],
      networkTraits: ["consistent"],
    },
    weights: {
      location: 15,
      network: 15,
      reputation: 15,
      timezone: 10,
      language: 10,
      browser: 10,
      dns: 10,
      webrtc: 10,
      services: 5,
    },
    checks: [
      LOCATION_CONSISTENCY,
      NETWORK,
      REPUTATION,
      TIMEZONE,
      LANGUAGE,
      BROWSER,
      DNS,
      WEBRTC,
      serviceCheck("services", "常用服务", "常用"),
    ],
    serviceIds: ["google", "youtube", "chatgpt"],
    serviceGroups: [
      { checkId: "services", serviceIds: ["google", "youtube", "chatgpt"] },
    ],
    scoreReadiness: {
      requiredSignalGroups: [
        ["location", "network", "reputation"],
        ["timezone", "language", "browser", "dns", "webrtc", "services"],
      ],
    },
    criticalRules: [],
  },
  {
    id: "us_consumer",
    name: "美国普通用户",
    icon: "🇺🇸",
    description: "分析数字环境与美国普通消费者画像的匹配程度。",
    target: {
      label: "美国普通消费者",
      summarySubject: "美国普通消费者画像",
      geography: { mode: "country", countryCodes: ["US"], label: "美国" },
      languageTags: ["en-US", "en"],
      timezonePrefixes: [
        "America/New_York",
        "America/Chicago",
        "America/Denver",
        "America/Phoenix",
        "America/Los_Angeles",
        "America/Anchorage",
        "Pacific/Honolulu",
      ],
      networkTraits: ["residential", "isp"],
    },
    weights: {
      location: 20,
      network: 20,
      timezone: 12,
      language: 10,
      dns: 10,
      webrtc: 10,
      browser: 8,
      consumer_services: 10,
    },
    checks: [
      LOCATION,
      NETWORK,
      TIMEZONE,
      LANGUAGE,
      DNS,
      WEBRTC,
      BROWSER,
      serviceCheck("consumer_services", "消费服务", "消费"),
    ],
    serviceIds: ["google", "youtube", "netflix", "chatgpt"],
    serviceGroups: [
      {
        checkId: "consumer_services",
        serviceIds: ["google", "youtube", "netflix", "chatgpt"],
      },
    ],
    scoreReadiness: {
      requiredSignalGroups: [
        ["location"],
        ["network"],
        ["timezone", "language", "browser", "dns", "webrtc", "consumer_services"],
      ],
    },
    criticalRules: [strictUsLocationRule()],
  },
  {
    id: "tiktok_creator",
    name: "TikTok 创作者",
    icon: "🎬",
    description: "分析数字环境与美国内容创作者常见使用环境的匹配程度。",
    target: {
      label: "美国内容创作者",
      summarySubject: "美国内容创作者画像",
      geography: { mode: "country", countryCodes: ["US"], label: "美国" },
      languageTags: ["en-US", "en"],
      timezonePrefixes: [
        "America/New_York",
        "America/Chicago",
        "America/Denver",
        "America/Phoenix",
        "America/Los_Angeles",
        "America/Anchorage",
        "Pacific/Honolulu",
      ],
      networkTraits: ["residential", "isp", "stable"],
    },
    weights: {
      network: 20,
      reputation: 10,
      location: 15,
      timezone: 10,
      language: 10,
      dns: 8,
      webrtc: 7,
      creator_services: 15,
      ads_environment: 5,
    },
    checks: [
      NETWORK,
      REPUTATION,
      LOCATION,
      TIMEZONE,
      LANGUAGE,
      DNS,
      WEBRTC,
      serviceCheck("creator_services", "创作者服务", "内容创作"),
      serviceCheck("ads_environment", "广告平台信号", "广告平台"),
    ],
    serviceIds: ["tiktok", "instagram", "youtube", "google_ads", "meta_ads"],
    serviceGroups: [
      {
        checkId: "creator_services",
        serviceIds: ["tiktok", "instagram", "youtube"],
      },
      {
        checkId: "ads_environment",
        serviceIds: ["google_ads", "meta_ads"],
      },
    ],
    scoreReadiness: {
      requiredSignalGroups: [
        ["network", "reputation", "location"],
        ["creator_services", "ads_environment"],
        ["timezone", "language", "dns", "webrtc"],
      ],
    },
    criticalRules: [strictUsLocationRule()],
  },
  {
    id: "cross_border_seller",
    name: "跨境卖家",
    icon: "🛒",
    description: "分析数字环境与美国商业用户常见使用环境的匹配程度。",
    target: {
      label: "美国商业用户",
      summarySubject: "美国商业用户画像",
      geography: { mode: "country", countryCodes: ["US"], label: "美国" },
      languageTags: ["en-US", "en"],
      timezonePrefixes: [
        "America/New_York",
        "America/Chicago",
        "America/Denver",
        "America/Phoenix",
        "America/Los_Angeles",
        "America/Anchorage",
        "Pacific/Honolulu",
      ],
      networkTraits: ["stable", "reputable"],
    },
    weights: {
      reputation: 15,
      network: 10,
      location: 15,
      timezone: 8,
      language: 7,
      browser: 10,
      dns: 5,
      webrtc: 5,
      commerce_services: 25,
    },
    checks: [
      REPUTATION,
      NETWORK,
      LOCATION,
      TIMEZONE,
      LANGUAGE,
      BROWSER,
      DNS,
      WEBRTC,
      serviceCheck("commerce_services", "商业服务", "商业"),
    ],
    serviceIds: ["shopify", "amazon", "paypal", "stripe"],
    serviceGroups: [
      {
        checkId: "commerce_services",
        serviceIds: ["shopify", "amazon", "paypal", "stripe"],
      },
    ],
    scoreReadiness: {
      requiredSignalGroups: [
        ["reputation", "network", "location", "browser"],
        ["commerce_services"],
        ["timezone", "language", "dns", "webrtc"],
      ],
    },
    criticalRules: [strictUsLocationRule()],
  },
  {
    id: "ai_worker",
    name: "AI Worker",
    icon: "🤖",
    description: "分析数字环境与国际 AI 开发者常见工作环境的匹配程度。",
    target: {
      label: "国际 AI 开发者",
      summarySubject: "国际 AI 开发者画像",
      geography: { mode: "any", countryCodes: [], label: "不限定单一国家" },
      languageTags: [],
      timezonePrefixes: [],
      networkTraits: ["stable", "developer"],
    },
    weights: {
      ai_services: 35,
      developer_services: 20,
      reputation: 10,
      network: 5,
      dns: 10,
      webrtc: 5,
      browser: 5,
      location: 10,
    },
    checks: [
      serviceCheck("ai_services", "AI 服务", "AI"),
      serviceCheck("developer_services", "开发者生态", "开发者生态"),
      REPUTATION,
      NETWORK,
      DNS,
      WEBRTC,
      BROWSER,
      LOCATION_CONSISTENCY,
    ],
    serviceIds: [
      "openai",
      "claude",
      "gemini",
      "cursor",
      "perplexity",
      "github",
      "npm",
      "pypi",
    ],
    serviceGroups: [
      {
        checkId: "ai_services",
        serviceIds: ["openai", "claude", "gemini", "cursor", "perplexity"],
      },
      {
        checkId: "developer_services",
        serviceIds: ["github", "npm", "pypi"],
      },
    ],
    scoreReadiness: {
      requiredSignalGroups: [
        ["ai_services", "developer_services"],
        ["reputation", "network", "dns", "webrtc", "browser", "location"],
      ],
    },
    criticalRules: [],
  },
];

export const IDENTITY_PROFILE_LIST = deepFreeze(profiles);

export const IDENTITY_PROFILES = deepFreeze(
  Object.fromEntries(IDENTITY_PROFILE_LIST.map((profile) => [profile.id, profile])),
);

export function getIdentityProfile(profileId) {
  if (typeof profileId !== "string") return null;
  return IDENTITY_PROFILES[profileId] ?? null;
}
