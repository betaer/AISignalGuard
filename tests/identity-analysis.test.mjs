import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  IDENTITY_PROFILES,
  IDENTITY_PROFILE_LIST,
  getIdentityProfile,
} from "../identityProfiles.js";
import {
  IDENTITY_SCORE_BANDS,
  IDENTITY_MIN_COVERAGE,
  IDENTITY_PENDING_BAND,
  IDENTITY_SIGNAL_STATUSES,
  analyzeIdentity,
  getIdentityScoreBand,
} from "../identityAnalysis.js";

const EXPECTED_PROFILE_IDS = [
  "generic",
  "us_consumer",
  "tiktok_creator",
  "cross_border_seller",
  "ai_worker",
];

const BLOCKED_COPY = ["\u4f2a\u88c5", "\u5047\u8eab\u4efd", "\u6b3a\u9a97", "\u5192\u5145"];

function matchAll(profile, confidence = 1) {
  return Object.fromEntries(
    profile.checks.map((check) => [
      check.id,
      {
        status: "match",
        confidence,
        evidence: `${check.label}\u7684\u68c0\u6d4b\u8bc1\u636e`,
      },
    ]),
  );
}

test("提供 5 个完整且唯一的身份画像（通用画像 + 4 个兼容画像）", () => {
  assert.deepEqual(
    IDENTITY_PROFILE_LIST.map((profile) => profile.id),
    EXPECTED_PROFILE_IDS,
  );
  assert.deepEqual(Object.keys(IDENTITY_PROFILES), EXPECTED_PROFILE_IDS);

  for (const profile of IDENTITY_PROFILE_LIST) {
    assert.equal(getIdentityProfile(profile.id), profile);
    assert.equal(typeof profile.name, "string");
    assert.equal(typeof profile.icon, "string");
    assert.equal(typeof profile.description, "string");
    assert.equal(typeof profile.target, "object");
    assert.ok(Array.isArray(profile.checks));
    assert.ok(Array.isArray(profile.serviceIds));
    assert.ok(Array.isArray(profile.serviceGroups));
    assert.ok(Array.isArray(profile.criticalRules));
    assert.ok(Array.isArray(profile.scoreReadiness.requiredSignalGroups));
    assert.ok(profile.checks.length > 0);

    const checkIds = profile.checks.map((check) => check.id);
    assert.equal(new Set(checkIds).size, checkIds.length);
    assert.deepEqual(Object.keys(profile.weights), checkIds);
    assert.equal(
      Object.values(profile.weights).reduce((sum, weight) => sum + weight, 0),
      100,
      `${profile.id} \u7684\u6743\u91cd\u5e94\u5408\u8ba1 100`,
    );
    const serviceCheckIds = new Set(profile.serviceGroups.map((group) => group.checkId));
    assert.equal(serviceCheckIds.size, profile.serviceGroups.length);
    for (const group of profile.serviceGroups) {
      assert.ok(checkIds.includes(group.checkId), `${profile.id}/${group.checkId} 必须对应一个评分检查`);
      assert.ok(group.serviceIds.length > 0);
      assert.ok(group.serviceIds.every((serviceId) => profile.serviceIds.includes(serviceId)));
    }
    assert.ok(
      profile.serviceGroups
        .flatMap((group) => group.serviceIds)
        .every((serviceId) => profile.serviceIds.includes(serviceId)),
      `${profile.id} 的评分服务必须属于完整探测清单`,
    );
    for (const signalGroup of profile.scoreReadiness.requiredSignalGroups) {
      assert.ok(signalGroup.length > 0);
      assert.ok(
        signalGroup.every((signalId) => checkIds.includes(signalId)),
        `${profile.id} 的正式评分门槛只能引用自身检查`,
      );
    }
  }

  assert.equal(getIdentityProfile("missing"), null);
  assert.equal(getIdentityProfile("enterprise_employee"), null);
});

test("\u753b\u50cf\u914d\u7f6e\u4e0e\u5168\u5206\u6bb5\u6587\u6848\u4e0d\u5305\u542b\u8d1f\u9762\u8868\u8fbe\u6216\u771f\u5b9e\u8eab\u4efd\u65ad\u8a00", () => {
  const configuredCopy = JSON.stringify(IDENTITY_PROFILE_LIST);
  const resultCopy = JSON.stringify(EXPECTED_PROFILE_IDS.flatMap((profileId) => {
    const profile = getIdentityProfile(profileId);
    return ["match", "partial", "mismatch", "unknown"].map((status) =>
      analyzeIdentity(
        profileId,
        Object.fromEntries(profile.checks.map((check) => [check.id, { status, confidence: 1 }])),
      ),
    );
  }));
  const staticHtml = readFileSync(new URL("../index.html", import.meta.url), "utf8");
  const allUserFacingCopy = configuredCopy + resultCopy + staticHtml;

  for (const phrase of BLOCKED_COPY) {
    assert.equal(allUserFacingCopy.includes(phrase), false, `用户文案出现禁用词：${phrase}`);
  }
  assert.doesNotMatch(configuredCopy, /服务仍受(?:浏览器或网络策略)?限制|状态受限/);
  assert.doesNotMatch(allUserFacingCopy, /你就是(?:美国人|美国用户|创作者|卖家|开发者|企业员工)/);
  assert.doesNotMatch(allUserFacingCopy, /你是(?:一位|一个)?(?:美国人|美国用户|创作者|卖家|开发者|企业员工)/);
});

test("画像精确声明需求中的服务及其评分分组", () => {
  const expected = {
    generic: { services: ["google", "youtube", "whatsapp", "reddit"] },
    us_consumer: { consumer_services: ["google", "youtube", "netflix", "chatgpt"] },
    tiktok_creator: {
      creator_services: ["tiktok", "youtube", "instagram", "x"],
      ads_environment: ["google_ads", "meta_ads"],
    },
    cross_border_seller: { commerce_services: ["shopify", "amazon", "paypal", "stripe"] },
    ai_worker: {
      ai_services: ["chatgpt", "openai", "claude", "gemini", "perplexity"],
    },
  };

  for (const [profileId, groups] of Object.entries(expected)) {
    assert.deepEqual(
      Object.fromEntries(getIdentityProfile(profileId).serviceGroups.map((group) => [group.checkId, group.serviceIds])),
      groups,
    );
  }

  assert.deepEqual(getIdentityProfile("generic").serviceIds, ["google", "youtube", "whatsapp", "reddit"]);
  assert.equal(getIdentityProfile("generic").serviceIds.includes("chatgpt"), false);
  assert.deepEqual(getIdentityProfile("tiktok_creator").serviceIds, [
    "tiktok",
    "youtube",
    "instagram",
    "x",
    "google_ads",
    "meta_ads",
  ]);
  assert.deepEqual(getIdentityProfile("cross_border_seller").serviceIds, [
    "shopify",
    "amazon",
    "paypal",
    "stripe",
  ]);
});

test("面向用户的画像名称覆盖更广泛的使用场景", () => {
  assert.equal(getIdentityProfile("ai_worker").name, "AI 用户");
  assert.equal(getIdentityProfile("tiktok_creator").name, "自媒体创作者");
  assert.equal(getIdentityProfile("cross_border_seller").name, "跨境商家");

  const aiProfileCopy = JSON.stringify(getIdentityProfile("ai_worker"));
  assert.doesNotMatch(aiProfileCopy, /AI Worker|AI 工作者|AI 开发者|开发者生态/);
});

test("AI 用户画像只以 AI 服务作为评分核心，开发者工具仅作补充探测", () => {
  const profile = getIdentityProfile("ai_worker");
  const checkIds = profile.checks.map((check) => check.id);

  assert.deepEqual(profile.serviceGroups, [
    {
      checkId: "ai_services",
      serviceIds: ["chatgpt", "openai", "claude", "gemini", "perplexity"],
    },
  ]);
  assert.deepEqual(profile.serviceIds, [
    "chatgpt",
    "openai",
    "claude",
    "gemini",
    "perplexity",
    "cursor",
    "github",
    "npm",
  ]);
  assert.equal(checkIds.includes("developer_services"), false);
  assert.equal(Object.hasOwn(profile.weights, "developer_services"), false);
  assert.equal(profile.weights.ai_services, 50);
  assert.deepEqual(profile.scoreReadiness.requiredSignalGroups, [
    ["ai_services"],
    ["reputation", "network"],
    ["dns", "webrtc", "browser", "location"],
  ]);
  assert.equal(profile.scoreReadiness.minCoverage, 40);
});

test("\u5b8c\u5168\u5339\u914d\u65f6\u8fd4\u56de 100 \u5206\u3001100% \u8986\u76d6\u7387\u548c\u6309\u5f71\u54cd\u6392\u5e8f\u7684\u6b63\u5411\u7406\u7531", () => {
  const profile = getIdentityProfile("us_consumer");
  const result = analyzeIdentity(profile.id, matchAll(profile));

  assert.equal(result.score, 100);
  assert.equal(result.scoreBeforeCaps, 100);
  assert.equal(result.coverage, 100);
  assert.equal(result.band.id, "high");
  assert.match(result.summary, /\u73af\u5883|\u4fe1\u53f7|\u753b\u50cf/);
  assert.equal(result.like.length, profile.checks.length);
  assert.equal(result.unlike.length, 0);
  assert.equal(result.pending.length, 0);
  assert.equal(result.caps.length, 0);
  assert.ok(result.like.every((item, index, list) => index === 0 || list[index - 1].impact >= item.impact));
});

test("\u672a\u77e5\u4fe1\u53f7\u56de\u5f52\u4e2d\u6027\u4f46\u4e0d\u8f93\u51fa\u6b63\u5f0f\u5206\u6570", () => {
  const profile = getIdentityProfile("generic");
  const result = analyzeIdentity(profile.id, {});

  assert.equal(result.score, null);
  assert.equal(result.scoreBeforeCaps, null);
  assert.equal(result.estimatedScore, 50);
  assert.equal(result.isScoreReady, false);
  assert.equal(result.coverage, 0);
  assert.equal(result.band, IDENTITY_PENDING_BAND);
  assert.equal(result.like.length, 0);
  assert.equal(result.unlike.length, 0);
  assert.equal(result.pending.length, profile.checks.length);
  assert.equal(result.details.every((detail) => detail.status === "unknown"), true);
  assert.match(result.summary, /\u8bc1\u636e|\u4fe1\u53f7|\u5f85\u786e\u8ba4/);
});

test("AI 用户缺少 AI 服务核心证据时不提前输出正式分数", () => {
  const profile = getIdentityProfile("ai_worker");
  const signals = Object.fromEntries(profile.checks.map((check) => [check.id, { status: "unknown" }]));
  for (const signalId of profile.checks.map((check) => check.id).filter((id) => id !== "ai_services")) {
    signals[signalId] = { status: "match", confidence: 1, evidence: `${signalId} \u5df2\u786e\u8ba4` };
  }

  const result = analyzeIdentity(profile.id, signals);

  assert.equal(result.coverage, 50);
  assert.equal(result.readiness.coverageReady, true);
  assert.equal(result.readiness.coreSignalsReady, false);
  assert.deepEqual(result.readiness.missingSignalGroups, [["ai_services"]]);
  assert.equal(result.isScoreReady, false);
  assert.equal(result.score, null);
  assert.equal(result.band, IDENTITY_PENDING_BAND);
});

test("\u7f6e\u4fe1\u5ea6\u4f7f\u5df2\u77e5\u7ed3\u679c\u5411\u4e2d\u6027\u5206\u56de\u5f52", () => {
  const profile = getIdentityProfile("generic");
  const highConfidence = analyzeIdentity(profile.id, matchAll(profile, 1));
  const lowConfidence = analyzeIdentity(profile.id, matchAll(profile, 0.3));

  assert.equal(highConfidence.score, 100);
  assert.equal(lowConfidence.score, 65);
  assert.equal(lowConfidence.coverage, 30);
  assert.ok(lowConfidence.score > 50);
  assert.ok(lowConfidence.score < highConfidence.score);
});

test("\u76f8\u540c\u4fe1\u53f7\u5728\u4e0d\u540c\u76ee\u6807\u753b\u50cf\u4e0b\u6309\u52a8\u6001\u6743\u91cd\u8ba1\u5206", () => {
  const genericProfile = getIdentityProfile("generic");
  const aiProfile = getIdentityProfile("ai_worker");
  const genericSignals = Object.fromEntries(
    genericProfile.checks.map((check) => [check.id, { status: "unknown" }]),
  );
  const aiSignals = Object.fromEntries(
    aiProfile.checks.map((check) => [check.id, { status: "unknown" }]),
  );

  for (const id of ["location", "network", "reputation"]) {
    if (genericSignals[id]) genericSignals[id] = { status: "partial", confidence: 1 };
    if (aiSignals[id]) aiSignals[id] = { status: "partial", confidence: 1 };
  }

  genericSignals.services = { status: "match", confidence: 1, evidence: "\u670d\u52a1\u8fde\u901a" };
  aiSignals.ai_services = { status: "match", confidence: 1, evidence: "AI \u670d\u52a1\u8fde\u901a" };

  const genericResult = analyzeIdentity("generic", genericSignals);
  const aiResult = analyzeIdentity("ai_worker", aiSignals);

  assert.equal(genericProfile.weights.services, 5);
  assert.equal(aiProfile.weights.ai_services, 50);
  assert.equal(genericResult.isScoreReady, true);
  assert.equal(aiResult.isScoreReady, true);
  assert.equal(genericResult.score, 57);
  assert.equal(aiResult.score, 78);
  assert.ok(aiResult.score > genericResult.score);
});

test("\u90e8\u5206\u5339\u914d\u4e0e\u4e0d\u5339\u914d\u4f1a\u8fdb\u5165\u5dee\u5f02\u5206\u6790\uff0c\u5e76\u6309\u6743\u91cd\u5f71\u54cd\u6392\u5e8f", () => {
  const profile = getIdentityProfile("cross_border_seller");
  const signals = matchAll(profile);
  signals.commerce_services = {
    status: "partial",
    confidence: 0.9,
    evidence: "\u90e8\u5206\u5546\u4e1a\u670d\u52a1\u53ef\u8fbe",
  };
  signals.language = {
    status: "mismatch",
    confidence: 1,
    evidence: "\u8bed\u8a00\u4e0e\u76ee\u6807\u8bbe\u7f6e\u4e0d\u4e00\u81f4",
  };

  const result = analyzeIdentity(profile.id, signals);

  assert.deepEqual(result.partial.map((item) => item.id), ["commerce_services"]);
  assert.deepEqual(result.unlike.map((item) => item.id), ["language"]);
  assert.deepEqual(result.differences.map((item) => item.id), ["commerce_services", "language"]);
  assert.ok(result.advice.length >= 2);
  assert.equal(result.advice[0].id, "commerce_services");
  assert.ok(result.details.find((item) => item.id === "commerce_services").scoreContribution < 25);
});

test("\u660e\u786e\u7684\u76ee\u6807\u5730\u7406\u51b2\u7a81\u4f1a\u900f\u660e\u89e6\u53d1\u5206\u6570\u4e0a\u9650", () => {
  const profile = getIdentityProfile("us_consumer");
  const signals = matchAll(profile);
  signals.location = {
    status: "mismatch",
    confidence: 0.95,
    evidence: "\u51fa\u53e3\u5730\u533a\u4e0e\u7f8e\u56fd\u76ee\u6807\u4e0d\u4e00\u81f4",
  };

  const result = analyzeIdentity(profile.id, signals);

  assert.ok(result.scoreBeforeCaps > 69);
  assert.equal(result.score, 69);
  assert.equal(result.caps.length, 1);
  assert.equal(result.caps[0].ruleId, "target_region_conflict");
  assert.equal(result.caps[0].cap, 69);
  assert.match(result.caps[0].reason, /\u76ee\u6807\u5730\u533a|\u5730\u7406/);
});

test("\u5730\u7406\u5dee\u5f02\u7f6e\u4fe1\u5ea6\u4e0d\u8db3\u65f6\u4e0d\u89e6\u53d1\u5173\u952e\u4e0a\u9650", () => {
  const profile = getIdentityProfile("us_consumer");
  const signals = matchAll(profile);
  signals.location = {
    status: "mismatch",
    confidence: 0.4,
    evidence: "\u5730\u7406\u6765\u6e90\u4e4b\u95f4\u4ecd\u6709\u5dee\u5f02",
  };

  const result = analyzeIdentity(profile.id, signals);

  assert.equal(result.score, result.scoreBeforeCaps);
  assert.equal(result.caps.length, 0);
});

test("\u8bc4\u5206\u5206\u6bb5\u8fb9\u754c\u4e3a 0/40/70/90/100", () => {
  assert.deepEqual(IDENTITY_SIGNAL_STATUSES, ["match", "partial", "mismatch", "unknown"]);
  assert.deepEqual(
    IDENTITY_SCORE_BANDS.map((band) => [band.id, band.min, band.max]),
    [
      ["low", 0, 39],
      ["mixed", 40, 69],
      ["close", 70, 89],
      ["high", 90, 100],
    ],
  );
  assert.equal(getIdentityScoreBand(0).id, "low");
  assert.equal(getIdentityScoreBand(39).id, "low");
  assert.equal(getIdentityScoreBand(40).id, "mixed");
  assert.equal(getIdentityScoreBand(69).id, "mixed");
  assert.equal(getIdentityScoreBand(70).id, "close");
  assert.equal(getIdentityScoreBand(89).id, "close");
  assert.equal(getIdentityScoreBand(90).id, "high");
  assert.equal(getIdentityScoreBand(100).id, "high");
  assert.equal(getIdentityScoreBand(null).id, "pending");
  assert.equal(IDENTITY_MIN_COVERAGE, 25);
});

test("\u65e0\u6548\u8f93\u5165\u88ab\u5b89\u5168\u5f52\u4e00\u5316\uff0c\u672a\u77e5\u753b\u50cf\u4f7f\u7528\u901a\u7528\u753b\u50cf", () => {
  const result = analyzeIdentity("not-a-profile", {
    location: {
      status: "unexpected",
      confidence: 8,
      evidence: "\u5f85\u786e\u8ba4",
    },
  });

  assert.equal(result.profile.id, "generic");
  assert.equal(result.details.find((detail) => detail.id === "location").status, "unknown");
  assert.equal(result.score, null);
  assert.ok(result.estimatedScore >= 0 && result.estimatedScore <= 100);
  assert.ok(result.coverage >= 0 && result.coverage <= 100);
});
