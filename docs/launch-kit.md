# AI Signal Guard 发布物料

这份文档用于集中管理发布时要复制的标题、介绍和渠道文案。所有文案都避免“绕过风控、防封、保证可用”这类风险表达，统一强调网络诊断、隐私自查和安全研究。

## 核心角度

AI Signal Guard 不是单点 IP 查询，而是把浏览器和网络侧能被网页看到的信号放到同一个页面里：出口 IP、DNS、WebRTC、语言、时区、字体、Emoji、AI 站点路径、服务状态和浏览器指纹。用户打开网页后，可以看到一个可解释的综合信任分，并复制不含敏感值的诊断摘要。

## 一句话介绍

中文：

> AI Signal Guard 是一个纯前端 AI 账号网络与身份信号体检工具，打开网页即可检查 IP、DNS、WebRTC、语言时区、AI 路径和浏览器指纹是否自洽。

English:

> AI Signal Guard is a client-side browser and network signal analyzer for AI services, covering IP quality, DNS/WebRTC leaks, locale consistency, AI paths, service status, and browser fingerprints.

## GitHub About

Description:

> Client-side browser and network signal analyzer for AI services.

Website:

> https://betaer.github.io/AISignalGuard/

Topics:

```text
ai-signal
browser-analyzer
network-diagnostics
privacy-tools
ip-checker
dns-leak-test
webrtc-leak-test
browser-fingerprint
cloudflare-trace
ai-tools
static-site
github-pages
security-research
network-privacy
```

## Show HN

Title:

```text
Show HN: AI Signal Guard – a client-side browser and network signal analyzer
```

First comment:

```text
I built AI Signal Guard because checking only your current IP is not enough when diagnosing access to AI services.

The page runs as a static client-side app. It groups the browser-visible signals into one view:

- exit IP quality and 8-source IP intelligence comparison
- browser language, system timezone, Emoji and font weak signals
- WebRTC and DNS leak checks
- connectivity probes for AI services and common overseas/mainland sites
- Cloudflare path checks for ChatGPT, Claude, OpenAI Platform and Perplexity
- OpenAI / Claude status APIs
- browser fingerprint fields visible to regular web pages

There is no backend owned by this project. Some checks call third-party IP, DNS, STUN and status APIs, and the privacy panel lists those boundaries. The “copy diagnostic summary” button intentionally excludes IPs, DNS resolver addresses, organizations and fingerprint values so users can share a safe summary when asking for help.

Repo: https://github.com/betaer/AISignalGuard
Demo: https://betaer.github.io/AISignalGuard/
```

## V2EX

标题：

```text
做了一个浏览器端 AI 网络信号体检工具：一次看 IP、DNS、WebRTC、时区语言、AI 路径
```

正文：

```text
最近把一个自用的网络信号排查页整理成了开源项目：AI Signal Guard。

它不是只查“当前 IP 是哪里”，而是把网页能看到的浏览器和网络信号放在一起：

- 出口 IP 质量、ASN、组织、机房/VPN/代理池特征
- 8 个 IP 情报源交叉，方便看地理和 ASN 信息有没有冲突
- 浏览器语言、系统时区、Emoji、中文字体等弱信号
- WebRTC 候选地址和 DNS 泄漏
- ChatGPT / Claude / OpenAI Platform / Perplexity 的 AI 路径
- OpenAI / Claude 服务状态
- 浏览器指纹字段
- 隐私模式、不含 IP/DNS/指纹值的诊断摘要复制和结果图分享

项目是纯静态页面，GitHub Pages 直接托管，没有自建后端。部分联网检测会访问第三方 IP、DNS、STUN 和状态 API，页面里写了隐私边界。

在线体验：https://betaer.github.io/AISignalGuard/
GitHub：https://github.com/betaer/AISignalGuard

欢迎提 issue，尤其是不同网络环境下 DNS/WebRTC/AI 路径的误判样本。
```

## X / Twitter

短帖：

```text
I open-sourced AI Signal Guard.

It is a client-side browser/network signal checker for AI services:

- IP quality + 8-source IP intelligence
- DNS and WebRTC leak checks
- timezone/language consistency
- Cloudflare path checks for ChatGPT, Claude, OpenAI and Perplexity
- privacy-safe diagnostic summary

Demo: https://betaer.github.io/AISignalGuard/
GitHub: https://github.com/betaer/AISignalGuard
```

中文短帖：

```text
开源了 AI Signal Guard。

它不是普通 IP 查询，而是一个浏览器端 AI 网络信号体检页：

- 出口 IP + 8 源情报交叉
- DNS / WebRTC 泄漏
- 语言、时区、字体、Emoji 弱信号
- ChatGPT / Claude / OpenAI / Perplexity 的 AI 路径
- 隐私模式 + 不含敏感值的诊断摘要

体验：https://betaer.github.io/AISignalGuard/
GitHub：https://github.com/betaer/AISignalGuard
```

## 20 秒 Demo 脚本

```text
0-3s：打开首页，信任分开始检测。
3-7s：展开出口 IP 和身份一致性，展示评分不是只看 IP。
7-11s：展开 DNS / WebRTC，展示泄漏检测。
11-15s：跳到 AI 路径和 AI 状态，展示访问排障。
15-18s：开启隐私模式，敏感字段模糊。
18-20s：点击右下角复制摘要，切到 GitHub 仓库。
```

## 发布顺序

1. 先补 GitHub Topics、About、Social preview 和 `v1.0.0` release。
2. 在 X 或朋友圈小范围发，收一轮误判反馈。
3. 修反馈后发 V2EX。
4. README 和 demo 稳定后发 Show HN。
5. 有截图、GIF、用户反馈后再考虑 Product Hunt。

## 禁用措辞

- 不写“绕过风控”“防封”“保证账号安全”“保证可用”。
- 不写“检测你会不会被平台识别”。
- 不承诺评分等价于任何平台真实结论。
- 统一使用“网络诊断、隐私自查、安全研究、访问异常排障、信号一致性检查”。
