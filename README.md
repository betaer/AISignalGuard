# AI Signal Guard

浏览器端 AI 账号网络与身份信号体检工具。打开网页即可检查出口 IP、DNS/WebRTC 泄漏、语言时区一致性、AI 站点路径、服务状态和浏览器指纹，适合在使用 ChatGPT、Claude、Gemini、Perplexity 等服务前做一次自查。

[在线体验](https://betaer.github.io/AISignalGuard/) · [反馈问题](https://github.com/betaer/AISignalGuard/issues/new/choose) · [发布物料](docs/launch-kit.md)

![AI Signal Guard social preview](assets/social-preview.svg)

## 为什么要做

很多网络自查工具只告诉你“当前 IP 是哪里”。但 AI 服务、Cloudflare、网站脚本和风控系统能看到的不止 IP，还包括 DNS 解析器、WebRTC 候选地址、系统时区、浏览器语言、字体、Emoji 渲染、浏览器指纹、访问 AI 站点时的边缘路径等信号。

AI Signal Guard 的目标不是给出绝对结论，而是把这些浏览器可见信号放在一个页面里，让你快速判断当前环境是否自洽，排查“服务故障、网络不可达、DNS 泄漏、真实出口暴露、身份信号矛盾”等问题。

## 核心能力

| 模块 | 检查内容 | 用途 |
|---|---|---|
| 综合信任分 | 启发式 100 分评分、风险项摘要、评分规则 | 快速判断当前环境是否存在明显暴露信号 |
| 出口 IP | IP、地区、ASN、组织、机房/VPN/代理池特征 | 判断最核心的网络出口质量 |
| 身份一致性 | 浏览器语言、系统时区、Emoji、中文字体 | 检查环境画像是否前后矛盾 |
| WebRTC 泄漏 | STUN 候选地址、公网/内网/mDNS 分类 | 发现代理外真实公网地址暴露 |
| DNS 泄漏 | 标准/深度 DNS 泄漏检测、中国解析器识别 | 判断 DNS 是否跟随代理或隧道 |
| 网络连通 | AI 服务、境外站点、境内站点可达性 | 区分本地网络问题和服务不可用 |
| 多源交叉 | 8 个 IP 情报源互证 | 发现 IP 地理、ASN、组织信息冲突 |
| AI 路径 | ChatGPT、Claude、OpenAI、Perplexity 等 Cloudflare 路径 | 观察访问 AI 站点时的边缘出口 |
| AI 状态 | OpenAI / Claude 官方状态 API | 排除平台自身故障 |
| 浏览器指纹 | UserAgent、平台、屏幕、硬件、Canvas、Audio 等 | 查看网页脚本能读到的本机环境 |
| 路由追踪 | macOS / Windows / Linux 命令模板 | 用本机命令复核浏览器无法执行的路径追踪 |
| 复制摘要 | 脱敏诊断文本 | 分享评分、判定口径和风险类别，不带 IP / DNS / 指纹值 |

## 适合谁用

- 经常使用 ChatGPT、Claude、Gemini、Perplexity 的用户，想在登录前检查网络与浏览器信号。
- 需要排查“AI 服务打不开、时好时坏、只有某个站点异常”的用户。
- 网络、代理、隐私、安全研究人员，想快速看到浏览器侧可见信号。
- 需要截图交流的人：页面提供隐私模式，会模糊 IP、组织、DNS 等敏感字段。

## 隐私边界

AI Signal Guard 是纯静态页面，没有自建后端。

| 类型 | 是否离开浏览器 | 说明 |
|---|---:|---|
| 语言、时区、字体、Emoji、指纹 | 否 | 在本机浏览器内读取和计算 |
| 出口 IP、多源 IP 情报 | 是 | 会请求第三方 IP 情报接口 |
| WebRTC | 是 | 会访问 STUN 服务以观察候选地址 |
| DNS 泄漏 | 是 | 通过 bash.ws 等第三方 DNS 泄漏检测服务完成 |
| AI 路径、AI 状态 | 是 | 会请求对应公开探针或状态 API |
| 复制诊断摘要 | 否 | 摘要只包含评分、判定口径和风险类别，不复制 IP、DNS、组织和指纹值 |

## 快速使用

1. 打开 [https://betaer.github.io/AISignalGuard/](https://betaer.github.io/AISignalGuard/)。
2. 等待自动检测完成，先看综合信任分和风险摘要。
3. 展开红色或黄色项目，查看详细解释和规避建议。
4. 需要交流时开启“隐私模式”，或点击右下角“复制摘要”分享不含敏感值的诊断文本。

## 本地运行

项目没有构建步骤，直接打开 `index.html` 即可。需要模拟 GitHub Pages 环境时，可以在仓库根目录运行：

```bash
python3 -m http.server 8080
```

然后访问 `http://localhost:8080/`。

## 部署

项目根目录直接提供 `index.html`，GitHub Pages 使用 `main` 分支根目录发布即可。

## 仓库推广设置

建议在 GitHub 仓库设置中补齐：

- Topics：`ai-signal`、`browser-analyzer`、`network-diagnostics`、`privacy-tools`、`ip-checker`、`dns-leak-test`、`webrtc-leak-test`、`browser-fingerprint`、`cloudflare-trace`、`ai-tools`、`static-site`、`github-pages`、`security-research`、`network-privacy`
- Social preview：上传 `assets/social-preview.png`
- About：`Client-side browser and network signal analyzer for AI services.`
- Website：`https://betaer.github.io/AISignalGuard/`
- Release：发布 `v1.0.0`，文案可直接使用 [docs/release-v1.0.0.md](docs/release-v1.0.0.md)

## 路线图

- 结果截图导出，自动套用隐私模式。
- 更多 AI 站点路径和状态源。
- 检测结果 JSON 导出，便于自查归档。
- 英文界面切换，方便国际社区传播。
- 更细的移动网络、住宅网络、云厂商识别规则。

## 免责声明

本项目用于网络诊断、隐私自查和安全研究。评分为启发式参考，不代表任何平台的真实风控结论，也不承诺账号、服务或网络可用性。
