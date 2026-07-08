# AI Signal Guard v1.0.0

首个可公开推广版本。

## 亮点

- 纯静态浏览器端应用，无需后端和构建步骤。
- 综合信任分：把出口 IP、DNS、WebRTC、AI 路径、语言、时区、字体、Emoji 等信号合并成可解释评分。
- 出口 IP 质量检测：识别中国口径、机房 / VPN / 代理池特征。
- 8 源 IP 情报交叉：对比 IP 地理、ASN、组织信息，发现冲突。
- DNS 泄漏检测：支持标准检测和深度检测。
- WebRTC 泄漏检测：区分公网候选、内网候选和 mDNS 隐藏地址。
- AI 路径检测：覆盖 Cloudflare 基准、ChatGPT、OpenAI Platform、Claude、Anthropic Console、Perplexity。
- AI 服务状态：读取 OpenAI / Claude 官方状态 API。
- 浏览器指纹：展示 UserAgent、平台、屏幕、硬件、Canvas、Audio 等网页可见字段。
- 隐私模式：截图交流时可模糊 IP、组织、DNS 等敏感字段。
- 诊断摘要复制：只复制评分和风险类别，不包含 IP、DNS、组织和指纹值。
- 右下角复制摘要：只复制评分和风险类别，不包含 IP、DNS、组织和指纹值。

## 在线体验

https://betaer.github.io/AISignalGuard/

## 仓库

https://github.com/betaer/AISignalGuard

## 隐私边界

本项目没有自建后端。语言、时区、字体、Emoji 和浏览器指纹在本地计算；出口 IP、多源情报、DNS 泄漏、WebRTC STUN、AI 路径和服务状态检测会访问对应第三方服务。

## 已知限制

- 评分是启发式参考，不代表任何平台的真实风控结论。
- 浏览器无法执行 traceroute，路由追踪需要用户在本机终端手动运行命令。
- DNS 泄漏检测依赖第三方服务，可因网络阻断、限流或跨源失败而无法完成。
- AI 路径检测只能反映当前浏览器网络到公开探针的结果，不能覆盖所有平台内部策略。

## 推荐发布文案

> AI Signal Guard v1.0.0：浏览器端 AI 账号网络与身份信号体检工具。一次检查 IP、DNS、WebRTC、语言时区、AI 路径、服务状态和浏览器指纹，纯静态、开箱即用。
