# KeymasterMarketProtocol

Keymaster 市场目录读取协议。市场决定收录哪些发布，App 作者通过现有发布证明签署 App 身份和发布内容。v1 共用一个完整目录读取接口，适用于 Keymaster Web 钱包、Keymaster CLI 和第三方市场。

- [v1 协议](./spec/v1.md)
- 参考服务端为 `KeymasterAppMarket`。钱包同步、来源留存及接入要求维护在 BSV8_Engineering 的 `docs/KeymasterMarketProtocol/README.md`。

## 共用编解码库

Go 与 TS 各提供目录层校验流程：JSON 解析、每项渠道结构、双渠道公钥与版本一致性、按验签公钥去重，任一条目无效使整份响应无效。发布签名、规范 URL 与展示字段的真值规则由产品侧注入的验证器复用现有实现，本库不重实现发布证明格式。

- Go：`DecodeDirectory(raw, verifyURL, verifyFiles)`（module `github.com/bsv8/KeymasterMarketProtocol`）
- TS：`decodeDirectory(raw, verifyUrl, verifyFiles)`（package `keymaster-market-protocol`，入口 `dist/index.js`）

跨语言一致性由工程仓 `pnpm run parity:keymaster-market-protocol` 固定语料锁定。
