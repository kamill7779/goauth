# GoAuth

GoAuth 是一个可独立部署的身份认证服务，面向后续新系统的脚手架场景。

当前规划中的能力包括：

- 以邮箱为主的注册与登录。
- Access Token 与 Refresh Token 的完整生命周期管理。
- 面向下游系统的 OAuth2 / OpenID Connect 提供方端点。
- 外部 OAuth2 身份提供方适配器，首个接入 GitHub。
- 基于 Redis 的验证码、限流、权限缓存与会话缓存。
- 以 MySQL 作为主权威数据库。

## 文档

- [设计文档](docs/design.md)
- [实现计划](docs/implementation-plan.md)
