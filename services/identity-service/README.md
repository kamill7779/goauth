# Identity Service

GoAuth 的 SSO/身份后端服务。提供 REST API、OIDC Provider 端点、RBAC 权限校验。

## 快速启动

```powershell
cd services/identity-service
Copy-Item .env.example .env
docker compose up --build
```

```powershell
curl http://127.0.0.1:8080/healthz
curl http://127.0.0.1:8080/readyz
curl http://127.0.0.1:8080/.well-known/openid-configuration
```

## 技术栈

`Go 1.24` · `Gin` · `GORM v2` · `MySQL` · `Redis` · `RS256 JWT` · `bcrypt`

## 文档

- 完整文档: [../../docs/](../../docs/README.md)
- 架构设计: [../../docs/architecture/](../../docs/architecture/)
- 配置参考: [../../docs/deployment/configuration.md](../../docs/deployment/configuration.md)
- API 规范: [../../docs/api/openapi.yaml](../../docs/api/openapi.yaml)

## 运行测试

```powershell
go test ./... -count=1
go test -short ./...  # 仅单元测试
```
