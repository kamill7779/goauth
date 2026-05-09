# 业务系统接入指南

本文面向需要接入 Goauth SSO 的业务系统。推荐方式是使用 OIDC Authorization Code + PKCE 获取用户身份，再通过 JWKS 校验 token，并在服务端按需调用权限校验接口。

## 1. 获取 Discovery

业务系统只需要配置 Goauth 的外部地址，例如本地 Compose：

```text
http://localhost:8080
```

启动后读取 OIDC discovery：

```http
GET http://localhost:8080/.well-known/openid-configuration
```

关键字段：

| 字段 | 用途 |
| --- | --- |
| `issuer` | token `iss` 必须等于该值。 |
| `authorization_endpoint` | 浏览器跳转授权入口。 |
| `token_endpoint` | 后端用 code 换 token。 |
| `userinfo_endpoint` | 用 access token 拉取用户资料。 |
| `jwks_uri` | 校验 JWT 签名的公钥集合。 |

`PUBLIC_ISSUER_URL` 必须配置成业务系统能访问的地址，否则 discovery 和 token `iss` 会不一致。

## 2. 准备 OAuth Client

当前服务没有公开的动态 client 注册 HTTP 接口。联调时需要由管理端、初始化脚本或后台任务写入 OAuth client 记录，字段含义如下：

| 字段 | 建议值 |
| --- | --- |
| `client_id` | 业务系统唯一标识，例如 `billing-web`。 |
| `client_secret` | 只保存在服务端，前端不要持有。 |
| `redirect_uris` | 精确匹配回调地址，例如 `http://localhost:3000/callback`。 |
| `allowed_scopes` | 至少包含 `openid`，常用 `openid profile email offline_access`。 |
| `grant_types` | 至少包含 `authorization_code`；如果业务需要长期会话和 refresh token，还要同时配置 `refresh_token`。 |
| `token_endpoint_auth_method` | `client_secret_post` 或 `client_secret_basic`。 |

## 3. Authorization Code + PKCE

业务前端生成 `code_verifier`，再生成 `S256` 方式的 `code_challenge`：

```text
code_challenge = BASE64URL(SHA256(code_verifier))
```

浏览器跳转到授权端点：

```http
GET /oauth2/authorize?
  response_type=code&
  client_id=billing-web&
  redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&
  scope=openid%20profile%20email%20offline_access&
  state=<random-state>&
  nonce=<random-nonce>&
  code_challenge=<challenge>&
  code_challenge_method=S256
```

注意事项：

- `redirect_uri` 必须和 client 注册值完全一致。
- `scope` 必须包含 `openid`。
- 用户浏览器可以直接访问 `/oauth2/authorize`。如果还没有 `goauth_oidc_session` cookie，GoAuth 会自动跳转到内置 `/oauth2/login` 页面，登录成功后继续原始授权请求。
- 非浏览器调用方如果直接请求授权端点，在缺少登录态时仍会收到 `login_required` JSON 错误。
- 本地 HTTP 调试如果遇到 Secure Cookie 不写入，建议通过 HTTPS 反向代理或浏览器信任的本地域名测试完整登录跳转。
- 回调时业务系统必须校验 `state`，并用 `nonce` 校验 ID Token。

## 4. 用 Code 换 Token

业务后端调用 token endpoint，使用 `application/x-www-form-urlencoded`：

```http
POST /oauth2/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&
client_id=billing-web&
client_secret=<client-secret>&
code=<authorization-code>&
redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&
code_verifier=<raw-code-verifier>
```

返回包含：

| 字段 | 用途 |
| --- | --- |
| `access_token` | 调用 userinfo 或业务后端鉴权。 |
| `id_token` | 登录态身份断言，给业务系统建立本地会话。 |
| `refresh_token` | 仅当请求了 `offline_access`，且 client 的 `grant_types` 包含 `refresh_token` 时返回；用于刷新会话，需安全保存。 |
| `expires_in` | access token 有效秒数。 |

如果 client 使用 `client_secret_basic`，则用 HTTP Basic 传 client 凭证，不要同时在表单里传 `client_id/client_secret`。

## 5. 校验 JWKS 和 Token

业务后端应从 `jwks_uri` 拉取公钥并缓存，按 JWT header 的 `kid` 选择 key。校验要求：

- 签名算法只接受 `RS256`。
- `iss` 必须等于 discovery 返回的 `issuer`。
- `aud` 必须包含本业务的 `client_id`。
- 校验 `exp`、`nbf`、`iat`。
- 校验登录回调时保存的 `nonce`。
- 根据需要读取 `sub`、`email`、`name`、`scope`、`tid`、`sid`。

本地开发如果未配置 `JWT_PRIVATE_KEY_PATH`，服务重启会生成新的临时 RSA key，业务系统需要刷新 JWKS 缓存。

## 6. 获取用户信息

```http
GET /oauth2/userinfo
Authorization: Bearer <access_token>
```

返回字段受 scope 控制：`openid` 返回 `sub`，`email` 返回邮箱，`profile` 返回展示名。

## 7. 调用权限校验

业务后端可以调用 RBAC 权限检查：

```http
POST /v1/authz/check
Authorization: Bearer <system-access-token>
Content-Type: application/json

{
  "user_id": 123,
  "tenant_id": 1,
  "permission": "project:read"
}
```

返回：

```json
{
  "success": true,
  "data": {
    "allowed": true
  }
}
```

`/v1/authz/check` 用于服务端到服务端调用，调用方 token 对应用户必须是系统用户或具有系统角色。普通用户查询自己的权限可调用：

```http
GET /v1/tenants/{tenant_id}/my-permissions
Authorization: Bearer <user-access-token>
```

业务系统建议在服务端缓存权限结果，缓存时间不要超过 access token 剩余有效期；遇到 401/403 时应重新登录或重新获取服务端凭证。
