# OIDC 集成细节

本文记录 identity-service 当前支持的 OIDC 能力和限制，便于本机联调和业务系统接入。

## 端点

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/.well-known/openid-configuration` | OIDC discovery。 |
| `GET` | `/oauth2/jwks` | RS256 公钥集合。 |
| `GET` | `/oauth2/authorize` | Authorization Code 授权端点。 |
| `POST` | `/oauth2/token` | code 换 token。 |
| `GET` | `/oauth2/userinfo` | 根据 access token 返回用户信息。 |
| `POST` | `/oauth2/introspect` | token introspection，需 client 凭证。 |
| `POST` | `/oauth2/revoke` | 撤销 refresh token，需 client 凭证。 |
| `GET` | `/oauth2/logout` | 清理 OIDC cookie，可按 session 撤销 refresh token。 |

Discovery 中声明：

- `response_types_supported`: `code`
- `grant_types_supported`: `authorization_code`
- `id_token_signing_alg_values_supported`: `RS256`
- `token_endpoint_auth_methods_supported`: `client_secret_basic`, `client_secret_post`
- `code_challenge_methods_supported`: `plain`, `S256`

推荐业务系统只使用 `S256` PKCE。

## Scope

| Scope | 说明 |
| --- | --- |
| `openid` | 必填，用于 OIDC 登录。 |
| `profile` | 在 ID Token/access token/userinfo 中返回展示名。 |
| `email` | 返回邮箱和邮箱验证状态。 |
| `offline_access` | 表示业务希望获得长期会话能力。 |

当前 token endpoint 在授权码交换成功后会返回 refresh token。业务系统仍应只在需要长期会话时申请 `offline_access`，并把 refresh token 放在服务端安全存储。

## Client 注册

当前没有公开动态注册端点。创建 client 时需要保证：

- `client_id` 全局唯一。
- `client_secret` 只保存 hash，明文只在创建时交付给业务系统。
- `redirect_uris` 精确保存允许回调地址，授权时完全匹配。
- `allowed_scopes` 覆盖业务需要的 scope，至少包含 `openid`。
- `grant_types` 包含 `authorization_code`。
- `token_endpoint_auth_method` 只能是 `client_secret_basic` 或 `client_secret_post`。

服务端会拒绝未知 client、禁用 client、不匹配 redirect URI、不允许的 scope 和未启用的 grant type。

## Authorization Endpoint

请求参数：

| 参数 | 必填 | 说明 |
| --- | --- | --- |
| `response_type` | 是 | 只能是 `code`。 |
| `client_id` | 是 | 已注册 client。 |
| `redirect_uri` | 是 | 必须和注册值完全一致。 |
| `scope` | 是 | 空格分隔，必须包含 `openid`。 |
| `state` | 建议 | 防 CSRF，业务回调时校验。 |
| `nonce` | 建议 | 绑定 ID Token，业务回调时校验。 |
| `code_challenge` | 是 | PKCE challenge。 |
| `code_challenge_method` | 是 | 推荐 `S256`。未传时按 `plain` 处理。 |

授权端点要求浏览器已经有有效的 `goauth_oidc_session` cookie，并且用户属于 client 所属租户。未登录返回 `login_required`，无租户权限返回 `access_denied`。

## Token Endpoint

只支持 `authorization_code`：

```http
POST /oauth2/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=<code>&redirect_uri=<redirect_uri>&code_verifier=<verifier>
```

Client 认证方式：

- `client_secret_post`: 表单传 `client_id` 和 `client_secret`。
- `client_secret_basic`: `Authorization: Basic base64(client_id:client_secret)`，表单里不要再传 client 凭证。

成功响应包含 `access_token`、`id_token`、`refresh_token`、`token_type=Bearer`、`expires_in` 和 `scope`。授权码只能使用一次，过期或 PKCE 校验失败会返回 `invalid_grant`。

## JWKS 与 Token 校验

`/oauth2/jwks` 返回单个 RSA 公钥，`alg=RS256`，`kid` 来自 `JWT_KEY_ID`。如果本地开发未配置 `JWT_PRIVATE_KEY_PATH`，服务重启会换 key，调用方需要重新拉取 JWKS。

校验 ID Token：

- `iss` 等于 `PUBLIC_ISSUER_URL` 去掉末尾斜杠后的值。
- `aud` 包含 `client_id`。
- `exp`、`nbf`、`iat` 在有效窗口内。
- `nonce` 等于授权请求中的 nonce。

校验 access token 时，还要关注 `scope`、`client_id`、`tid`、`sid`、`ver`。identity-service 自己在受保护接口中还会实时校验用户状态、session 状态和租户成员状态，因此 logout、禁用用户、移除租户成员会立即生效。

## UserInfo

```http
GET /oauth2/userinfo
Authorization: Bearer <access_token>
```

返回示例：

```json
{
  "sub": "123",
  "email": "user@example.com",
  "email_verified": true,
  "name": "User"
}
```

缺少 `email` 或 `profile` scope 时，对应字段不会返回。

## Introspect

```http
POST /oauth2/introspect
Content-Type: application/x-www-form-urlencoded

client_id=<client_id>&client_secret=<secret>&token=<token>
```

可用于服务端校验 access token 或 refresh token 是否仍然有效。返回 `active=false` 表示 token 无效、过期、client 不匹配或实时状态校验失败。

## Revoke

```http
POST /oauth2/revoke
Content-Type: application/x-www-form-urlencoded

client_id=<client_id>&client_secret=<secret>&token=<refresh_token>
```

当前撤销逻辑主要作用于 refresh token。接口对空 token 或不存在 token 也返回成功，便于客户端做幂等退出。

## Logout

```http
GET /oauth2/logout?client_id=<client_id>&post_logout_redirect_uri=<redirect_uri>
```

行为：

- 清理 `goauth_oidc_session` cookie。
- 如果能从 cookie 或 `session_id` 参数解析出会话，会撤销该 session 下未撤销的 refresh token。
- 传 `session_id` 时必须和 cookie 中 session 一致。
- 传 `post_logout_redirect_uri` 时必须提供 `client_id`，并且 redirect URI 必须属于该 client 的已注册 redirect URI。

业务系统自己的 session 也要同步清理，不能只依赖 Goauth logout。
