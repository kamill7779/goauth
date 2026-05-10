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
| `GET` | `/oauth2/logout` | 没有活动浏览器 SSO cookie 时可幂等退出；带活动 cookie 时只用于拿确认页。 |
| `POST` | `/oauth2/logout` | 提交浏览器退出确认表单，校验 CSRF 后撤销当前 OIDC session。 |

Discovery 中声明：

- `response_types_supported`: `code`
- `grant_types_supported`: `authorization_code`, `refresh_token`
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

当前 token endpoint 只会在两个条件都满足时返回 refresh token：

- 授权请求包含 `offline_access` scope。
- 对应 OAuth client 的 `grant_types` 显式包含 `refresh_token`。

业务系统仍应只在需要长期会话时申请 `offline_access`，并把 refresh token 放在服务端安全存储。

## Client 注册

当前没有公开动态注册端点。创建 client 时需要保证：

- `client_id` 全局唯一。
- `client_secret` 只保存 hash，明文只在创建时交付给业务系统。
- `redirect_uris` 精确保存允许回调地址，授权时完全匹配。
- `allowed_scopes` 覆盖业务需要的 scope，至少包含 `openid`。
- `grant_types` 包含 `authorization_code`。
- `token_endpoint_auth_method` 只能是 `client_secret_basic` 或 `client_secret_post`。
- 公共业务系统可开启 `auto_provision_members`，让活跃用户首次访问该 client 时自动加入 client 所属租户；内部系统建议关闭。
- 若需要“注册后默认入组”，在 GoAuth 运行配置中设置 `DEFAULT_MEMBER_TENANT_SLUGS`，由身份服务按租户 slug 对新用户执行通用 membership 初始化；下游业务系统不需要写 GoAuth 业务规则。

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

授权端点要求浏览器有有效的 `goauth_oidc_session` cookie，并且用户属于 client 所属租户。若 GoAuth 配置了 `DEFAULT_MEMBER_TENANT_SLUGS`，新用户创建时会先加入这些默认租户。若 client 开启 `auto_provision_members`，活跃用户首次授权时会被自动加入该 client 租户；被显式禁用或删除的租户成员不会被自动恢复。

- 浏览器导航请求如果缺少或持有失效 cookie，会被 `302` 跳到 `BROWSER_LOGIN_URL?return_to=...`，默认是 `/login?return_to=...`。
- `return_to` 只允许本地 `/oauth2/authorize?...` 路径，避免开放重定向。
- 非浏览器调用方仍会收到 JSON `login_required`，无租户权限返回 `access_denied`。

GoAuth 后端不托管登录/注册 UI。独立前端应调用 `POST /v1/auth/login` 完成登录；该接口返回 token pair，并设置 `goauth_oidc_session` cookie。前端登录成功后把浏览器跳回 `return_to`，继续原始 `/oauth2/authorize` 流程。

## Token Endpoint

支持 `authorization_code` 与 `refresh_token`：

```http
POST /oauth2/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=<code>&redirect_uri=<redirect_uri>&code_verifier=<verifier>
```

Client 认证方式：

- `client_secret_post`: 表单传 `client_id` 和 `client_secret`。
- `client_secret_basic`: `Authorization: Basic base64(client_id:client_secret)`，表单里不要再传 client 凭证。

授权码成功响应至少包含 `access_token`、`id_token`、`token_type=Bearer`、`expires_in` 和 `scope`；只有在请求了 `offline_access` 且 client 支持 `refresh_token` 时，才会额外返回 `refresh_token`。授权码只能使用一次，过期或 PKCE 校验失败会返回 `invalid_grant`。

Refresh Token 轮换：

```http
POST /oauth2/token
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token&refresh_token=<refresh_token>
```

如果 refresh token 已被撤销、复用检测击中，或对应登录 session 已失效，也会返回 `invalid_grant`。

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

- 如果请求携带当前 `goauth_oidc_session` cookie，且看起来像浏览器文档导航（例如 `Accept: text/html`、`Sec-Fetch-Mode: navigate` 或 `Sec-Fetch-Dest: document`），服务会先返回确认页，再通过 `POST /oauth2/logout` + CSRF token 完成退出。
- 其他仍然携带当前 `goauth_oidc_session` cookie 的 `GET /oauth2/logout` 请求会返回 `invalid_request`；这样同站非文档请求也不能直接触发登出。
- 清理 `goauth_oidc_session` cookie。
- 如果能从 cookie 或 `session_id` 参数解析出会话，会撤销该 session 下未撤销的 refresh token。
- 传 `session_id` 时必须和 cookie 中 session 一致。
- 传 `post_logout_redirect_uri` 时必须提供 `client_id`，并且 redirect URI 必须属于该 client 的已注册 redirect URI。

业务系统自己的 session 也要同步清理，不能只依赖 Goauth logout。
