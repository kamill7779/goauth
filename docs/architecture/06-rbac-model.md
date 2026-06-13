# 06 — RBAC Model

GoAuth 基于租户的 RBAC 权限模型和权限检查流程。

## 权限模型关系图

```mermaid
graph LR
    subgraph "全局"
        Perm["Permission<br/>code: 'user:read'<br/>resource + action"]
    end

    subgraph "租户 Tenant A"
        direction TB
        UserA1[User]
        UserA2[User]
        TmA1[TenantMember<br/>status=active<br/>permission_version]
        TmA2[TenantMember]
        RoleAdmin[Role: admin<br/>is_system=false]
        RoleMember[Role: member<br/>is_system=false]
        RpAdmin[RolePermission]
        RpMember[RolePermission]
        MrA1[MemberRole]
        MrA2[MemberRole]

        UserA1 --> TmA1
        UserA2 --> TmA2
        TmA1 --> MrA1
        TmA2 --> MrA2
        MrA1 --> RoleAdmin
        MrA2 --> RoleMember
        RoleAdmin --> RpAdmin
        RoleMember --> RpMember
        RpAdmin --> Perm
        RpMember --> Perm
    end

    subgraph "租户 Tenant B (system)"
        UserS[User (系统用户)]
        TmS[TenantMember]
        RoleRoot[Role: root<br/>is_system=true]
        MrS[MemberRole]
        RpRoot[RolePermission]

        UserS --> TmS
        TmS --> MrS
        MrS --> RoleRoot
        RoleRoot --> RpRoot
        RpRoot --> Perm
    end
```

## 实体关系

```
User  (全局唯一)
  │
  │ 1:N
  ▼
TenantMember  (每租户最多一条记录，唯一约束 (tenant_id, user_id))
  │  - status: "active" | "disabled"
  │  - permission_version: 缓存版本号
  │
  │ 1:N
  ▼
MemberRole  (成员与角色的多对多映射)
  │
  │ N:1
  ▼
Role  (租户内，唯一约束 (tenant_id, code))
  │  - is_system: true = 受保护角色，不可被用户删除/禁用
  │
  │ 1:N
  ▼
RolePermission  (角色与权限的多对多映射)
  │
  │ N:1
  ▼
Permission  (全局唯一，code 如 "user:read")
  - resource: "user", "tenant", "oauth_client" ...
  - action: "read", "write", "delete", "admin"
  - code: "user:read", "tenant:admin" ...
```

## 权限检查流程

```mermaid
sequenceDiagram
    actor Biz as Business App
    participant Handler as rbac.Handler
    participant Svc as rbac.Service
    participant Redis as Redis
    participant DB as MySQL

    Biz->>Handler: POST /v1/authz/check {user_id, tenant_id, permission: "user:read"}
    Handler->>Handler: AuthMiddleware (JWT 验证)
    Handler->>Handler: SystemUserMiddleware (系统角色检查)
    Handler->>Svc: Can(userID, tenantID, "user:read")

    Svc->>Svc: ListPermissions(userID, tenantID)
    
    rect rgb(240, 255, 240)
        Note over Svc,Redis: Step 1: 查询 Redis 缓存
        Svc->>Redis: GET auth:permissions:<tenantID>:<userID>
        alt 缓存命中
            Redis-->>Svc: {version: 3, permissions: ["user:read","tenant:admin"]}
            Svc->>DB: 查询当前 permission_version (tenant_members)
            alt 版本匹配
                Note over Svc: 直接返回缓存 (命中率 ~99%)
            end
        end
    end

    rect rgb(255, 240, 240)
        Note over Svc,DB: Step 2: 版本不匹配 → DB 回源
        Svc->>DB: SELECT id FROM tenant_members WHERE tenant_id=? AND user_id=? AND status='active'
        DB-->>Svc: memberIDs
        Svc->>DB: SELECT DISTINCT role_id FROM member_roles WHERE member_id IN (?)
        DB-->>Svc: roleIDs
        Svc->>DB: 过滤 role 属于当前 tenant
        Svc->>DB: SELECT DISTINCT permission_id FROM role_permissions WHERE role_id IN (?)
        DB-->>Svc: permissionIDs
        Svc->>DB: SELECT DISTINCT code FROM permissions WHERE id IN (?) ORDER BY code
        DB-->>Svc: ["user:read", "tenant:admin", ...]
    end

    rect rgb(240, 240, 255)
        Note over Svc,Redis: Step 3: 写回缓存
        Svc->>DB: 重新读取 permission_version (乐观并发)
        Svc->>Redis: SET auth:permissions:<tenantID>:<userID> {version, permissions} EX 120
        Note over Svc: 如果 version 已变 → 丢弃写入，下次重算
    end

    Svc-->>Handler: ["user:read", "tenant:admin", ...]
    Handler->>Handler: 检查 "user:read" 是否在列表中
    Handler-->>Biz: {"allowed": true}
```

## 缓存失效机制

```mermaid
graph TD
    subgraph "触发操作"
        A1["GrantPermissions<br/>给角色分配权限"]
        A2["RevokePermission<br/>撤销权限"]
        A3["AssignRoles<br/>给成员分配角色"]
        A4["RemoveRole<br/>移除成员角色"]
        A5["RemoveMember<br/>移除成员"]
        A6["DeleteRole<br/>删除角色"]
        A7["UpdateTenant<br/>状态变更"]
    end

    subgraph "数据库操作"
        B1["UPDATE tenant_members<br/>SET permission_version = version + 1<br/>WHERE ..."]
    end

    subgraph "Redis 操作"
        C1["DEL auth:permissions:<tenantID>:<userID>"]
    end

    A1 --> B1
    A2 --> B1
    A3 --> B1
    A4 --> B1
    A5 --> B1
    A6 --> B1
    A7 --> B1

    A1 --> C1
    A2 --> C1
    A3 --> C1
    A4 --> C1
    A5 --> C1
    A6 --> C1
    A7 --> C1
```

## 系统用户

**不是单独的表**，是一种约定：

- 用户在 `"system"` 租户 (slug="system") 有一个活跃的 `TenantMember`
- 该成员持有一个 `Role`，其 `is_system = true` 或 `code ∈ ("root", "system-admin", "system_admin")`

**特权**：
- 可以通过 `SystemUserMiddleware`（访问 `/v1/admin/*` 等管理端点）
- **不能被 DisableUser**——保护角色检查 `isProtectedUser(userID)` 返回 true 时拒绝

**引导** (`user/service.go:MarkSystemUser`)：
1. Upsert `Tenant{slug:"system"}`
2. Upsert `TenantMember{user_id, tenant_id(system)}`
3. Upsert `Role{tenant_id, code:"root", is_system:true}`
4. Assign `MemberRole{member_id, role_id}`

## 受保护角色

角色 code 在以下列表中时不可被禁用对应的用户：

```go
var protectedRoleCodes = []string{"root", "system-admin", "system_admin"}
```

详见 `services/identity-service/internal/user/service.go:22`。
