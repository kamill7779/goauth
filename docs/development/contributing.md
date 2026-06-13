# Contributing

向 GoAuth 贡献代码的流程。

## 分支策略

```
main          ← 稳定分支，只通过 PR 合入
feat/<name>   ← 功能分支
fix/<name>    ← 修复分支
docs/<name>   ← 文档更新
```

## PR 流程

1. **创建 worktree** (并行开发建议):
   ```powershell
   git worktree add .worktrees/<branch-name> -b feat/<branch-name> main
   cd .worktrees/<branch-name>
   ```

2. **开发 + 测试**:
   ```powershell
   go test ./... -count=1
   ```

3. **提交**:
   ```
   type: brief summary (≤50 chars)
   
   Detailed explanation if needed.
   ```

   Type 必须是以下之一:
   - `feat:` — 新功能
   - `fix:` — Bug 修复
   - `refactor:` — 重构
   - `docs:` — 文档
   - `test:` — 测试
   - `chore:` — 构建/工具

4. **推送到远程**:
   ```powershell
   git push origin feat/<branch-name>
   ```

5. **合并到 main**:
   ```powershell
   git checkout main
   git merge feat/<branch-name> --no-edit
   git push origin main
   git worktree remove .worktrees/<branch-name> --force
   git branch -d feat/<branch-name>
   ```

## 代码审查要点

- [ ] 分层遵守: Handler → Service → Repository，没有越级调用
- [ ] 没有 `gin.Context` 泄漏到 Service 层
- [ ] Redis key 使用 `cache` 包的生成函数
- [ ] 密码/Token/Secret 不存明文
- [ ] 审计事件记录了关键操作
- [ ] 新路由参数有校验
- [ ] 测试覆盖了主要路径

## 文档更新

新增或修改 API 后:
1. 更新 `docs/api/openapi.yaml`
2. 如果涉及架构变更，更新 `docs/architecture/` 对应章节
3. 如果是关键决策，写一篇 ADR 到 `docs/adr/`

## 环境变量

新增环境变量:
1. 在 `internal/config/config.go` 添加字段 + env tag
2. 在 `config.Load()` 设置默认值
3. 在 `services/identity-service/.env.example` 添加注释
4. 如果影响前端行为，更新 `docs/deployment/configuration.md` 中的公开可见性
