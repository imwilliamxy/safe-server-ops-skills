# safe-server-ops-skill

Credential-isolated production server operations gateway (**Progressive Skill + Zero-Dependency Rust `opsctl` / `opsd` / `ops-approve` Binaries**) for AI coding agents.

* 架构设计与安全边界说明：[DESIGN.md](DESIGN.md)
* 详细 macOS 隔离部署与生产服务器加固手册：**[INSTALL.md](INSTALL.md)**

## 核心特性

* **零运行时依赖（纯 Rust 单文件二进制）**：编译产出 3 个原生单文件可执行程序（`opsd`、`opsctl`、`ops-approve`），宿主机无需安装 Python、虚拟环境或包管理器；内存中的配置密文通过 `zeroize` 在使用后自动清零。
* **极低日常上下文占用**：采用渐进式 Skill（`skills/safe-server-ops/SKILL.md` + `references/*.md`），平时仅占 ~30 Tokens，需要运维时按需加载。
* **OS 级凭据隔离**：`opsd` 运行在独立无登录系统用户（`sshops`）下，独占 `/Users/sshops/.local/` 与私钥；AI Agent 只接触逻辑代号与零凭据的 `/Users/<username>/.local/bin/opsctl`。
* **双 Unix Socket 防 AI 自批**：
  * `ops.sock`（业务通道）：严禁调用任何审批方法；
  * `admin.sock`（`0600` 仅属主可访问）：必须由人类通过 `sudo -u sshops /Users/sshops/.local/bin/ops-approve`（密码 / Touch ID，禁止 `NOPASSWD`）独立批准 `plan_token`。
* **四类生产运维能力全闭环**：
  * **L0 只读巡检**：白名单日志读取（本地字面量过滤、脱敏、截断）、Docker 状态巡检（绝不暴露 `Env`）。
  * **L1 Docker 重启**：两阶段 `restart-plan` → 人类审批 → `restart-apply`（自动带回重启后状态与最近 30 行脱敏启动日志）。
  * **L2 `rsync` 同步**：软链逃逸扫描、文件数/体积限制、`--dry-run` 预演、Manifest SHA256 防篡改（TOCTOU）、`--delete` 熔断、兼容服务端 `rrsync`。
  * **L2 配置修改与回滚**：密文占位符脱敏读取、占位符防篡改还原、并发乐观锁（`base_sha256`）、本地 JSON/YAML + 远端校验器（如 `nginx -t`）预检、Unified Diff、自动备份与重载失败自动回滚。

## 快速本地构建与测试

```bash
# 1. 运行全部单元测试与真实二进制双 Socket 端到端测试
cargo test

# 2. 编译优化后的单文件二进制（产物位于 target/release/{opsd,opsctl,ops-approve}）
cargo build --release

# 3. 查看三个 CLI 入口帮助
./target/release/opsctl --help
./target/release/opsd --help
./target/release/ops-approve --help
```

## 快速过渡体验（本机单用户启动）

```bash
# 准备最小配置（切勿提交到 git！）
cp deploy/ssh-servers.example.env /tmp/dev-servers.env
cp deploy/policy.example.yaml /tmp/dev-policy.yaml
# 按需编辑上述两个文件后启动 opsd：
./target/release/opsd \
  --servers-env /tmp/dev-servers.env \
  --policy /tmp/dev-policy.yaml \
  --socket /tmp/ops.sock \
  --admin-socket /tmp/ops-admin.sock \
  --audit-log /tmp/ops-audit.jsonl

# 另一个终端里用 opsctl 测试：
export OPS_SOCKET=/tmp/ops.sock
./target/release/opsctl capabilities
```

## 生产真隔离部署（macOS `sshops` + `launchd`）

完整 8 步安装、服务端加固、验收与排障步骤见 **[INSTALL.md](INSTALL.md)**：

```bash
cargo build --release
sudo ./deploy/setup-macos-isolation.sh <username>
sudo ./deploy/install.sh <username>
```
