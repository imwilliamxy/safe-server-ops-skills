# safe-server-ops-skill

Credential-isolated production server operations gateway (**Progressive Skill + Zero-Dependency Rust `opsctl` / `opsd` / `ops-approve` Binaries**) for AI coding agents.

[English](README.md)

* 架构设计与安全边界说明：[DESIGN_zh.md](docs/DESIGN_zh.md)
* 详细 macOS 隔离部署与生产服务器加固手册：**[INSTALL_zh.md](docs/INSTALL_zh.md)**

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
* **内嵌只读 Web 审计监控台（默认 `http://127.0.0.1:10100`）**：
  * 仅绑定本机回环地址且全接口严格只读（拒绝非 `GET/HEAD`，防止 AI 通过 HTTP 自批）；
  * 左侧按 **Agent Session** 聚合（自动识别 Paseo 多对话 `PASEO_AGENT_ID`、Antigravity、Claude Code、Codex、终端会话，并支持 `--session-title` 语义标题），右侧实时（SSE）展示近期 100 条命令调用、具体远端命令、脱敏输出、Diff、审批链路与高危命令风险标红；
  * 支持审计日志按大小自动轮转（默认 `20 MiB` 保留 5 份）及 `ops-approve reload` / `SIGHUP` 配置零中断热重载。

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

完整 8 步安装、服务端加固、验收与排障步骤见 **[INSTALL_zh.md](docs/INSTALL_zh.md)**：

```bash
# 一键全自动部署（依次执行 1->2->3 并初始化 Key、配置模板、Skill 与 launchd）
cargo build --release
sudo ./deploy/0-bootstrap-macos.sh <username>
sudo ./deploy/4-add-server.sh --import-ssh-login --key-mode ai
```

## 在其他 AI Agent 中安装本 Skill

本机所有 AI Agent 共享同一个后台守护进程 `opsd` 与无凭据客户端 `opsctl`，无需重复部署后端。

### 方式一：直接发给目标 Agent 的“一键安装提示词”（推荐）

将下面这段提示词直接复制发送给 Claude Code、Codex、Cursor、Antigravity 等任意本地 Coding Agent（把仓库路径替换为你本机实际路径即可）：

```text
请帮我为当前 Agent 安装本地的 `safe-server-ops` Skill：
1. Skill 源码目录位于：`/path/to/safe-server-ops-skill/skills/safe-server-ops`（内含 `SKILL.md` 和 `references/`）。
2. 请识别你当前所属 Agent 的用户级 skills 目录（例如 `~/.claude/skills`、`~/.codex/skills`、`~/.cursor/skills`、`~/.gemini/config/skills` 或 `~/.agents/skills`），将上述目录软链接（`ln -sfn`）为 `<你的skills目录>/safe-server-ops`。
3. 检查 `which opsctl` 是否在 PATH 中，并运行一次只读命令 `opsctl capabilities` 验证能否正常与本地 `opsd` 通信。
4. 安全约束：全程严禁读取 `/Users/sshops/`、`~/.ssh/` 或任何 SSH 配置文件与私钥；以后操作生产或远程服务器时，必须按 `safe-server-ops` Skill 规范仅通过 `opsctl` 执行，写操作等待我本人通过 `ops-approve` 批准。
5. 完成后向我汇报软链路径、`opsctl capabilities` 状态，以及是否需要重开会话使 Skill 生效。
```

### 方式二：手动软链速查

```bash
SKILL_SRC="/path/to/safe-server-ops-skill/skills/safe-server-ops"

# Antigravity（0-bootstrap-macos.sh 已自动配置）
mkdir -p ~/.gemini/config/skills && ln -sfn "$SKILL_SRC" ~/.gemini/config/skills/safe-server-ops

# Claude Code
mkdir -p ~/.claude/skills && ln -sfn "$SKILL_SRC" ~/.claude/skills/safe-server-ops

# OpenAI Codex CLI
mkdir -p ~/.codex/skills && ln -sfn "$SKILL_SRC" ~/.codex/skills/safe-server-ops

# Cursor / 通用 Agent Skills 标准目录
mkdir -p ~/.cursor/skills ~/.agents/skills
ln -sfn "$SKILL_SRC" ~/.cursor/skills/safe-server-ops
ln -sfn "$SKILL_SRC" ~/.agents/skills/safe-server-ops
```
