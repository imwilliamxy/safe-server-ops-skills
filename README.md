# safe-server-ops-skill

Credential-isolated production server operations gateway (**Progressive Skill + Zero-Credential `opsctl` CLI + Isolated `opsd` Daemon**) for AI coding agents.

完整架构设计与安全边界说明请阅读 [DESIGN.md](DESIGN.md)。

## 核心特性

* **极低日常上下文占用**：采用渐进式 Skill（`skills/safe-server-ops/SKILL.md` + `references/*.md`），平时仅占 ~30 Tokens，需要运维时按需加载。
* **OS 级凭据隔离**：`opsd` 守护进程运行在独立无登录系统用户（`sshops`）下，独占 `.ssh-servers.env`、`policy.yaml` 与私钥；AI Agent 只接触逻辑代号与零凭据的 `opsctl`。
* **双 Unix Socket 防 AI 自批**：
  * `ops.sock`（业务通道）：严禁调用任何审批方法；
  * `admin.sock`（`0600` 仅属主可访问）：必须由人类通过 `sudo -u sshops ops-approve`（密码 / Touch ID，禁止 `NOPASSWD`）独立批准 `plan_token`。
* **四类生产运维能力全闭环**：
  * **L0 只读巡检**：白名单日志读取（本地字面量过滤、脱敏、截断）、Docker 状态巡检（绝不暴露 `Env`）。
  * **L1 Docker 重启**：两阶段 `restart-plan` → 人类审批 → `restart-apply`（自动带回重启后状态与最近 30 行脱敏启动日志）。
  * **L2 `rsync` 同步**：软链逃逸扫描、文件数/体积限制、`--dry-run` 预演、Manifest SHA256 防篡改（TOCTOU）、`--delete` 熔断、兼容服务端 `rrsync`。
  * **L2 配置修改与回滚**：密文占位符脱敏读取、占位符防篡改还原、并发乐观锁（`base_sha256`）、本地 JSON/YAML + 远端校验器（如 `nginx -t`）预检、Unified Diff、自动备份与重载失败自动回滚。

## 快速本地开发与测试

```bash
# 1. 创建虚拟环境并安装（仅依赖 PyYAML）
python3 -m venv .venv
source .venv/bin/activate
pip install -e .

# 2. 运行完整单元与双 Socket 端到端测试
python3 -m unittest discover -s tests -v
```

## 快速过渡体验（本机单用户启动）

```bash
# 准备最小配置（切勿提交到 git！）
cp deploy/ssh-servers.example.env /tmp/dev-servers.env
cp deploy/policy.example.yaml /tmp/dev-policy.yaml
# 按需编辑上述两个文件后启动 opsd：
opsd \
  --servers-env /tmp/dev-servers.env \
  --policy /tmp/dev-policy.yaml \
  --socket /tmp/ops.sock \
  --admin-socket /tmp/ops-admin.sock \
  --audit-log /tmp/ops-audit.jsonl

# 另一个终端里用 opsctl 测试（AI Agent 只需要这两个环境变量和 opsctl）：
export OPS_SOCKET=/tmp/ops.sock
opsctl capabilities
```

## 生产真隔离部署（macOS `sshops` + `launchd`）

1. 参考 [deploy/setup-macos-isolation.sh](deploy/setup-macos-isolation.sh) 准备独立用户 `sshops`、组 `opsclients` 及 `/var/lib/sshops`、`/var/run/sshops`、`/var/tmp/sshops-staging`。
2. 在生产服务器部署 [remote/ai-ops-ssh-entry.sh](remote/ai-ops-ssh-entry.sh) 与 [remote/ai-ops-gate.sh](remote/ai-ops-gate.sh)，按需配置 `rrsync`。
3. 使用 [deploy/com.local.safe-server-opsd.plist](deploy/com.local.safe-server-opsd.plist) 将 `opsd` 注册为开机自启守护进程。
4. 将 `skills/safe-server-ops/` 软链或复制到你的 Agent skills 目录（例如 `~/.gemini/config/skills/safe-server-ops`）。
