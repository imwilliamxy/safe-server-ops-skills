# `safe-server-ops-skill` 详细部署与安装指南（macOS 隔离版）

本文档提供从零搭建 **OS 级凭据隔离（`sshops` 独立用户）+ 生产服务器纵深防御 + 渐进式 Skill** 的完整可复制操作步骤。

> **约定**：下文命令中的 `<username>` 请替换为你本机日常登录的 macOS 用户名（例如 `john`）。  
> 为保障系统安全，所有涉及 `sudo` 的步骤均需由你本人在终端执行。

---

## 前置条件

* 本机（macOS）：已安装 `uv`、Python 3.11+、OpenSSH、`rsync`。
* 生产服务器（Linux）：拥有 `sudo` / `root` 权限用于创建受限运维账号 `ai-ops` 与安装门控脚本。

### 安装完成后的最终目录与权限布局

```text
隔离账号（/Users/sshops，权限 700，日常账号与 AI 均不可读、不可篡改）
├── /Users/sshops/.local/
│   ├── bin/
│   │   ├── opsd                      # 后台守护进程
│   │   └── ops-approve               # 人类独立审批工具
│   ├── venv/safe-server-ops/         # sshops 独占 Python 虚拟环境
│   ├── config/opsd/
│   │   ├── opsd.conf                 # 主入口配置（600）
│   │   ├── .ssh-servers.env          # 服务器凭据（600）
│   │   ├── policy.yaml               # 白名单策略（600）
│   │   └── excludes/                 # rsync 目标排除规则
│   └── state/opsd/
│       ├── audit.jsonl               # 只追加审计日志（600）
│       ├── opsd.stdout.log
│       └── opsd.stderr.log
└── /Users/sshops/.ssh/               # AI 专用私钥与 known_hosts（700/600）

日常账号（/Users/<username>，AI Agent 运行域，零凭据）
└── /Users/<username>/.local/
    ├── bin/opsctl                    # 零凭据客户端（仅连 ops.sock）
    └── venv/safe-server-ops/         # 客户端独立虚拟环境

共享通信与发布中转
├── /var/run/sshops/ops.sock          # 660 (sshops:opsclients) — 业务通道
├── /var/run/sshops/admin.sock        # 600 (仅 sshops)          — 审批通道
└── /var/tmp/sshops-staging/          # 750 (<username>:opsclients) — rsync 中转区
```

---

## 一、本机 macOS 隔离环境搭建

### 第 1 步：创建共享组 `opsclients` 与隐藏无登录用户 `sshops`

```bash
# 1. 创建组 opsclients，并将日常用户加入该组
sudo dseditgroup -o create opsclients
sudo dseditgroup -o edit -a <username> -t user opsclients

# 2. 获取 opsclients 组 GID
OPS_GID=$(dscl . -read /Groups/opsclients PrimaryGroupID | awk '{print $2}')

# 3. 检查 UID 455 是否空闲（无输出即表示可用；若被占用则换一个 450~499 之间的数字）
dscl . -list /Users UniqueID | awk '$2 == 455'

# 4. 创建隐藏无登录系统用户 sshops（家目录设为 /Users/sshops，禁止交互式登录）
sudo dscl . -create /Users/sshops
sudo dscl . -create /Users/sshops UserShell /usr/bin/false
sudo dscl . -create /Users/sshops RealName "Safe Server Ops Daemon"
sudo dscl . -create /Users/sshops UniqueID 455
sudo dscl . -create /Users/sshops PrimaryGroupID "$OPS_GID"
sudo dscl . -create /Users/sshops NFSHomeDirectory /Users/sshops
sudo dscl . -create /Users/sshops IsHidden 1
```

> **注意**：将 `<username>` 加入新组 `opsclients` 后，需**新开一个终端窗口**（或重新登录会话）才能使新组权限生效；执行 `id` 看到 `opsclients` 即表示已生效。

---

### 第 2 步：初始化隔离目录结构与权限

进入项目根目录运行初始化脚本 [deploy/setup-macos-isolation.sh](deploy/setup-macos-isolation.sh)：

```bash
cd /path/to/safe-server-ops-skill
sudo ./deploy/setup-macos-isolation.sh <username>
```

---

### 第 3 步：双端隔离安装 `opsd` / `ops-approve` / `opsctl`

运行安装脚本 [deploy/install.sh](deploy/install.sh)：

```bash
sudo ./deploy/install.sh <username>
```

脚本会自动：
1. 用 `uv` 将当前源码打包为 wheel；
2. 安装至 `/Users/sshops/.local/venv/safe-server-ops`，软链出 `/Users/sshops/.local/bin/opsd` 与 `/Users/sshops/.local/bin/ops-approve`（属主 `sshops`，权限 `go-rwx`）；
3. 安装零凭据客户端至 `/Users/<username>/.local/venv/safe-server-ops`，软链出 `/Users/<username>/.local/bin/opsctl`。

请确认 `/Users/<username>/.local/bin` 已在你的 `PATH` 中（如未加入，在 `~/.zshrc` 中添加 `export PATH="$HOME/.local/bin:$PATH"`）。

---

### 第 4 步：为 `sshops` 准备 AI 专用 SSH 私钥与 `known_hosts`

**强烈建议**单独生成两把 AI 专用密钥（运维 Key 与 `rsync` 同步 Key 分离），不要直接复用你个人的最高权限私钥：

```bash
# 1. 生成运维专用 Key（日志 / Docker / 配置修改）
sudo -u sshops ssh-keygen -t ed25519 -N "" -C "ai-ops" -f /Users/sshops/.ssh/id_ed25519_ai_ops

# 2. 生成 rsync 同步专用 Key
sudo -u sshops ssh-keygen -t ed25519 -N "" -C "ai-rrsync" -f /Users/sshops/.ssh/id_ed25519_ai_rrsync

# 3. 写入生产服务器 Host Key 指纹（将 <端口> 和 <服务器IP或域名> 替换为真实值）
sudo -u sshops bash -c 'ssh-keyscan -p <端口> <服务器IP或域名> >> /Users/sshops/.ssh/known_hosts'
sudo chmod 600 /Users/sshops/.ssh/known_hosts

# 4. 打印两把公钥内容，留待第 6 步贴到生产服务器
sudo cat /Users/sshops/.ssh/id_ed25519_ai_ops.pub
sudo cat /Users/sshops/.ssh/id_ed25519_ai_rrsync.pub
```

> **如果过渡期想暂时复用已有私钥**（不修改原私钥文件）：
> ```bash
> sudo cp /path/to/your_existing_key /Users/sshops/.ssh/id_ed25519_ai_ops
> sudo chown sshops:opsclients /Users/sshops/.ssh/id_ed25519_ai_ops
> sudo chmod 600 /Users/sshops/.ssh/id_ed25519_ai_ops
> ```

---

### 第 5 步：配置 `/Users/sshops/.local/config/opsd/` 下 3 个核心文件

```bash
# 1. 复制模板
sudo cp deploy/opsd.example.conf       /Users/sshops/.local/config/opsd/opsd.conf
sudo cp deploy/ssh-servers.example.env /Users/sshops/.local/config/opsd/.ssh-servers.env
sudo cp deploy/policy.example.yaml     /Users/sshops/.local/config/opsd/policy.yaml

# 2. 分别编辑（按实际服务器、日志、容器、配置与 rsync 目标填写）
sudo vim /Users/sshops/.local/config/opsd/opsd.conf
sudo vim /Users/sshops/.local/config/opsd/.ssh-servers.env
sudo vim /Users/sshops/.local/config/opsd/policy.yaml

# 3. 收紧属主与 600 权限（日常账号与 AI 均无法读取）
sudo chown sshops:opsclients \
  /Users/sshops/.local/config/opsd/opsd.conf \
  /Users/sshops/.local/config/opsd/.ssh-servers.env \
  /Users/sshops/.local/config/opsd/policy.yaml
sudo chmod 600 \
  /Users/sshops/.local/config/opsd/opsd.conf \
  /Users/sshops/.local/config/opsd/.ssh-servers.env \
  /Users/sshops/.local/config/opsd/policy.yaml
```

> **渐进上手提示**：如果暂不立即在生产机部署第 6 步的门控脚本，可先在 `policy.yaml` 中将 `global.gate_mode` 设为 `false`，先体验只读日志与 Docker 状态查询；待生产机脚本就绪后再改回 `gate_mode: true` 启用完整写操作与自动回滚能力。

---

## 二、生产服务器（Linux）纵深防御配置

### 第 6 步：创建受限账号 `ai-ops` 并绑定 `ForceCommand` / `rrsync`

登录生产服务器后执行：

#### 6.1 创建低权限账号（严禁加入 `docker` 组）

```bash
sudo useradd -m -s /bin/bash ai-ops
sudo mkdir -p /home/ai-ops/.ssh
sudo chown ai-ops:ai-ops /home/ai-ops/.ssh
sudo chmod 700 /home/ai-ops/.ssh
```

> **重要安全说明**：Linux 中将账号直接加入 `docker` 组在安全上等价于 `root` 提权。请**绝对不要**执行 `usermod -aG docker ai-ops`，而是通过下面的 `ai-ops-gate.sh` 白名单门控。

#### 6.2 安装并配置门控脚本

将本仓库的 [remote/ai-ops-ssh-entry.sh](remote/ai-ops-ssh-entry.sh) 与 [remote/ai-ops-gate.sh](remote/ai-ops-gate.sh) 上传到生产服务器的 `/usr/local/bin/`：

```bash
sudo chown root:root /usr/local/bin/ai-ops-ssh-entry.sh /usr/local/bin/ai-ops-gate.sh
sudo chmod 755 /usr/local/bin/ai-ops-ssh-entry.sh /usr/local/bin/ai-ops-gate.sh

# 编辑 ai-ops-gate.sh 顶部的白名单映射（与本机 policy.yaml 中的逻辑 ID 保持一致）
sudo vim /usr/local/bin/ai-ops-gate.sh
```

#### 6.3 配置精确 `sudoers` 规则

```bash
sudo visudo -f /etc/sudoers.d/ai-ops
```

仅写入这一行：

```text
ai-ops ALL=(root) NOPASSWD: /usr/local/bin/ai-ops-gate.sh *
```

#### 6.4 确认 `rrsync` 可用（若启用 `rsync` 同步）

* Ubuntu / Debian 通常位于 `/usr/bin/rrsync` 或 `/usr/share/doc/rsync/scripts/rrsync`（若是 `.gz` 先解压并 `chmod +x` 复制到 `/usr/local/bin/rrsync`）；
* 确保 `ai-ops` 对目标发布目录具备写权限（或按需调整目录属组权限）。

#### 6.5 写入 `/home/ai-ops/.ssh/authorized_keys`

将第 4 步的两把公钥按如下格式写入（每把 Key 强制绑定入口命令，彻底禁止交互式 Shell 与端口转发）：

```text
command="/usr/local/bin/ai-ops-ssh-entry.sh",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty <粘贴 id_ed25519_ai_ops.pub>
command="/usr/bin/rrsync -wo /var/www/你的发布目录",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty <粘贴 id_ed25519_ai_rrsync.pub>
```

收紧权限：

```bash
sudo chown ai-ops:ai-ops /home/ai-ops/.ssh/authorized_keys
sudo chmod 600 /home/ai-ops/.ssh/authorized_keys
```

---

## 三、启动守护进程与安装渐进式 Skill

### 第 7 步：注册 `launchd` 开机自启并安装 Skill

回到本机 macOS 终端：

```bash
cd /path/to/safe-server-ops-skill

# 1. 注册并启动 opsd 后台守护进程（以 sshops 身份运行）
sudo cp deploy/com.local.safe-server-opsd.plist /Library/LaunchDaemons/
sudo chown root:wheel /Library/LaunchDaemons/com.local.safe-server-opsd.plist
sudo chmod 644 /Library/LaunchDaemons/com.local.safe-server-opsd.plist
sudo launchctl bootstrap system /Library/LaunchDaemons/com.local.safe-server-opsd.plist

# 2. 检查守护进程启动状态
sudo launchctl print system/com.local.safe-server-opsd | head -n 25
```

安装渐进式 Skill（以 Antigravity 为例；如使用其他 Agent，软链至对应 skills 目录即可）：

```bash
mkdir -p ~/.gemini/config/skills
ln -sfn /path/to/safe-server-ops-skill/skills/safe-server-ops \
        ~/.gemini/config/skills/safe-server-ops
```

**推荐（可选）**：在 `~/.zshrc` 中添加一个快捷审批别名（依然走 `sudo` 密码或 macOS Touch ID 校验，**严禁**对 `ops-approve` 配置 `NOPASSWD`）：

```bash
alias ops-approve='sudo -u sshops /Users/sshops/.local/bin/ops-approve'
```

> **提示（macOS 开启终端 Touch ID `sudo`）**：在 `/etc/pam.d/sudo_local` 中加入 `auth sufficient pam_tid.so`（参考系统自带 `/etc/pam.d/sudo_local.template`），以后审批高危操作只需敲 `ops-approve approve <token>` 并按一下指纹，既安全又丝滑。

---

## 四、安全自检验收（必做）

### 第 8 步：新开一个终端窗口，依次验证 4 项安全边界

```bash
# 1. 验证凭据不可读：日常账号与 AI 绝对无法查看 sshops 下的配置或私钥
cat /Users/sshops/.local/config/opsd/.ssh-servers.env
# ✅ 预期输出：Permission denied

# 2. 验证二进制不可篡改：日常账号与 AI 无法读取或覆盖 opsd
ls /Users/sshops/.local/bin/opsd
# ✅ 预期输出：Permission denied

# 3. 验证业务通道可用且零凭据泄露
opsctl capabilities
# ✅ 预期输出：仅列出逻辑代号（servers / sync_targets），不含任何 IP、用户名或路径

# 4. 验证防 AI 自批 + 人类审批通道可用
# 4a) 模拟不走 sudo 直接连 admin.sock（必须被内核拒绝）
OPS_SOCKET=/var/run/sshops/admin.sock opsctl capabilities
# ✅ 预期输出：ERROR: Permission denied connecting to '/var/run/sshops/admin.sock'.

# 4b) 人类经 sudo 密码 / Touch ID 访问审批通道
sudo -u sshops /Users/sshops/.local/bin/ops-approve --list
# ✅ 预期输出：No pending approval plans.
```

---

## 五、日常维护、升级与排障

### 1. 代码更新后升级并重启 `opsd`

```bash
cd /path/to/safe-server-ops-skill
sudo ./deploy/install.sh <username>
sudo launchctl kickstart -k system/com.local.safe-server-opsd
```

### 2. 修改 `opsd.conf` / `policy.yaml` / `.ssh-servers.env` 后重载

```bash
sudo launchctl kickstart -k system/com.local.safe-server-opsd
```

### 3. 查看守护进程日志与审计日志

```bash
# 查看 opsd 启动与运行错误日志
sudo tail -n 50 /Users/sshops/.local/state/opsd/opsd.stderr.log

# 查看只追加审计记录
sudo tail -n 50 /Users/sshops/.local/state/opsd/audit.jsonl
```

### 4. 常见排障

* **`ERROR: Permission denied connecting to '/var/run/sshops/ops.sock'`**
  * 原因：当前终端尚未加载新加入的 `opsclients` 组。
  * 解决：新开一个终端窗口，运行 `id` 确认包含 `opsclients`，并检查 `ls -l /var/run/sshops/ops.sock` 属组为 `opsclients`、权限为 `srw-rw----`。
* **`Socket not found at '/var/run/sshops/ops.sock'`**
  * 原因：`opsd` 启动报错（常见为 `policy.yaml` 语法错、私钥不存在或权限校验未通过）。
  * 解决：查看 `sudo cat /Users/sshops/.local/state/opsd/opsd.stderr.log`。
* **`Host key verification failed`**
  * 原因：目标服务器指纹尚未写入 `/Users/sshops/.ssh/known_hosts`。
  * 解决：重新执行第 4 步的 `ssh-keyscan` 命令写入并核对指纹。

### 5. 彻底卸载

```bash
sudo launchctl bootout system /Library/LaunchDaemons/com.local.safe-server-opsd.plist || true
sudo rm -f /Library/LaunchDaemons/com.local.safe-server-opsd.plist
rm -f /Users/<username>/.local/bin/opsctl ~/.gemini/config/skills/safe-server-ops
rm -rf /Users/<username>/.local/venv/safe-server-ops
sudo rm -rf /var/run/sshops /var/tmp/sshops-staging /Users/sshops
sudo dscl . -delete /Users/sshops
sudo dseditgroup -o delete opsclients
```
