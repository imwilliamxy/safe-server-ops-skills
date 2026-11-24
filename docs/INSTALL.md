# `safe-server-ops-skill` Deployment and Installation Guide v0.2.0 (Standalone Rust Binaries with macOS Isolation)

[简体中文](INSTALL_zh.md)

This guide walks through a fresh installation with zero runtime dependencies beyond macOS system tools, OS-level credential isolation under a dedicated `sshops` account, defense in depth on production servers, and a progressive skill. The Rust tools each ship as a single native executable.

> Replace `<username>` in the commands below with your regular macOS login name, such as `john`.
>
> Run all commands that require `sudo` yourself in your terminal.

---

## Prerequisites

* **Runtime on the target Mac** requires only the `ssh` and `rsync` tools bundled with macOS. Python, `uv`, virtual environments, and Rust are unnecessary.
* **Building from source** requires the Rust toolchain (`cargo` and `rustc`) on the build machine. To install the three prebuilt executables on another Mac of the same architecture without a toolchain, follow Option B below.
* **Linux production servers** require `sudo` or `root` access to create the restricted `ai-ops` account and install the gate scripts.

### Directory layout and permissions after installation

```text
Isolated account (/Users/sshops, mode 700, inaccessible to the regular account and AI)
├── /Users/sshops/.local/
│   ├── bin/
│   │   ├── opsd                      # Background daemon (standalone native binary, 700)
│   │   └── ops-approve               # Separate approval tool for human operators (standalone native binary, 700)
│   ├── config/opsd/
│   │   ├── opsd.conf                 # Main configuration file (600)
│   │   ├── .ssh-servers.env          # Server credentials (600)
│   │   ├── policy.yaml               # Allowlist policy (600)
│   │   └── excludes/                 # Exclusion rules for rsync targets
│   └── state/opsd/
│       ├── audit.jsonl               # Append-only audit log (600)
│       ├── opsd.stdout.log
│       └── opsd.stderr.log
└── /Users/sshops/.ssh/               # Dedicated AI SSH private keys and known_hosts (700/600)

Regular account (/Users/<username>, where the AI agent runs, with no credentials)
└── /Users/<username>/.local/
    └── bin/opsctl                    # Credential-free client (standalone native binary, connects only to ops.sock)

Shared sockets and deployment staging
├── /var/run/sshops/ops.sock          # 660 (sshops:opsclients) — operations channel
├── /var/run/sshops/admin.sock        # 600 (sshops only)       — approval channel
└── /var/tmp/sshops-staging/          # 750 (<username>:opsclients) — rsync staging area
```

---

## 1. Automated macOS setup (recommended)

Run [deploy/0-bootstrap-macos.sh](../deploy/0-bootstrap-macos.sh) to set up the Mac in one command. The script creates the restricted `sshops` account and directories, installs the three Rust executables, generates dedicated AI keys, sets up configuration templates, symlinks the skill, and registers and starts the daemon with `launchd`.

```bash
cd /path/to/safe-server-ops-skill
sudo ./deploy/0-bootstrap-macos.sh <username>
```

Next, run the interactive script to add a production server and automatically trust its SSH host key fingerprint. You can also import and convert an existing `ssh_login.sh` configuration. The import preserves the original configuration file and private keys.

```bash
# Option 1. Import from an existing ~/.local/config/ssh_login/.ssh-servers.env
#   --key-mode ai   (recommended default) points KEY_FILE at the dedicated AI private key. Add the AI public key to the production server.
#   --key-mode copy (quick trial) reads and copies the original private key into /Users/sshops/.ssh/ without modifying the original.
sudo ./deploy/4-add-server.sh --import-ssh-login --key-mode ai
# Use --only prod-a,prod-b to import selected aliases, or preview the import with --dry-run.
./deploy/4-add-server.sh --import-ssh-login --dry-run

# Option 2. Enter one server interactively
sudo ./deploy/4-add-server.sh
```

Edit the allowlist policy as needed, then reload the daemon.

```bash
sudo vim /Users/sshops/.local/config/opsd/policy.yaml
sudo launchctl kickstart -k system/com.local.safe-server-opsd
```

> For manual setup or troubleshooting, use the numbered steps below (`1 -> 2 -> 3 -> 4`).

---

## 1. Manual macOS setup (reference)

### Step 1. Create the `opsclients` group and the hidden, non-login `sshops` account

Run [deploy/1-create-sshops-user.sh](../deploy/1-create-sshops-user.sh). It selects an unused UID between 450 and 499, locks password login, disables the interactive shell, hides the account from the login screen, and sets its home directory to `/Users/sshops`.

```bash
cd /path/to/safe-server-ops-skill

# Optional preview. Shows the commands without requiring sudo or changing the system.
./deploy/1-create-sshops-user.sh --dry-run <username>

# Create the group and account
sudo ./deploy/1-create-sshops-user.sh <username>
```

> After adding `<username>` to `opsclients`, **open a new terminal window** or log in again to pick up the group membership. Run `id` and confirm that `opsclients` appears in the output.

---

### Step 2. Set up the isolated directories and permissions

Run [deploy/2-setup-macos-isolation.sh](../deploy/2-setup-macos-isolation.sh) from the repository root.

```bash
cd /path/to/safe-server-ops-skill
sudo ./deploy/2-setup-macos-isolation.sh <username>
```

---

### Step 3. Install the three standalone native executables (`opsd`, `ops-approve`, and `opsctl`)

#### Option A. Build from source and install automatically on a Mac with Rust (recommended)

```bash
cd /path/to/safe-server-ops-skill
cargo build --release
sudo ./deploy/3-install.sh <username>
```

The script installs the three executables from `target/release/` in these locations.

1. `/Users/sshops/.local/bin/opsd` and `/Users/sshops/.local/bin/ops-approve` are owned by `sshops:opsclients` with mode `700`, which prevents the regular account and AI from reading or overwriting them.
2. `/Users/<username>/.local/bin/opsctl` is owned by `<username>` with mode `755` and holds no credentials.

#### Option B. Copy prebuilt executables to a Mac without Rust

If `opsd`, `ops-approve`, and `opsctl` are already built on another Mac with the same architecture, install them directly with the permissions shown below. The target Mac needs no development toolchain.

```bash
sudo install -m 700 -o sshops -g opsclients ./opsd        /Users/sshops/.local/bin/opsd
sudo install -m 700 -o sshops -g opsclients ./ops-approve /Users/sshops/.local/bin/ops-approve
install -d -m 755 /Users/<username>/.local/bin
install -m 755 ./opsctl /Users/<username>/.local/bin/opsctl
```

Confirm that `/Users/<username>/.local/bin` is in your `PATH`, then check that the executables run.

```bash
opsctl --help
sudo -u sshops /Users/sshops/.local/bin/opsd --help
```

---

### Step 4. Set up dedicated AI SSH keys and `known_hosts` for `sshops`

**Use two dedicated AI keys**, one for operations and one for `rsync` transfers. Keep your personal high-privilege private key separate.

```bash
# 1. Generate an operations key for logs, Docker, and configuration changes
sudo -u sshops ssh-keygen -t ed25519 -N "" -C "ai-ops" -f /Users/sshops/.ssh/id_ed25519_ai_ops

# 2. Generate a dedicated rsync key
sudo -u sshops ssh-keygen -t ed25519 -N "" -C "ai-rrsync" -f /Users/sshops/.ssh/id_ed25519_ai_rrsync

# 3. Record the production server's host key. Replace <port> and <server-ip-or-hostname> with actual values.
sudo -u sshops bash -c 'ssh-keyscan -p <port> <server-ip-or-hostname> >> /Users/sshops/.ssh/known_hosts'
sudo chmod 600 /Users/sshops/.ssh/known_hosts

# 4. Print both public keys to paste on the production server in Step 6
sudo cat /Users/sshops/.ssh/id_ed25519_ai_ops.pub
sudo cat /Users/sshops/.ssh/id_ed25519_ai_rrsync.pub
```

> To reuse an existing private key temporarily, make a copy. The original file stays intact.
> ```bash
> sudo cp /path/to/your_existing_key /Users/sshops/.ssh/id_ed25519_ai_ops
> sudo chown sshops:opsclients /Users/sshops/.ssh/id_ed25519_ai_ops
> sudo chmod 600 /Users/sshops/.ssh/id_ed25519_ai_ops
> ```

---

### Step 5. Configure the three core files in `/Users/sshops/.local/config/opsd/`

```bash
# 1. Copy the templates
sudo cp deploy/opsd.example.conf       /Users/sshops/.local/config/opsd/opsd.conf
sudo cp deploy/ssh-servers.example.env /Users/sshops/.local/config/opsd/.ssh-servers.env
sudo cp deploy/policy.example.yaml     /Users/sshops/.local/config/opsd/policy.yaml

# 2. Edit each file for your servers, logs, containers, configuration, and rsync targets
sudo vim /Users/sshops/.local/config/opsd/opsd.conf
sudo vim /Users/sshops/.local/config/opsd/.ssh-servers.env
sudo vim /Users/sshops/.local/config/opsd/policy.yaml

# 3. Set ownership and mode 600 to keep the files unreadable by the regular account and AI
sudo chown sshops:opsclients \
  /Users/sshops/.local/config/opsd/opsd.conf \
  /Users/sshops/.local/config/opsd/.ssh-servers.env \
  /Users/sshops/.local/config/opsd/policy.yaml
sudo chmod 600 \
  /Users/sshops/.local/config/opsd/opsd.conf \
  /Users/sshops/.local/config/opsd/.ssh-servers.env \
  /Users/sshops/.local/config/opsd/policy.yaml
```

> If you plan to install the production gate scripts in Step 6 later, set `global.gate_mode` to `false` in `policy.yaml` to try read-only log access and Docker status checks. Once the server scripts are ready, restore `gate_mode: true` to enable full write operations and automatic rollback.

---

## 2. Defense in depth on Linux production servers

> You can reuse an existing Linux account. OpenSSH applies the restrictions in `authorized_keys` per public key. With an existing operations user such as `ubuntu`, `deploy`, or `root`, your primary public key retains full interactive shell access, while the dedicated AI public keys are restricted to allowlisted commands through `ForceCommand` and `rrsync`. For stronger isolation, use `--create-user` to create a dedicated `ai-ops` account.

### Recommended approach with the server installer script

Upload the repository's `remote/` directory to the production server, then run [remote/install-remote-gate.sh](../remote/install-remote-gate.sh).

```bash
# Reuse an existing account such as ubuntu
sudo ./remote/install-remote-gate.sh \
  --user ubuntu \
  --ops-pubkey "<paste the contents of /Users/sshops/.ssh/id_ed25519_ai_ops.pub>" \
  --sync-pubkey "<paste the contents of /Users/sshops/.ssh/id_ed25519_ai_rrsync.pub>" \
  --sync-dir /var/www/your-deployment-directory

# Edit the allowlist at the top of the script to match the server's paths
sudo vim /usr/local/bin/ai-ops-gate.sh
```

> To create a dedicated low-privilege `ai-ops` account, replace `--user ubuntu` with `--user ai-ops --create-user`.

### Step 6. Create the restricted `ai-ops` account and set up `ForceCommand` and `rrsync` (manual reference)

Log in to the production server before following these steps.

#### 6.1 Create the low-privilege account and keep it out of the `docker` group

```bash
sudo useradd -m -s /bin/bash ai-ops
sudo mkdir -p /home/ai-ops/.ssh
sudo chown ai-ops:ai-ops /home/ai-ops/.ssh
sudo chmod 700 /home/ai-ops/.ssh
```

> On Linux, membership in the `docker` group effectively grants `root` access. Use the `ai-ops-gate.sh` allowlist below and **never** run `usermod -aG docker ai-ops`.

#### 6.2 Install and configure the gate scripts

Upload [remote/ai-ops-ssh-entry.sh](../remote/ai-ops-ssh-entry.sh) and [remote/ai-ops-gate.sh](../remote/ai-ops-gate.sh) to `/usr/local/bin/` on the production server.

```bash
sudo chown root:root /usr/local/bin/ai-ops-ssh-entry.sh /usr/local/bin/ai-ops-gate.sh
sudo chmod 755 /usr/local/bin/ai-ops-ssh-entry.sh /usr/local/bin/ai-ops-gate.sh

# Edit the allowlist mappings at the top of ai-ops-gate.sh to match the logical IDs in your local policy.yaml
sudo vim /usr/local/bin/ai-ops-gate.sh
```

#### 6.3 Configure the scoped `sudoers` rule

```bash
sudo visudo -f /etc/sudoers.d/ai-ops
```

Add only the following line.

```text
ai-ops ALL=(root) NOPASSWD: /usr/local/bin/ai-ops-gate.sh *
```

#### 6.4 Confirm that `rrsync` is available if you use `rsync` transfers

* Ubuntu and Debian typically provide it at `/usr/bin/rrsync` or `/usr/share/doc/rsync/scripts/rrsync`. If it comes as a `.gz` file, extract it, run `chmod +x` on the script, and copy it to `/usr/local/bin/rrsync`.
* Make sure `ai-ops` can write to the deployment directory. Adjust that directory's group permissions if needed.

#### 6.5 Add the public keys to `/home/ai-ops/.ssh/authorized_keys`

Use the following format for the two public keys from Step 4. The restrictions bind each key to a forced command and prevent interactive shells and port forwarding.

```text
command="/usr/local/bin/ai-ops-ssh-entry.sh",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty <paste the contents of id_ed25519_ai_ops.pub>
command="/usr/bin/rrsync -wo /var/www/your-deployment-directory",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty <paste the contents of id_ed25519_ai_rrsync.pub>
```

Set ownership and permissions on the file.

```bash
sudo chown ai-ops:ai-ops /home/ai-ops/.ssh/authorized_keys
sudo chmod 600 /home/ai-ops/.ssh/authorized_keys
```

---

## 3. Start the daemon and install the progressive skill

### Step 7. Set up automatic startup with `launchd` and install the skill

Return to your local macOS terminal.

```bash
cd /path/to/safe-server-ops-skill

# 1. Register and start the opsd daemon, which runs as sshops
sudo cp deploy/com.local.safe-server-opsd.plist /Library/LaunchDaemons/
sudo chown root:wheel /Library/LaunchDaemons/com.local.safe-server-opsd.plist
sudo chmod 644 /Library/LaunchDaemons/com.local.safe-server-opsd.plist
sudo launchctl bootstrap system /Library/LaunchDaemons/com.local.safe-server-opsd.plist

# 2. Check the daemon status
sudo launchctl print system/com.local.safe-server-opsd | head -n 25
```

Install the progressive skill. The commands below use Antigravity. For another agent, symlink the skill into that agent's skills directory.

```bash
mkdir -p ~/.gemini/config/skills
ln -sfn /path/to/safe-server-ops-skill/skills/safe-server-ops \
        ~/.gemini/config/skills/safe-server-ops
```

You can add a shortcut for approvals in `~/.zshrc`. The alias keeps `sudo` password or macOS Touch ID authentication in place. **Never** configure `NOPASSWD` for `ops-approve`.

```bash
alias ops-approve='sudo -u sshops /Users/sshops/.local/bin/ops-approve'
```

> To enable Touch ID for `sudo` in the macOS terminal, add `auth sufficient pam_tid.so` to `/etc/pam.d/sudo_local`. Use the system-provided `/etc/pam.d/sudo_local.template` as a reference. You can then approve high-risk operations by running `ops-approve approve <token>` and authenticating with Touch ID.

---

## 4. Required security checks

### Step 8. Open a new terminal window and verify four security boundaries

```bash
# 1. Verify that the regular account and AI cannot read the sshops configuration or private keys
cat /Users/sshops/.local/config/opsd/.ssh-servers.env
# ✅ Expected output: Permission denied

# 2. Verify that the regular account and AI cannot read or overwrite the opsd binary
ls /Users/sshops/.local/bin/opsd
# ✅ Expected output: Permission denied

# 3. Verify that the operations channel works without exposing credentials
opsctl capabilities
# ✅ Expected output: Only logical IDs (servers / sync_targets), with no IP addresses, usernames, or paths

# 4. Verify that AI cannot approve its own requests and that humans can access the approval channel
# 4a) Try connecting directly to admin.sock without sudo. The kernel must deny access.
OPS_SOCKET=/var/run/sshops/admin.sock opsctl capabilities
# ✅ Expected output: ERROR: Permission denied connecting to '/var/run/sshops/admin.sock'.

# 4b) Access the approval channel using a sudo password or Touch ID
sudo -u sshops /Users/sshops/.local/bin/ops-approve --list
# ✅ Expected output: No pending approval plans.
```

---

## 5. Maintenance, upgrades, and troubleshooting

### 1. Upgrade and restart `opsd` after a code update

```bash
cd /path/to/safe-server-ops-skill
cargo build --release
sudo ./deploy/3-install.sh <username>
sudo launchctl kickstart -k system/com.local.safe-server-opsd
```

### 2. Reload after editing `opsd.conf`, `policy.yaml`, or `.ssh-servers.env`

```bash
sudo launchctl kickstart -k system/com.local.safe-server-opsd
```

### 3. Read daemon and audit logs

```bash
# Read opsd startup and runtime errors
sudo tail -n 50 /Users/sshops/.local/state/opsd/opsd.stderr.log

# Read the append-only audit log
sudo tail -n 50 /Users/sshops/.local/state/opsd/audit.jsonl
```

### 4. Troubleshoot common errors

* **`ERROR: Permission denied connecting to '/var/run/sshops/ops.sock'`**
  * The current terminal session has yet to pick up the new `opsclients` group membership.
  * Open a new terminal window and run `id` to confirm that `opsclients` appears. Run `ls -l /var/run/sshops/ops.sock` and confirm that the group is `opsclients` and the mode is `srw-rw----`.
* **`Socket not found at '/var/run/sshops/ops.sock'`**
  * `opsd` failed to start. Common causes include a syntax error in `policy.yaml`, a missing private key, or a failed permissions check.
  * Inspect the error log with `sudo cat /Users/sshops/.local/state/opsd/opsd.stderr.log`.
* **`Host key verification failed`**
  * The target server's host key is missing from `/Users/sshops/.ssh/known_hosts`.
  * Run the `ssh-keyscan` command from Step 4 again to add the host key, then verify its fingerprint.

### 5. Uninstall completely

```bash
sudo launchctl bootout system /Library/LaunchDaemons/com.local.safe-server-opsd.plist || true
sudo rm -f /Library/LaunchDaemons/com.local.safe-server-opsd.plist
rm -f /Users/<username>/.local/bin/opsctl ~/.gemini/config/skills/safe-server-ops
sudo rm -rf /var/run/sshops /var/tmp/sshops-staging /Users/sshops
sudo dscl . -delete /Users/sshops
sudo dseditgroup -o delete opsclients
```
