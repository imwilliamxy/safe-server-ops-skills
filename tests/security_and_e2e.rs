//! Comprehensive security, unit, executor, and real-binary dual-socket E2E tests.

use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::process::Command;
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use tempfile::TempDir;

use safe_server_ops::audit::AuditLogger;
use safe_server_ops::config::{load_daemon_config, load_policy, load_server_profiles};
use safe_server_ops::daemon::OpsDaemon;
use safe_server_ops::engine::OpsEngine;
use safe_server_ops::executors::ssh_exec::{CommandResult, CommandRunner};
use safe_server_ops::planner::{PlanPayload, PlanStore};
use safe_server_ops::protocol::send_request;
use safe_server_ops::redactor::{
    mask_config_secrets, truncate_output, unmask_config_secrets, Redactor,
};

struct MockState {
    calls: Vec<(Vec<String>, Option<String>)>,
    remote_config_content: String,
    validator_should_fail: bool,
    reload_should_fail: bool,
    rsync_preview_stdout: String,
}

struct MockRunner {
    state: Arc<Mutex<MockState>>,
}

impl CommandRunner for MockRunner {
    fn run(&self, argv: &[String], stdin_data: Option<&str>, _timeout_secs: u64) -> CommandResult {
        let mut st = self.state.lock().unwrap();
        st.calls
            .push((argv.to_vec(), stdin_data.map(ToString::to_string)));

        if argv.first().map(String::as_str) == Some("rsync") {
            if argv.iter().any(|a| a == "--dry-run") {
                return CommandResult {
                    exit_code: 0,
                    stdout: st.rsync_preview_stdout.clone(),
                    stderr: String::new(),
                    timed_out: false,
                };
            }
            return CommandResult {
                exit_code: 0,
                stdout: ">f+++++++++ index.php\nNumber of files transferred: 2\n".to_string(),
                stderr: String::new(),
                timed_out: false,
            };
        }

        let remote_cmd = argv.last().map(String::as_str).unwrap_or("");
        if remote_cmd.starts_with("logs-file ") {
            return CommandResult {
                exit_code: 0,
                stdout: "INFO boot ok\nERROR upstream 203.0.113.77 timeout for prod_secret_user\nINFO done\n"
                    .to_string(),
                stderr: String::new(),
                timed_out: false,
            };
        }
        if remote_cmd.starts_with("docker-status ") {
            return CommandResult {
                exit_code: 0,
                stdout: "/web-app\trunning\thealthy\t0\t2026-11-24T00:00:00Z\n".to_string(),
                stderr: String::new(),
                timed_out: false,
            };
        }
        if remote_cmd.starts_with("docker-restart ") {
            return CommandResult {
                exit_code: 0,
                stdout: "web-app\n".to_string(),
                stderr: String::new(),
                timed_out: false,
            };
        }
        if remote_cmd.starts_with("logs-docker ") {
            return CommandResult {
                exit_code: 0,
                stdout: "Started web-app on 203.0.113.77\n".to_string(),
                stderr: String::new(),
                timed_out: false,
            };
        }
        if remote_cmd.starts_with("config-read ") {
            return CommandResult {
                exit_code: 0,
                stdout: st.remote_config_content.clone(),
                stderr: String::new(),
                timed_out: false,
            };
        }
        if remote_cmd.starts_with("config-validate ") {
            if st.validator_should_fail {
                return CommandResult {
                    exit_code: 1,
                    stdout: String::new(),
                    stderr: "nginx: [emerg] unexpected token in /etc/nginx/conf.d/app.conf"
                        .to_string(),
                    timed_out: false,
                };
            }
            return CommandResult {
                exit_code: 0,
                stdout: "nginx: configuration file ok\n".to_string(),
                stderr: String::new(),
                timed_out: false,
            };
        }
        if remote_cmd.starts_with("config-apply ") {
            if st.reload_should_fail {
                return CommandResult {
                    exit_code: 1,
                    stdout: json!({
                        "backup_id": "nginx-site.20261124.bak",
                        "reloaded": false,
                        "rolled_back": true
                    })
                    .to_string(),
                    stderr: "nginx reload failed".to_string(),
                    timed_out: false,
                };
            }
            st.remote_config_content = stdin_data.unwrap_or("").to_string();
            return CommandResult {
                exit_code: 0,
                stdout: json!({
                    "backup_id": "nginx-site.20261124.bak",
                    "reloaded": true,
                    "rolled_back": false
                })
                .to_string(),
                stderr: String::new(),
                timed_out: false,
            };
        }
        if remote_cmd.starts_with("config-backups ") {
            return CommandResult {
                exit_code: 0,
                stdout: "nginx-site.20261124.bak\n".to_string(),
                stderr: String::new(),
                timed_out: false,
            };
        }
        if remote_cmd.starts_with("config-rollback ") {
            return CommandResult {
                exit_code: 0,
                stdout: "Rolled back nginx-site to nginx-site.20261124.bak\n".to_string(),
                stderr: String::new(),
                timed_out: false,
            };
        }
        CommandResult {
            exit_code: 1,
            stdout: String::new(),
            stderr: format!("Unexpected command: {remote_cmd}"),
            timed_out: false,
        }
    }
}

fn setup_fixture() -> (TempDir, Arc<Mutex<MockState>>, OpsEngine) {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let key_ops = root.join("id_ops");
    let key_sync = root.join("id_sync");
    fs::write(&key_ops, "ops-key").unwrap();
    fs::write(&key_sync, "sync-key").unwrap();

    let staging = root.join("staging");
    fs::create_dir_all(&staging).unwrap();
    fs::write(staging.join("index.php"), "<?php echo 'v1';\n").unwrap();
    fs::write(staging.join("style.css"), "body { color: #111; }\n").unwrap();

    let env_file = root.join(".ssh-servers.env");
    fs::write(
        &env_file,
        format!(
            "[prod-web]\nHOST=203.0.113.77\nUSER=prod_secret_user\nPORT=2200\nKEY_FILE={}\nSYNC_KEY_FILE={}\n",
            key_ops.display(),
            key_sync.display()
        ),
    )
    .unwrap();

    let policy_file = root.join("policy.yaml");
    fs::write(
        &policy_file,
        format!(
            r#"
global:
  plan_ttl_seconds: 180
  max_output_bytes: 16384
  gate_mode: true
  strict_host_key_checking: "yes"

servers:
  prod-web:
    description: "Main prod node"
    logs:
      nginx-err:
        type: file
        path: /var/log/nginx/error.log
        max_lines: 50
    docker:
      allowed_containers:
        - web-app
    configs:
      nginx-site:
        path: /etc/nginx/conf.d/app.conf
        backup_dir: /var/backups/ai-ops/nginx
        validator: nginx_test
        reload_action: nginx_reload
        redact_patterns:
          - '(?i)api_secret=[^\s;]+'
    sync_targets:
      plugin-release:
        direction: push
        local_base: {}
        remote_base: /var/www/html/wp-content/plugins/my-plugin
        use_rrsync: true
        allow_delete: false
        max_files: 50
        max_size_mb: 10
      strict-delete-target:
        direction: push
        local_base: {}
        remote_base: /var/www/html/static
        allow_delete: true
        max_delete_files: 1
        max_files: 50
        max_size_mb: 10
"#,
            staging.display(),
            staging.display()
        ),
    )
    .unwrap();

    let state = Arc::new(Mutex::new(MockState {
        calls: Vec::new(),
        remote_config_content:
            "server {\n  listen 80;\n  proxy_set_header X-Secret api_secret=topsecret_42;\n}\n"
                .to_string(),
        validator_should_fail: false,
        reload_should_fail: false,
        rsync_preview_stdout: ">f+++++++++ index.php\n>f.st...... style.css\n".to_string(),
    }));

    let profiles = load_server_profiles(&env_file, false, true).unwrap();
    let known: HashSet<String> = profiles.keys().cloned().collect();
    let policy = load_policy(&policy_file, Some(&known), false).unwrap();
    let audit = AuditLogger::new(root.join("audit.jsonl")).unwrap();
    let runner: Arc<dyn CommandRunner> = Arc::new(MockRunner {
        state: Arc::clone(&state),
    });
    let engine = OpsEngine::new(profiles, policy, audit, Some(runner), 0);

    (tmp, state, engine)
}

#[test]
fn test_config_parsers_reject_symlinks_and_insecure_options() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let key = root.join("id_ops");
    fs::write(&key, "dummy").unwrap();

    let real_env = root.join("real.env");
    fs::write(
        &real_env,
        format!(
            "[prod-web]\nHOST='198.51.100.42'\nUSER=\"deploy_ai\"\nPORT=2222\nKEY_FILE={}\n",
            key.display()
        ),
    )
    .unwrap();
    let profs = load_server_profiles(&real_env, false, true).unwrap();
    assert_eq!(profs["prod-web"].host, "198.51.100.42");
    assert_eq!(profs["prod-web"].port, 2222);

    let link_env = root.join("link.env");
    symlink(&real_env, &link_env).unwrap();
    assert!(load_server_profiles(&link_env, false, true).is_err());

    let bad_pol = root.join("bad_pol.yaml");
    fs::write(
        &bad_pol,
        "global:\n  strict_host_key_checking: \"no\"\nservers: {}\n",
    )
    .unwrap();
    assert!(load_policy(&bad_pol, None, false).is_err());

    let trav_pol = root.join("trav_pol.yaml");
    fs::write(
        &trav_pol,
        "servers:\n  prod-web:\n    logs:\n      bad:\n        type: file\n        path: /var/log/../../etc/shadow\n",
    )
    .unwrap();
    assert!(load_policy(&trav_pol, None, false).is_err());

    // opsd.conf literal parser + symlink rejection
    let conf = root.join("opsd.conf");
    fs::write(
        &conf,
        "servers_env = real.env\npolicy = policy.yaml\nsocket_group = opsclients\ncheck_ownership = true\n",
    )
    .unwrap();
    let dc = load_daemon_config(&conf, false).unwrap();
    assert_eq!(dc.servers_env, root.join("real.env"));
    assert_eq!(dc.socket_group.as_deref(), Some("opsclients"));
    assert!(dc.check_ownership);

    let link_conf = root.join("link.conf");
    symlink(&conf, &link_conf).unwrap();
    assert!(load_daemon_config(&link_conf, false).is_err());
}

#[test]
fn test_redactor_and_config_secret_placeholder_integrity() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let key = root.join("id_ops");
    fs::write(&key, "k").unwrap();
    let env_file = root.join(".ssh-servers.env");
    fs::write(
        &env_file,
        format!(
            "[prod-web]\nHOST=198.51.100.42\nUSER=deploy_ai\nPORT=22\nKEY_FILE={}\n",
            key.display()
        ),
    )
    .unwrap();
    let profiles = load_server_profiles(&env_file, false, true).unwrap();
    let redactor = Redactor::new(&profiles);

    let dirty = format!(
        "ssh: connect to host 198.51.100.42 port 22: Permission denied for deploy_ai@198.51.100.42\n\
         Using key {} with -e 'ssh -i {} -p 22'\n\
         Extra IP 10.20.30.40 and mysql://dbuser:SuperPass123@10.0.0.5/app\n\
         Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload\n\
         AWS=AKIAIOSFODNN7EXAMPLE\n\
         -----BEGIN OPENSSH PRIVATE KEY-----\nSECRETBODY\n-----END OPENSSH PRIVATE KEY-----\n\
         Remote root /var/www/secret-site",
        key.display(),
        key.display()
    );
    let clean = redactor.redact(
        &dirty,
        Some(&profiles["prod-web"]),
        &[("/var/www/secret-site", "[TARGET_REMOTE_ROOT]")],
    );
    for secret in [
        "198.51.100.42",
        "deploy_ai",
        &key.display().to_string(),
        "10.20.30.40",
        "SuperPass123",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
        "AKIAIOSFODNN7EXAMPLE",
        "SECRETBODY",
        "/var/www/secret-site",
    ] {
        assert!(!clean.contains(secret), "Leaked secret '{secret}' in: {clean}");
    }
    assert!(clean.contains("[REDACTED_PRIVATE_KEY]"));
    assert!(clean.contains("[TARGET_REMOTE_ROOT]"));

    let raw = "server_name example.com;\nproxy_set_header X-Api-Key api_key=my_ultra_secret_99;\nlisten 80;\n";
    let patterns = vec![r"(?i)(password|secret|token|api_key)\s*[:=]\s*[^\s;]+".to_string()];
    let (masked, smap) = mask_config_secrets(raw, &patterns).unwrap();
    assert!(!masked.contains("my_ultra_secret_99"));
    assert!(masked.contains("{{REDACTED_SECRET_1}}"));

    let restored = unmask_config_secrets(&masked.replace("listen 80;", "listen 443;"), &smap).unwrap();
    assert!(restored.contains("api_key=my_ultra_secret_99"));
    assert!(restored.contains("listen 443;"));

    assert!(unmask_config_secrets(&masked.replace("{{REDACTED_SECRET_1}}", "hacked"), &smap).is_err());
    assert!(unmask_config_secrets(&format!("{masked}\n# {{{{REDACTED_SECRET_99}}}}\n"), &smap).is_err());

    let trunc = truncate_output(&"a".repeat(5000), 1024);
    assert!(trunc.len() <= 1024);
    assert!(trunc.contains("[OUTPUT TRUNCATED]"));
}

#[test]
fn test_planner_lifecycle_expiration_and_anti_self_approval() {
    let store = PlanStore::new(60);
    let plan = store
        .create(
            "prod-web".to_string(),
            "web-app".to_string(),
            "OOM".to_string(),
            "Restart web-app".to_string(),
            String::new(),
            PlanPayload::DockerRestart {
                server: "prod-web".to_string(),
                target: "web-app".to_string(),
            },
        )
        .unwrap();

    assert!(store.consume_approved(&plan.token, "docker_restart").is_err());
    let approved = store.approve(&plan.token, "human:alice").unwrap();
    assert_eq!(approved["status"], "APPROVED");
    assert!(store.consume_approved(&plan.token, "rsync_sync").is_err());
    let consumed = store.consume_approved(&plan.token, "docker_restart").unwrap();
    assert_eq!(consumed.approved_by.as_deref(), Some("human:alice"));
    assert!(store.consume_approved(&plan.token, "docker_restart").is_err());

    let p2 = store
        .create(
            "prod-web".to_string(),
            "release".to_string(),
            "deploy".to_string(),
            "sync".to_string(),
            String::new(),
            PlanPayload::DockerRestart {
                server: "prod-web".to_string(),
                target: "web-app".to_string(),
            },
        )
        .unwrap();
    store.expire_for_test(&p2.token);
    assert!(store.approve(&p2.token, "human:alice").is_err());

    let (_tmp, _st, engine) = setup_fixture();
    let bad = engine.handle_client_request("admin.approve", &json!({ "plan_token": "pln_123" }));
    assert_eq!(bad["ok"], false);
    assert!(bad["error"].as_str().unwrap().to_lowercase().contains("forbidden"));
}

#[test]
fn test_capabilities_logs_and_docker_two_phase() {
    let (_tmp, _st, engine) = setup_fixture();

    let caps = engine.handle_client_request("capabilities", &json!({}));
    assert_eq!(caps["ok"], true);
    let caps_str = caps.to_string();
    for hidden in ["203.0.113.77", "prod_secret_user", "/var/www/html"] {
        assert!(!caps_str.contains(hidden));
    }

    let logs = engine.handle_client_request(
        "logs",
        &json!({ "server": "prod-web", "log_id": "nginx-err", "lines": 9999, "keyword": "ERROR" }),
    );
    assert_eq!(logs["ok"], true);
    assert_eq!(logs["data"]["lines_requested"], 50);
    let content = logs["data"]["content"].as_str().unwrap();
    assert!(content.contains("ERROR upstream"));
    assert!(!content.contains("INFO boot ok"));
    assert!(!content.contains("203.0.113.77"));
    assert!(!content.contains("prod_secret_user"));

    assert_eq!(
        engine.handle_client_request("logs", &json!({ "server": "prod-web", "log_id": "shadow" }))["ok"],
        false
    );

    let plan = engine.handle_client_request(
        "docker.restart_plan",
        &json!({ "server": "prod-web", "target": "web-app", "reason": "Memory spike" }),
    );
    assert_eq!(plan["ok"], true);
    let tok = plan["data"]["plan_token"].as_str().unwrap().to_string();

    assert_eq!(
        engine.handle_client_request("docker.restart_apply", &json!({ "plan_token": tok }))["ok"],
        false
    );
    assert_eq!(
        engine.handle_admin_request(
            "admin.approve",
            &json!({ "plan_token": tok, "actor": "human:bob" })
        )["ok"],
        true
    );
    let applied = engine.handle_client_request("docker.restart_apply", &json!({ "plan_token": tok }));
    assert_eq!(applied["ok"], true);
    assert_eq!(applied["data"]["exit_code"], 0);
    let startup = applied["data"]["startup_logs"].as_str().unwrap();
    assert!(startup.contains("Started web-app"));
    assert!(!startup.contains("203.0.113.77"));
}

#[test]
fn test_rsync_symlink_escape_delete_fuse_and_toctou() {
    let (tmp, state, engine) = setup_fixture();
    let staging = tmp.path().join("staging");

    // 1. Delete circuit breaker
    state.lock().unwrap().rsync_preview_stdout = "*deleting a.php\n*deleting b.php\n".to_string();
    let fuse = engine.handle_client_request(
        "rsync.preview",
        &json!({ "server": "prod-web", "target": "strict-delete-target" }),
    );
    assert_eq!(fuse["ok"], false);
    assert!(fuse["error"]
        .as_str()
        .unwrap()
        .to_lowercase()
        .contains("circuit breaker"));

    // 2. TOCTOU tampering detection + clean apply
    state.lock().unwrap().rsync_preview_stdout =
        ">f+++++++++ index.php\n>f.st...... style.css\n".to_string();
    let prev = engine.handle_client_request(
        "rsync.preview",
        &json!({ "server": "prod-web", "target": "plugin-release" }),
    );
    assert_eq!(prev["ok"], true);
    let tok = prev["data"]["plan_token"].as_str().unwrap().to_string();
    engine.handle_admin_request(
        "admin.approve",
        &json!({ "plan_token": tok, "actor": "human:bob" }),
    );

    fs::write(staging.join("index.php"), "<?php system($_GET['x']);\n").unwrap();
    let tampered = engine.handle_client_request("rsync.apply", &json!({ "plan_token": tok }));
    assert_eq!(tampered["ok"], false);
    assert!(tampered["error"]
        .as_str()
        .unwrap()
        .to_lowercase()
        .contains("toctou"));

    let prev2 = engine.handle_client_request(
        "rsync.preview",
        &json!({ "server": "prod-web", "target": "plugin-release" }),
    );
    let tok2 = prev2["data"]["plan_token"].as_str().unwrap().to_string();
    engine.handle_admin_request(
        "admin.approve",
        &json!({ "plan_token": tok2, "actor": "human:bob" }),
    );
    let ok_apply = engine.handle_client_request("rsync.apply", &json!({ "plan_token": tok2 }));
    assert_eq!(ok_apply["ok"], true);
    assert_eq!(ok_apply["data"]["exit_code"], 0);
    let last_rsync = state
        .lock()
        .unwrap()
        .calls
        .iter()
        .rev()
        .find(|(a, _)| a.first().map(String::as_str) == Some("rsync"))
        .unwrap()
        .0
        .clone();
    assert!(last_rsync.last().unwrap().ends_with(":."));

    // 3. Escaping symlink rejected
    let outside = tmp.path().join("outside_secret.txt");
    fs::write(&outside, "SECRET").unwrap();
    symlink(&outside, staging.join("leak.txt")).unwrap();
    let sym = engine.handle_client_request(
        "rsync.preview",
        &json!({ "server": "prod-web", "target": "plugin-release" }),
    );
    assert_eq!(sym["ok"], false);
    assert!(sym["error"].as_str().unwrap().to_lowercase().contains("symlink"));
}

#[test]
fn test_config_lifecycle_validation_and_rollback() {
    let (_tmp, state, engine) = setup_fixture();

    let read = engine.handle_client_request(
        "config.read",
        &json!({ "server": "prod-web", "config_id": "nginx-site" }),
    );
    assert_eq!(read["ok"], true);
    let base_sha = read["data"]["base_sha256"].as_str().unwrap().to_string();
    let masked = read["data"]["content"].as_str().unwrap().to_string();
    assert!(!masked.contains("topsecret_42"));
    assert!(masked.contains("{{REDACTED_SECRET_1}}"));

    let draft = masked.replace("listen 80;", "listen 443 ssl;");

    // Validator failure blocks token issuance & redacts remote path
    state.lock().unwrap().validator_should_fail = true;
    let bad = engine.handle_client_request(
        "config.plan",
        &json!({
            "server": "prod-web",
            "config_id": "nginx-site",
            "draft_content": draft,
            "base_sha256": base_sha,
            "reason": "Enable TLS"
        }),
    );
    assert_eq!(bad["ok"], false);
    assert!(!bad["error"]
        .as_str()
        .unwrap()
        .contains("/etc/nginx/conf.d/app.conf"));

    // Valid plan
    state.lock().unwrap().validator_should_fail = false;
    let plan = engine.handle_client_request(
        "config.plan",
        &json!({
            "server": "prod-web",
            "config_id": "nginx-site",
            "draft_content": draft,
            "base_sha256": base_sha,
            "reason": "Enable TLS"
        }),
    );
    assert_eq!(plan["ok"], true);
    let diff = plan["data"]["diff"].as_str().unwrap();
    assert!(!diff.contains("topsecret_42"));
    assert!(diff.contains("+  listen 443 ssl;"));
    let tok = plan["data"]["plan_token"].as_str().unwrap().to_string();

    engine.handle_admin_request(
        "admin.approve",
        &json!({ "plan_token": tok, "actor": "human:bob" }),
    );
    let applied = engine.handle_client_request("config.apply", &json!({ "plan_token": tok }));
    assert_eq!(applied["ok"], true);
    assert_eq!(applied["data"]["reloaded"], true);
    assert_eq!(applied["data"]["rolled_back"], false);
    assert_eq!(applied["data"]["backup_id"], "nginx-site.20261124.bak");

    let written = state.lock().unwrap().remote_config_content.clone();
    assert!(written.contains("api_secret=topsecret_42"));
    assert!(written.contains("listen 443 ssl;"));

    // Rollback two-phase
    let rb_plan = engine.handle_client_request(
        "config.rollback_plan",
        &json!({
            "server": "prod-web",
            "config_id": "nginx-site",
            "backup_id": "nginx-site.20261124.bak",
            "reason": "Revert TLS"
        }),
    );
    assert_eq!(rb_plan["ok"], true);
    let rb_tok = rb_plan["data"]["plan_token"].as_str().unwrap().to_string();
    engine.handle_admin_request(
        "admin.approve",
        &json!({ "plan_token": rb_tok, "actor": "human:bob" }),
    );
    let rb_applied =
        engine.handle_client_request("config.rollback_apply", &json!({ "plan_token": rb_tok }));
    assert_eq!(rb_applied["ok"], true);
    assert_eq!(rb_applied["data"]["exit_code"], 0);
}

#[test]
fn test_real_binaries_dual_socket_e2e() {
    let (tmp, _state, engine) = setup_fixture();
    let client_sock = tmp.path().join("ops.sock");
    let admin_sock = tmp.path().join("admin.sock");
    let audit_path = tmp.path().join("audit.jsonl");

    let daemon = OpsDaemon::start(
        Arc::new(engine),
        client_sock.clone(),
        admin_sock.clone(),
        0o600,
        None,
    )
    .unwrap();

    // Admin socket must strictly be 0600
    let admin_mode = fs::metadata(&admin_sock).unwrap().permissions().mode() & 0o777;
    assert_eq!(admin_mode, 0o600);

    let opsctl_bin = env!("CARGO_BIN_EXE_opsctl");
    let approve_bin = env!("CARGO_BIN_EXE_ops-approve");

    // 1. opsctl capabilities
    let out = Command::new(opsctl_bin)
        .args([
            "--socket",
            client_sock.to_str().unwrap(),
            "--json",
            "capabilities",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.contains("203.0.113.77"));

    // 2. opsctl docker restart-plan
    let out = Command::new(opsctl_bin)
        .args([
            "--socket",
            client_sock.to_str().unwrap(),
            "--json",
            "docker",
            "restart-plan",
            "prod-web",
            "web-app",
            "--reason",
            "rust e2e",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let parsed: Value = serde_json::from_slice(&out.stdout).unwrap();
    let token = parsed["data"]["plan_token"].as_str().unwrap().to_string();

    // 3. Attempting admin.approve directly on client socket MUST fail
    let bad = send_request(&client_sock, "admin.approve", json!({ "plan_token": token }), 10)
        .unwrap();
    assert_eq!(bad["ok"], false);

    // 4. ops-approve lists and approves on admin socket
    let out = Command::new(approve_bin)
        .args(["--admin-socket", admin_sock.to_str().unwrap(), "--list"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains(&token));

    let out = Command::new(approve_bin)
        .args([
            "--admin-socket",
            admin_sock.to_str().unwrap(),
            "approve",
            &token,
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("APPROVED"));

    // 5. opsctl applies approved plan
    let out = Command::new(opsctl_bin)
        .args([
            "--socket",
            client_sock.to_str().unwrap(),
            "--json",
            "docker",
            "restart-apply",
            &token,
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let applied: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(applied["ok"], true);
    assert!(!applied["data"]["startup_logs"]
        .as_str()
        .unwrap()
        .contains("203.0.113.77"));

    // 6. Audit log recorded actions without leaking secrets
    let audit_text = fs::read_to_string(&audit_path).unwrap();
    assert!(audit_text.contains("docker.restart_apply"));
    assert!(audit_text.contains("admin.approve"));
    assert!(!audit_text.contains("203.0.113.77"));
    assert!(!audit_text.contains("prod_secret_user"));

    daemon.stop();
}

#[test]
fn test_example_deploy_configs_are_valid() {
    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let dc = load_daemon_config(&repo_root.join("deploy/opsd.example.conf"), false).unwrap();
    assert!(dc
        .servers_env
        .to_string_lossy()
        .ends_with(".ssh-servers.env"));
    let profs = load_server_profiles(
        &repo_root.join("deploy/ssh-servers.example.env"),
        false,
        false,
    )
    .unwrap();
    let known: HashSet<String> = profs.keys().cloned().collect();
    let pol = load_policy(
        &repo_root.join("deploy/policy.example.yaml"),
        Some(&known),
        false,
    )
    .unwrap();
    assert!(pol.servers.contains_key("prod-web-1"));
    assert!(pol.servers["prod-web-1"]
        .sync_targets
        .contains_key("wp-plugin-release"));
}

#[test]
fn test_allow_unlisted_servers_default_open_and_exec_approval() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let key = root.join("id_ops");
    fs::write(&key, "ops-key").unwrap();

    let staging_root = root.join("staging-root");
    let app_stage = staging_root.join("my-app");
    fs::create_dir_all(&app_stage).unwrap();
    fs::write(app_stage.join("app.php"), "<?php echo 'ok';\n").unwrap();

    let outside_dir = root.join("outside-dir");
    fs::create_dir_all(&outside_dir).unwrap();
    fs::write(outside_dir.join("secret.txt"), "nope").unwrap();

    let env_file = root.join(".ssh-servers.env");
    fs::write(
        &env_file,
        format!(
            "[locked-srv]\nHOST=198.51.100.10\nUSER=locked_user\nPORT=22\nKEY_FILE={0}\n\n\
             [open-srv]\nHOST=198.51.100.20\nUSER=open_user\nPORT=22\nKEY_FILE={0}\n",
            key.display()
        ),
    )
    .unwrap();

    let policy_file = root.join("policy.yaml");
    fs::write(
        &policy_file,
        format!(
            r#"
global:
  gate_mode: false
  allow_unlisted_servers: true
  unlisted_staging_root: {}
  strict_host_key_checking: "yes"

servers:
  locked-srv:
    description: "Explicitly restricted server"
    logs:
      only-app:
        type: file
        path: /var/log/app.log
"#,
            staging_root.display()
        ),
    )
    .unwrap();

    struct OpenMockRunner;
    impl CommandRunner for OpenMockRunner {
        fn run(&self, argv: &[String], _stdin: Option<&str>, _timeout: u64) -> CommandResult {
            if argv.first().map(String::as_str) == Some("rsync") {
                return CommandResult {
                    exit_code: 0,
                    stdout: ">f+++++++++ app.php\n".to_string(),
                    stderr: String::new(),
                    timed_out: false,
                };
            }
            let cmd = argv.last().map(String::as_str).unwrap_or("");
            if cmd.starts_with("docker ps ") {
                return CommandResult {
                    exit_code: 0,
                    stdout: "web\trunning\tUp 2 hours\n".to_string(),
                    stderr: String::new(),
                    timed_out: false,
                };
            }
            if cmd.contains("uname -a") {
                return CommandResult {
                    exit_code: 0,
                    stdout: "Linux prod 198.51.100.20 open_user\n".to_string(),
                    stderr: String::new(),
                    timed_out: false,
                };
            }
            if cmd.starts_with("cat ") {
                return CommandResult {
                    exit_code: 0,
                    stdout: "listen 80;\nsecret=super_hidden_99;\n".to_string(),
                    stderr: String::new(),
                    timed_out: false,
                };
            }
            if cmd.contains(".opsbak.") {
                return CommandResult {
                    exit_code: 0,
                    stdout: r#"{"backup_id":"app.conf.opsbak.20261124","reloaded":false,"rolled_back":false}"#.to_string(),
                    stderr: String::new(),
                    timed_out: false,
                };
            }
            CommandResult {
                exit_code: 0,
                stdout: "ok line\n".to_string(),
                stderr: String::new(),
                timed_out: false,
            }
        }
    }

    let profiles = load_server_profiles(&env_file, false, true).unwrap();
    let known: HashSet<String> = profiles.keys().cloned().collect();
    let policy = load_policy(&policy_file, Some(&known), false).unwrap();
    let audit = AuditLogger::new(root.join("audit.jsonl")).unwrap();
    let engine = OpsEngine::new(profiles, policy, audit, Some(Arc::new(OpenMockRunner)), 0);

    // 1. capabilities exposes open-srv as default_open and locked-srv as restricted without leaking IPs
    let caps = engine.handle_client_request("capabilities", &json!({}));
    assert_eq!(caps["ok"], true);
    assert_eq!(caps["data"]["servers"]["open-srv"]["policy_mode"], "default_open");
    assert_eq!(caps["data"]["servers"]["locked-srv"]["policy_mode"], "restricted");
    assert!(!caps.to_string().contains("198.51.100.20"));

    // 2. locked-srv still rejects custom exec (explicit policy overrides allow_unlisted_servers)
    let locked_exec = engine.handle_client_request(
        "exec.plan",
        &json!({ "server": "locked-srv", "command": "uname -a", "reason": "check" }),
    );
    assert_eq!(locked_exec["ok"], false);

    // 3. open-srv blocks sensitive system paths in logs & config
    assert_eq!(
        engine.handle_client_request("logs", &json!({ "server": "open-srv", "log_id": "/etc/shadow" }))["ok"],
        false
    );
    assert_eq!(
        engine.handle_client_request("config.read", &json!({ "server": "open-srv", "config_id": "/root/.ssh/authorized_keys" }))["ok"],
        false
    );

    // 4. open-srv docker status lists all containers
    let dstat = engine.handle_client_request("docker.status", &json!({ "server": "open-srv" }));
    assert_eq!(dstat["ok"], true);
    assert!(dstat["data"]["targets"][0]["status"].as_str().unwrap().contains("web"));

    // 5. open-srv exec requires human approval and redacts output
    let eplan = engine.handle_client_request(
        "exec.plan",
        &json!({ "server": "open-srv", "command": "uname -a", "reason": "check kernel" }),
    );
    assert_eq!(eplan["ok"], true);
    let etok = eplan["data"]["plan_token"].as_str().unwrap().to_string();
    assert_eq!(
        engine.handle_client_request("exec.apply", &json!({ "plan_token": etok }))["ok"],
        false
    );
    engine.handle_admin_request("admin.approve", &json!({ "plan_token": etok, "actor": "human:bob" }));
    let eapp = engine.handle_client_request("exec.apply", &json!({ "plan_token": etok }));
    assert_eq!(eapp["ok"], true);
    let out = eapp["data"]["stdout"].as_str().unwrap();
    assert!(out.contains("Linux prod"));
    assert!(!out.contains("198.51.100.20"));
    assert!(!out.contains("open_user"));

    // 6. open-srv dynamic rsync blocks paths outside unlisted_staging_root, allows inside
    let bad_sync = engine.handle_client_request(
        "rsync.preview",
        &json!({
            "server": "open-srv",
            "local": outside_dir.to_str().unwrap(),
            "remote": "/var/www/app"
        }),
    );
    assert_eq!(bad_sync["ok"], false);

    let ok_sync = engine.handle_client_request(
        "rsync.preview",
        &json!({
            "server": "open-srv",
            "local": "my-app",
            "remote": "/var/www/app"
        }),
    );
    assert_eq!(ok_sync["ok"], true);
    let rtok = ok_sync["data"]["plan_token"].as_str().unwrap().to_string();
    engine.handle_admin_request("admin.approve", &json!({ "plan_token": rtok, "actor": "human:bob" }));
    let rapp = engine.handle_client_request("rsync.apply", &json!({ "plan_token": rtok }));
    assert_eq!(rapp["ok"], true);

    // 7. open-srv direct config read/plan/apply works in gate_mode=false with secret masking
    let cread = engine.handle_client_request(
        "config.read",
        &json!({ "server": "open-srv", "config_id": "/etc/nginx/conf.d/app.conf" }),
    );
    assert_eq!(cread["ok"], true);
    let sha = cread["data"]["base_sha256"].as_str().unwrap().to_string();
    let masked = cread["data"]["content"].as_str().unwrap().to_string();
    assert!(!masked.contains("super_hidden_99"));
    let cplan = engine.handle_client_request(
        "config.plan",
        &json!({
            "server": "open-srv",
            "config_id": "/etc/nginx/conf.d/app.conf",
            "draft_content": masked.replace("listen 80;", "listen 443;"),
            "base_sha256": sha,
            "reason": "test direct config"
        }),
    );
    assert_eq!(cplan["ok"], true);
    let ctok = cplan["data"]["plan_token"].as_str().unwrap().to_string();
    engine.handle_admin_request("admin.approve", &json!({ "plan_token": ctok, "actor": "human:bob" }));
    let capp = engine.handle_client_request("config.apply", &json!({ "plan_token": ctok }));
    assert_eq!(capp["ok"], true);
    assert_eq!(capp["data"]["backup_id"], "app.conf.opsbak.20261124");
}
