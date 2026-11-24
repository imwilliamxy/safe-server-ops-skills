//! Embedded zero-dependency read-only HTTP/1.1 + SSE monitoring server (loopback only).

use std::collections::HashMap;
use std::io::{BufRead, BufReader, ErrorKind, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::RecvTimeoutError;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use serde_json::{json, Value};

use crate::audit::RecordFilter;
use crate::config::validate_loopback_listen_addr;
use crate::engine::OpsEngine;

const WEB_UI_HTML: &str = include_str!("web_ui.html");
const MAX_HTTP_HEADER_LINES: usize = 64;

pub struct WebServer {
    local_addr: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl WebServer {
    pub fn start(engine: Arc<OpsEngine>, listen_addr: &str) -> Result<Self, String> {
        let addr = validate_loopback_listen_addr(listen_addr)?;
        let listener = TcpListener::bind(addr)
            .map_err(|e| format!("Failed to bind web server on {addr}: {e}"))?;
        let local_addr = listener
            .local_addr()
            .map_err(|e| format!("Failed to inspect web server local address: {e}"))?;
        listener
            .set_nonblocking(true)
            .map_err(|e| format!("Failed to set web listener nonblocking: {e}"))?;

        let stop = Arc::new(AtomicBool::new(false));
        let stop_loop = Arc::clone(&stop);

        let handle = thread::Builder::new()
            .name("opsd-web".to_string())
            .spawn(move || {
                while !stop_loop.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((stream, _peer)) => {
                            let eng = Arc::clone(&engine);
                            let st = Arc::clone(&stop_loop);
                            thread::spawn(move || handle_http_connection(stream, eng, st));
                        }
                        Err(e) if e.kind() == ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(20));
                        }
                        Err(_) => {
                            thread::sleep(Duration::from_millis(50));
                        }
                    }
                }
            })
            .map_err(|e| format!("Failed to spawn web server thread: {e}"))?;

        Ok(Self {
            local_addr,
            stop,
            thread: Some(handle),
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn stop(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.thread.take() {
            let _ = h.join();
        }
    }
}

impl Drop for WebServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.thread.take() {
            let _ = h.join();
        }
    }
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                if let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                    out.push((hi << 4) | lo);
                    i += 3;
                } else {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn parse_query(query: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = match pair.split_once('=') {
            Some((k, v)) => (percent_decode(k), percent_decode(v)),
            None => (percent_decode(pair), String::new()),
        };
        if !k.is_empty() {
            map.insert(k, v);
        }
    }
    map
}

fn query_bool(params: &HashMap<String, String>, key: &str) -> bool {
    params
        .get(key)
        .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
}

fn write_response(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &[u8],
    head_only: bool,
    extra_headers: &[(&str, &str)],
) {
    let mut header = format!(
        "HTTP/1.1 {status}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         X-Content-Type-Options: nosniff\r\n\
         X-Frame-Options: DENY\r\n\
         Referrer-Policy: no-referrer\r\n",
        body.len()
    );
    for (k, v) in extra_headers {
        header.push_str(&format!("{k}: {v}\r\n"));
    }
    header.push_str("\r\n");

    let _ = stream.write_all(header.as_bytes());
    if !head_only && !body.is_empty() {
        let _ = stream.write_all(body);
    }
    let _ = stream.flush();
}

fn write_json(stream: &mut TcpStream, status: &str, payload: &Value, head_only: bool) {
    let body = serde_json::to_vec(payload).unwrap_or_else(|_| b"{}".to_vec());
    write_response(
        stream,
        status,
        "application/json; charset=utf-8",
        &body,
        head_only,
        &[("Cache-Control", "no-store")],
    );
}

fn handle_sse(mut stream: TcpStream, engine: Arc<OpsEngine>, stop: Arc<AtomicBool>) {
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
    let headers = "HTTP/1.1 200 OK\r\n\
                   Content-Type: text/event-stream; charset=utf-8\r\n\
                   Cache-Control: no-cache\r\n\
                   Connection: close\r\n\
                   X-Accel-Buffering: no\r\n\
                   X-Content-Type-Options: nosniff\r\n\
                   X-Frame-Options: DENY\r\n\r\n\
                   event: connected\ndata: {\"ok\":true}\n\n";
    if stream.write_all(headers.as_bytes()).is_err() || stream.flush().is_err() {
        return;
    }

    let rx = engine.audit_logger().subscribe();
    let mut idle_ticks: u32 = 0;

    while !stop.load(Ordering::Relaxed) {
        match rx.recv_timeout(Duration::from_millis(500)) {
            Ok(frame) => {
                idle_ticks = 0;
                if stream.write_all(frame.as_bytes()).is_err() || stream.flush().is_err() {
                    break;
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                idle_ticks += 1;
                if idle_ticks >= 30 {
                    idle_ticks = 0;
                    if stream.write_all(b": keepalive\n\n").is_err() || stream.flush().is_err() {
                        break;
                    }
                }
            }
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
}

fn handle_http_connection(mut stream: TcpStream, engine: Arc<OpsEngine>, stop: Arc<AtomicBool>) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(15)));

    let request_line = {
        let mut reader = BufReader::new(&stream);
        let mut first = String::new();
        match reader.read_line(&mut first) {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
        // Drain request headers up to empty line
        for _ in 0..MAX_HTTP_HEADER_LINES {
            let mut hdr = String::new();
            match reader.read_line(&mut hdr) {
                Ok(0) | Err(_) => break,
                Ok(_) if hdr == "\r\n" || hdr == "\n" => break,
                Ok(_) => {}
            }
        }
        first
    };

    let mut parts = request_line.split_whitespace();
    let Some(method) = parts.next() else {
        write_json(
            &mut stream,
            "400 Bad Request",
            &json!({ "error": "Malformed HTTP request line." }),
            false,
        );
        return;
    };
    let Some(raw_target) = parts.next() else {
        write_json(
            &mut stream,
            "400 Bad Request",
            &json!({ "error": "Missing request target." }),
            false,
        );
        return;
    };

    // Strictly enforce read-only HTTP interface (prevent AI self-approval via localhost HTTP).
    if method != "GET" && method != "HEAD" {
        write_response(
            &mut stream,
            "405 Method Not Allowed",
            "application/json; charset=utf-8",
            br#"{"error":"Read-only monitoring UI: only GET and HEAD are allowed."}"#,
            false,
            &[("Allow", "GET, HEAD"), ("Cache-Control", "no-store")],
        );
        return;
    }
    let head_only = method == "HEAD";

    let (raw_path, raw_query) = match raw_target.split_once('?') {
        Some((p, q)) => (p, q),
        None => (raw_target, ""),
    };
    let query = parse_query(raw_query);

    if raw_path == "/" || raw_path == "/index.html" {
        write_response(
            &mut stream,
            "200 OK",
            "text/html; charset=utf-8",
            WEB_UI_HTML.as_bytes(),
            head_only,
            &[("Cache-Control", "no-cache")],
        );
        return;
    }

    if raw_path == "/api/events" {
        if head_only {
            write_response(
                &mut stream,
                "200 OK",
                "text/event-stream; charset=utf-8",
                b"",
                true,
                &[("Cache-Control", "no-cache")],
            );
            return;
        }
        handle_sse(stream, engine, stop);
        return;
    }

    if raw_path == "/api/overview" {
        let stats = engine.audit_logger().stats();
        let servers = engine.web_servers_snapshot();
        let pending_count = engine.planner().pending_count();
        write_json(
            &mut stream,
            "200 OK",
            &json!({
                "status": "running",
                "read_only": true,
                "pending_count": pending_count,
                "servers": servers,
                "stats": stats,
            }),
            head_only,
        );
        return;
    }

    if raw_path == "/api/pending" {
        let pending = engine.planner().list_pending_with_diff(true);
        let count = pending.len();
        write_json(
            &mut stream,
            "200 OK",
            &json!({
                "count": count,
                "pending": pending,
            }),
            head_only,
        );
        return;
    }

    if raw_path == "/api/sessions" {
        let pending_map = engine.planner().pending_counts_by_session();
        let mut sessions = engine.audit_logger().list_sessions(&pending_map);

        let q = query
            .get("q")
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty());
        let srv_filter = query
            .get("server")
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let agent_filter = query
            .get("agent")
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty());
        let only_errors = query_bool(&query, "only_errors");
        let only_writes = query_bool(&query, "only_writes");

        sessions.retain(|s| {
            if let Some(ref srv) = srv_filter {
                if !s.servers.iter().any(|x| x == srv) {
                    return false;
                }
            }
            if let Some(ref ag) = agent_filter {
                if s.agent.to_ascii_lowercase() != *ag {
                    return false;
                }
            }
            if only_errors && s.error_calls == 0 {
                return false;
            }
            if only_writes && s.write_calls == 0 {
                return false;
            }
            if let Some(ref needle) = q {
                let hay = format!(
                    "{}\n{}\n{}\n{}\n{}",
                    s.title,
                    s.session_id,
                    s.agent,
                    s.project_name.as_deref().unwrap_or(""),
                    s.servers.join(" ")
                )
                .to_ascii_lowercase();
                if !hay.contains(needle) {
                    return false;
                }
            }
            true
        });

        let total = sessions.len();
        write_json(
            &mut stream,
            "200 OK",
            &json!({
                "total": total,
                "sessions": sessions,
            }),
            head_only,
        );
        return;
    }

    if let Some(rest) = raw_path.strip_prefix("/api/sessions/") {
        if let Some(encoded_sid) = rest.strip_suffix("/records") {
            let sid = percent_decode(encoded_sid);
            let limit = query
                .get("limit")
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(100);
            let offset = query
                .get("offset")
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(0);
            let filter = RecordFilter {
                session_id: Some(sid),
                server: query
                    .get("server")
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty()),
                risk_level: query
                    .get("risk")
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty()),
                only_errors: query_bool(&query, "only_errors"),
                only_high_risk: query_bool(&query, "only_high_risk"),
                query: query
                    .get("q")
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty()),
                limit,
                offset,
            };
            let page = engine.audit_logger().query_records(&filter);
            write_json(
                &mut stream,
                "200 OK",
                &serde_json::to_value(page).unwrap_or_else(|_| json!({})),
                head_only,
            );
            return;
        }
    }

    write_json(
        &mut stream,
        "404 Not Found",
        &json!({ "error": format!("Not found: {raw_path}") }),
        head_only,
    );
}
