// Copyright (C) 2019-2026 Algorand Foundation Ltd.
// Modifications Copyright (C) 2026 Algod DAO
// This file is part of algod-rust, a modified work based on go-algorand
// (https://github.com/algorand/go-algorand).
//
// algod-rust is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// algod-rust is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with algod-rust.  If not, see <https://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Process control for `goal node start|stop|restart` (issue #1992) -- a port
//! of go-algorand's `nodecontrol` package (`nodecontrol/algodControl.go`,
//! `NodeController.go`).
//!
//! * [`NodeController::start_algod`]: if a daemon already answers on the data
//!   directory (`algod.pid` readable *and* `/health` OK) report "already
//!   running"; otherwise spawn `algod -d <dir> [-t ..] [-p ..] [-l ..]` with
//!   stdout/stderr captured in `<dir>/algod-out.log` / `algod-err.log`, and
//!   poll `/health` every 100 ms until it answers or the process exits.
//! * [`NodeController::stop_algod`]: read `algod.pid`, send SIGTERM, wait up
//!   to 30 s for the process to disappear, then SIGKILL (and remove the pid
//!   file, reporting [`StopError::Killed`]).
//!
//! Unlike go, a stale `algod.pid` (the process is gone) is treated as "not
//! running" and the file is removed rather than signalled blindly, because
//! algod-rust can leave one behind after SIGKILL (issue #1990 review).

use std::fmt;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Where stderr is captured when output is not redirected to the host
/// (go: `StdErrFilename`).
pub const STD_ERR_FILENAME: &str = "algod-err.log";
/// Where stdout is captured (go: `StdOutFilename`).
pub const STD_OUT_FILENAME: &str = "algod-out.log";

/// go: `NodeNotRunningError`, `NodeKilledError`, `MissingDataDirError`.
#[derive(Debug, PartialEq, Eq)]
pub enum StopError {
    MissingDataDir(String),
    NotRunning(String),
    /// The node ignored SIGTERM and was killed with SIGKILL.
    Killed,
    /// A signalling failure.
    Other(String),
}

impl fmt::Display for StopError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StopError::MissingDataDir(dir) => {
                write!(f, "the provided directory '{dir}' does not exist")
            }
            StopError::NotRunning(dir) => write!(f, "no running node in directory '{dir}'"),
            StopError::Killed => write!(f, "node was killed"),
            StopError::Other(msg) => write!(f, "{msg}"),
        }
    }
}

/// go: `AlgodStartArgs` (the subset algod-rust supports; `RunUnderHost` needs
/// `algoh`, which does not exist here).
#[derive(Debug, Default, Clone)]
pub struct StartArgs {
    pub peer_address: Option<String>,
    pub listen_ip: Option<String>,
    pub telemetry_override: Option<String>,
}

/// How to reach the `/health` endpoint of the node in a data directory.
type HealthFn = Box<dyn Fn(&Path) -> bool + Send + Sync>;

pub struct NodeController {
    data_dir: PathBuf,
    program: PathBuf,
    /// Arguments placed before `-d` (e.g. `algod` when the program is the
    /// multi-command `algod-rust` binary).
    prefix_args: Vec<String>,
    healthy: HealthFn,
    /// How long SIGTERM gets before SIGKILL (go: 30 s).
    term_wait: Duration,
}

impl NodeController {
    /// Controller for `data_dir`, locating the daemon next to the running
    /// executable (go: `MakeNodeController(binDir, dataDir)`).
    pub fn new(data_dir: &Path) -> Self {
        let exe_dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(Path::to_path_buf));
        let (program, prefix_args) = resolve_algod(exe_dir.as_deref());
        Self::with_program(data_dir, program, prefix_args)
    }

    pub fn with_program(data_dir: &Path, program: PathBuf, prefix_args: Vec<String>) -> Self {
        Self {
            data_dir: data_dir.to_path_buf(),
            program,
            prefix_args,
            healthy: Box::new(http_health_ok),
            term_wait: Duration::from_secs(30),
        }
    }

    #[cfg(all(test, unix))]
    fn with_term_wait(mut self, wait: Duration) -> Self {
        self.term_wait = wait;
        self
    }

    /// go: `GetAlgodPID`.
    pub fn algod_pid(&self) -> Result<i64, String> {
        read_pid(&self.data_dir)
    }

    /// go: `algodRunning` -- a readable pid file AND a healthy REST endpoint.
    pub fn algod_running(&self) -> bool {
        self.algod_pid().is_ok() && (self.healthy)(&self.data_dir)
    }

    /// go: `buildAlgodCommand` -- `-d <dir>` first, then `-t`, `-p`, `-l`.
    pub fn algod_args(&self, args: &StartArgs) -> Vec<String> {
        let mut v = self.prefix_args.clone();
        v.push("-d".into());
        v.push(self.data_dir.to_string_lossy().to_string());
        if let Some(t) = args.telemetry_override.as_deref().filter(|s| !s.is_empty()) {
            v.push("-t".into());
            v.push(t.into());
        }
        if let Some(p) = args.peer_address.as_deref().filter(|s| !s.is_empty()) {
            v.push("-p".into());
            v.push(p.into());
        }
        if let Some(l) = args.listen_ip.as_deref().filter(|s| !s.is_empty()) {
            v.push("-l".into());
            v.push(l.into());
        }
        v
    }

    /// go: `StartAlgod`. `Ok(true)` means "already running".
    pub fn start_algod(&self, args: &StartArgs) -> Result<bool, String> {
        if self.algod_running() {
            return Ok(true);
        }
        // the new daemon rewrites algod.net; a leftover from a previous run
        // could otherwise answer the health probe for some other service
        let _ = fs::remove_file(self.data_dir.join("algod.net"));
        let out = open_log(&self.data_dir.join(STD_OUT_FILENAME));
        let err = open_log(&self.data_dir.join(STD_ERR_FILENAME));
        let mut cmd = Command::new(&self.program);
        cmd.args(self.algod_args(args)).stdin(Stdio::null());
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt as _;
            cmd.process_group(0);
        }
        cmd.stdout(out.map_or_else(Stdio::null, Stdio::from));
        cmd.stderr(err.map_or_else(Stdio::null, Stdio::from));
        let mut child = cmd
            .spawn()
            .map_err(|e| format!("{}: {e}", self.program.display()))?;
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    return Err(match status.code() {
                        Some(0) | None => "node exited before we could contact it".to_string(),
                        Some(code) => format!(
                            "node exited with an error code, check node.log for more details : exit status {code}"
                        ),
                    });
                }
                Ok(None) => {}
                Err(e) => return Err(e.to_string()),
            }
            std::thread::sleep(Duration::from_millis(100));
            if (self.healthy)(&self.data_dir) {
                // go keeps a `Wait` goroutine so the child never lingers as a
                // zombie (which would still answer `kill -0`); same here.
                std::thread::spawn(move || {
                    let _ = child.wait();
                });
                return Ok(false);
            }
        }
    }

    /// go: `StopAlgod`.
    pub fn stop_algod(&self) -> Result<(), StopError> {
        if !self.data_dir.is_dir() {
            return Err(StopError::MissingDataDir(
                self.data_dir.display().to_string(),
            ));
        }
        let pid_file = self.data_dir.join("algod.pid");
        let Ok(pid) = read_pid(&self.data_dir) else {
            return Err(StopError::NotRunning(self.data_dir.display().to_string()));
        };
        if !cfg!(unix) {
            return Err(StopError::Other(
                "stopping a node is only supported on unix platforms".to_string(),
            ));
        }
        if !process_alive(pid) || !(looks_like_algod(pid) || lock_is_held(&self.data_dir)) {
            // stale pid file (the process is gone, or the pid was reused by
            // something that is not algod): nothing to signal
            let _ = fs::remove_file(&pid_file);
            return Ok(());
        }
        send_signal(pid, Signal::Term).map_err(StopError::Other)?;
        let deadline = Instant::now() + self.term_wait;
        loop {
            if !process_alive(pid) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                send_signal(pid, Signal::Kill).map_err(StopError::Other)?;
                let _ = fs::remove_file(&pid_file);
                return Err(StopError::Killed);
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

/// go: the first line of `algod.pid`, parsed as an integer.
pub fn read_pid(data_dir: &Path) -> Result<i64, String> {
    let text = fs::read_to_string(data_dir.join("algod.pid")).map_err(|e| e.to_string())?;
    let line = text.lines().next().unwrap_or("").trim();
    let pid = line.parse::<i64>().map_err(|e| e.to_string())?;
    // kill(2) treats 0 and negative pids as process groups / "everything":
    // a corrupt pid file must never turn into that.
    if pid <= 0 || pid > i64::from(i32::MAX) {
        return Err(format!("invalid pid {pid} in algod.pid"));
    }
    Ok(pid)
}

fn open_log(path: &Path) -> Option<File> {
    match File::create(path) {
        Ok(f) => Some(f),
        Err(e) => {
            eprintln!(
                "error creating file for capturing {}: {e}",
                path.file_name().and_then(|n| n.to_str()).unwrap_or("output")
            );
            None
        }
    }
}

/// Locate the daemon the way go does (next to `goal`), preferring a real
/// `algod`, then the multi-command `algod-rust algod`, then `PATH`.
pub fn resolve_algod(exe_dir: Option<&Path>) -> (PathBuf, Vec<String>) {
    let ext = if cfg!(windows) { ".exe" } else { "" };
    if let Some(dir) = exe_dir {
        let algod = dir.join(format!("algod{ext}"));
        if algod.is_file() {
            return (algod, Vec::new());
        }
        let rust = dir.join(format!("algod-rust{ext}"));
        if rust.is_file() {
            return (rust, vec!["algod".into()]);
        }
    }
    if find_on_path(&format!("algod{ext}")).is_some() {
        return (PathBuf::from("algod"), Vec::new());
    }
    (PathBuf::from("algod-rust"), vec!["algod".into()])
}

pub(crate) fn find_on_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join(name))
        .find(|p| p.is_file())
}

/// The address to probe for the `algod.net` value: a node listening on all
/// interfaces writes `0.0.0.0:port` / `[::]:port`, which is not connectable
/// everywhere, so it is probed on loopback.
pub(crate) fn probe_addr(net: &str) -> String {
    let addr = net
        .trim()
        .trim_start_matches("http://")
        .trim_end_matches('/');
    if let Some(port) = addr.strip_prefix("0.0.0.0:") {
        return format!("127.0.0.1:{port}");
    }
    if let Some(port) = addr.strip_prefix("[::]:") {
        return format!("[::1]:{port}");
    }
    addr.to_string()
}

/// go: `HealthCheck` -- `GET /health` on the address in `algod.net`.
fn http_health_ok(data_dir: &Path) -> bool {
    let Ok(net) = fs::read_to_string(data_dir.join("algod.net")) else {
        return false;
    };
    http_get_ok(net.lines().next().unwrap_or(""), "/health", None)
}

/// Does `GET <path>` on `net` (an `algod.net` / `kmd.net` style address, probed
/// on loopback when it is a bind-all address) answer 200? `header` is an
/// optional `(name, value)` request header (kmd's API token).
pub(crate) fn http_get_ok(net: &str, path: &str, header: Option<(&str, &str)>) -> bool {
    let addr = probe_addr(net);
    if addr.is_empty() {
        return false;
    }
    let Some(mut stream) = addr.to_socket_addrs().ok().and_then(|addrs| {
        addrs
            .filter_map(|a| TcpStream::connect_timeout(&a, Duration::from_secs(2)).ok())
            .next()
    }) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
    let extra = header
        .map(|(k, v)| format!("{k}: {v}\r\n"))
        .unwrap_or_default();
    let request =
        format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n{extra}Connection: close\r\n\r\n");
    if stream.write_all(request.as_bytes()).is_err() {
        return false;
    }
    let mut head = [0u8; 12];
    if stream.read_exact(&mut head).is_err() {
        return false;
    }
    std::str::from_utf8(&head).is_ok_and(|s| s == "HTTP/1.1 200" || s == "HTTP/1.0 200")
}

pub(crate) enum Signal {
    Term,
    Kill,
}

#[cfg(unix)]
pub(crate) fn process_alive(pid: i64) -> bool {
    let Ok(pid) = i32::try_from(pid) else {
        return false;
    };
    if pid <= 0 {
        return false;
    }
    // SAFETY: signal 0 only checks that the process exists.
    if unsafe { libc::kill(pid, 0) } == 0 {
        // kill(pid, 0) also succeeds for a zombie that nobody has reaped yet
        return !is_zombie(pid);
    }
    // EPERM: the process exists but belongs to someone else.
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// Linux: `/proc/<pid>/stat` state `Z`. Elsewhere we cannot tell.
#[cfg(unix)]
fn is_zombie(pid: i32) -> bool {
    let Ok(stat) = fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return false;
    };
    // "<pid> (<comm>) <state> ..." -- comm may contain spaces and parentheses
    stat.rsplit_once(')')
        .and_then(|(_, rest)| rest.trim_start().chars().next())
        == Some('Z')
}

/// Is `<dir>/algod.lock` held by another process? Every algod (go's and
/// algod-rust's) holds it for its whole life, so this identifies a daemon
/// that was started under a different executable name.
pub fn lock_is_held(data_dir: &Path) -> bool {
    let Ok(file) = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(data_dir.join("algod.lock"))
    else {
        return false;
    };
    matches!(file.try_lock(), Err(std::fs::TryLockError::WouldBlock))
}

/// Does `pid` look like an algod? On Linux the command line says so; where
/// `/proc` is not available we cannot tell and give the pid file the benefit
/// of the doubt (as go does).
#[cfg(unix)]
fn looks_like_algod(pid: i64) -> bool {
    looks_like(pid, "algod")
}

/// Does `pid`'s executable (or interpreted script) name start with `prefix`?
/// Where `/proc` is unavailable the pid file gets the benefit of the doubt.
#[cfg(unix)]
pub(crate) fn looks_like(pid: i64, prefix: &str) -> bool {
    match fs::read(format!("/proc/{pid}/cmdline")) {
        Ok(bytes) => cmdline_has_prefix(&bytes, prefix),
        Err(_) => true,
    }
}

/// Is the NUL-separated `/proc/<pid>/cmdline` an algod? Judged by the
/// executable's file name only (`algod`, `algod-rust`, ...): matching anywhere
/// in the line would also match a checkout path such as `.../algod-rust/...`
/// or a test name. A script run through an interpreter is judged by the
/// script's name.
#[cfg(all(unix, test))]
fn cmdline_is_algod(cmdline: &[u8]) -> bool {
    cmdline_has_prefix(cmdline, "algod")
}

#[cfg(unix)]
fn cmdline_has_prefix(cmdline: &[u8], prefix: &str) -> bool {
    let mut args = cmdline
        .split(|b| *b == 0)
        .filter(|a| !a.is_empty())
        .map(|a| String::from_utf8_lossy(a).to_string());
    let base = |a: &str| a.rsplit('/').next().unwrap_or("").to_string();
    let Some(first) = args.next() else {
        return false;
    };
    let mut name = base(&first);
    if ["sh", "bash", "dash", "env", "python", "python3"].contains(&name.as_str()) {
        let rest: Vec<String> = args.collect();
        // `sh -c "/opt/algod/bin/algod -d /data"`: judge the command string's
        // first word
        let command_string = rest
            .iter()
            .position(|a| a == "-c" || a == "-lc")
            .and_then(|i| rest.get(i + 1));
        name = match command_string {
            Some(cmd) => base(cmd.split_whitespace().next().unwrap_or("")),
            // otherwise skip options and `VAR=value` words, take the script
            None => rest
                .iter()
                .find(|a| !a.starts_with('-') && !a.contains('='))
                .map(|a| base(a))
                .unwrap_or_default(),
        };
    }
    name.starts_with(prefix)
}

#[cfg(unix)]
pub(crate) fn send_signal(pid: i64, sig: Signal) -> Result<(), String> {
    let pid = i32::try_from(pid).map_err(|e| e.to_string())?;
    let signo = match sig {
        Signal::Term => libc::SIGTERM,
        Signal::Kill => libc::SIGKILL,
    };
    // SAFETY: plain kill(2) on the pid recorded in algod.pid.
    if unsafe { libc::kill(pid, signo) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error().to_string())
    }
}

#[cfg(not(unix))]
pub(crate) fn process_alive(_pid: i64) -> bool {
    false
}

#[cfg(not(unix))]
fn looks_like_algod(_pid: i64) -> bool {
    false
}

#[cfg(not(unix))]
pub(crate) fn looks_like(_pid: i64, _prefix: &str) -> bool {
    false
}

#[cfg(not(unix))]
pub(crate) fn send_signal(_pid: i64, _sig: Signal) -> Result<(), String> {
    Err("stopping a node is only supported on unix platforms".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    fn controller(dir: &Path) -> NodeController {
        NodeController::with_program(dir, PathBuf::from("algod"), Vec::new())
    }

    #[test]
    fn error_texts_match_go() {
        assert_eq!(
            StopError::MissingDataDir("/d".into()).to_string(),
            "the provided directory '/d' does not exist"
        );
        assert_eq!(
            StopError::NotRunning("/d".into()).to_string(),
            "no running node in directory '/d'"
        );
        assert_eq!(StopError::Killed.to_string(), "node was killed");
    }

    #[test]
    fn the_algod_command_line_is_go_s_d_then_t_p_l() {
        let nc = controller(Path::new("/data"));
        assert_eq!(nc.algod_args(&StartArgs::default()), vec!["-d", "/data"]);
        let all = StartArgs {
            peer_address: Some("1.2.3.4:4160".into()),
            listen_ip: Some("0.0.0.0:8080".into()),
            telemetry_override: Some("false".into()),
        };
        assert_eq!(
            nc.algod_args(&all),
            vec![
                "-d", "/data", "-t", "false", "-p", "1.2.3.4:4160", "-l", "0.0.0.0:8080"
            ]
        );
        let multi = NodeController::with_program(
            Path::new("/data"),
            PathBuf::from("algod-rust"),
            vec!["algod".into()],
        );
        assert_eq!(multi.algod_args(&StartArgs::default()), vec!["algod", "-d", "/data"]);
    }

    #[test]
    fn the_pid_is_the_first_line_of_algod_pid() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(read_pid(tmp.path()).is_err());
        fs::write(tmp.path().join("algod.pid"), "4242\nignored\n").unwrap();
        assert_eq!(read_pid(tmp.path()), Ok(4242));
        fs::write(tmp.path().join("algod.pid"), "not a pid\n").unwrap();
        assert!(read_pid(tmp.path()).is_err());
    }

    /// Serve `status_line` to the next health probe; returns the address.
    fn health_stub(status_line: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut s) = stream else { break };
                let mut buf = [0u8; 256];
                let _ = s.read(&mut buf);
                let _ = write!(s, "{status_line}\r\nContent-Length: 0\r\n\r\n");
            }
        });
        addr
    }

    #[cfg(unix)]
    #[test]
    fn interpreter_launches_are_judged_by_the_command_they_run() {
        let line = |parts: &[&str]| parts.join("\0").into_bytes();
        assert!(cmdline_is_algod(&line(&["sh", "-c", "/opt/algod/bin/algod -d /data"])));
        assert!(cmdline_is_algod(&line(&["env", "FOO=1", "algod", "-d", "/d"])));
        assert!(!cmdline_is_algod(&line(&["bash", "-c", "tail -f /algod/data/node.log"])));
    }

    #[test]
    fn the_lock_file_tells_whether_a_daemon_holds_the_data_dir() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(!lock_is_held(tmp.path()), "no lock file");
        let held = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(tmp.path().join("algod.lock"))
            .unwrap();
        held.try_lock().unwrap();
        assert!(lock_is_held(tmp.path()), "a live daemon's flock is visible");
        drop(held);
        assert!(!lock_is_held(tmp.path()), "released");
    }

    #[test]
    fn localhost_is_probed_on_every_address_it_resolves_to() {
        let tmp = tempfile::tempdir().unwrap();
        let addr = health_stub("HTTP/1.1 200 OK");
        let port = addr.rsplit(':').next().unwrap();
        fs::write(tmp.path().join("algod.net"), format!("localhost:{port}")).unwrap();
        assert!(http_health_ok(tmp.path()), "stub listens on 127.0.0.1 only");
    }

    #[cfg(unix)]
    #[test]
    fn only_a_process_named_algod_is_taken_for_algod() {
        let line = |parts: &[&str]| parts.join("\0").into_bytes();
        for yes in [
            line(&["/usr/local/bin/algod", "-d", "/data"]),
            line(&["algod-rust", "algod", "-d", "/data"]),
            line(&["/algod/bin/algod", "-o"]),
            line(&["/bin/sh", "/tmp/algod-fake", "-d", "/data"]),
            line(&["sh", "-e", "/opt/algod", "-d", "/d"]),
        ] {
            assert!(cmdline_is_algod(&yes), "{:?}", String::from_utf8_lossy(&yes));
        }
        for no in [
            // the checkout path and the test name both contain "algod"
            line(&[
                "/home/runner/work/algod-rust/algod-rust/target/debug/deps/goal_rust-1a2b",
                "nodecontrol::tests::a_reused_pid_that_is_not_algod",
            ]),
            line(&["/usr/bin/vim", "algod.log"]),
            line(&["bash", "-lc", "tail -f /algod/data/node.log"]),
            Vec::new(),
        ] {
            assert!(!cmdline_is_algod(&no), "{:?}", String::from_utf8_lossy(&no));
        }
    }

    #[test]
    fn a_pid_must_be_a_positive_process_id() {
        let tmp = tempfile::tempdir().unwrap();
        for bad in ["0", "-1", "-4242", "99999999999", "x"] {
            fs::write(tmp.path().join("algod.pid"), format!("{bad}\n")).unwrap();
            assert!(read_pid(tmp.path()).is_err(), "{bad} must be rejected");
        }
        fs::write(tmp.path().join("algod.pid"), "1\n").unwrap();
        assert_eq!(read_pid(tmp.path()), Ok(1));
    }

    #[test]
    fn a_bind_all_address_is_probed_on_loopback() {
        assert_eq!(probe_addr("0.0.0.0:8080\n"), "127.0.0.1:8080");
        assert_eq!(probe_addr("[::]:8080"), "[::1]:8080");
        assert_eq!(probe_addr("http://127.0.0.1:4001/"), "127.0.0.1:4001");
        assert_eq!(probe_addr("10.1.2.3:99"), "10.1.2.3:99");
    }

    #[cfg(not(unix))]
    #[test]
    fn stop_never_claims_success_where_it_cannot_signal() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("algod.pid"), "4242\n").unwrap();
        assert!(matches!(
            controller(tmp.path()).stop_algod(),
            Err(StopError::Other(_))
        ));
        assert!(tmp.path().join("algod.pid").exists(), "pid file must stay");
    }

    #[test]
    fn the_health_probe_wants_a_200_from_the_net_file_address() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(!http_health_ok(tmp.path()), "no algod.net -> not healthy");
        fs::write(tmp.path().join("algod.net"), health_stub("HTTP/1.1 200 OK")).unwrap();
        assert!(http_health_ok(tmp.path()));
        fs::write(
            tmp.path().join("algod.net"),
            health_stub("HTTP/1.1 503 Service Unavailable"),
        )
        .unwrap();
        assert!(!http_health_ok(tmp.path()));
        fs::write(tmp.path().join("algod.net"), "127.0.0.1:1\n").unwrap();
        assert!(!http_health_ok(tmp.path()), "nothing listening");
    }

    #[test]
    fn running_needs_both_a_pid_file_and_a_healthy_endpoint() {
        let tmp = tempfile::tempdir().unwrap();
        let mut nc = controller(tmp.path());
        nc.healthy = Box::new(|_| true);
        assert!(!nc.algod_running(), "healthy but no pid file");
        fs::write(tmp.path().join("algod.pid"), "1\n").unwrap();
        assert!(nc.algod_running());
        nc.healthy = Box::new(|_| false);
        assert!(!nc.algod_running(), "pid file but unhealthy");
    }

    #[test]
    fn stop_without_a_data_dir_or_pid_file_is_gos_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("nope");
        assert_eq!(
            controller(&missing).stop_algod(),
            Err(StopError::MissingDataDir(missing.display().to_string()))
        );
        assert_eq!(
            controller(tmp.path()).stop_algod(),
            Err(StopError::NotRunning(tmp.path().display().to_string()))
        );
    }

    #[test]
    fn resolve_prefers_algod_then_algod_rust_then_path() {
        let tmp = tempfile::tempdir().unwrap();
        let ext = if cfg!(windows) { ".exe" } else { "" };
        // only algod-rust beside goal -> run its `algod` subcommand
        fs::write(tmp.path().join(format!("algod-rust{ext}")), "").unwrap();
        let (p, args) = resolve_algod(Some(tmp.path()));
        assert!(p.ends_with(format!("algod-rust{ext}")));
        assert_eq!(args, vec!["algod"]);
        // a real algod beside goal wins
        fs::write(tmp.path().join(format!("algod{ext}")), "").unwrap();
        let (p, args) = resolve_algod(Some(tmp.path()));
        assert!(p.ends_with(format!("algod{ext}")));
        assert!(args.is_empty());
    }

    #[cfg(unix)]
    mod unix {
        use super::*;
        use std::os::unix::fs::PermissionsExt;

        /// A stand-in daemon: writes go's discovery files, then idles until
        /// SIGTERM (removing its pid file, as algod does) -- or ignores SIGTERM
        /// when `ignore_term` is set.
        fn fake_daemon(dir: &Path, ignore_term: bool) -> PathBuf {
            let script = dir.join("algod-fake");
            let trap = if ignore_term {
                "trap '' TERM".to_string()
            } else {
                "trap 'rm -f \"$DIR/algod.pid\"; exit 0' TERM".to_string()
            };
            let body = format!(
                "#!/bin/sh\nwhile [ \"$1\" != \"-d\" ]; do shift; done\nDIR=\"$2\"\necho $$ > \"$DIR/algod.pid\"\necho 127.0.0.1:1 > \"$DIR/algod.net\"\necho tok > \"$DIR/algod.token\"\n{trap}\nwhile :; do sleep 0.1; done\n"
            );
            fs::write(&script, body).unwrap();
            fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
            script
        }

        fn nc_with(dir: &Path, program: PathBuf) -> NodeController {
            let mut nc = NodeController::with_program(dir, program, Vec::new());
            // health = "the daemon wrote algod.net" (no real REST server here)
            nc.healthy = Box::new(|d| d.join("algod.net").exists());
            nc
        }

        #[test]
        fn start_launches_the_daemon_and_a_second_start_reports_already_running() {
            let tmp = tempfile::tempdir().unwrap();
            let data = tmp.path().join("data");
            fs::create_dir(&data).unwrap();
            let nc = nc_with(&data, fake_daemon(tmp.path(), false));

            assert_eq!(nc.start_algod(&StartArgs::default()), Ok(false));
            assert!(nc.algod_running());
            assert!(data.join(STD_OUT_FILENAME).exists(), "stdout is captured");
            assert!(data.join(STD_ERR_FILENAME).exists(), "stderr is captured");
            assert_eq!(nc.start_algod(&StartArgs::default()), Ok(true));

            nc.stop_algod().expect("stop");
            assert!(!data.join("algod.pid").exists());
        }

        #[test]
        fn a_daemon_that_exits_immediately_is_a_start_failure() {
            let tmp = tempfile::tempdir().unwrap();
            let data = tmp.path().join("data");
            fs::create_dir(&data).unwrap();
            let script = tmp.path().join("dies");
            fs::write(&script, "#!/bin/sh\nexit 3\n").unwrap();
            fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
            let mut nc = NodeController::with_program(&data, script, Vec::new());
            nc.healthy = Box::new(|_| false);
            let err = nc.start_algod(&StartArgs::default()).unwrap_err();
            assert_eq!(
                err,
                "node exited with an error code, check node.log for more details : exit status 3"
            );
        }

        #[test]
        fn stop_terminates_a_running_daemon_with_sigterm() {
            let tmp = tempfile::tempdir().unwrap();
            let data = tmp.path().join("data");
            fs::create_dir(&data).unwrap();
            let nc = nc_with(&data, fake_daemon(tmp.path(), false));
            nc.start_algod(&StartArgs::default()).expect("start");
            let pid = read_pid(&data).expect("pid");
            assert_eq!(nc.stop_algod(), Ok(()));
            assert!(!process_alive(pid), "the daemon must be gone");
        }

        #[test]
        fn a_daemon_that_ignores_sigterm_is_killed_and_reported() {
            let tmp = tempfile::tempdir().unwrap();
            let data = tmp.path().join("data");
            fs::create_dir(&data).unwrap();
            let nc = nc_with(&data, fake_daemon(tmp.path(), true))
                .with_term_wait(Duration::from_millis(300));
            nc.start_algod(&StartArgs::default()).expect("start");
            let pid = read_pid(&data).expect("pid");
            assert_eq!(nc.stop_algod(), Err(StopError::Killed));
            // give the kernel a moment to reap
            std::thread::sleep(Duration::from_millis(200));
            assert!(!data.join("algod.pid").exists(), "pid file removed after SIGKILL");
            let _ = pid;
        }

        #[test]
        fn an_unreaped_zombie_is_not_alive() {
            let mut child = Command::new("sh").args(["-c", "exit 0"]).spawn().unwrap();
            let pid = i64::from(child.id());
            // let it exit; it stays a zombie until we wait on it
            let start = Instant::now();
            while process_alive(pid) && start.elapsed() < Duration::from_secs(5) {
                std::thread::sleep(Duration::from_millis(50));
            }
            assert!(!process_alive(pid), "zombie must not count as alive");
            child.wait().unwrap();
        }

        #[test]
        fn a_stale_algod_net_is_cleared_before_a_start() {
            let tmp = tempfile::tempdir().unwrap();
            let data = tmp.path().join("data");
            fs::create_dir(&data).unwrap();
            fs::write(data.join("algod.net"), "stale-from-a-previous-run\n").unwrap();
            let mut nc = NodeController::with_program(&data, fake_daemon(tmp.path(), false), Vec::new());
            // healthy only once the daemon has rewritten algod.net
            nc.healthy = Box::new(|d| {
                fs::read_to_string(d.join("algod.net")).is_ok_and(|t| t.trim() == "127.0.0.1:1")
            });
            assert_eq!(nc.start_algod(&StartArgs::default()), Ok(false));
            nc.stop_algod().expect("stop");
        }

        #[test]
        fn a_process_owned_by_someone_else_still_counts_as_alive() {
            // pid 1 exists on every unix box; unprivileged kill(1, 0) is EPERM
            assert!(process_alive(1));
        }

        #[test]
        fn a_reused_pid_that_is_not_algod_is_never_signalled() {
            let tmp = tempfile::tempdir().unwrap();
            let data = tmp.path().join("data");
            fs::create_dir(&data).unwrap();
            // this very test process is alive and is not an algod
            let me = std::process::id();
            fs::write(data.join("algod.pid"), format!("{me}\n")).unwrap();
            let nc = controller(&data);
            assert_eq!(nc.stop_algod(), Ok(()), "treated as a stale pid file");
            assert!(!data.join("algod.pid").exists());
            assert!(process_alive(i64::from(me)), "must not have been signalled");
        }

        #[test]
        fn a_stale_pid_file_is_cleaned_up_not_signalled() {
            let tmp = tempfile::tempdir().unwrap();
            let data = tmp.path().join("data");
            fs::create_dir(&data).unwrap();
            // a pid that cannot exist (above the kernel's pid_max)
            fs::write(data.join("algod.pid"), "2147483646\n").unwrap();
            let nc = controller(&data);
            assert_eq!(nc.stop_algod(), Ok(()));
            assert!(!data.join("algod.pid").exists());
        }
    }
}
