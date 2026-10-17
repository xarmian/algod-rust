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

//! Starting and stopping kmd for `goal kmd start|stop` and for the commands
//! that need it (issue #1993) -- a port of go's `nodecontrol/kmdControl.go`
//! (`KMDController`) and of the auto-start in `libgoal`'s `getKMDClient`.
//!
//! * [`KmdController::start`]: if `kmd.pid` names a live kmd report "already
//!   running"; otherwise create the (absolute, private) data directory, spawn
//!   `kmd -d <dir> -t <timeout>` with stdout/stderr appended to
//!   `kmd-out.log` / `kmd-err.log`, and poll `GET /versions` until it answers.
//! * [`KmdController::stop`]: SIGTERM the pid in `kmd.pid`, wait up to 30 s,
//!   then SIGKILL; a missing pid file means "already stopped".

use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::nodecontrol::{
    find_on_path, http_get_ok, looks_like, process_alive, send_signal, Signal,
};

/// go: `DefaultKMDDataDir`.
pub const DEFAULT_KMD_DATA_DIR: &str = "kmd-v0.5";
/// go: `libgoal.defaultKMDTimeoutSecs` -- what a command that needs kmd starts it with.
pub const DEFAULT_KMD_TIMEOUT_SECS: u64 = 180;
/// go: `codes.ExitCodeKMDAlreadyRunning`.
const EXIT_CODE_KMD_ALREADY_RUNNING: i32 = 4;

type HealthFn = Box<dyn Fn(&Path) -> bool + Send + Sync>;

pub struct KmdController {
    data_dir: PathBuf,
    program: PathBuf,
    prefix_args: Vec<String>,
    healthy: HealthFn,
    term_wait: Duration,
    /// How long `start` waits for kmd to answer before giving up.
    start_wait: Duration,
}

/// Locate kmd next to `goal` (go: `binDir/kmd`), preferring a real `kmd`, then
/// the multi-command `kmd-rust` (whose daemon mode is `kmd-rust serve`), then
/// `PATH`.
pub fn resolve_kmd(exe_dir: Option<&Path>) -> (PathBuf, Vec<String>) {
    let ext = if cfg!(windows) { ".exe" } else { "" };
    if let Some(dir) = exe_dir {
        let kmd = dir.join(format!("kmd{ext}"));
        if kmd.is_file() {
            return (kmd, Vec::new());
        }
        let rust = dir.join(format!("kmd-rust{ext}"));
        if rust.is_file() {
            return (rust, vec!["serve".into()]);
        }
    }
    if find_on_path(&format!("kmd{ext}")).is_some() {
        return (PathBuf::from("kmd"), Vec::new());
    }
    (PathBuf::from("kmd-rust"), vec!["serve".into()])
}

/// go: `GetKMDPID` -- the first line of `kmd.pid`, a positive pid.
pub fn read_kmd_pid(kmd_dir: &Path) -> Result<i64, String> {
    let text = fs::read_to_string(kmd_dir.join("kmd.pid")).map_err(|e| e.to_string())?;
    let pid = text
        .lines()
        .next()
        .unwrap_or("")
        .trim()
        .parse::<i64>()
        .map_err(|e| e.to_string())?;
    if pid <= 0 || pid > i64::from(i32::MAX) {
        return Err(format!("invalid pid {pid} in kmd.pid"));
    }
    Ok(pid)
}

/// go: `KMDClient()` + a `versions` request -- `GET /versions` with the API token.
fn kmd_http_ok(kmd_dir: &Path) -> bool {
    let Ok(net) = fs::read_to_string(kmd_dir.join("kmd.net")) else {
        return false;
    };
    let Ok(token) = fs::read_to_string(kmd_dir.join("kmd.token")) else {
        return false;
    };
    http_get_ok(
        net.lines().next().unwrap_or(""),
        "/versions",
        Some(("X-KMD-API-Token", token.trim())),
    )
}

impl KmdController {
    /// Controller for `kmd_dir`, finding kmd next to the running executable.
    pub fn new(kmd_dir: &Path) -> Self {
        let exe_dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(Path::to_path_buf));
        let (program, prefix_args) = resolve_kmd(exe_dir.as_deref());
        Self::with_program(kmd_dir, program, prefix_args)
    }

    pub fn with_program(kmd_dir: &Path, program: PathBuf, prefix_args: Vec<String>) -> Self {
        Self {
            data_dir: kmd_dir.to_path_buf(),
            program,
            prefix_args,
            healthy: Box::new(kmd_http_ok),
            term_wait: Duration::from_secs(30),
            start_wait: Duration::from_secs(120),
        }
    }

    #[cfg(all(test, unix))]
    fn with_start_wait(mut self, wait: Duration) -> Self {
        self.start_wait = wait;
        self
    }

    #[cfg(all(test, unix))]
    fn with_term_wait(mut self, wait: Duration) -> Self {
        self.term_wait = wait;
        self
    }

    /// go: `buildKMDCommand` -- `-d <dir> -t <timeout>`.
    pub fn kmd_args(&self, timeout_secs: u64) -> Vec<String> {
        let mut v = self.prefix_args.clone();
        v.push("-d".into());
        v.push(self.data_dir.to_string_lossy().to_string());
        v.push("-t".into());
        v.push(timeout_secs.to_string());
        v
    }

    fn pid_path(&self) -> PathBuf {
        self.data_dir.join("kmd.pid")
    }

    /// Is `kmd.pid` the pid of a live kmd?
    fn kmd_alive(&self) -> bool {
        read_kmd_pid(&self.data_dir)
            .is_ok_and(|pid| process_alive(pid) && looks_like(pid, "kmd"))
    }

    /// go: `StartKMD`. `Ok(true)` means "already running".
    pub fn start(&self, timeout_secs: u64) -> Result<bool, String> {
        if read_kmd_pid(&self.data_dir).is_ok() {
            if self.kmd_alive() {
                return Ok(true);
            }
            // a zombie kmd left its pid file behind
            let _ = fs::remove_file(self.pid_path());
        }

        if !self.data_dir.is_absolute() {
            return Err("kmd data dir must be absolute path".to_string());
        }
        match fs::metadata(&self.data_dir) {
            Ok(meta) => {
                if !meta.is_dir() {
                    return Err("bad kmd data dir".to_string());
                }
                if !directory_is_safe(&meta) {
                    return Err("kmd data dir not secure".to_string());
                }
            }
            Err(_) => create_private_dir(&self.data_dir)?,
        }

        let out = open_log_append(&self.data_dir.join("kmd-out.log"));
        let err = open_log_append(&self.data_dir.join("kmd-err.log"));
        let mut cmd = Command::new(&self.program);
        cmd.args(self.kmd_args(timeout_secs)).stdin(Stdio::null());
        cmd.stdout(out.map_or_else(Stdio::null, Stdio::from));
        cmd.stderr(err.map_or_else(Stdio::null, Stdio::from));
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt as _;
            cmd.process_group(0);
        }
        let mut child = cmd
            .spawn()
            .map_err(|e| format!("{}: {e}", self.program.display()))?;
        let deadline = Instant::now() + self.start_wait;

        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    if status.code() == Some(EXIT_CODE_KMD_ALREADY_RUNNING) {
                        // somebody else's kmd holds the directory: wait for it to answer
                        while !(self.healthy)(&self.data_dir) {
                            if Instant::now() >= deadline {
                                return Err(self.not_answering());
                            }
                            std::thread::sleep(Duration::from_millis(100));
                        }
                        return Ok(true);
                    }
                    return Err("kmd exited before we could contact it".to_string());
                }
                Ok(None) => {}
                Err(e) => return Err(e.to_string()),
            }
            std::thread::sleep(Duration::from_millis(100));
            if (self.healthy)(&self.data_dir) {
                // reap the child when it eventually exits (no lingering zombie)
                std::thread::spawn(move || {
                    let _ = child.wait();
                });
                return Ok(false);
            }
            if Instant::now() >= deadline {
                // a kmd that never answers must not hang the caller (or linger)
                let _ = child.kill();
                let _ = child.wait();
                return Err(self.not_answering());
            }
        }
    }

    fn not_answering(&self) -> String {
        format!(
            "kmd did not answer within {}s (see {})",
            self.start_wait.as_secs(),
            self.data_dir.join("kmd-err.log").display()
        )
    }

    /// go: `StopKMD`. `Ok(true)` means "already stopped".
    pub fn stop(&self) -> Result<bool, String> {
        let Ok(pid) = read_kmd_pid(&self.data_dir) else {
            return Ok(true);
        };
        if !cfg!(unix) {
            return Err("stopping kmd is only supported on unix platforms".to_string());
        }
        if !self.kmd_alive() {
            // stale pid file (dead process, or a pid reused by something else)
            let _ = fs::remove_file(self.pid_path());
            return Ok(true);
        }
        send_signal(pid, Signal::Term)?;
        let deadline = Instant::now() + self.term_wait;
        loop {
            if !process_alive(pid) {
                return Ok(false);
            }
            if Instant::now() >= deadline {
                send_signal(pid, Signal::Kill)?;
                // go removes the pid file after a kill
                let _ = fs::remove_file(self.pid_path());
                return Ok(false);
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

/// libgoal's `getKMDClient`: make sure kmd is running for `kmd_dir` before a
/// command talks to it.
pub fn ensure_kmd_running(kmd_dir: &Path) -> Result<(), String> {
    KmdController::new(kmd_dir)
        .start(DEFAULT_KMD_TIMEOUT_SECS)
        .map(|_| ())
}

fn open_log_append(path: &Path) -> Option<File> {
    match fs::OpenOptions::new().create(true).append(true).open(path) {
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

/// go: `isDirectorySafe` -- not writable by group or others.
#[cfg(unix)]
fn directory_is_safe(meta: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    meta.permissions().mode() & 0o022 == 0
}

#[cfg(not(unix))]
fn directory_is_safe(_meta: &fs::Metadata) -> bool {
    true
}

/// go: `os.MkdirAll(dir, DefaultKMDDataDirPerms)` (0700).
fn create_private_dir(dir: &Path) -> Result<(), String> {
    fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    fn controller(dir: &Path) -> KmdController {
        KmdController::with_program(dir, PathBuf::from("kmd"), Vec::new())
    }

    #[test]
    fn the_command_line_is_gos_d_then_t() {
        let nc = controller(Path::new("/k"));
        assert_eq!(nc.kmd_args(0), vec!["-d", "/k", "-t", "0"]);
        assert_eq!(nc.kmd_args(180), vec!["-d", "/k", "-t", "180"]);
        let multi = KmdController::with_program(
            Path::new("/k"),
            PathBuf::from("kmd-rust"),
            vec!["serve".into()],
        );
        assert_eq!(multi.kmd_args(5), vec!["serve", "-d", "/k", "-t", "5"]);
    }

    #[test]
    fn resolve_prefers_kmd_then_kmd_rust() {
        let tmp = tempfile::tempdir().unwrap();
        let ext = if cfg!(windows) { ".exe" } else { "" };
        fs::write(tmp.path().join(format!("kmd-rust{ext}")), "").unwrap();
        let (p, args) = resolve_kmd(Some(tmp.path()));
        assert!(p.ends_with(format!("kmd-rust{ext}")));
        assert_eq!(args, vec!["serve"]);
        fs::write(tmp.path().join(format!("kmd{ext}")), "").unwrap();
        let (p, args) = resolve_kmd(Some(tmp.path()));
        assert!(p.ends_with(format!("kmd{ext}")));
        assert!(args.is_empty());
    }

    #[test]
    fn the_pid_must_be_positive() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(read_kmd_pid(tmp.path()).is_err());
        for (text, ok) in [("12\n", true), ("0\n", false), ("-3\n", false), ("x\n", false)] {
            fs::write(tmp.path().join("kmd.pid"), text).unwrap();
            assert_eq!(read_kmd_pid(tmp.path()).is_ok(), ok, "{text:?}");
        }
    }

    #[test]
    fn a_relative_data_dir_is_refused_like_go() {
        let nc = controller(Path::new("relative/kmd"));
        assert_eq!(nc.start(0), Err("kmd data dir must be absolute path".to_string()));
    }

    #[test]
    fn stopping_without_a_pid_file_is_already_stopped() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(controller(tmp.path()).stop(), Ok(true));
    }

    /// A stub kmd answering `GET /versions` with 200 only when the token header
    /// matches; returns the address.
    fn versions_stub(expected_token: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut s) = stream else { break };
                let mut buf = [0u8; 1024];
                let n = s.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let ok = req.starts_with("GET /versions ")
                    && req.contains(&format!("X-KMD-API-Token: {expected_token}"));
                let status = if ok { "HTTP/1.1 200 OK" } else { "HTTP/1.1 401 Unauthorized" };
                let _ = write!(s, "{status}\r\nContent-Length: 0\r\n\r\n");
            }
        });
        addr
    }

    #[test]
    fn the_health_probe_sends_the_api_token_to_versions() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(!kmd_http_ok(tmp.path()), "no kmd.net");
        fs::write(tmp.path().join("kmd.net"), versions_stub("secret")).unwrap();
        fs::write(tmp.path().join("kmd.token"), "secret\n").unwrap();
        assert!(kmd_http_ok(tmp.path()));
        fs::write(tmp.path().join("kmd.token"), "wrong\n").unwrap();
        assert!(!kmd_http_ok(tmp.path()), "a wrong token is not healthy");
    }

    #[cfg(unix)]
    mod unix {
        use super::*;
        use std::os::unix::fs::PermissionsExt;

        /// A stand-in kmd (named `kmd-fake`): writes kmd.pid / kmd.net /
        /// kmd.token, idles, removes kmd.pid on SIGTERM (or ignores SIGTERM).
        fn fake_kmd(dir: &Path, ignore_term: bool) -> PathBuf {
            let script = dir.join("kmd-fake");
            let trap = if ignore_term {
                "trap '' TERM".to_string()
            } else {
                "trap 'rm -f \"$DIR/kmd.pid\"; exit 0' TERM".to_string()
            };
            let body = format!(
                "#!/bin/sh\nwhile [ \"$1\" != \"-d\" ]; do shift; done\nDIR=\"$2\"\necho $$ > \"$DIR/kmd.pid\"\necho 127.0.0.1:1 > \"$DIR/kmd.net\"\necho tok > \"$DIR/kmd.token\"\n{trap}\nwhile :; do sleep 0.1; done\n"
            );
            fs::write(&script, body).unwrap();
            fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
            script
        }

        fn nc_with(dir: &Path, program: PathBuf) -> KmdController {
            let mut nc = KmdController::with_program(dir, program, Vec::new());
            nc.healthy = Box::new(|d| d.join("kmd.net").exists());
            nc
        }

        #[test]
        fn start_creates_a_private_dir_runs_kmd_and_a_second_start_is_already_running() {
            let tmp = tempfile::tempdir().unwrap();
            let kmd_dir = tmp.path().join("kmd-v0.5");
            let nc = nc_with(&kmd_dir, fake_kmd(tmp.path(), false));
            assert_eq!(nc.start(0), Ok(false));
            let mode = fs::metadata(&kmd_dir).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "the kmd data dir is created 0700");
            assert!(kmd_dir.join("kmd-out.log").exists() && kmd_dir.join("kmd-err.log").exists());
            assert_eq!(nc.start(0), Ok(true));
            assert_eq!(nc.stop(), Ok(false));
            assert!(!kmd_dir.join("kmd.pid").exists());
            assert_eq!(nc.stop(), Ok(true), "stopped now");
        }

        #[test]
        fn a_group_writable_data_dir_is_refused() {
            let tmp = tempfile::tempdir().unwrap();
            let kmd_dir = tmp.path().join("kmd-v0.5");
            fs::create_dir(&kmd_dir).unwrap();
            fs::set_permissions(&kmd_dir, fs::Permissions::from_mode(0o770)).unwrap();
            let nc = nc_with(&kmd_dir, fake_kmd(tmp.path(), false));
            assert_eq!(nc.start(0), Err("kmd data dir not secure".to_string()));
        }

        #[test]
        fn a_kmd_that_exits_at_once_is_a_start_failure() {
            let tmp = tempfile::tempdir().unwrap();
            let kmd_dir = tmp.path().join("kmd-v0.5");
            let script = tmp.path().join("kmd-dies");
            fs::write(&script, "#!/bin/sh\nexit 3\n").unwrap();
            fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
            let mut nc = KmdController::with_program(&kmd_dir, script, Vec::new());
            nc.healthy = Box::new(|_| false);
            assert_eq!(nc.start(0), Err("kmd exited before we could contact it".to_string()));
        }

        #[test]
        fn a_kmd_that_never_answers_is_killed_and_reported() {
            let tmp = tempfile::tempdir().unwrap();
            let kmd_dir = tmp.path().join("kmd-v0.5");
            let script = tmp.path().join("kmd-mute");
            fs::write(&script, "#!/bin/sh
exec sleep 30
").unwrap();
            fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
            let mut nc = KmdController::with_program(&kmd_dir, script, Vec::new())
                .with_start_wait(Duration::from_millis(500));
            nc.healthy = Box::new(|_| false);
            let e = nc.start(0).unwrap_err();
            assert!(e.starts_with("kmd did not answer within 0s"), "{e}");
        }

        #[test]
        fn exit_code_4_means_another_kmd_already_holds_the_directory() {
            let tmp = tempfile::tempdir().unwrap();
            let kmd_dir = tmp.path().join("kmd-v0.5");
            let script = tmp.path().join("kmd-busy");
            fs::write(&script, "#!/bin/sh\nexit 4\n").unwrap();
            fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
            let mut nc = KmdController::with_program(&kmd_dir, script, Vec::new());
            // the other kmd only answers after a few probes, i.e. after the
            // exit code 4 of our own child has been seen
            let probes = std::sync::atomic::AtomicUsize::new(0);
            nc.healthy = Box::new(move |_| {
                probes.fetch_add(1, std::sync::atomic::Ordering::SeqCst) >= 3
            });
            assert_eq!(nc.start(0), Ok(true));
        }

        #[test]
        fn a_kmd_that_ignores_sigterm_is_killed() {
            let tmp = tempfile::tempdir().unwrap();
            let kmd_dir = tmp.path().join("kmd-v0.5");
            let nc = nc_with(&kmd_dir, fake_kmd(tmp.path(), true))
                .with_term_wait(Duration::from_millis(300));
            assert_eq!(nc.start(0), Ok(false));
            let pid = read_kmd_pid(&kmd_dir).unwrap();
            assert_eq!(nc.stop(), Ok(false));
            std::thread::sleep(Duration::from_millis(200));
            assert!(!process_alive(pid), "SIGKILL ended it");
            assert!(!kmd_dir.join("kmd.pid").exists());
        }

        #[test]
        fn a_stale_pid_file_is_cleaned_up_by_start_and_stop() {
            let tmp = tempfile::tempdir().unwrap();
            let kmd_dir = tmp.path().join("kmd-v0.5");
            fs::create_dir(&kmd_dir).unwrap();
            fs::set_permissions(&kmd_dir, fs::Permissions::from_mode(0o700)).unwrap();
            fs::write(kmd_dir.join("kmd.pid"), "2147483646\n").unwrap();
            let nc = nc_with(&kmd_dir, fake_kmd(tmp.path(), false));
            assert_eq!(nc.stop(), Ok(true), "a stale pid is `not running`, not `stopped`");
            assert!(!kmd_dir.join("kmd.pid").exists());
            fs::write(kmd_dir.join("kmd.pid"), "2147483646\n").unwrap();
            assert_eq!(nc.start(0), Ok(false), "stale pid does not mean running");
            assert_eq!(nc.stop(), Ok(false));
        }
    }
}
