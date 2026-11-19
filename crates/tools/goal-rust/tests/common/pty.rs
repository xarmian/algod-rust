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

//! Run a `goal` binary (go's or goal-rust's) with a real pseudo-terminal as its
//! stdin, the only way go's `terminal.ReadPassword` accepts a password (issue
//! #2391: neither binary reads a password from a pipe). stdout and stderr stay
//! pipes, so the prompt is read from stdout: when `answer_after` shows up there
//! the line is typed into the terminal.

#![cfg(unix)]

use std::io::{Read, Write};
use std::os::fd::{FromRawFd, OwnedFd};
use std::path::Path;
use std::process::{Command, Stdio};

/// What the child sees as stdin.
pub enum Stdin<'a> {
    /// `/dev/null`.
    Null,
    /// A pipe carrying these bytes (not a terminal).
    Pipe(&'a str),
    /// A pseudo-terminal; once stdout contains `prompt`, `line` + `\n` is typed.
    Pty { prompt: &'a str, line: &'a str },
}

pub struct Ran {
    pub code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

fn open_pty() -> (OwnedFd, OwnedFd) {
    let mut master: libc::c_int = -1;
    let mut slave: libc::c_int = -1;
    // SAFETY: valid out-pointers; the null name/termios/winsize are allowed.
    let rc = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    assert_eq!(rc, 0, "openpty: {}", std::io::Error::last_os_error());
    // SAFETY: both fds were just created and are owned here.
    unsafe {
        libc::fcntl(master, libc::F_SETFD, libc::FD_CLOEXEC);
        (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave))
    }
}

/// `bin -d <dd> <args>` in `dd`, `ALGORAND_DATA` unset.
pub fn run(bin: &Path, dd: &Path, args: &[&str], stdin: Stdin<'_>) -> Ran {
    run_env(bin, dd, args, stdin, &[])
}

/// [`run`] with `envs` set in the child's environment.
pub fn run_env(
    bin: &Path,
    dd: &Path,
    args: &[&str],
    stdin: Stdin<'_>,
    envs: &[(&str, &str)],
) -> Ran {
    let mut cmd = Command::new(bin);
    cmd.envs(envs.iter().copied());
    cmd.arg("-d")
        .arg(dd)
        .args(args)
        .current_dir(dd)
        .env_remove("ALGORAND_DATA")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut master = None;
    let mut answer: Option<(String, String)> = None;
    let mut pipe_input = None;
    match stdin {
        Stdin::Null => {
            cmd.stdin(Stdio::null());
        }
        Stdin::Pipe(s) => {
            cmd.stdin(Stdio::piped());
            pipe_input = Some(s.to_string());
        }
        Stdin::Pty { prompt, line } => {
            let (m, slave) = open_pty();
            cmd.stdin(Stdio::from(slave));
            master = Some(std::fs::File::from(m));
            answer = Some((prompt.to_string(), line.to_string()));
        }
    }
    let mut child = cmd.spawn().expect("spawn goal");
    drop(cmd); // closes the parent's copy of the pty slave
    if let Some(s) = pipe_input {
        let mut si = child.stdin.take().unwrap();
        let _ = si.write_all(s.as_bytes());
    }
    // A goal that waits for input nobody types must fail the test, not hang it.
    let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (pid, flag) = (child.id() as libc::pid_t, done.clone());
    std::thread::spawn(move || {
        for _ in 0..100 {
            std::thread::sleep(std::time::Duration::from_millis(100));
            if flag.load(std::sync::atomic::Ordering::SeqCst) {
                return;
            }
        }
        // SAFETY: signalling the child spawned above, still unreaped.
        unsafe { libc::kill(pid, libc::SIGKILL) };
    });
    let mut stderr = child.stderr.take().unwrap();
    let err_thread = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = stderr.read_to_end(&mut b);
        b
    });
    let mut so = child.stdout.take().unwrap();
    let mut stdout = Vec::new();
    let mut typed = 0usize;
    let mut chunk = [0u8; 4096];
    loop {
        let n = match so.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        stdout.extend_from_slice(&chunk[..n]);
        if let (Some((prompt, line)), Some(m)) = (&answer, master.as_mut()) {
            let seen = String::from_utf8_lossy(&stdout)
                .matches(prompt.as_str())
                .count();
            while typed < seen {
                m.write_all(format!("{line}\n").as_bytes())
                    .expect("type into the pty");
                typed += 1;
            }
        }
    }
    let status = child.wait().expect("wait goal");
    done.store(true, std::sync::atomic::Ordering::SeqCst);
    Ran {
        code: status.code(),
        stdout,
        stderr: err_thread.join().unwrap(),
    }
}
