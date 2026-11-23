//! Windows' named pipe as Windows tells it: named in the discovery file
//! only, owned by the user who made it, its DACL admitting the owner
//! alone; another user refused. Windows only (the release workflow's
//! Windows runners); `tests/server.rs` runs the round trips over it too.
//! The pipe is read through PowerShell's .NET (`NamedPipeClientStream`,
//! `PipeSecurity`), which Windows PowerShell 5.1 has everywhere.
#![cfg(windows)]
#![allow(clippy::unwrap_used, reason = "test helpers fail loudly")]

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use binbun_protocol::discovery;
use binbun_protocol::server::Server;

/// A fresh directory of this test's for the servers.
fn scratch(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("{name}-{}", std::process::id()))
        .join("binbun");
    let _ = fs::remove_dir_all(&dir);
    dir
}

/// What PowerShell prints running `script`, which must succeed.
fn powershell(script: &str) -> String {
    let output = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        output.status.success(),
        "{stdout}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    stdout
}

/// `server`'s pipe's name under `\\.\pipe\`.
fn pipe_name(server: &Server) -> String {
    let socket = server.socket().to_str().unwrap();
    socket.strip_prefix(r"\\.\pipe\").unwrap().to_owned()
}

#[test]
fn the_pipe_is_named_in_the_discovery_file_and_admits_its_owner_alone() {
    let dir = scratch("pipe-dacl");
    let server = Server::start(&dir, "test/pipe").unwrap();
    let name = pipe_name(&server);
    assert!(
        name.starts_with(&format!("binbun-gui-{}-", std::process::id())),
        "{name}"
    );
    // Nothing beside the discovery file: the pipe is named there only.
    let files: Vec<_> = fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert!(
        files.len() == 1 && files[0].to_string_lossy().ends_with(".json"),
        "{files:?}"
    );
    assert_eq!(discovery::servers(&dir).unwrap()[0].socket, server.socket());

    let told = powershell(&format!(
        "$pipe = New-Object System.IO.Pipes.NamedPipeClientStream('.', '{name}', 'InOut'); \
         $pipe.Connect(10000); \
         $security = $pipe.GetAccessControl(); \
         $security.GetSecurityDescriptorSddlForm('Access'); \
         $security.GetOwner([System.Security.Principal.SecurityIdentifier]).Value; \
         [System.Security.Principal.WindowsIdentity]::GetCurrent().Owner.Value; \
         $pipe.Dispose()"
    ));
    let lines: Vec<&str> = told.lines().map(str::trim).collect();
    let [dacl, owner, token_owner] = lines.as_slice() else {
        panic!("{told}")
    };
    // All access for the pipe's owner, nothing for anyone else.
    assert_eq!(*dacl, "D:P(A;;FA;;;OW)");
    // The owner is who made it: this process's token's owner.
    assert_eq!(owner, token_owner);
}

/// Another user (made for the test, not an administrator) opening the
/// pipe is refused. Making a user needs an administrator, as the CI's
/// Windows runners are: run with `--ignored` there.
#[test]
#[ignore = "makes a local Windows user: needs an administrator"]
fn another_user_is_refused() {
    let dir = scratch("pipe-other-user");
    let server = Server::start(&dir, "test/pipe").unwrap();
    let name = pipe_name(&server);
    let told = powershell(&format!(
        "$ErrorActionPreference = 'Stop'; \
         $user = 'binbun-pipe-' + $PID; \
         $password = [guid]::NewGuid().ToString() + 'aA1!'; \
         net user $user $password /add | Out-Null; \
         try {{ \
           $credential = New-Object System.Management.Automation.PSCredential($user, \
             (ConvertTo-SecureString $password -AsPlainText -Force)); \
           $out = [System.IO.Path]::GetTempFileName(); \
           $try = \"try {{ `$p = New-Object System.IO.Pipes.NamedPipeClientStream('.', '{name}', 'InOut'); \
             `$p.Connect(10000); 'connected' }} \
             catch [System.UnauthorizedAccessException] {{ 'refused' }} \
             catch {{ 'failed: ' + `$_ }}\"; \
           $encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($try)); \
           Start-Process powershell -Credential $credential -WorkingDirectory $env:SystemRoot \
             -ArgumentList \"-NoProfile -NonInteractive -EncodedCommand $encoded\" \
             -RedirectStandardOutput $out -Wait -NoNewWindow; \
           Get-Content $out; \
           Remove-Item $out \
         }} finally {{ net user $user /delete | Out-Null }}"
    ));
    assert_eq!(told.trim(), "refused");
}
