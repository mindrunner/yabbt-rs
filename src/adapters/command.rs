use super::AdapterError;
use std::ffi::OsString;

#[derive(Clone, PartialEq, Eq, Default)]
pub struct CommandRequest {
    pub program: String,
    pub args: Vec<String>,
    /// Start the child from an empty environment instead of inheriting the
    /// parent's; `env` then is the child's complete environment.
    pub env_clear: bool,
    /// Environment variables set on the child process (applied after
    /// `env_clear`).
    pub env: Vec<(OsString, OsString)>,
    /// Bytes piped to the child's stdin. Used to keep secrets (the base64
    /// item payload handed to `bw create/edit item`) off the command line,
    /// where they would otherwise be visible via `/proc/<pid>/cmdline`,
    /// `ps`, and process-accounting logs.
    pub stdin: Option<Vec<u8>>,
}

impl CommandRequest {
    pub fn new(program: impl Into<String>, args: Vec<String>) -> Self {
        Self {
            program: program.into(),
            args,
            env_clear: false,
            env: Vec::new(),
            stdin: None,
        }
    }
}

// Env values and stdin can carry secrets (BW_SESSION, item payloads); print
// env keys and only the stdin length so the request can never leak a session
// or payload into logs or panic messages.
impl std::fmt::Debug for CommandRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommandRequest")
            .field("program", &self.program)
            .field("args", &self.args)
            .field(
                "env",
                &self
                    .env
                    .iter()
                    .map(|(name, _)| format!("{}=<redacted>", name.to_string_lossy()))
                    .collect::<Vec<_>>(),
            )
            .field("env_clear", &self.env_clear)
            .field(
                "stdin",
                &self
                    .stdin
                    .as_ref()
                    .map(|bytes| format!("<redacted {} bytes>", bytes.len())),
            )
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct CommandOutput {
    pub status: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

// stdout can be a full `bw export` (the entire vault); show only lengths so a
// stray debug format never dumps secrets.
impl std::fmt::Debug for CommandOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommandOutput")
            .field("status", &self.status)
            .field("stdout", &format_args!("<{} bytes>", self.stdout.len()))
            .field("stderr", &format_args!("<{} bytes>", self.stderr.len()))
            .finish()
    }
}

pub trait CommandRunner {
    fn run(&self, request: CommandRequest) -> Result<CommandOutput, AdapterError>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct StdCommandRunner;

impl CommandOutput {
    pub fn success(&self) -> bool {
        self.status == 0
    }

    pub fn stdout_string(&self) -> Result<String, AdapterError> {
        String::from_utf8(self.stdout.clone())
            .map_err(|error| AdapterError::new(format!("command stdout was not UTF-8: {error}")))
    }

    pub fn stderr_lossy(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }
}

impl CommandRunner for StdCommandRunner {
    fn run(&self, request: CommandRequest) -> Result<CommandOutput, AdapterError> {
        use std::io::Write;
        use std::process::Stdio;

        let mut command = std::process::Command::new(&request.program);
        command.args(&request.args);
        if request.env_clear {
            command.env_clear();
        }
        command.envs(request.env.iter().map(|(name, value)| (name, value)));

        let Some(stdin) = &request.stdin else {
            let output = command.output()?;
            return Ok(CommandOutput {
                status: output.status.code().unwrap_or(-1),
                stdout: output.stdout,
                stderr: output.stderr,
            });
        };

        // Pipe the payload via stdin from a separate thread while
        // `wait_with_output` drains stdout/stderr, so neither side can block
        // on a full pipe buffer, and the child is always reaped.
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn()?;
        let mut child_stdin = child.stdin.take().expect("stdin is piped");
        let (output, write_result) = std::thread::scope(|scope| {
            let writer = scope.spawn(move || {
                // Dropping `child_stdin` at the end closes the pipe (EOF).
                child_stdin.write_all(stdin)
            });
            let output = child.wait_with_output();
            let write_result = writer.join().expect("stdin writer thread panicked");
            (output, write_result)
        });
        let output = output?;
        let output = CommandOutput {
            status: output.status.code().unwrap_or(-1),
            stdout: output.stdout,
            stderr: output.stderr,
        };

        match write_result {
            Ok(()) => Ok(output),
            // The child exited before consuming its input. If it failed,
            // report its own status and stderr (the real cause) rather than
            // the broken pipe.
            Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => {
                if output.success() {
                    Err(AdapterError::new(format!(
                        "`{}` exited before reading its input",
                        request.program
                    )))
                } else {
                    Ok(output)
                }
            }
            Err(error) => Err(error.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn std_runner_clears_inherited_env_and_sets_requested_vars() {
        let mut request = CommandRequest::new(
            "sh",
            vec![
                "-c".to_string(),
                r#"printf '%s/%s' "${YABBT_TEST_SET:-unset}" "${YABBT_TEST_INHERITED:-unset}""#
                    .to_string(),
            ],
        );
        request.env_clear = true;
        request
            .env
            .push(("PATH".into(), std::env::var_os("PATH").unwrap_or_default()));
        request
            .env
            .push(("YABBT_TEST_SET".into(), "set-value".into()));

        // SAFETY: test-local variable name; no other thread in this test
        // binary reads or writes it.
        unsafe { std::env::set_var("YABBT_TEST_INHERITED", "leaked") };
        let output = StdCommandRunner.run(request).expect("sh runs");
        unsafe { std::env::remove_var("YABBT_TEST_INHERITED") };

        assert_eq!(output.status, 0);
        assert_eq!(output.stdout, b"set-value/unset");
    }

    #[test]
    fn command_request_debug_redacts_env_values() {
        let mut request = CommandRequest::new("bw", vec!["sync".to_string()]);
        request
            .env
            .push(("BW_SESSION".into(), "super-secret-session".into()));

        let debug = format!("{request:?}");
        assert!(!debug.contains("super-secret-session"));
        assert!(debug.contains("BW_SESSION=<redacted>"));
    }

    #[test]
    fn command_request_debug_redacts_stdin() {
        let mut request = CommandRequest::new("bw", vec!["create".to_string(), "item".to_string()]);
        request.stdin = Some(b"super-secret-payload".to_vec());

        let debug = format!("{request:?}");
        assert!(!debug.contains("super-secret-payload"));
        assert!(debug.contains("<redacted 20 bytes>"));
    }

    #[test]
    fn std_runner_reports_child_failure_when_child_exits_before_reading_stdin() {
        // Larger than any pipe buffer, so the write hits EPIPE once the child
        // has exited without reading.
        let mut request = CommandRequest::new(
            "sh",
            vec![
                "-c".to_string(),
                "echo 'bw: refused' >&2; exit 3".to_string(),
            ],
        );
        request.stdin = Some(vec![b'x'; 1024 * 1024]);

        let output = StdCommandRunner
            .run(request)
            .expect("child's own failure is reported, not the broken pipe");

        assert_eq!(output.status, 3);
        assert_eq!(output.stderr_lossy().trim(), "bw: refused");
    }

    #[test]
    fn std_runner_rejects_success_when_child_ignored_its_stdin() {
        let mut request = CommandRequest::new("sh", vec!["-c".to_string(), "exit 0".to_string()]);
        request.stdin = Some(vec![b'x'; 1024 * 1024]);

        let error = StdCommandRunner
            .run(request)
            .expect_err("unread payload must not count as success");

        assert!(error.to_string().contains("before reading"), "{error}");
    }

    #[test]
    fn std_runner_pipes_large_stdin_while_child_streams_large_stdout() {
        // Both directions exceed the pipe buffer; writing stdin before
        // draining stdout would deadlock.
        let payload = vec![b'y'; 1024 * 1024];
        let mut request = CommandRequest::new("cat", Vec::new());
        request.stdin = Some(payload.clone());

        let output = StdCommandRunner.run(request).expect("cat runs");

        assert_eq!(output.status, 0);
        assert_eq!(output.stdout, payload);
    }

    #[test]
    fn std_runner_pipes_stdin_to_child() {
        let mut request = CommandRequest::new("cat", Vec::new());
        request.stdin = Some(b"piped-payload".to_vec());

        let output = StdCommandRunner.run(request).expect("cat runs");

        assert_eq!(output.status, 0);
        assert_eq!(output.stdout, b"piped-payload");
    }
}
