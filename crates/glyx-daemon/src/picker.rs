use std::path::PathBuf;

#[derive(Debug, Clone, Copy)]
pub enum PickKind {
    File,
    Folder,
    Save,
}

pub fn pick(
    kind: PickKind,
    title: &str,
    file_name: Option<&str>,
) -> Result<Option<PathBuf>, String> {
    #[cfg(target_os = "linux")]
    {
        linux_pick(kind, title, file_name)
    }
    #[cfg(target_os = "macos")]
    {
        macos_pick(kind, title)
    }
    #[cfg(target_os = "windows")]
    {
        windows_pick(kind, title, file_name)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = (kind, title, file_name);
        Err("no native picker for this platform".to_owned())
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
mod host {
    use super::PickKind;
    use std::io::Read as _;
    use std::path::PathBuf;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    /// Environment variables used to hand caller-supplied strings to the native
    /// dialog helper. Values are passed out-of-band instead of being
    /// interpolated into a script or command line, so a hostile title or file
    /// name can never turn into executable code (`PowerShell` injection,
    /// `AppleScript` injection).
    pub const TITLE_ENV: &str = "GLYX_PICK_TITLE";
    pub const NAME_ENV: &str = "GLYX_PICK_NAME";

    /// How long a native dialog may stay open before we treat it as unavailable.
    ///
    /// A dialog that never returns (no display, a frozen session, a helper that
    /// is not installed) would otherwise block the requesting HTTP call forever.
    pub const PICK_TIMEOUT: Duration = Duration::from_secs(120);

    #[cfg(target_os = "linux")]
    pub fn linux_pick(
        kind: PickKind,
        title: &str,
        file_name: Option<&str>,
    ) -> Result<Option<PathBuf>, String> {
        if std::env::var_os("DISPLAY").is_none() && std::env::var_os("WAYLAND_DISPLAY").is_none() {
            return Err("the daemon has no graphical session to show a dialog in".to_owned());
        }
        let zenity = match kind {
            PickKind::File => vec!["--file-selection".to_owned()],
            PickKind::Folder => vec!["--file-selection".to_owned(), "--directory".to_owned()],
            PickKind::Save => vec![
                "--file-selection".to_owned(),
                "--save".to_owned(),
                "--confirm-overwrite".to_owned(),
            ],
        };
        let mut zenity_args = zenity;
        zenity_args.push(format!("--title={title}"));
        if let Some(name) = file_name {
            zenity_args.push(format!("--filename={name}"));
        }
        match run_until("zenity", &zenity_args, title, file_name) {
            Outcome::Picked(path) => return Ok(Some(path)),
            Outcome::Cancelled => return Ok(None),
            Outcome::Unavailable => {}
        }
        let kdialog = match kind {
            PickKind::File => vec!["--getopenfilename".to_owned(), ".".to_owned()],
            PickKind::Folder => vec!["--getexistingdirectory".to_owned(), ".".to_owned()],
            PickKind::Save => vec!["--getsavefilename".to_owned(), ".".to_owned()],
        };
        let mut kdialog_args = kdialog;
        kdialog_args.push(format!("--title={title}"));
        match run_until("kdialog", &kdialog_args, title, None) {
            Outcome::Picked(path) => Ok(Some(path)),
            Outcome::Cancelled => Ok(None),
            Outcome::Unavailable => {
                Err("no native file dialog is available; install zenity or kdialog".to_owned())
            }
        }
    }

    /// The AppleScript chooser. The prompt is read from the environment so
    /// quotes or AppleScript tokens in the title stay data.
    #[cfg(target_os = "macos")]
    pub fn macos_script(kind: PickKind) -> String {
        let chooser = match kind {
            PickKind::File => "choose file",
            PickKind::Folder => "choose folder",
            PickKind::Save => "choose file name",
        };
        format!(
            "set thePrompt to system attribute \"{TITLE_ENV}\"\nPOSIX path of ({chooser} with prompt thePrompt)"
        )
    }

    #[cfg(target_os = "macos")]
    pub fn macos_pick(kind: PickKind, title: &str) -> Result<Option<PathBuf>, String> {
        let args = ["-e".to_owned(), macos_script(kind)];
        match run_until("osascript", &args, title, None) {
            Outcome::Picked(path) => Ok(Some(path)),
            Outcome::Cancelled => Ok(None),
            Outcome::Unavailable => Err("osascript is unavailable".to_owned()),
        }
    }

    /// The PowerShell dialog script. Every caller-supplied value is read from
    /// the environment so PowerShell never parses it as script source.
    #[cfg(target_os = "windows")]
    pub fn windows_script(kind: PickKind, file_name: Option<&str>) -> String {
        let dialog = match kind {
            PickKind::Folder => "FolderBrowserDialog",
            PickKind::File | PickKind::Save => "OpenFileDialog",
        };
        let mut script = format!(
            "Add-Type -AssemblyName System.Windows.Forms; $d = New-Object System.Windows.Forms.{dialog}; $d.Title = $env:{TITLE_ENV};"
        );
        if file_name.is_some() {
            script.push_str(&format!(
                " if ($env:{NAME_ENV}) {{ $d.FileName = $env:{NAME_ENV} }}"
            ));
        }
        if matches!(kind, PickKind::Save) {
            script.push_str(" $d.CheckFileExists = $false; $d.OverwritePrompt = $true;");
        }
        let value = if matches!(kind, PickKind::Folder) {
            "$d.SelectedPath"
        } else {
            "$d.FileName"
        };
        script.push_str(&format!(
            " if ($d.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {{ Write-Output {value} }}"
        ));
        script
    }

    #[cfg(target_os = "windows")]
    pub fn windows_pick(
        kind: PickKind,
        title: &str,
        file_name: Option<&str>,
    ) -> Result<Option<PathBuf>, String> {
        let args = [
            "-NoProfile".to_owned(),
            "-Command".to_owned(),
            windows_script(kind, file_name),
        ];
        match run_until("powershell", &args, title, file_name) {
            Outcome::Picked(path) => Ok(Some(path)),
            Outcome::Cancelled => Ok(None),
            Outcome::Unavailable => Err("powershell is unavailable".to_owned()),
        }
    }

    /// What a native dialog helper did.
    enum Outcome {
        /// The user picked a path.
        Picked(PathBuf),
        /// The dialog opened and the user dismissed it.
        Cancelled,
        /// The helper could not run at all: missing binary, no display, or a
        /// dialog that outlived [`PICK_TIMEOUT`].
        Unavailable,
    }

    /// Run a helper and wait for it with a hard timeout.
    ///
    /// A helper that never returns (no display, a frozen session, a binary that
    /// is not installed) would otherwise block the requesting HTTP call. The
    /// child is killed on timeout so no stray dialog survives the request.
    fn run_until(bin: &str, args: &[String], title: &str, file_name: Option<&str>) -> Outcome {
        let Ok(mut child) = Command::new(bin)
            .args(args)
            .env(TITLE_ENV, title)
            .env(NAME_ENV, file_name.unwrap_or_default())
            .stdout(Stdio::piped())
            .spawn()
        else {
            return Outcome::Unavailable;
        };
        let deadline = Instant::now() + PICK_TIMEOUT;
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    if !status.success() {
                        return Outcome::Cancelled;
                    }
                    let mut text = String::new();
                    if let Some(mut stdout) = child.stdout.take() {
                        let _ = stdout.read_to_string(&mut text);
                    }
                    let text = text.trim();
                    if text.is_empty() {
                        return Outcome::Cancelled;
                    }
                    return Outcome::Picked(PathBuf::from(text));
                }
                Ok(None) => {
                    if Instant::now() >= deadline {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Outcome::Unavailable;
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(_) => return Outcome::Unavailable,
            }
        }
    }
}

#[cfg(target_os = "linux")]
use host::linux_pick;
#[cfg(target_os = "macos")]
use host::macos_pick;
#[cfg(target_os = "windows")]
use host::windows_pick;

#[cfg(all(test, any(target_os = "macos", target_os = "windows")))]
mod tests {
    use super::{host, PickKind};

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_chooser_reads_the_prompt_from_the_environment() {
        let script = host::macos_script(PickKind::File);
        assert!(script.contains("system attribute \"GLYX_PICK_TITLE\""));
        assert!(!script.contains("'; rm"));
        assert!(!script.contains("evil"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn powershell_script_keeps_caller_data_out_of_code() {
        for kind in [PickKind::File, PickKind::Folder, PickKind::Save] {
            let script = host::windows_script(kind, Some("evil'); Remove-Item -Recurse #"));
            assert!(script.contains("$env:GLYX_PICK_TITLE"));
            assert!(script.contains("$env:GLYX_PICK_NAME"));
            assert!(!script.contains("Remove-Item"));
            assert!(!script.contains("evil"));
        }
    }
}
