use std::path::PathBuf;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use std::process::Command;

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
        Ok(linux_pick(kind, title, file_name))
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

#[cfg(target_os = "linux")]
fn linux_pick(kind: PickKind, title: &str, file_name: Option<&str>) -> Option<PathBuf> {
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
    if let Some(path) = run_picker("zenity", &zenity_args) {
        return Some(path);
    }
    let kdialog = match kind {
        PickKind::File => vec!["--getopenfilename".to_owned(), ".".to_owned()],
        PickKind::Folder => vec!["--getexistingdirectory".to_owned(), ".".to_owned()],
        PickKind::Save => vec!["--getsavefilename".to_owned(), ".".to_owned()],
    };
    let mut kdialog_args = kdialog;
    kdialog_args.push(format!("--title={title}"));
    run_picker("kdialog", &kdialog_args)
}

#[cfg(target_os = "linux")]
fn run_picker(bin: &str, args: &[String]) -> Option<PathBuf> {
    let Ok(output) = Command::new(bin).args(args).output() else {
        return None;
    };
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if text.is_empty() {
        return None;
    }
    Some(PathBuf::from(text))
}

#[cfg(target_os = "macos")]
fn macos_pick(kind: PickKind, title: &str) -> Result<Option<PathBuf>, String> {
    let script = match kind {
        PickKind::File => format!("POSIX path of (choose file with prompt \"{title}\")"),
        PickKind::Folder => format!("POSIX path of (choose folder with prompt \"{title}\")"),
        PickKind::Save => format!("POSIX path of (choose file name with prompt \"{title}\")"),
    };
    let output = Command::new("osascript")
        .args(["-e", &script])
        .output()
        .map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Ok(None);
    }
    let text = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if text.is_empty() {
        return Ok(None);
    }
    Ok(Some(PathBuf::from(text)))
}

#[cfg(target_os = "windows")]
fn windows_pick(
    kind: PickKind,
    title: &str,
    file_name: Option<&str>,
) -> Result<Option<PathBuf>, String> {
    let dialog = match kind {
        PickKind::Folder => "FolderBrowserDialog",
        PickKind::File | PickKind::Save => "OpenFileDialog",
    };
    let mut script = format!(
        "Add-Type -AssemblyName System.Windows.Forms; $d = New-Object System.Windows.Forms.{dialog}; $d.Title = '{title}';"
    );
    if let Some(name) = file_name {
        script.push_str(&format!(" $d.FileName = '{name}';"));
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
    let output = Command::new("powershell")
        .args(["-NoProfile", "-Command", &script])
        .output()
        .map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Ok(None);
    }
    let text = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if text.is_empty() {
        return Ok(None);
    }
    Ok(Some(PathBuf::from(text)))
}
