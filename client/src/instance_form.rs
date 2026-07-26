//! The create/edit instance form: field layout, and the parsing that turns
//! flat text back into an `InstanceConfig`'s worth of typed values

use std::collections::HashMap;
use std::path::PathBuf;

use protocol::{InstanceConfig, RetryPolicy, Source};

use crate::form::{Field, Form};

pub const NAME: usize = 0;
pub const SOURCE: usize = 1;
pub const LOCATION: usize = 2;
pub const BRANCH: usize = 3;
pub const COMMAND: usize = 4;
pub const ARGS: usize = 5;
pub const ENV: usize = 6;
pub const AUTOSTART: usize = 7;
pub const POLICY: usize = 8;
pub const RETRIES: usize = 9;

const POLICIES: [&str; 4] = ["Never", "OnCrash", "Always", "Retry"];
const SOURCES: [&str; 4] = ["Git", "URL", "Upload", "Empty"];

pub fn build(existing: Option<&InstanceConfig>) -> Form {
    let title = match existing {
        Some(c) => format!("Edit instance · {}", c.name),
        None => "New instance".to_string(),
    };

    let (policy_index, retries) = match existing.map(|c| &c.retry_policy) {
        Some(RetryPolicy::Never) | None => (0, String::new()),
        Some(RetryPolicy::OnCrash) => (1, String::new()),
        Some(RetryPolicy::Always) => (2, String::new()),
        Some(RetryPolicy::Retry(n)) => (3, n.to_string()),
    };

    let (source_index, location, branch) = match existing.map(|c| &c.source) {
        None | Some(Source::None) => (0, String::new(), String::new()),
        Some(Source::Git { url, branch }) => (0, url.clone(), branch.clone().unwrap_or_default()),
        Some(Source::Url { url }) => (1, url.clone(), String::new()),
        Some(Source::Upload { desc }) => (2, desc.clone(), String::new()),
        // Round-trips: reopening the form must not silently turn an Empty
        // instance into a Git one with a blank URL.
        Some(Source::Empty) => (3, String::new(), String::new()),
    };

    let s = if let Some(existing) = existing {
        match existing.source {
            Source::Git { .. } => "git url",
            Source::Url { .. } => "download url",
            Source::Upload { .. } => "local path",
            Source::Empty => "unused — an Empty source has no location",
            Source::None => "git url, download url or a local path - or nothing"
        }
    } else { "git url, download url or a local path - or nothing" };

    let fields = vec![
        Field::text("Name", existing.map(|c| c.name.as_str()).unwrap_or("")),
        Field::select("Source", SOURCES.iter().map(|s| s.to_string()).collect(), source_index),
        Field::text("Location", location)
            .hint(s),
        Field::text("Branch", branch)
            .hint("git only, blank = the repo's default"),
        Field::text("Command", existing.map(|c| c.command.as_str()).unwrap_or("")),
        Field::text("Arguments", existing.map(|c| fmt_args(&c.args)).unwrap_or_default())
            .hint("space separated, \"quote\" to group"),
        Field::text("Environment", existing.map(|c| fmt_env(&c.env)).unwrap_or_default())
            .hint("KEY=VALUE; KEY=VALUE"),
        Field::toggle("Autostart", existing.map(|c| c.autostart).unwrap_or(false))
            .hint("start with the server"),
        Field::select("Restart policy", POLICIES.iter().map(|s| s.to_string()).collect(), policy_index),
        Field::text("Retry limit", retries).hint("only used by the Retry policy"),
    ];

    Form::new(title, fields)
}

/// What the source fields resolved to.
pub enum SourceSpec {
    Git { url: String, branch: Option<String> },
    Url { url: String },
    /// A local path whose content gets pushed after saving.
    Upload { path: PathBuf },
    /// Editing an Upload instance without giving a new path: the content on
    /// the server stays as it is.
    UploadKeep { desc: String },
    Nothing
}

/// Everything the form yields, validated. Field order matches `Action`'s
pub struct Parsed {
    pub name: String,
    pub source: SourceSpec,
    pub command: String,
    pub args: Vec<String>,
    pub env: HashMap<String, String>,
    pub autostart: bool,
    pub retry_policy: RetryPolicy,
}

/// `keep_desc` is the recorded description when editing an Upload instance;
/// leaving the location at that text means "keep the uploaded content".
pub fn parse(form: &Form, keep_desc: Option<&str>) -> Result<Parsed, String> {
    let empty = form.field(SOURCE).select_index() == 3;

    let name = form.field(NAME).text_value().trim().to_string();
    if name.is_empty() {
        return Err("a name is required".to_string());
    }
    let command = form.field(COMMAND).text_value().trim().to_string();
    if command.is_empty() && !empty {
        return Err("a command is required".to_string());
    }

    let location = form.field(LOCATION).text_value().trim().to_string();
    if location.is_empty() && !empty {
        return Err("a location is required".to_string());
    }
    let branch = match form.field(BRANCH).text_value().trim() {
        "" => None,
        b => Some(b.to_string()),
    };
    let source = match form.field(SOURCE).select_index() {
        0 => SourceSpec::Git { url: location, branch },
        1 => SourceSpec::Url { url: location },
        2 if Some(location.as_str()) == keep_desc => {
            SourceSpec::UploadKeep { desc: location }
        }
        2 => {
            let path = PathBuf::from(&location);
            if !path.exists() {
                return Err(format!("'{location}' does not exist here, so there is nothing to upload"));
            }
            SourceSpec::Upload { path }
        }
        _ => {
            SourceSpec::Nothing
        }
    };

    let retry_policy = match form.field(POLICY).select_index() {
        0 => RetryPolicy::Never,
        1 => RetryPolicy::OnCrash,
        2 => RetryPolicy::Always,
        _ => {
            let raw = form.field(RETRIES).text_value().trim().to_string();
            if raw.is_empty() {
                return Err("the Retry policy needs a retry limit".to_string());
            }
            match raw.parse::<u32>() {
                Ok(n) => RetryPolicy::Retry(n),
                Err(_) => return Err(format!("'{raw}' is not a whole number of retries")),
            }
        }
    };

    Ok(Parsed {
        name,
        source,
        command,
        args: parse_args(&form.field(ARGS).text_value()),
        env: parse_env(&form.field(ENV).text_value())?,
        autostart: form.field(AUTOSTART).bool_value(),
        retry_policy,
    })
}

impl SourceSpec {
    /// The wire form; an upload is recorded by what was pushed.
    pub fn to_source(&self) -> Source {
        match self {
            SourceSpec::Git { url, branch } => Source::Git { url: url.clone(), branch: branch.clone() },
            SourceSpec::Url { url } => Source::Url { url: url.clone() },
            SourceSpec::Upload { path } => Source::Upload {
                desc: path.file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| path.display().to_string()),
            },
            SourceSpec::UploadKeep { desc } => Source::Upload { desc: desc.clone() },
            SourceSpec::Nothing => Source::Empty
        }
    }

    /// The local path to push after saving, when there is one.
    pub fn upload_path(&self) -> Option<PathBuf> {
        match self {
            SourceSpec::Upload { path } => Some(path.clone()),
            _ => None,
        }
    }
}

/// One line for the detail pane.
pub fn fmt_source(source: &Source) -> String {
    match source {
        Source::Git { url, branch } => {
            let branch = branch.clone().unwrap_or_else(|| "default branch".to_string());
            format!("{url} ({branch})")
        }
        Source::Url { url } => format!("{url} (download)"),
        Source::Upload { desc } => format!("uploaded '{desc}'"),
        Source::Empty => "empty — content is managed by hand".to_string(),
        Source::None => "—".to_string(),
    }
}

/// CL-style argument parsing
pub fn parse_args(text: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut started = false;

    for c in text.chars() {
        match c {
            '"' => {
                quoted = !quoted;
                started = true;
            }
            c if c.is_whitespace() && !quoted => {
                if started {
                    args.push(std::mem::take(&mut current));
                    started = false;
                }
            }
            c => {
                current.push(c);
                started = true;
            }
        }
    }
    if started {
        args.push(current);
    }
    args
}

pub fn fmt_args(args: &[String]) -> String {
    args.iter()
        .map(|a| if a.contains(char::is_whitespace) { format!("\"{a}\"") } else { a.clone() })
        .collect::<Vec<_>>()
        .join(" ")
}

fn parse_env(text: &str) -> Result<HashMap<String, String>, String> {
    let mut env = HashMap::new();
    for entry in text.split(';').map(str::trim).filter(|e| !e.is_empty()) {
        match entry.split_once('=') {
            Some((key, value)) if !key.trim().is_empty() => {
                env.insert(key.trim().to_string(), value.to_string());
            }
            _ => return Err(format!("'{entry}' is not KEY=VALUE")),
        }
    }
    Ok(env)
}

/// Sorted, so editing an instance twice does not shuffle the field
pub fn fmt_env(env: &HashMap<String, String>) -> String {
    let mut pairs: Vec<_> = env.iter().collect();
    pairs.sort_by(|a, b| a.0.cmp(b.0));
    pairs.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("; ")
}
