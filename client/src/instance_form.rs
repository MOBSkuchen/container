//! The create/edit instance form: field layout, and the parsing that turns
//! flat text back into an `InstanceConfig`'s worth of typed values

use std::collections::HashMap;

use protocol::{InstanceConfig, RetryPolicy};

use crate::form::{Field, Form};

pub const NAME: usize = 0;
pub const REPO: usize = 1;
pub const BRANCH: usize = 2;
pub const COMMAND: usize = 3;
pub const ARGS: usize = 4;
pub const ENV: usize = 5;
pub const AUTOSTART: usize = 6;
pub const POLICY: usize = 7;
pub const RETRIES: usize = 8;

const POLICIES: [&str; 4] = ["Never", "OnCrash", "Always", "Retry"];

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

    let fields = vec![
        Field::text("Name", existing.map(|c| c.name.as_str()).unwrap_or("")),
        Field::text("Repository", existing.map(|c| c.repo_url.as_str()).unwrap_or(""))
            .hint("public git URL"),
        Field::text("Branch", existing.and_then(|c| c.branch.as_deref()).unwrap_or(""))
            .hint("blank = the repo's default"),
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

/// Everything the form yields, validated. Field order matches `Action`'s
pub struct Parsed {
    pub name: String,
    pub repo_url: String,
    pub branch: Option<String>,
    pub command: String,
    pub args: Vec<String>,
    pub env: HashMap<String, String>,
    pub autostart: bool,
    pub retry_policy: RetryPolicy,
}

pub fn parse(form: &Form) -> Result<Parsed, String> {
    let name = form.field(NAME).text_value().trim().to_string();
    if name.is_empty() {
        return Err("a name is required".to_string());
    }
    let repo_url = form.field(REPO).text_value().trim().to_string();
    if repo_url.is_empty() {
        return Err("a repository URL is required".to_string());
    }
    let command = form.field(COMMAND).text_value().trim().to_string();
    if command.is_empty() {
        return Err("a command is required".to_string());
    }

    let branch = match form.field(BRANCH).text_value().trim() {
        "" => None,
        b => Some(b.to_string()),
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
        repo_url,
        branch,
        command,
        args: parse_args(&form.field(ARGS).text_value()),
        env: parse_env(&form.field(ENV).text_value())?,
        autostart: form.field(AUTOSTART).bool_value(),
        retry_policy,
    })
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
