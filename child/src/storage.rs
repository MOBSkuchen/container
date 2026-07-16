use bierpc::serialize::Serialize;
use bierpc::serialize::Deserialize;
use std::collections::HashMap;
use std::net::{SocketAddr};
use std::path::PathBuf;
use bier_derive::{Deserialize, Serialize};
use tokio::fs;
use crate::manager::RetryPolicy;

/// Full definition of an instance: a public git repo plus how to run it.
/// This is what gets persisted to the instance index and restored on boot.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct InstanceConfig {
    pub id: u128,
    pub name: String,
    pub repo_url: String,
    pub branch: Option<String>,
    pub command: String,
    pub args: Vec<String>,
    pub env: HashMap<String, String>,
    pub autostart: bool,
    pub retry_policy: RetryPolicy,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ChildStg {
    pub addr: SocketAddr,
    pub config_path: PathBuf,
    pub storage_path: PathBuf,
    /// Roots (besides the instances dir) that file upload/download may touch.
    pub file_roots: Vec<PathBuf>,
    /// How long a terminal/file-transfer session offer stays connectable.
    pub session_ttl_secs: u64,
    /// Shell spawned for terminal Shell sessions.
    pub shell: String,
}

pub fn default_shell() -> String {
    if cfg!(windows) { "cmd.exe".to_string() } else { "/bin/sh".to_string() }
}

impl ChildStg {
    pub fn instances_index_path(&self) -> PathBuf {
        self.storage_path.join("instances.chld")
    }

    pub fn instances_dir(&self) -> PathBuf {
        self.storage_path.join("instances")
    }

    pub fn instance_dir(&self, id: u128) -> PathBuf {
        self.instances_dir().join(format!("{:032x}", id))
    }

    pub fn repo_dir(&self, id: u128) -> PathBuf {
        self.instance_dir(id).join("repo")
    }

    pub async fn new(
        addr: SocketAddr,
        config_path: PathBuf,
        storage_path: PathBuf,
        file_roots: Vec<PathBuf>,
        session_ttl_secs: u64,
        shell: String,
    ) -> anyhow::Result<(Self, Vec<InstanceConfig>)> {
        if config_path.exists() {
            fs::remove_file(&config_path).await?;
        }
        fs::create_dir_all(&storage_path).await?;
        let mut f = fs::File::options().create_new(true).truncate(true).write(true).open(&config_path).await?;
        let ft = Self {
            addr,
            config_path,
            storage_path,
            file_roots,
            session_ttl_secs,
            shell,
        };
        fs::create_dir_all(ft.instances_dir()).await?;
        ft.serialize(&mut f).await?;
        let instances = ft.load_instances().await?;
        Ok((ft, instances))
    }

    pub async fn load(config_path: PathBuf) -> anyhow::Result<(Self, Vec<InstanceConfig>)> {
        let mut f = fs::File::options().read(true).open(&config_path).await?;
        let ft = ChildStg::deserialize(&mut f).await?;
        fs::create_dir_all(ft.instances_dir()).await?;
        let instances = ft.load_instances().await?;
        Ok((ft, instances))
    }

    pub async fn load_instances(&self) -> anyhow::Result<Vec<InstanceConfig>> {
        let path = self.instances_index_path();
        if path.exists() {
            let mut file = fs::File::open(path).await?;
            Ok(Vec::<InstanceConfig>::deserialize(&mut file).await?)
        } else {
            Ok(Vec::new())
        }
    }

    /// Atomically rewrite the instance index (write temp file, then rename).
    pub async fn save_instances(&self, instances: &Vec<InstanceConfig>) -> anyhow::Result<()> {
        let path = self.instances_index_path();
        let tmp = path.with_extension("chld.tmp");
        {
            let mut f = fs::File::options().create(true).truncate(true).write(true).open(&tmp).await?;
            instances.serialize(&mut f).await?;
            use tokio::io::AsyncWriteExt;
            f.flush().await?;
        }
        if path.exists() {
            fs::remove_file(&path).await?;
        }
        fs::rename(&tmp, &path).await?;
        Ok(())
    }
}
