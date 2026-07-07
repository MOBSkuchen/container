use bierpc::serialize::Serialize;
use bierpc::serialize::Deserialize;
use std::net::{SocketAddr};
use std::path::PathBuf;
use bier_derive::{Deserialize, Serialize};
use tokio::fs;

#[derive(Serialize, Deserialize)]
pub struct Object {
    pub storage_path: PathBuf,
    pub id: u128,
}

#[derive(Serialize, Deserialize)]
pub struct ChildStg {
    pub addr: SocketAddr,
    pub config_path: PathBuf,
    pub storage_path: PathBuf,
}

#[derive(Serialize, Deserialize)]
pub struct InstanceCfg {
    pub objects_path: PathBuf,
    pub objects: Vec<Object>
}

impl InstanceCfg {
    pub async fn new(objects_path: PathBuf) -> anyhow::Result<Self> {
        if objects_path.exists() {
            let mut file = fs::File::open(objects_path).await?;
            let objects = InstanceCfg::deserialize(&mut file).await?;
            Ok(objects)
        } else {
            Ok(Self {
                objects_path,
                objects: Vec::new()
            })
        }
    }
}

impl ChildStg {
    pub async fn new(addr: SocketAddr, config_path: PathBuf, storage_path: PathBuf) -> anyhow::Result<(Self, InstanceCfg)> {
        if config_path.exists() {
            fs::remove_file(&config_path).await?;
        }
        fs::create_dir(&storage_path).await?;
        let objects_path = storage_path.join("instances");
        let mut f = fs::File::options().create_new(true).truncate(true).write(true).open(&config_path).await?;
        let ft = Self {
            addr,
            config_path,
            storage_path };
        ft.serialize(&mut f).await?;
        Ok((ft,
            InstanceCfg::new(objects_path).await?)
        )
    }

    pub async fn load(config_path: PathBuf) -> anyhow::Result<(Self, InstanceCfg)> {
        let mut f = fs::File::options().read(true).open(&config_path).await?;
        let ft = ChildStg::deserialize(&mut f).await?;
        let objects_path = ft.storage_path.join("instances");
        Ok((ft, InstanceCfg::new(objects_path).await?))
    }
}
