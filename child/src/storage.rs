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
pub struct Objects {
    pub objects_path: PathBuf,
    pub objects: Vec<Object>
}

impl Objects {
    pub async fn new(objects_path: PathBuf) -> anyhow::Result<Self> {
        if objects_path.exists() {
            let mut file = fs::File::open(objects_path).await?;
            let objects = Objects::deserialize(&mut file).await?;
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
    pub async fn new(addr: SocketAddr, config_path: PathBuf, storage_path: PathBuf) -> anyhow::Result<(Self, Objects)> {
        fs::create_dir(&storage_path).await?;
        let objects_path = storage_path.join("objects");
        let mut f = fs::File::options().create(true).write(true).open(&config_path).await?;
        let ft = Self {
            addr,
            config_path,
            storage_path };
        ft.serialize(&mut f).await?;
        Ok((ft,
            Objects::new(objects_path).await?)
        )
    }

    pub async fn load(config_path: PathBuf) -> anyhow::Result<(Self, Objects)> {
        let mut f = fs::File::options().create(true).read(true).open(&config_path).await?;
        let ft = ChildStg::deserialize(&mut f).await?;
        let objects_path = ft.storage_path.join("objects");
        Ok((ft, Objects::new(objects_path).await?))
    }
}
