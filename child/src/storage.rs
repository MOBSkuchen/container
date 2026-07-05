use bierpc::serialize::Serialize;
use bierpc::serialize::Deserialize;
use std::net::{SocketAddr};
use std::path::PathBuf;
use bier_derive::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct Object {
    storage_path: PathBuf,
    id: u128,
}

#[derive(Serialize, Deserialize)]
struct ChildStg {
    addr: SocketAddr,
    file_path: PathBuf,

    objects: Vec<Object>
}