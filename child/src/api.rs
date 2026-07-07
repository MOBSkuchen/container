use bierpc::serialize::Deserialize;
use bierpc::serialize::Serialize;
use bier_derive::{Deserialize, Serialize};
use bierpc::error::RpcResult;
use bierpc::RpcServerHandler;
use sysinfo::{
    Components, Disks, Networks, System,
};
use crate::manager::{Instance, InstanceStatResult};

#[derive(Serialize, Deserialize, Debug)]
pub enum Action {
    Ping,
    Stat
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Response {
    Pong,
    StatResponse {
        total_stg: u64,
        free_stg: u64,

        total_ram: u64,
        free_ram: u64,

        network_recv: u64,
        network_trans: u64,

        cpu_usage: f64,

        instances: Vec::<InstanceStatResult>
    }
}

type RR = RpcResult<Response>;

pub struct Api {
    instances: Vec<Instance>
}

impl Api {
    pub fn new() -> Self {
        Self {
            instances: Vec::new()
        }
    }

    pub async fn ping(&self) -> RR {
        Ok(Response::Pong)
    }

    pub async fn stat(&self) -> RR {
        let sys = System::new_all();
        let instances = self.instances.iter().map(|i| {i.stat()}).collect::<Vec<InstanceStatResult>>();

        let mut total_stg = 0;
        let mut free_stg = 0;
        for disk in Disks::new_with_refreshed_list().iter() {
            total_stg += disk.total_space();
            free_stg +=disk.available_space();
        }

        let mut recv = 0;
        let mut trans = 0;
        for (_, data) in &Networks::new_with_refreshed_list() {
            recv += data.received();
            trans += data.transmitted();
        }

        Ok(Response::StatResponse {
            total_stg,
            free_stg,
            total_ram: sys.total_memory(),
            free_ram: sys.free_memory(),
            cpu_usage: sys.global_cpu_usage() as f64,
            network_recv: recv,
            network_trans: trans,
            instances
        })
    }
}

impl RpcServerHandler<Action, Response> for Api {
    async fn handle(&self, action: Action) -> RR {
        match action {
            Action::Ping => self.ping().await,
            Action::Stat => self.stat().await
        }
    }
}