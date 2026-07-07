use bier_derive::{Deserialize, Serialize};
use bierpc::serialize::{Serialize, Deserialize};

pub struct Instance {

}

impl Instance {
    pub fn stat(&self) -> InstanceStatResult {
        todo!()
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct InstanceStatResult {
    id: u128
}
