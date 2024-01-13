use glam::IVec3;

#[derive(serde::Serialize, serde::Deserialize, Default, Debug)]
pub struct Map {
    pub boxes: indexmap::IndexSet<IVec3>,
    pub nodes: indexmap::IndexMap<IVec3, Tile>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Tile {
    Wire,
    ElectronHead,
    ElectronTail,
}
