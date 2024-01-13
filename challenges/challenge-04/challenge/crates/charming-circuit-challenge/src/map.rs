use bevy::{
    asset::{AssetLoader, AsyncReadExt},
    prelude::*,
    utils::BoxedFuture,
};

pub struct MapPlugin;

impl Plugin for MapPlugin {
    fn build(&self, app: &mut App) {
        app.init_asset::<Map>().register_asset_loader(MapLoader);
    }
}

#[derive(Asset, TypePath, Debug)]
pub struct Map {
    pub map: map::Map,
}

pub struct MapLoader;

impl AssetLoader for MapLoader {
    type Asset = Map;
    type Settings = ();
    type Error = std::io::Error;

    fn load<'a>(
        &'a self,
        reader: &'a mut bevy::asset::io::Reader,
        _settings: &(),
        _load_context: &'a mut bevy::asset::LoadContext,
    ) -> BoxedFuture<'a, Result<Self::Asset, Self::Error>> {
        Box::pin(async move {
            let mut bytes = Vec::new();
            reader.read_to_end(&mut bytes).await?;
            let map = bincode::deserialize(&bytes)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
            Ok(Map { map })
        })
    }

    fn extensions(&self) -> &[&str] {
        &["wiremap"]
    }
}
