use bevy::{
    asset::{AssetLoader, AsyncReadExt},
    prelude::*,
    utils::BoxedFuture,
};
use wirelang::{interpret::Direction, ErrorCtx};

use crate::map::Map;

pub struct WirelangPlugin;

impl Plugin for WirelangPlugin {
    fn build(&self, app: &mut App) {
        app.register_asset_loader(WirelangLoader);
    }
}

pub struct WirelangLoader;

impl AssetLoader for WirelangLoader {
    type Asset = Map;
    type Settings = ();
    type Error = std::io::Error;

    fn load<'a>(
        &'a self,
        reader: &'a mut bevy::asset::io::Reader,
        _settings: &(),
        load_context: &'a mut bevy::asset::LoadContext,
    ) -> BoxedFuture<'a, Result<Self::Asset, Self::Error>> {
        Box::pin(async move {
            let mut bytes = Vec::new();
            reader.read_to_end(&mut bytes).await?;
            let buffer = String::from_utf8(bytes)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
            let mut error_ctx = ErrorCtx::new(load_context.path(), buffer);

            if let Ok(program) = wirelang::parse_str(&mut error_ctx) {
                let mut map = map::Map::default();
                if let Ok(()) = program.interpret(
                    &mut map,
                    &mut IVec3::default(),
                    &mut Direction::default(),
                    &mut error_ctx,
                ) {
                    return Ok(Map { map });
                }
            }

            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Could not load file",
            ))
        })
    }

    fn extensions(&self) -> &[&str] {
        &["wirelang"]
    }
}
