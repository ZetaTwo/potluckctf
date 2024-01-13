use bevy::{
    asset::{AssetLoader, AsyncReadExt},
    prelude::*,
    utils::{BoxedFuture, HashSet},
};

use crate::util::option_deserializer;

pub struct StaticTransformPlugin;

impl Plugin for StaticTransformPlugin {
    fn build(&self, app: &mut App) {
        app.init_asset::<StaticTransform>()
            .register_asset_loader(StaticTransformLoader)
            .add_systems(Update, sync_changes);
    }
}

#[derive(serde::Serialize, serde::Deserialize, Copy, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct EulerAngles {
    yaw: f32,
    pitch: f32,
}

#[derive(Asset, TypePath, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticTransform {
    translation: Vec3,
    #[serde(default, deserialize_with = "option_deserializer")]
    looking_at: Option<Vec3>,
    #[serde(default, deserialize_with = "option_deserializer")]
    looking_to: Option<Vec3>,
    #[serde(default, deserialize_with = "option_deserializer")]
    euler: Option<EulerAngles>,
}

pub struct StaticTransformLoader;

#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum StaticTransformLoaderError {
    /// An [IO Error](std::io::Error)
    #[error("Error while trying to read the static transform file: {0}")]
    Io(#[from] std::io::Error),
    /// A [RON Error](ron::error::SpannedError)
    #[error("Could not parse RON while parsing static transform file: {0}")]
    RonSpannedError(#[from] ron::error::SpannedError),
}

impl AssetLoader for StaticTransformLoader {
    type Asset = StaticTransform;
    type Settings = ();
    type Error = StaticTransformLoaderError;

    fn load<'a>(
        &'a self,
        reader: &'a mut bevy::asset::io::Reader,
        _settings: &(),
        _load_context: &'a mut bevy::asset::LoadContext,
    ) -> BoxedFuture<'a, Result<Self::Asset, Self::Error>> {
        Box::pin(async move {
            let mut bytes = Vec::new();
            reader.read_to_end(&mut bytes).await?;
            Ok(ron::de::from_bytes(&bytes)?)
        })
    }

    fn extensions(&self) -> &[&str] {
        &["transform.ron"]
    }
}

fn sync_changes(
    mut asset_events: EventReader<AssetEvent<StaticTransform>>,
    assets: Res<Assets<StaticTransform>>,
    mut to_update: Query<(&mut Transform, &Handle<StaticTransform>)>,
    mut seen: Local<HashSet<AssetId<StaticTransform>>>,
) {
    seen.clear();
    for event in asset_events.read() {
        match event {
            AssetEvent::Added { id } | AssetEvent::Modified { id } | AssetEvent::Removed { id } => {
                seen.insert(*id);
            }
            AssetEvent::LoadedWithDependencies { .. } => (),
        }
    }

    for (mut transform, handle) in to_update.iter_mut() {
        if seen.contains(&handle.id()) {
            if let Some(static_transform) = assets.get(handle) {
                let mut new = Transform::from_translation(static_transform.translation);
                if let Some(looking_at) = static_transform.looking_at {
                    new.look_at(looking_at, Vec3::Y);
                } else if let Some(looking_at) = static_transform.looking_to {
                    new.look_to(looking_at, Vec3::Y);
                } else if let Some(euler) = static_transform.euler {
                    new.rotation = Quat::from_euler(
                        EulerRot::YXZ,
                        (180.0 - euler.yaw).to_radians(),
                        euler.pitch.to_radians(),
                        0.0,
                    );
                }

                *transform = new;
            }
        }
    }
}
