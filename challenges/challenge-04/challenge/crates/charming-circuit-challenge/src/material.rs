use bevy::{
    asset::embedded_asset,
    pbr::{ExtendedMaterial, MaterialExtension},
    prelude::*,
    render::render_resource::{AsBindGroup, ShaderRef},
};

pub struct OurMaterialPlugin;

pub type OurMaterial = ExtendedMaterial<StandardMaterial, OurMaterialExtension>;

impl Plugin for OurMaterialPlugin {
    fn build(&self, app: &mut App) {
        embedded_asset!(app, "assets/shaders/ourmaterial.wgsl");
        app.add_plugins(MaterialPlugin::<OurMaterial>::default());
    }
}

#[derive(Asset, AsBindGroup, TypePath, Debug, Clone, Default)]
pub struct OurMaterialExtension {
    // Start at a high binding number to ensure bindings don't conflict
    // with the base material
    #[uniform(100)]
    pub animated: u32,
    // TODO: Why is this needed to actually keep the reload working as intended?
    pub dependencies: Vec<Handle<OurMaterial>>,
}

impl MaterialExtension for OurMaterialExtension {
    fn fragment_shader() -> ShaderRef {
        if cfg!(feature = "embed") {
            "embedded://charming_circuit_challenge/assets/shaders/ourmaterial.wgsl".into()
        } else {
            "shaders/ourmaterial.wgsl".into()
        }
    }
}
