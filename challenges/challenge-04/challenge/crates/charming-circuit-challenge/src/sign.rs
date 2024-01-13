use bevy::{asset::embedded_asset, prelude::*};
use bevy_text_mesh::{
    Quality, SizeUnit, TextMesh, TextMeshBundle, TextMeshFont, TextMeshPlugin, TextMeshStyle,
};

use crate::util::fix_assetpath;

pub struct SignPlugin;

#[derive(Resource)]
pub struct SignState {
    model: Handle<Scene>,
    font: Handle<TextMeshFont>,
}

impl FromWorld for SignState {
    fn from_world(world: &mut World) -> Self {
        let asset_server = world.resource_mut::<AssetServer>();
        let font = asset_server.load(fix_assetpath("fonts/FiraSans-Bold.ttf#mesh"));
        let model = asset_server.load(fix_assetpath("models/signpost.glb#Scene0"));

        Self { model, font }
    }
}

#[derive(Component, Default, Reflect, Debug)]
#[reflect(Component)]
pub struct Sign {
    text: String,
    translation: Vec3,
    font_size: f32,
}

#[derive(Component, Default, Debug)]
pub struct SignLoaded;
#[derive(Component, Default, Debug)]
pub struct SignText;

impl Plugin for SignPlugin {
    fn build(&self, app: &mut App) {
        embedded_asset!(app, "assets/scenes/sign.scn.ron");
        embedded_asset!(app, "assets/models/signpost.glb");
        embedded_asset!(app, "assets/fonts/FiraSans-Bold.ttf");

        app.add_plugins(TextMeshPlugin)
            .register_type::<Sign>()
            .init_resource::<SignState>()
            .add_systems(Startup, setup)
            .add_systems(Update, (load_data, fiddle_text));
    }
}

fn setup(mut commands: Commands, asset_server: Res<AssetServer>) {
    let scene = asset_server.load(fix_assetpath("scenes/sign.scn.ron"));
    commands.spawn(DynamicSceneBundle { scene, ..default() });
}

fn load_data(
    mut commands: Commands,
    sign_data: Res<SignState>,
    query: Query<(Entity, &Sign), Without<SignLoaded>>,
) {
    for (entity, sign) in &query {
        commands
            .entity(entity)
            .insert((
                Visibility::Visible,
                GlobalTransform::default(),
                ViewVisibility::default(),
                InheritedVisibility::default(),
                SignLoaded,
            ))
            .with_children(|children| {
                children.spawn(SceneBundle {
                    scene: sign_data.model.clone(),
                    transform: Transform::from_scale(Vec3::splat(5.0)),
                    ..default()
                });
                children.spawn((
                    TextMeshBundle {
                        text_mesh: TextMesh {
                            text: sign.text.clone(),
                            style: TextMeshStyle {
                                font: sign_data.font.clone(),
                                font_size: SizeUnit::NonStandard(sign.font_size),
                                color: Color::rgb(0.0, 0.0, 0.0),
                                mesh_quality: Quality::Custom(128),
                                ..Default::default()
                            },
                            ..Default::default()
                        },
                        transform: Transform {
                            translation: sign.translation,
                            rotation: Quat::from_axis_angle(Vec3::Y, 90.0_f32.to_radians()),
                            ..Default::default()
                        },
                        ..Default::default()
                    },
                    SignText,
                ));
            });
    }
}

fn fiddle_text(
    mut text_query: Query<(&Parent, &SignText, &mut TextMesh, &mut Transform)>,
    sign_query: Query<&Sign, Without<SignText>>,
) {
    for (sign_entity, _, mut text_mesh, mut transform) in text_query.iter_mut() {
        let sign = sign_query.get(sign_entity.get()).unwrap();
        transform.translation = sign.translation;
        if text_mesh.text != sign.text {
            text_mesh.text = sign.text.clone();
        }
        if let SizeUnit::NonStandard(cur_size) = text_mesh.style.font_size {
            if cur_size != sign.font_size {
                text_mesh.style.font_size = SizeUnit::NonStandard(sign.font_size);
            }
        }
    }
}
