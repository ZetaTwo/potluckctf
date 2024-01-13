#![allow(unused_parens)]
mod capless_cylinder;
mod character;
mod map;
mod map_sync;
mod material;
mod material_properties;
pub mod sign;
mod simulation;
mod static_transform;
mod ui;
mod util;
#[cfg(feature = "wirelang")]
mod wirelang;

use bevy::{
    core_pipeline::{bloom::BloomSettings, tonemapping::Tonemapping},
    pbr::{ClusterConfig, NotShadowCaster},
    prelude::*,
    window::CursorGrabMode,
};
use bevy_xpbd_3d::prelude::{
    CoefficientCombine, Collider, Friction, GravityScale, PhysicsPlugins, Restitution, RigidBody,
};
use character::CharacterControllerBundle;
use sign::SignPlugin;
use static_transform::{StaticTransform, StaticTransformPlugin};

fn main() {
    let mut app = App::new();

    if cfg!(feature = "embed") {
        app.add_plugins(DefaultPlugins.set(AssetPlugin {
            file_path: ".".into(),
            ..default()
        }));
    } else {
        app.add_plugins(DefaultPlugins);
    }
    app.add_plugins((
        material::OurMaterialPlugin,
        material_properties::MaterialPropertiesPlugin,
        map::MapPlugin,
        map_sync::MapSyncPlugin,
        ui::UiPlugin,
        simulation::SimulationPlugin,
        SignPlugin,
    ));

    #[cfg(feature = "wirelang")]
    app.add_plugins(wirelang::WirelangPlugin);

    if cfg!(feature = "static-camera") {
        app.add_plugins(StaticTransformPlugin)
            .add_systems(Startup, setup_static_camera);
    } else {
        app.add_plugins((
            PhysicsPlugins::default(),
            character::CharacterControllerPlugin,
        ))
        .add_systems(Startup, setup_player);
    }
    app.add_systems(Startup, (setup_terrain_scene, setup_mouse_grab))
        .add_systems(Update, (grab_mouse))
        .run();
}
const EYE_HEIGHT: f32 = 2.6;
const PLAYER_HEIGHT: f32 = 2.8;

#[derive(Component)]
struct MainCamera;

#[derive(Component)]
struct Player;

fn camera_bundle(transform: Transform) -> impl Bundle {
    (
        Camera3dBundle {
            transform,
            tonemapping: Tonemapping::TonyMcMapface,
            camera: Camera {
                hdr: true,
                ..default()
            },
            projection: Projection::Perspective(PerspectiveProjection {
                fov: std::f32::consts::PI / 2.5,
                ..default()
            }),
            ..default()
        },
        BloomSettings::default(),
        ClusterConfig::None,
        FogSettings {
            color: Color::rgba(0.35, 0.48, 0.66, 1.0),
            directional_light_color: Color::rgba(1.0, 0.95, 0.85, 0.5),
            directional_light_exponent: 30.0,
            falloff: FogFalloff::from_visibility_colors(
                60.0, // distance in world units up to which objects retain visibility (>= 5% contrast)
                Color::rgb(0.35, 0.5, 0.66), // atmospheric extinction color (after light is lost due to absorption by atmospheric particles)
                Color::rgb(0.8, 0.844, 1.0), // atmospheric inscattering color (light gained due to scattering from the sun)
            ),
            ..default()
        },
        Name::new("Camera"),
        MainCamera,
    )
}

fn setup_player(mut commands: Commands) {
    commands
        .spawn((
            Transform::from_xyz(0.0, 5.0, 0.0).looking_to(Vec3::new(0.0, -0.1, 1.0), Vec3::Y),
            GlobalTransform::default(),
            CharacterControllerBundle::new(Collider::cylinder(PLAYER_HEIGHT, 0.4)),
            Friction::ZERO.with_combine_rule(CoefficientCombine::Min),
            Restitution::ZERO.with_combine_rule(CoefficientCombine::Min),
            GravityScale(2.0),
            Name::new("PlayerCharacter"),
            Player,
        ))
        .with_children(|child_builder| {
            child_builder.spawn(camera_bundle(Transform::from_xyz(
                0.0,
                EYE_HEIGHT - PLAYER_HEIGHT / 2.0,
                0.0,
            )));
        });
}

fn setup_static_camera(mut commands: Commands, asset_server: Res<AssetServer>) {
    commands.spawn((
        camera_bundle(Transform::from_xyz(
            0.0,
            EYE_HEIGHT - PLAYER_HEIGHT / 2.0,
            0.0,
        )),
        asset_server.load::<StaticTransform>("static_camera.transform.ron"),
        Player,
    ));
}

fn setup_terrain_scene(
    mut commands: Commands,
    mut meshes: ResMut<Assets<Mesh>>,
    mut materials: ResMut<Assets<StandardMaterial>>,
) {
    // Sun
    commands.spawn(DirectionalLightBundle {
        directional_light: DirectionalLight {
            color: Color::rgb(0.98, 0.95, 0.82),
            shadows_enabled: false,
            ..default()
        },
        transform: Transform::from_xyz(0.0, 0.0, 0.0)
            .looking_at(Vec3::new(-0.15, -0.45, 0.25), Vec3::Y),
        ..default()
    });

    // Sky
    commands.spawn((
        PbrBundle {
            mesh: meshes.add(Mesh::from(shape::Box::default())),
            material: materials.add(StandardMaterial {
                base_color: Color::hex("888888").unwrap(),
                unlit: true,
                cull_mode: None,
                ..default()
            }),
            transform: Transform::from_scale(Vec3::splat(3000.0)),
            ..default()
        },
        NotShadowCaster,
    ));

    // ground plane
    commands.spawn((
        PbrBundle {
            mesh: meshes.add(shape::Plane::from_size(10000.0).into()),
            material: materials.add(Color::GREEN.into()),
            ..default()
        },
        RigidBody::Static,
        Collider::halfspace(Vec3::Y),
        Name::new("Ground"),
    ));
}

fn setup_mouse_grab(mut windows: Query<&mut Window>) {
    let mut window = windows.single_mut();
    window.cursor.visible = false;
    window.cursor.grab_mode = CursorGrabMode::Locked;
}

fn grab_mouse(
    mut windows: Query<&mut Window>,
    mouse: Res<Input<MouseButton>>,
    key: Res<Input<KeyCode>>,
) {
    let mut window = windows.single_mut();

    if mouse.just_pressed(MouseButton::Left) {
        window.cursor.visible = false;
        window.cursor.grab_mode = CursorGrabMode::Locked;
    }

    if key.just_pressed(KeyCode::Escape) {
        window.cursor.visible = true;
        window.cursor.grab_mode = CursorGrabMode::None;
    }
}
