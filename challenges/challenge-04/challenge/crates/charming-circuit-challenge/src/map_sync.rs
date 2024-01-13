use bevy::{
    asset::embedded_asset,
    math::Vec3A,
    pbr::{NotShadowCaster, NotShadowReceiver},
    prelude::*,
    render::primitives::Aabb,
};
use bevy_xpbd_3d::prelude::Collider;
use map::Tile;

use crate::{
    map::Map,
    material::OurMaterial,
    simulation::{
        EdgeState, NodeState, SimulationHandles, SimulationState, BALL_RADIUS, EDGE_INACTIVE,
        WIRE_RADIUS,
    },
};

pub struct MapSyncPlugin;

impl Plugin for MapSyncPlugin {
    fn build(&self, app: &mut App) {
        embedded_asset!(app, "assets/world.wiremap");

        app.init_resource::<SyncState>()
            .add_systems(Update, (set_debounce, update_world.run_if(update_debounce)));
    }
}

#[derive(Resource)]
struct SyncState {
    handle: Handle<Map>,
    reload_debounce: u8,
}

impl FromWorld for SyncState {
    fn from_world(world: &mut World) -> Self {
        #[cfg(feature = "wirelang")]
        let handle = world.resource_mut::<AssetServer>().load("world.wirelang");

        #[cfg(not(feature = "wirelang"))]
        let handle = world
            .resource_mut::<AssetServer>()
            .load("embedded://charming_circuit_challenge/assets/world.wiremap");

        Self {
            handle,
            reload_debounce: 0,
        }
    }
}

fn set_debounce(mut state: ResMut<SyncState>, mut asset_events: EventReader<AssetEvent<Map>>) {
    state.reload_debounce = state.reload_debounce.saturating_sub(1);

    for event in asset_events.read() {
        match event {
            AssetEvent::Added { id }
            | AssetEvent::Modified { id }
            | AssetEvent::LoadedWithDependencies { id }
            | AssetEvent::Removed { id }
                if id == &state.handle.id() =>
            {
                state.reload_debounce = 2;
            }
            _ => (),
        }
    }
}

fn update_debounce(state: Res<SyncState>) -> bool {
    state.reload_debounce == 1
}

fn update_world(
    mut commands: Commands,
    sync_state: ResMut<SyncState>,
    mut simulation_state: ResMut<SimulationState>,
    simulation_handles: Res<SimulationHandles>,
    maps: Res<Assets<Map>>,
    to_despawn: Query<Entity, With<DespawnOnReload>>,
) {
    for entity in &to_despawn {
        commands.entity(entity).despawn_recursive()
    }

    let simulation_state = &mut *simulation_state;

    if let Some(map) = maps.get(&sync_state.handle) {
        simulation_state.activation_counts_next_cycle.truncate(0);
        simulation_state.nodes.clear();
        simulation_state.edges.clear();
        simulation_state.steps = 0;

        let box_collider = Collider::cuboid(1.0, 1.0, 1.0);
        for pos in &map.map.boxes {
            commands.spawn((
                SpatialBundle {
                    transform: Transform::from_xyz(pos.x as f32, pos.y as f32 + 0.5, pos.z as f32),
                    ..default()
                },
                Aabb {
                    center: Vec3A::new(0.0, 0.0, 0.0),
                    half_extents: Vec3A::splat(0.5),
                },
                DespawnOnReload,
                WantsDrawing((
                    simulation_handles.cube_mesh.clone_weak(),
                    simulation_handles.cube_material.clone_weak(),
                )),
                WantsCollider(box_collider.clone()),
                NotShadowCaster,
                NotShadowReceiver,
            ));
        }

        for &pos in map.map.nodes.keys() {
            let mut count = 0;
            for dx in -1..=1 {
                for dy in -1..=1 {
                    for dz in -1..=1 {
                        if (dx, dy, dz) == (0, 0, 0) {
                            continue;
                        }
                        let neighbor_pos = IVec3::new(pos.x + dx, pos.y + dy, pos.z + dz);
                        if map.map.nodes.get(&neighbor_pos) == Some(&Tile::ElectronHead) {
                            count += 1;
                        };
                    }
                }
            }
            simulation_state.activation_counts_next_cycle.push(count);
        }

        let node_collider = Collider::cylinder(2.0 * BALL_RADIUS, BALL_RADIUS);
        for (node_id, ((&pos, kind), activation_count_next_cycle)) in map
            .map
            .nodes
            .iter()
            .zip(&simulation_state.activation_counts_next_cycle)
            .enumerate()
        {
            let last_activation_step: i64 = match kind {
                Tile::ElectronHead => 0,
                Tile::ElectronTail => -1,
                Tile::Wire => -10,
            };

            let entity = commands
                .spawn((
                    SpatialBundle {
                        transform: Transform::from_xyz(
                            pos.x as f32,
                            pos.y as f32 + 0.5,
                            pos.z as f32,
                        ),
                        ..default()
                    },
                    Aabb {
                        center: Vec3A::new(0.0, 0.0, 0.0),
                        half_extents: Vec3A::splat(BALL_RADIUS),
                    },
                    DespawnOnReload,
                    WantsCollider(node_collider.clone()),
                    WantsDrawing((
                        simulation_handles.sphere_mesh.clone_weak(),
                        simulation_handles
                            .material_for_node(
                                simulation_state.steps.saturating_sub(last_activation_step),
                                *activation_count_next_cycle,
                            )
                            .clone_weak(),
                    )),
                    NotShadowCaster,
                    NotShadowReceiver,
                ))
                .id();

            let mut neighbors = Vec::new();

            let wire_collider = Collider::cuboid(WIRE_RADIUS, 0.95, WIRE_RADIUS);

            for dx in -1..=1 {
                for dy in -1..=1 {
                    for dz in -1..=1 {
                        if (dx, dy, dz) == (0, 0, 0) {
                            continue;
                        }
                        let delta = IVec3::new(dx, dy, dz);
                        let neighbor_pos = pos + delta;
                        let Some(neighbor_id) = map.map.nodes.get_index_of(&neighbor_pos) else {
                            continue;
                        };
                        neighbors.push(neighbor_id);

                        if node_id < neighbor_id {
                            let length = delta.as_vec3().length()
                                - 2.0
                                    * (BALL_RADIUS * BALL_RADIUS - WIRE_RADIUS * WIRE_RADIUS)
                                        .sqrt();
                            let entity = commands
                                .spawn((
                                    SpatialBundle {
                                        transform: Transform {
                                            translation: pos.as_vec3()
                                                + delta.as_vec3() / 2.0
                                                + Vec3::new(0.0, 0.5, 0.0),
                                            rotation: Quat::from_rotation_arc(
                                                Vec3::Y,
                                                delta.as_vec3().normalize(),
                                            ),
                                            scale: Vec3::new(1.0, length, 1.0),
                                        },
                                        ..default()
                                    },
                                    Aabb {
                                        center: Vec3A::new(0.0, 0.0, 0.0),
                                        half_extents: Vec3A::new(WIRE_RADIUS, 0.5, WIRE_RADIUS),
                                    },
                                    DespawnOnReload,
                                    WantsCollider(wire_collider.clone()),
                                    WantsDrawing((
                                        simulation_handles.edge_mesh.clone_weak(),
                                        simulation_handles.materials[EDGE_INACTIVE].clone_weak(),
                                    )),
                                    NotShadowCaster,
                                    NotShadowReceiver,
                                ))
                                .id();
                            simulation_state.edges.push(EdgeState {
                                entity,
                                start_node: node_id,
                                end_node: neighbor_id,
                            })
                        }
                    }
                }
            }

            simulation_state.nodes.push(NodeState {
                entity,
                last_activation_step,
                neighbors,
            });
        }
    }
}

#[derive(Component)]
pub struct WantsCollider(pub Collider);

#[derive(Component)]
pub struct WantsDrawing(pub (Handle<Mesh>, Handle<OurMaterial>));

#[derive(Component)]
pub struct DespawnOnReload;
