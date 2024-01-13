use bevy::{asset::embedded_asset, prelude::*};
use bevy_xpbd_3d::prelude::{Collider, RigidBody};

use crate::{
    capless_cylinder::CaplessCylinder,
    map_sync::{DespawnOnReload, WantsCollider, WantsDrawing},
    material::OurMaterial,
    MainCamera,
};

pub struct SimulationPlugin;

impl Plugin for SimulationPlugin {
    fn build(&self, app: &mut App) {
        embedded_asset!(app, "assets/materials/node_active.mat.ron");
        embedded_asset!(app, "assets/materials/node_inactive1.mat.ron");
        embedded_asset!(app, "assets/materials/node_inactive2.mat.ron");
        embedded_asset!(app, "assets/materials/node_inactive3.mat.ron");
        embedded_asset!(app, "assets/materials/node_inactive4.mat.ron");
        embedded_asset!(app, "assets/materials/node_active_next2.mat.ron");
        embedded_asset!(app, "assets/materials/node_active_next3.mat.ron");
        embedded_asset!(app, "assets/materials/node_active_next4.mat.ron");
        embedded_asset!(app, "assets/materials/edge_inactive.mat.ron");
        embedded_asset!(app, "assets/materials/edge_double_active.mat.ron");
        embedded_asset!(app, "assets/materials/edge_active1.mat.ron");
        embedded_asset!(app, "assets/materials/edge_active2.mat.ron");
        embedded_asset!(app, "assets/materials/edge_overactive1.mat.ron");
        embedded_asset!(app, "assets/materials/edge_overactive2.mat.ron");
        embedded_asset!(app, "assets/materials/cube.mat.ron");
        embedded_asset!(app, "assets/materials/nodes.mat.ron");
        embedded_asset!(app, "assets/materials/edges.mat.ron");
        embedded_asset!(app, "assets/materials/glass.mat.ron");
        embedded_asset!(app, "assets/textures/edge_active1.png");
        embedded_asset!(app, "assets/textures/edge_active2.png");
        embedded_asset!(app, "assets/textures/edge_double_active.png");
        embedded_asset!(app, "assets/textures/edge_inactive.png");
        embedded_asset!(app, "assets/textures/edge_overactive1.png");
        embedded_asset!(app, "assets/textures/edge_overactive2.png");
        embedded_asset!(app, "assets/textures/node_active_next2.png");
        embedded_asset!(app, "assets/textures/node_active_next3.png");
        embedded_asset!(app, "assets/textures/node_active_next4.png");
        embedded_asset!(app, "assets/textures/node_active.png");
        embedded_asset!(app, "assets/textures/node_inactive1.png");
        embedded_asset!(app, "assets/textures/node_inactive2.png");
        embedded_asset!(app, "assets/textures/node_inactive3.png");
        embedded_asset!(app, "assets/textures/node_inactive4.png");

        app.init_resource::<SimulationState>()
            .init_resource::<SimulationHandles>()
            .add_systems(
                Update,
                (simulation_keyboard_events, simulation_tick, set_visibility),
            );
    }
}

pub const NODE_ACTIVE: usize = 0;
pub const NODE_INACTIVE_1: usize = 1;
pub const NODE_INACTIVE_2: usize = 2;
pub const NODE_INACTIVE_3: usize = 3;
pub const NODE_INACTIVE_4: usize = 4;
pub const NODE_ACTIVE_NEXT_2: usize = 5;
pub const NODE_ACTIVE_NEXT_3: usize = 6;
pub const NODE_ACTIVE_NEXT_4: usize = 7;
pub const EDGE_INACTIVE: usize = 8;
pub const EDGE_DOUBLE_ACTIVE: usize = 9;
pub const EDGE_ACTIVE1: usize = 10;
pub const EDGE_ACTIVE2: usize = 11;
pub const EDGE_OVERACTIVE1: usize = 12;
pub const EDGE_OVERACTIVE2: usize = 13;
pub const CUBE: usize = 14;
pub const MATERIAL_TYPES: usize = 15;

pub const BALL_RADIUS: f32 = 0.22;
pub const WIRE_RADIUS: f32 = 0.06;

#[derive(Resource, Debug)]
pub struct SimulationHandles {
    pub materials: [Handle<OurMaterial>; MATERIAL_TYPES],
    pub cube_material: Handle<OurMaterial>,
    pub cube_mesh: Handle<Mesh>,
    pub sphere_mesh: Handle<Mesh>,
    pub edge_mesh: Handle<Mesh>,
}

#[derive(Resource, Debug)]
pub struct SimulationState {
    pub steps: i64,
    pub timer: Timer,
    pub speed: i32,
    pub nodes: Vec<NodeState>,
    pub activation_counts_next_cycle: Vec<usize>,
    pub edges: Vec<EdgeState>,
}

#[derive(Debug)]
pub struct NodeState {
    pub entity: Entity,
    pub last_activation_step: i64,
    pub neighbors: Vec<usize>,
}

#[derive(Debug)]
pub struct EdgeState {
    pub entity: Entity,
    pub start_node: usize,
    pub end_node: usize,
}

impl FromWorld for SimulationHandles {
    fn from_world(world: &mut World) -> Self {
        #[cfg(feature = "embed")]
        let texture_names = [
            "embedded://charming_circuit_challenge/assets/materials/node_active.mat.ron",
            "embedded://charming_circuit_challenge/assets/materials/node_inactive1.mat.ron",
            "embedded://charming_circuit_challenge/assets/materials/node_inactive2.mat.ron",
            "embedded://charming_circuit_challenge/assets/materials/node_inactive3.mat.ron",
            "embedded://charming_circuit_challenge/assets/materials/node_inactive4.mat.ron",
            "embedded://charming_circuit_challenge/assets/materials/node_active_next2.mat.ron",
            "embedded://charming_circuit_challenge/assets/materials/node_active_next3.mat.ron",
            "embedded://charming_circuit_challenge/assets/materials/node_active_next4.mat.ron",
            "embedded://charming_circuit_challenge/assets/materials/edge_inactive.mat.ron",
            "embedded://charming_circuit_challenge/assets/materials/edge_double_active.mat.ron",
            "embedded://charming_circuit_challenge/assets/materials/edge_active1.mat.ron",
            "embedded://charming_circuit_challenge/assets/materials/edge_active2.mat.ron",
            "embedded://charming_circuit_challenge/assets/materials/edge_overactive1.mat.ron",
            "embedded://charming_circuit_challenge/assets/materials/edge_overactive2.mat.ron",
            "embedded://charming_circuit_challenge/assets/materials/cube.mat.ron",
        ];
        #[cfg(not(feature = "embed"))]
        let texture_names = [
            "materials/node_active.mat.ron",
            "materials/node_inactive1.mat.ron",
            "materials/node_inactive2.mat.ron",
            "materials/node_inactive3.mat.ron",
            "materials/node_inactive4.mat.ron",
            "materials/node_active_next2.mat.ron",
            "materials/node_active_next3.mat.ron",
            "materials/node_active_next4.mat.ron",
            "materials/edge_inactive.mat.ron",
            "materials/edge_double_active.mat.ron",
            "materials/edge_active1.mat.ron",
            "materials/edge_active2.mat.ron",
            "materials/edge_overactive1.mat.ron",
            "materials/edge_overactive2.mat.ron",
            "materials/cube.mat.ron",
        ];
        let asset_server = world.resource::<AssetServer>();
        let materials = texture_names.map(|name| asset_server.load(name));
        let cube_material = materials[CUBE].clone();

        let mut meshes = world.resource_mut::<Assets<Mesh>>();
        let cube_mesh = meshes.add(shape::Cube::default().into());
        let sphere_mesh = meshes.add(
            shape::Icosphere {
                radius: BALL_RADIUS,
                subdivisions: 6,
            }
            .try_into()
            .unwrap(),
        );
        let edge_mesh = meshes.add(
            CaplessCylinder {
                radius: WIRE_RADIUS,
                height: 1.0,
                ..default()
            }
            .into(),
        );

        Self {
            materials,
            cube_material,
            cube_mesh,
            sphere_mesh,
            edge_mesh,
        }
    }
}

impl Default for SimulationState {
    fn default() -> Self {
        Self {
            steps: 0,
            timer: Timer::from_seconds(1.0, TimerMode::Repeating),
            speed: 0,
            nodes: Vec::new(),
            activation_counts_next_cycle: Vec::new(),
            edges: Vec::new(),
        }
    }
}

impl SimulationState {
    pub fn step(&mut self) {
        self.steps += 1;
        for (node, activation_count) in self
            .nodes
            .iter_mut()
            .zip(self.activation_counts_next_cycle.iter().copied())
        {
            if (activation_count == 1 || activation_count == 2)
                && node.last_activation_step + 2 < self.steps
            {
                node.last_activation_step = self.steps;
            }
        }
        self.calculate_activation_counts();
    }

    pub fn calculate_activation_counts(&mut self) {
        self.activation_counts_next_cycle.fill(0);
        for node in &self.nodes {
            if node.last_activation_step == self.steps {
                for &neighbor in &node.neighbors {
                    self.activation_counts_next_cycle[neighbor] += 1;
                }
            }
        }
    }

    pub fn update_materials(
        &self,
        mut material_handles: Query<&mut Handle<OurMaterial>>,
        mut wants_drawing: Query<&mut WantsDrawing>,
        simulation_handles: &SimulationHandles,
    ) {
        for (node, &activation_count_next_cycle) in
            self.nodes.iter().zip(&self.activation_counts_next_cycle)
        {
            let new_handle = simulation_handles.material_for_node(
                self.steps.saturating_sub(node.last_activation_step),
                activation_count_next_cycle,
            );
            if let Ok(mut handle) = material_handles.get_mut(node.entity.clone()) {
                handle.set_if_neq(new_handle.clone_weak());
            }
            if let Ok(mut handle) = wants_drawing.get_mut(node.entity.clone()) {
                if handle.0 .1.id() != new_handle.id() {
                    handle.0 .1 = new_handle.clone_weak();
                }
            }
        }
        for edge in &self.edges {
            let node1 = &self.nodes[edge.start_node];
            let node2 = &self.nodes[edge.end_node];
            let node1_counts = self.activation_counts_next_cycle[edge.start_node];
            let node2_counts = self.activation_counts_next_cycle[edge.end_node];
            let new_handle = simulation_handles.material_for_edge(
                self.steps.saturating_sub(node1.last_activation_step),
                node1_counts,
                self.steps.saturating_sub(node2.last_activation_step),
                node2_counts,
            );
            if let Ok(mut handle) = material_handles.get_mut(edge.entity.clone()) {
                handle.set_if_neq(new_handle.clone_weak());
            }
            if let Ok(mut handle) = wants_drawing.get_mut(edge.entity.clone()) {
                if handle.0 .1.id() != new_handle.id() {
                    handle.0 .1 = new_handle.clone_weak();
                }
            }
        }
    }
}

impl SimulationHandles {
    pub fn material_for_node(
        &self,
        time_since_last_activation: i64,
        activation_count_next_cycle: usize,
    ) -> &Handle<OurMaterial> {
        match (
            time_since_last_activation,
            activation_count_next_cycle == 1 || activation_count_next_cycle == 2,
        ) {
            (0, _) => &self.materials[NODE_ACTIVE],
            (1, _) => &self.materials[NODE_INACTIVE_1],
            (2, false) => &self.materials[NODE_INACTIVE_2],
            (2, true) => &self.materials[NODE_ACTIVE_NEXT_2],
            (3, false) => &self.materials[NODE_INACTIVE_3],
            (3, true) => &self.materials[NODE_ACTIVE_NEXT_3],
            (_, false) => &self.materials[NODE_INACTIVE_4],
            (_, true) => &self.materials[NODE_ACTIVE_NEXT_4],
        }
    }

    fn material_for_edge(
        &self,
        node1_last_activation: i64,
        node1_counts: usize,
        node2_last_activation: i64,
        node2_counts: usize,
    ) -> &Handle<OurMaterial> {
        match (
            node1_last_activation,
            node1_counts == 1 || node1_counts == 2,
            node1_counts > 2,
            node2_last_activation,
            node2_counts == 1 || node2_counts == 2,
            node2_counts > 2,
        ) {
            (0, _, _, 0, _, _) => &self.materials[EDGE_DOUBLE_ACTIVE],
            (_, _, _, 1, _, _) | (1, _, _, _, _, _) => &self.materials[EDGE_INACTIVE],
            (0, _, _, _, true, _) => &self.materials[EDGE_ACTIVE1],
            (_, true, _, 0, _, _) => &self.materials[EDGE_ACTIVE2],
            (0, _, _, _, _, true) => &self.materials[EDGE_OVERACTIVE1],
            (_, _, true, 0, _, _) => &self.materials[EDGE_OVERACTIVE2],
            _ => &self.materials[EDGE_INACTIVE],
        }
    }
}

fn simulation_tick(
    time: Res<Time>,
    mut simulation_state: ResMut<SimulationState>,
    simulation_handles: Res<SimulationHandles>,
    material_handles: Query<&mut Handle<OurMaterial>>,
    wants_drawing: Query<&mut WantsDrawing>,
) {
    let mut have_run = false;
    for _ in 0..simulation_state
        .timer
        .tick(time.delta())
        .times_finished_this_tick()
    {
        simulation_state.step();
        have_run = true;
    }
    if have_run {
        simulation_state.update_materials(material_handles, wants_drawing, &*simulation_handles);
    }
}

fn simulation_keyboard_events(
    keyboard_input: Res<Input<KeyCode>>,
    mut time: ResMut<Time<Virtual>>,
    mut state: ResMut<SimulationState>,
) {
    let mut change = 0;
    if keyboard_input.just_pressed(KeyCode::Up) {
        change += 1;
    }
    if keyboard_input.just_pressed(KeyCode::Down) {
        change -= 1;
    }
    if change != 0 {
        state.speed = (state.speed + change).clamp(-20, 20);
        let speed = 1.3f64.powi(state.speed);
        let scale = 10.0f64.powf(2.0 - speed.log10().floor());
        let speed = (speed * scale).round() / scale;
        time.set_relative_speed_f64(speed);
    }

    if keyboard_input.just_pressed(KeyCode::P) {
        if time.is_paused() {
            time.unpause();
        } else {
            time.pause();
        }
    }
}

fn set_visibility(
    mut commands: Commands,
    camera: Query<&GlobalTransform, With<MainCamera>>,
    mut entities: Query<
        (
            Entity,
            &GlobalTransform,
            &WantsCollider,
            &WantsDrawing,
            Has<RigidBody>,
            Has<Handle<Mesh>>,
        ),
        (With<DespawnOnReload>, Without<MainCamera>),
    >,
) {
    let camera_translation = camera.single().translation();
    for (entity, translation, wants_collider, wants_draw, has_collider, has_draw) in
        entities.iter_mut()
    {
        let dist_squared =
            (translation.translation().xz() - camera_translation.xz()).length_squared();
        match (dist_squared < 80.0 * 80.0, has_draw) {
            (false, true) => {
                commands.entity(entity).remove::<(
                    Handle<Mesh>,
                    Handle<OurMaterial>,
                    ViewVisibility,
                    InheritedVisibility,
                    Visibility,
                )>();
            }
            (true, false) => {
                commands.entity(entity).insert((
                    wants_draw.0.clone(),
                    Visibility::Visible,
                    InheritedVisibility::default(),
                    ViewVisibility::default(),
                ));
            }
            _ => (),
        }

        match (dist_squared < 2.0 * 2.0, has_collider) {
            (false, true) => {
                commands.entity(entity).remove::<(RigidBody, Collider)>();
            }
            (true, false) => {
                commands
                    .entity(entity)
                    .insert((wants_collider.0.clone(), RigidBody::Static));
            }
            _ => (),
        }
    }
}
