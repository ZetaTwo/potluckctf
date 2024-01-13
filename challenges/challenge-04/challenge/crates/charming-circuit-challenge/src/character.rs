use bevy::{ecs::query::Has, input::mouse::MouseMotion, prelude::*, window::CursorGrabMode};
use bevy_xpbd_3d::{math::*, prelude::*};

pub struct CharacterControllerPlugin;

impl Plugin for CharacterControllerPlugin {
    fn build(&self, app: &mut App) {
        app.add_event::<MovementAction>()
            .init_resource::<GravityToggle>()
            .add_systems(
                Update,
                (
                    keyboard_input,
                    update_grounded,
                    apply_deferred,
                    movement,
                    apply_movement_damping,
                    mouse_motion,
                )
                    .chain(),
            );
    }
}

/// An event sent for a movement input action.
#[derive(Event)]
pub enum MovementAction {
    Move(Vector2),
    Jump,
    ToggleGravity,
}

/// A marker component indicating that an entity is using a character controller.
#[derive(Component)]
pub struct CharacterController;

/// A marker component indicating that an entity is on the ground.
#[derive(Component)]
#[component(storage = "SparseSet")]
pub struct Grounded;
/// The acceleration used for character movement.
#[derive(Component)]
pub struct MovementAcceleration(Scalar);

/// The damping factor used for slowing down movement.
#[derive(Component)]
pub struct MovementDampingFactor(Scalar);

/// The strength of a jump.
#[derive(Component)]
pub struct JumpImpulse(Scalar);

/// The maximum angle a slope can have for a character controller
/// to be able to climb and jump. If the slope is steeper than this angle,
/// the character will slide down.
#[derive(Component)]
pub struct MaxSlopeAngle(Scalar);

#[derive(Resource)]
pub struct GravityToggle(pub bool);

impl Default for GravityToggle {
    fn default() -> Self {
        Self(true)
    }
}

/// A bundle that contains the components needed for a basic
/// kinematic character controller.
#[derive(Bundle)]
pub struct CharacterControllerBundle {
    character_controller: CharacterController,
    rigid_body: RigidBody,
    collider: Collider,
    ground_caster: ShapeCaster,
    locked_axes: LockedAxes,
    movement: MovementBundle,
}

/// A bundle that contains components for character movement.
#[derive(Bundle)]
pub struct MovementBundle {
    acceleration: MovementAcceleration,
    damping: MovementDampingFactor,
    jump_impulse: JumpImpulse,
    max_slope_angle: MaxSlopeAngle,
}

impl MovementBundle {
    pub const fn new(
        acceleration: Scalar,
        damping: Scalar,
        jump_impulse: Scalar,
        max_slope_angle: Scalar,
    ) -> Self {
        Self {
            acceleration: MovementAcceleration(acceleration),
            damping: MovementDampingFactor(damping),
            jump_impulse: JumpImpulse(jump_impulse),
            max_slope_angle: MaxSlopeAngle(max_slope_angle),
        }
    }
}

impl Default for MovementBundle {
    fn default() -> Self {
        Self::new(50.0, 0.9, 7.0, PI * 0.45)
    }
}

impl CharacterControllerBundle {
    pub fn new(collider: Collider) -> Self {
        // Create shape caster as a slightly smaller version of collider
        let mut caster_shape = collider.clone();
        caster_shape.set_scale(Vector::ONE * 0.99, 10);

        Self {
            character_controller: CharacterController,
            rigid_body: RigidBody::Dynamic,
            collider,
            ground_caster: ShapeCaster::new(
                caster_shape,
                Vector::ZERO,
                Quaternion::default(),
                Vector::NEG_Y,
            )
            .with_max_time_of_impact(0.2),
            locked_axes: LockedAxes::ROTATION_LOCKED,
            movement: MovementBundle::default(),
        }
    }
}

/// Sends [`MovementAction`] events based on keyboard input.
fn keyboard_input(
    mut movement_event_writer: EventWriter<MovementAction>,
    keyboard_input: Res<Input<KeyCode>>,
) {
    let up = keyboard_input.pressed(KeyCode::W);
    let down = keyboard_input.pressed(KeyCode::S);
    let left = keyboard_input.pressed(KeyCode::A);
    let right = keyboard_input.pressed(KeyCode::D);
    let shift = keyboard_input.pressed(KeyCode::ShiftLeft);

    let horizontal = right as i8 - left as i8;
    let vertical = up as i8 - down as i8;
    let mut direction =
        Vector2::new(horizontal as Scalar, vertical as Scalar).clamp_length_max(1.0);
    if shift {
        direction *= 10.0;
    }

    if direction != Vector2::ZERO {
        movement_event_writer.send(MovementAction::Move(direction));
    }

    if keyboard_input.just_pressed(KeyCode::Space) {
        movement_event_writer.send(MovementAction::Jump);
    }

    if keyboard_input.just_pressed(KeyCode::G) {
        movement_event_writer.send(MovementAction::ToggleGravity);
    }
}

/// Updates the [`Grounded`] status for character controllers.
fn update_grounded(
    mut commands: Commands,
    mut query: Query<
        (Entity, &ShapeHits, &Rotation, Option<&MaxSlopeAngle>),
        With<CharacterController>,
    >,
) {
    for (entity, hits, rotation, max_slope_angle) in &mut query {
        // The character is grounded if the shape caster has a hit with a normal
        // that isn't too steep.
        let is_grounded = hits.iter().any(|hit| {
            if let Some(angle) = max_slope_angle {
                rotation.rotate(-hit.normal2).angle_between(Vector::Y).abs() <= angle.0
            } else {
                true
            }
        });

        if is_grounded {
            commands.entity(entity).insert(Grounded);
        } else {
            commands.entity(entity).remove::<Grounded>();
        }
    }
}

/// Responds to [`MovementAction`] events and moves character controllers accordingly.
fn movement(
    time: Res<Time<Real>>,
    mut movement_event_reader: EventReader<MovementAction>,
    mut gravity: ResMut<Gravity>,
    mut controllers: Query<(
        &MovementAcceleration,
        &JumpImpulse,
        &mut LinearVelocity,
        &Transform,
        Has<Grounded>,
    )>,
    mut gravity_toggle: ResMut<GravityToggle>,
) {
    // Precision is adjusted so that the example works with
    // both the `f32` and `f64` features. Otherwise you don't need this.
    let delta_time = time.delta_seconds_f64().adjust_precision();

    for event in movement_event_reader.read() {
        for (movement_acceleration, jump_impulse, mut linear_velocity, transform, _is_grounded) in
            &mut controllers
        {
            match event {
                MovementAction::Move(direction) => {
                    let dir = (transform.forward().xz() * direction.x
                        + transform.left().xz() * direction.y)
                        * movement_acceleration.0
                        * delta_time;
                    linear_velocity.x -= dir.y;
                    linear_velocity.z += dir.x;
                }
                MovementAction::Jump => {
                    // if is_grounded {
                    if gravity_toggle.0 {
                        linear_velocity.y = jump_impulse.0;
                    }
                    // }
                }
                MovementAction::ToggleGravity => {
                    gravity_toggle.0 = !gravity_toggle.0;
                    if gravity_toggle.0 {
                        gravity.0 = Gravity::default().0;
                    } else {
                        linear_velocity.y = 0.0;
                        gravity.0 = Vec3::ZERO;
                    }
                }
            }
        }
    }
}

/// Slows down movement in the XZ plane.
fn apply_movement_damping(mut query: Query<(&MovementDampingFactor, &mut LinearVelocity)>) {
    for (damping_factor, mut linear_velocity) in &mut query {
        // We could use `LinearDamping`, but we don't want to dampen movement along the Y axis
        linear_velocity.x *= damping_factor.0;
        linear_velocity.z *= damping_factor.0;
    }
}

fn mouse_motion(
    mut motion_evr: EventReader<MouseMotion>,
    mut player: Query<&mut Transform, (With<CharacterController>, Without<Camera3d>)>,
    mut camera: Query<&mut Transform, (With<Camera3d>, Without<CharacterController>)>,
    windows: Query<&Window>,
) {
    let sensitivity = 0.00002;
    let mut delta: Option<Vec2> = None;
    for ev in motion_evr.read() {
        *delta.get_or_insert(Vec2::ZERO) += ev.delta;
    }

    if let Some(delta) = delta {
        let window = windows.single();
        if window.cursor.grab_mode == CursorGrabMode::None {
            return;
        }
        let window_scale = window.height().min(window.width());

        let mut player_transform = player.single_mut();
        let mut camera_transform = camera.single_mut();
        let (mut yaw, _, _) = player_transform.rotation.to_euler(EulerRot::YXZ);
        let (_, mut pitch, _) = camera_transform.rotation.to_euler(EulerRot::YXZ);

        // Using smallest of height or width ensures equal vertical and horizontal sensitivity
        pitch -= (sensitivity * delta.y * window_scale).to_radians();
        yaw -= (sensitivity * delta.x * window_scale).to_radians();

        pitch = pitch.clamp(-1.54, 1.54);

        // Order is important to prevent unintended roll
        player_transform.rotation = Quat::from_axis_angle(Vec3::Y, yaw);
        camera_transform.rotation = Quat::from_axis_angle(Vec3::X, pitch);
    }
}
