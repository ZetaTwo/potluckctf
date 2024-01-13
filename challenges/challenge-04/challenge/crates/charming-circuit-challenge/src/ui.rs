use bevy::prelude::*;

use crate::{character::GravityToggle, simulation::SimulationState, Player};

pub struct UiPlugin;

impl Plugin for UiPlugin {
    fn build(&self, app: &mut App) {
        app.add_systems(Startup, setup_ui)
            .add_systems(Update, update_ui);
    }
}

fn setup_ui(mut commands: Commands) {
    let style = TextStyle {
        font_size: 20.,
        ..default()
    };
    commands
        .spawn(NodeBundle {
            style: Style {
                position_type: PositionType::Absolute,
                padding: UiRect::all(Val::Px(5.0)),
                ..default()
            },
            z_index: ZIndex::Global(i32::MAX),
            background_color: Color::BLACK.with_a(0.75).into(),
            ..default()
        })
        .with_children(|c| {
            c.spawn(TextBundle::from_sections([
                TextSection::new("Controls:\n", style.clone()),
                TextSection::new("WSAD    - forward/back/strafe left/right\n", style.clone()),
                TextSection::new(
                    "space   - jump (you can double jump as much as you want)\n",
                    style.clone(),
                ),
                TextSection::new("shift   - sprint\n", style.clone()),
                TextSection::new("P       - pause\n", style.clone()),
                TextSection::new("G       - toggle gravity\n", style.clone()),
                TextSection::new(
                    "up/down - increment/decrement simulation speed\n\n",
                    style.clone(),
                ),
                TextSection::new("Current simulation speed: ", style.clone()),
                TextSection::new("1.0", style.clone()),
                TextSection::new("\n", style.clone()),
                TextSection::new("Pause: ", style.clone()),
                TextSection::new("false", style.clone()),
                TextSection::new("\n", style.clone()),
                TextSection::new("Steps: ", style.clone()),
                TextSection::new("0", style.clone()),
                TextSection::new("\n", style.clone()),
                TextSection::new("x: ", style.clone()),
                TextSection::new("0", style.clone()),
                TextSection::new("\n", style.clone()),
                TextSection::new("y: ", style.clone()),
                TextSection::new("0", style.clone()),
                TextSection::new("\n", style.clone()),
                TextSection::new("z: ", style.clone()),
                TextSection::new("0", style.clone()),
                TextSection::new("\n", style.clone()),
                TextSection::new("gravity: ", style.clone()),
                TextSection::new("on", style.clone()),
                TextSection::new("\n", style.clone()),
            ]));
        });
}

fn update_ui(
    mut text: Query<&mut Text>,
    camera: Query<&GlobalTransform, With<Player>>,
    time: Res<Time<Virtual>>,
    simulation_state: Res<SimulationState>,
    gravity_toggle: Res<GravityToggle>,
) {
    let mut text = text.single_mut();
    text.sections[8].value = format!("{}", time.relative_speed());
    text.sections[11].value = time.is_paused().to_string();
    text.sections[14].value = simulation_state.steps.to_string();
    let translation = camera.single().translation();
    text.sections[17].value = format!("{:7.02}", translation.x);
    text.sections[20].value = format!("{:7.02}", translation.y);
    text.sections[23].value = format!("{:7.02}", translation.z);
    text.sections[26].value = (if gravity_toggle.0 { "on" } else { "off" }).to_string();
}
