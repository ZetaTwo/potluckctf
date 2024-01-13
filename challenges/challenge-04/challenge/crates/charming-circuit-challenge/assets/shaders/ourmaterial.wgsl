#import bevy_pbr::{
    pbr_fragment::pbr_input_from_standard_material,
    pbr_functions::alpha_discard,
    mesh_view_bindings::globals,
}
#import bevy_pbr::{
    forward_io::{VertexOutput, FragmentOutput},
    pbr_functions::{apply_pbr_lighting, main_pass_post_lighting_processing},
}

struct OurMaterialExtension {
    animated: u32,
}

@group(1) @binding(100)
var<uniform> our_material_extension: OurMaterialExtension;

@fragment
fn fragment(
    input: VertexOutput,
    @builtin(front_facing) is_front: bool,
) -> FragmentOutput {
    var new_input = input;
    if (our_material_extension.animated != u32(0)) {
        new_input.uv.x = globals.time % 1.0;
    }
    // Generate a PbrInput struct from the StandardMaterial bindings
    var pbr_input = pbr_input_from_standard_material(new_input, is_front);

    pbr_input.material.base_color = alpha_discard(
        pbr_input.material,
        pbr_input.material.base_color
    );

    var out: FragmentOutput;

    // Apply lighting
    out.color = apply_pbr_lighting(pbr_input);

    // Apply in-shader post processing.
    // Ex: fog, alpha-premultiply, etc. For non-hdr cameras: tonemapping and debanding
    out.color = main_pass_post_lighting_processing(pbr_input, out.color);

    return out;
}
