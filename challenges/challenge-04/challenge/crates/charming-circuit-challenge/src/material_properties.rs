pub use bevy::prelude::*;
use bevy::{
    asset::{io::Reader, AssetLoader, AsyncReadExt, LoadContext},
    render::render_resource::Face,
    utils::BoxedFuture,
};

use crate::material::{OurMaterial, OurMaterialExtension};
use crate::util::option_deserializer;

pub struct MaterialPropertiesPlugin;

impl Plugin for MaterialPropertiesPlugin {
    fn build(&self, app: &mut App) {
        app.init_asset::<MaterialProperties>()
            .register_asset_loader(MaterialLoader);
    }
}

#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum MaterialPropertiesLoaderError {
    /// An [IO Error](std::io::Error)
    #[error("Error while trying to read the material properties file: {0}")]
    Io(#[from] std::io::Error),
    /// A [RON Error](ron::error::SpannedError)
    #[error("Could not parse RON while parsing material properties file: {0}")]
    RonSpannedError(#[from] ron::error::SpannedError),
    #[error(transparent)]
    LoadDirectError(#[from] bevy::asset::LoadDirectError),
    #[error("Unexpected value {value} for field {field}")]
    UnexpectedKey { value: String, field: &'static str },
}

pub struct MaterialLoader;

impl AssetLoader for MaterialLoader {
    type Asset = OurMaterial;
    type Settings = ();
    type Error = MaterialPropertiesLoaderError;

    fn load<'a>(
        &'a self,
        reader: &'a mut Reader,
        _settings: &'a (),
        load_context: &'a mut LoadContext,
    ) -> BoxedFuture<'a, Result<Self::Asset, Self::Error>> {
        Box::pin(async move {
            let mut bytes = Vec::new();
            reader.read_to_end(&mut bytes).await?;
            let props: MaterialProperties = ron::de::from_bytes(&bytes)?;

            let mut mat = if let Some(inherit) = props.inherit {
                #[cfg(feature = "embed")]
                let inherit = format!("embedded://charming_circuit_challenge/assets/{inherit}");

                let loaded = load_context.load_direct(&inherit).await?;
                let mat = loaded.get::<OurMaterial>().unwrap().clone();
                // mat.extension
                //     .dependencies
                //     .push(load_context.load::<OurMaterial>(&inherit));
                mat
            } else {
                OurMaterial {
                    base: StandardMaterial::default(),
                    extension: OurMaterialExtension::default(),
                }
            };

            macro_rules! field {
                ($field:ident) => {
                    if let Some($field) = props.$field {
                        mat.base.$field = $field;
                    }
                };
                ($field:ident texture) => {
                    if let Some($field) = props.$field {
                        if $field == "" {
                            mat.base.$field = None;
                        } else {
                            #[cfg(not(feature = "embed"))]
                            {
                                load_context.load_direct(&$field).await?; // TODO: Why is this needed to get hot reload to work?
                                mat.base.$field = Some(load_context.load(&$field));
                            }
                            #[cfg(feature = "embed")]
                            {
                                mat.base.$field = Some(load_context.load(&format!("embedded://charming_circuit_challenge/assets/{}", $field)));
                            }
                        }
                    }
                };
                ($field:ident, $e:expr) => {
                    if let Some($field) = props.$field {
                        mat.base.$field = $e;
                    }
                };
            }

            field!(base_color);
            field!(base_color_texture texture);
            field!(emissive);
            field!(emissive_texture texture);
            field!(perceptual_roughness);
            field!(metallic);
            field!(metallic_roughness_texture texture);
            field!(reflectance);
            field!(diffuse_transmission);
            field!(specular_transmission);
            field!(thickness);
            field!(ior);
            field!(attenuation_distance);
            field!(attenuation_color);
            field!(normal_map_texture texture);
            field!(flip_normal_map_y);
            field!(occlusion_texture texture);
            field!(double_sided);
            field!(
                cull_mode,
                match cull_mode.as_str() {
                    "front" => Some(Face::Front),
                    "back" => Some(Face::Back),
                    "none" => None,
                    _ =>
                        return Err(MaterialPropertiesLoaderError::UnexpectedKey {
                            value: cull_mode,
                            field: "cull_mode"
                        }),
                }
            );
            field!(unlit);
            field!(fog_enabled);
            field!(
                alpha_mode,
                match alpha_mode.as_str() {
                    "opaque" => AlphaMode::Opaque,
                    "blend" => AlphaMode::Blend,
                    _ =>
                        return Err(MaterialPropertiesLoaderError::UnexpectedKey {
                            value: alpha_mode,
                            field: "alpha_mode"
                        }),
                }
            );
            field!(depth_bias);
            field!(depth_map texture);
            field!(parallax_depth_scale);
            field!(max_parallax_layer_count);

            if let Some(animated) = props.animated {
                mat.extension.animated = animated as u32;
            }

            Ok(mat)
        })
    }

    fn extensions(&self) -> &[&str] {
        &["mat.ron"]
    }
}

/// Used for loading material properties from ron files, which can
/// then be used to overwrite standard materials
#[derive(serde::Serialize, serde::Deserialize, Asset, Debug, Clone, TypePath, Default)]
#[serde(default, deny_unknown_fields)]
pub struct MaterialProperties {
    /// Inherit from this base material
    #[serde(deserialize_with = "option_deserializer")]
    pub inherit: Option<String>,

    /// Animate the material using our extension method
    #[serde(deserialize_with = "option_deserializer")]
    pub animated: Option<bool>,

    /// The color of the surface of the material before lighting.
    ///
    /// Doubles as diffuse albedo for non-metallic, specular for metallic and a mix for everything
    /// in between. If used together with a `base_color_texture`, this is factored into the final
    /// base color as `base_color * base_color_texture_value`
    ///
    /// Defaults to [`Color::WHITE`].
    #[serde(deserialize_with = "option_deserializer")]
    pub base_color: Option<Color>,

    /// The texture component of the material's color before lighting.
    /// The actual pre-lighting color is `base_color * this_texture`.
    ///
    /// See [`base_color`] for details.
    ///
    /// You should set `base_color` to [`Color::WHITE`] (the default)
    /// if you want the texture to show as-is.
    ///
    /// Setting `base_color` to something else than white will tint
    /// the texture. For example, setting `base_color` to pure red will
    /// tint the texture red.
    ///
    /// [`base_color`]: StandardMaterial::base_color
    #[serde(deserialize_with = "option_deserializer")]
    pub base_color_texture: Option<String>,

    // Use a color for user friendliness even though we technically don't use the alpha channel
    // Might be used in the future for exposure correction in HDR
    /// Color the material "emits" to the camera.
    ///
    /// This is typically used for monitor screens or LED lights.
    /// Anything that can be visible even in darkness.
    ///
    /// The emissive color is added to what would otherwise be the material's visible color.
    /// This means that for a light emissive value, in darkness,
    /// you will mostly see the emissive component.
    ///
    /// The default emissive color is black, which doesn't add anything to the material color.
    ///
    /// Note that **an emissive material won't light up surrounding areas like a light source**,
    /// it just adds a value to the color seen on screen.
    #[serde(deserialize_with = "option_deserializer")]
    pub emissive: Option<Color>,

    /// The emissive map, multiplies pixels with [`emissive`]
    /// to get the final "emitting" color of a surface.
    ///
    /// This color is multiplied by [`emissive`] to get the final emitted color.
    /// Meaning that you should set [`emissive`] to [`Color::WHITE`]
    /// if you want to use the full range of color of the emissive texture.
    ///
    /// [`emissive`]: StandardMaterial::emissive
    #[serde(deserialize_with = "option_deserializer")]
    pub emissive_texture: Option<String>,

    /// Linear perceptual roughness, clamped to `[0.089, 1.0]` in the shader.
    ///
    /// Defaults to `0.5`.
    ///
    /// Low values result in a "glossy" material with specular highlights,
    /// while values close to `1` result in rough materials.
    ///
    /// If used together with a roughness/metallic texture, this is factored into the final base
    /// color as `roughness * roughness_texture_value`.
    ///
    /// 0.089 is the minimum floating point value that won't be rounded down to 0 in the
    /// calculations used.
    //
    // Technically for 32-bit floats, 0.045 could be used.
    // See <https://google.github.io/filament/Filament.html#materialsystem/parameterization/>
    #[serde(deserialize_with = "option_deserializer")]
    pub perceptual_roughness: Option<f32>,

    /// How "metallic" the material appears, within `[0.0, 1.0]`.
    ///
    /// This should be set to 0.0 for dielectric materials or 1.0 for metallic materials.
    /// For a hybrid surface such as corroded metal, you may need to use in-between values.
    ///
    /// Defaults to `0.00`, for dielectric.
    ///
    /// If used together with a roughness/metallic texture, this is factored into the final base
    /// color as `metallic * metallic_texture_value`.
    #[serde(deserialize_with = "option_deserializer")]
    pub metallic: Option<f32>,

    /// Metallic and roughness maps, stored as a single texture.
    ///
    /// The blue channel contains metallic values,
    /// and the green channel contains the roughness values.
    /// Other channels are unused.
    ///
    /// Those values are multiplied by the scalar ones of the material,
    /// see [`metallic`] and [`perceptual_roughness`] for details.
    ///
    /// Note that with the default values of [`metallic`] and [`perceptual_roughness`],
    /// setting this texture has no effect. If you want to exclusively use the
    /// `metallic_roughness_texture` values for your material, make sure to set [`metallic`]
    /// and [`perceptual_roughness`] to `1.0`.
    ///
    /// [`metallic`]: StandardMaterial::metallic
    /// [`perceptual_roughness`]: StandardMaterial::perceptual_roughness
    #[serde(deserialize_with = "option_deserializer")]
    pub metallic_roughness_texture: Option<String>,

    /// Specular intensity for non-metals on a linear scale of `[0.0, 1.0]`.
    ///
    /// Use the value as a way to control the intensity of the
    /// specular highlight of the material, i.e. how reflective is the material,
    /// rather than the physical property "reflectance."
    ///
    /// Set to `0.0`, no specular highlight is visible, the highlight is strongest
    /// when `reflectance` is set to `1.0`.
    ///
    /// Defaults to `0.5` which is mapped to 4% reflectance in the shader.
    #[doc(alias = "specular_intensity")]
    #[serde(deserialize_with = "option_deserializer")]
    pub reflectance: Option<f32>,

    /// The amount of light transmitted _diffusely_ through the material (i.e. “translucency”)
    ///
    /// Implemented as a second, flipped [Lambertian diffuse](https://en.wikipedia.org/wiki/Lambertian_reflectance) lobe,
    /// which provides an inexpensive but plausible approximation of translucency for thin dieletric objects (e.g. paper,
    /// leaves, some fabrics) or thicker volumetric materials with short scattering distances (e.g. porcelain, wax).
    ///
    /// For specular transmission usecases with refraction (e.g. glass) use the [`StandardMaterial::specular_transmission`] and
    /// [`StandardMaterial::ior`] properties instead.
    ///
    /// - When set to `0.0` (the default) no diffuse light is transmitted;
    /// - When set to `1.0` all diffuse light is transmitted through the material;
    /// - Values higher than `0.5` will cause more diffuse light to be transmitted than reflected, resulting in a “darker”
    ///   appearance on the side facing the light than the opposite side. (e.g. plant leaves)
    ///
    /// ## Notes
    ///
    /// - The material's [`StandardMaterial::base_color`] also modulates the transmitted light;
    /// - To receive transmitted shadows on the diffuse transmission lobe (i.e. the “backside”) of the material,
    ///   use the [`TransmittedShadowReceiver`] component.
    #[doc(alias = "translucency")]
    #[serde(deserialize_with = "option_deserializer")]
    pub diffuse_transmission: Option<f32>,

    /// The amount of light transmitted _specularly_ through the material (i.e. via refraction)
    ///
    /// - When set to `0.0` (the default) no light is transmitted.
    /// - When set to `1.0` all light is transmitted through the material.
    ///
    /// The material's [`StandardMaterial::base_color`] also modulates the transmitted light.
    ///
    /// **Note:** Typically used in conjunction with [`StandardMaterial::thickness`], [`StandardMaterial::ior`] and [`StandardMaterial::perceptual_roughness`].
    ///
    /// ## Performance
    ///
    /// Specular transmission is implemented as a relatively expensive screen-space effect that allows ocluded objects to be seen through the material,
    /// with distortion and blur effects.
    ///
    /// - [`Camera3d::screen_space_specular_transmission_steps`](bevy_core_pipeline::core_3d::Camera3d::screen_space_specular_transmission_steps) can be used to enable transmissive objects
    /// to be seen through other transmissive objects, at the cost of additional draw calls and texture copies; (Use with caution!)
    ///     - If a simplified approximation of specular transmission using only environment map lighting is sufficient, consider setting
    /// [`Camera3d::screen_space_specular_transmission_steps`](bevy_core_pipeline::core_3d::Camera3d::screen_space_specular_transmission_steps) to `0`.
    /// - If purely diffuse light transmission is needed, (i.e. “translucency”) consider using [`StandardMaterial::diffuse_transmission`] instead,
    /// for a much less expensive effect.
    /// - Specular transmission is rendered before alpha blending, so any material with [`AlphaMode::Blend`], [`AlphaMode::Premultiplied`], [`AlphaMode::Add`] or [`AlphaMode::Multiply`]
    ///   won't be visible through specular transmissive materials.
    #[doc(alias = "refraction")]
    #[serde(deserialize_with = "option_deserializer")]
    pub specular_transmission: Option<f32>,

    /// Thickness of the volume beneath the material surface.
    ///
    /// When set to `0.0` (the default) the material appears as an infinitely-thin film,
    /// transmitting light without distorting it.
    ///
    /// When set to any other value, the material distorts light like a thick lens.
    ///
    /// **Note:** Typically used in conjunction with [`StandardMaterial::specular_transmission`] and [`StandardMaterial::ior`], or with
    /// [`StandardMaterial::diffuse_transmission`].
    #[doc(alias = "volume")]
    #[doc(alias = "thin_walled")]
    #[serde(deserialize_with = "option_deserializer")]
    pub thickness: Option<f32>,

    /// The [index of refraction](https://en.wikipedia.org/wiki/Refractive_index) of the material.
    ///
    /// Defaults to 1.5.
    ///
    /// | Material        | Index of Refraction  |
    /// |:----------------|:---------------------|
    /// | Vacuum          | 1                    |
    /// | Air             | 1.00                 |
    /// | Ice             | 1.31                 |
    /// | Water           | 1.33                 |
    /// | Eyes            | 1.38                 |
    /// | Quartz          | 1.46                 |
    /// | Olive Oil       | 1.47                 |
    /// | Honey           | 1.49                 |
    /// | Acrylic         | 1.49                 |
    /// | Window Glass    | 1.52                 |
    /// | Polycarbonate   | 1.58                 |
    /// | Flint Glass     | 1.69                 |
    /// | Ruby            | 1.71                 |
    /// | Glycerine       | 1.74                 |
    /// | Saphire         | 1.77                 |
    /// | Cubic Zirconia  | 2.15                 |
    /// | Diamond         | 2.42                 |
    /// | Moissanite      | 2.65                 |
    ///
    /// **Note:** Typically used in conjunction with [`StandardMaterial::specular_transmission`] and [`StandardMaterial::thickness`].
    #[doc(alias = "index_of_refraction")]
    #[doc(alias = "refraction_index")]
    #[doc(alias = "refractive_index")]
    #[serde(deserialize_with = "option_deserializer")]
    pub ior: Option<f32>,

    /// How far, on average, light travels through the volume beneath the material's
    /// surface before being absorbed.
    ///
    /// Defaults to [`f32::INFINITY`], i.e. light is never absorbed.
    ///
    /// **Note:** To have any effect, must be used in conjunction with:
    /// - [`StandardMaterial::attenuation_color`];
    /// - [`StandardMaterial::thickness`];
    /// - [`StandardMaterial::diffuse_transmission`] or [`StandardMaterial::specular_transmission`].
    #[doc(alias = "absorption_distance")]
    #[doc(alias = "extinction_distance")]
    #[serde(deserialize_with = "option_deserializer")]
    pub attenuation_distance: Option<f32>,

    /// The resulting (non-absorbed) color after white light travels through the attenuation distance.
    ///
    /// Defaults to [`Color::WHITE`], i.e. no change.
    ///
    /// **Note:** To have any effect, must be used in conjunction with:
    /// - [`StandardMaterial::attenuation_distance`];
    /// - [`StandardMaterial::thickness`];
    /// - [`StandardMaterial::diffuse_transmission`] or [`StandardMaterial::specular_transmission`].
    #[doc(alias = "absorption_color")]
    #[doc(alias = "extinction_color")]
    #[serde(deserialize_with = "option_deserializer")]
    pub attenuation_color: Option<Color>,

    /// Used to fake the lighting of bumps and dents on a material.
    ///
    /// A typical usage would be faking cobblestones on a flat plane mesh in 3D.
    ///
    /// # Notes
    ///
    /// Normal mapping with `StandardMaterial` and the core bevy PBR shaders requires:
    /// - A normal map texture
    /// - Vertex UVs
    /// - Vertex tangents
    /// - Vertex normals
    ///
    /// Tangents do not have to be stored in your model,
    /// they can be generated using the [`Mesh::generate_tangents`] or
    /// [`Mesh::with_generated_tangents`] methods.
    /// If your material has a normal map, but still renders as a flat surface,
    /// make sure your meshes have their tangents set.
    ///
    /// [`Mesh::generate_tangents`]: bevy_render::mesh::Mesh::generate_tangents
    /// [`Mesh::with_generated_tangents`]: bevy_render::mesh::Mesh::with_generated_tangents
    #[serde(deserialize_with = "option_deserializer")]
    pub normal_map_texture: Option<String>,

    /// Normal map textures authored for DirectX have their y-component flipped. Set this to flip
    /// it to right-handed conventions.
    #[serde(deserialize_with = "option_deserializer")]
    pub flip_normal_map_y: Option<bool>,

    /// Specifies the level of exposure to ambient light.
    ///
    /// This is usually generated and stored automatically ("baked") by 3D-modelling software.
    ///
    /// Typically, steep concave parts of a model (such as the armpit of a shirt) are darker,
    /// because they have little exposure to light.
    /// An occlusion map specifies those parts of the model that light doesn't reach well.
    ///
    /// The material will be less lit in places where this texture is dark.
    /// This is similar to ambient occlusion, but built into the model.
    #[serde(deserialize_with = "option_deserializer")]
    pub occlusion_texture: Option<String>,

    /// Support two-sided lighting by automatically flipping the normals for "back" faces
    /// within the PBR lighting shader.
    ///
    /// Defaults to `false`.
    /// This does not automatically configure backface culling,
    /// which can be done via `cull_mode`.
    #[serde(deserialize_with = "option_deserializer")]
    pub double_sided: Option<bool>,

    /// Whether to cull the "front", "back" or neither side of a mesh.
    /// If set to `None`, the two sides of the mesh are visible.
    ///
    /// Defaults to `Some(Face::Back)`.
    /// In bevy, the order of declaration of a triangle's vertices
    /// in [`Mesh`] defines the triangle's front face.
    ///
    /// When a triangle is in a viewport,
    /// if its vertices appear counter-clockwise from the viewport's perspective,
    /// then the viewport is seeing the triangle's front face.
    /// Conversely, if the vertices appear clockwise, you are seeing the back face.
    ///
    /// In short, in bevy, front faces winds counter-clockwise.
    ///
    /// Your 3D editing software should manage all of that.
    ///
    /// [`Mesh`]: bevy_render::mesh::Mesh
    // TODO: include this in reflection somehow (maybe via remote types like serde https://serde.rs/remote-derive.html)
    #[serde(deserialize_with = "option_deserializer")]
    pub cull_mode: Option<String>,

    /// Whether to apply only the base color to this material.
    ///
    /// Normals, occlusion textures, roughness, metallic, reflectance, emissive,
    /// shadows, alpha mode and ambient light are ignored if this is set to `true`.
    #[serde(deserialize_with = "option_deserializer")]
    pub unlit: Option<bool>,

    /// Whether to enable fog for this material.
    #[serde(deserialize_with = "option_deserializer")]
    pub fog_enabled: Option<bool>,

    /// How to apply the alpha channel of the `base_color_texture`.
    ///
    /// See [`AlphaMode`] for details. Defaults to [`AlphaMode::Opaque`].
    #[serde(deserialize_with = "option_deserializer")]
    pub alpha_mode: Option<String>,

    /// Adjust rendered depth.
    ///
    /// A material with a positive depth bias will render closer to the
    /// camera while negative values cause the material to render behind
    /// other objects. This is independent of the viewport.
    ///
    /// `depth_bias` affects render ordering and depth write operations
    /// using the `wgpu::DepthBiasState::Constant` field.
    ///
    /// [z-fighting]: https://en.wikipedia.org/wiki/Z-fighting
    #[serde(deserialize_with = "option_deserializer")]
    pub depth_bias: Option<f32>,

    /// The depth map used for [parallax mapping].
    ///
    /// It is a greyscale image where white represents bottom and black the top.
    /// If this field is set, bevy will apply [parallax mapping].
    /// Parallax mapping, unlike simple normal maps, will move the texture
    /// coordinate according to the current perspective,
    /// giving actual depth to the texture.
    ///
    /// The visual result is similar to a displacement map,
    /// but does not require additional geometry.
    ///
    /// Use the [`parallax_depth_scale`] field to control the depth of the parallax.
    ///
    /// ## Limitations
    ///
    /// - It will look weird on bent/non-planar surfaces.
    /// - The depth of the pixel does not reflect its visual position, resulting
    ///   in artifacts for depth-dependent features such as fog or SSAO.
    /// - For the same reason, the geometry silhouette will always be
    ///   the one of the actual geometry, not the parallaxed version, resulting
    ///   in awkward looks on intersecting parallaxed surfaces.
    ///
    /// ## Performance
    ///
    /// Parallax mapping requires multiple texture lookups, proportional to
    /// [`max_parallax_layer_count`], which might be costly.
    ///
    /// Use the [`parallax_mapping_method`] and [`max_parallax_layer_count`] fields
    /// to tweak the shader, trading graphical quality for performance.
    ///
    /// To improve performance, set your `depth_map`'s [`Image::sampler`]
    /// filter mode to `FilterMode::Nearest`, as [this paper] indicates, it improves
    /// performance a bit.
    ///
    /// To reduce artifacts, avoid steep changes in depth, blurring the depth
    /// map helps with this.
    ///
    /// Larger depth maps haves a disproportionate performance impact.
    ///
    /// [this paper]: https://www.diva-portal.org/smash/get/diva2:831762/FULLTEXT01.pdf
    /// [parallax mapping]: https://en.wikipedia.org/wiki/Parallax_mapping
    /// [`parallax_depth_scale`]: StandardMaterial::parallax_depth_scale
    /// [`parallax_mapping_method`]: StandardMaterial::parallax_mapping_method
    /// [`max_parallax_layer_count`]: StandardMaterial::max_parallax_layer_count
    #[serde(deserialize_with = "option_deserializer")]
    pub depth_map: Option<String>,

    /// How deep the offset introduced by the depth map should be.
    ///
    /// Default is `0.1`, anything over that value may look distorted.
    /// Lower values lessen the effect.
    ///
    /// The depth is relative to texture size. This means that if your texture
    /// occupies a surface of `1` world unit, and `parallax_depth_scale` is `0.1`, then
    /// the in-world depth will be of `0.1` world units.
    /// If the texture stretches for `10` world units, then the final depth
    /// will be of `1` world unit.
    #[serde(deserialize_with = "option_deserializer")]
    pub parallax_depth_scale: Option<f32>,

    /// In how many layers to split the depth maps for parallax mapping.
    ///
    /// If you are seeing jaggy edges, increase this value.
    /// However, this incurs a performance cost.
    ///
    /// Dependent on the situation, switching to [`ParallaxMappingMethod::Relief`]
    /// and keeping this value low might have better performance than increasing the
    /// layer count while using [`ParallaxMappingMethod::Occlusion`].
    ///
    /// Default is `16.0`.
    #[serde(deserialize_with = "option_deserializer")]
    pub max_parallax_layer_count: Option<f32>,
}
