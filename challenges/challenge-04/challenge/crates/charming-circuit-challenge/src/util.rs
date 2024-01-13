// #[serde(deserialize_with = "path")]
pub fn option_deserializer<'de, T, D>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

pub fn fix_assetpath(path: &str) -> String {
    if cfg!(not(feature = "embed")) {
        path.to_string()
    } else {
        format!("embedded://charming_circuit_challenge/assets/{path}")
    }
}
