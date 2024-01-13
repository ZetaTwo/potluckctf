use std::io::Read;

use color_eyre::Result;
use map::Map;
use wirelang::{interpret::Direction, parse_str, ErrorCtx};

pub fn main() -> Result<()> {
    color_eyre::install()?;

    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;

    let mut error_ctx = ErrorCtx::new("<stdin>", input);

    if let Ok(program) = parse_str(&mut error_ctx) {
        let mut map = Map::default();
        if let Ok(()) = program.interpret(
            &mut map,
            &mut glam::IVec3::default(),
            &mut Direction::default(),
            &mut error_ctx,
        ) {
            println!("{map:?}");
        }
    }

    Ok(())
}
