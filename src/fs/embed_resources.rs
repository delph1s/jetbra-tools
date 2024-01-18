use rust_embed::{RustEmbed, EmbeddedFile};

#[derive(RustEmbed)]
#[folder = "src/resources/"]
struct Asset;

pub fn get_products_list_default() -> Option<EmbeddedFile> {
    Asset::get("./products.toml")
}