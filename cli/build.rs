#[expect(clippy::unwrap_used)]
fn main() {
    shadow_rs::ShadowBuilder::builder().build().unwrap();
}
