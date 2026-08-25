use color_eyre::Result;

fn main() -> Result<()> {
    inquire::Select::new("What is your favourite color?", vec!["red", "blue"]).prompt()?;
    Ok(())
}
