use console::style;
use jiff::{Timestamp, Unit, Zoned};

// pub trait Fragment {
//     fn fragment(&self, fragment: &mut IndexMap<String, String>);
//     fn as_fragment(&self) -> String {
//         let mut fragment = IndexMap::new();
//         self.fragment(&mut fragment);
//         fragment.en
//     }
// }

/// # Panics
/// idk maybe
#[must_use]
#[expect(clippy::unwrap_used, clippy::arithmetic_side_effects)]
pub fn time_diff(timestamp: Timestamp, unit: Unit, threshold: f64, smallest: Unit) -> String {
    let span = (timestamp - jiff::Timestamp::now())
        .round(
            jiff::SpanRound::new()
                .largest(jiff::Unit::Month)
                .smallest(smallest)
                .relative(&Zoned::now())
                .mode(jiff::RoundMode::Trunc),
        )
        .unwrap();

    if span.total((unit, &Zoned::now())).unwrap().abs() < threshold {
        style(format!("{span:#}")).green().bold()
    } else {
        style(format!("{span:#}")).red().bold()
    }
    .to_string()
}
