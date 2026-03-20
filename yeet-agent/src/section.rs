pub type Section = (String, Vec<(String, String)>);

pub trait DisplaySection {
    fn as_section(&self) -> Section;
}

pub trait DisplaySectionItem {
    fn as_section_item(&self) -> (String, String);
}

pub trait ColoredDisplay<D> {
    fn colored_display(&self) -> StyledObject<D>;
}

macro_rules! section {
    ( $title:expr => [ $( $k:expr, $v:expr ),* $(,)? ] ) => {
        ( $title.to_string(),
            vec![ $( ($k.to_string(), $v.to_string()) ),*]
        )
    };
}
use console::StyledObject;
pub(crate) use section;

#[expect(clippy::print_stdout, clippy::unwrap_used)]
pub fn print_sections(sections: &[Section]) {
    let width = sections
        .iter()
        .flat_map(|(_, section_value)| section_value)
        .map(|(item_key, _)| item_key.len())
        .max()
        .unwrap_or(0)
        .saturating_add(1);
    for (section, items) in sections {
        println!("{section}");

        for (key, value) in items {
            let value = value.clone();
            // Test if it is a multiline
            if value.lines().count() > 1 {
                let mut lines = value.lines();
                // print first normally key: Value
                println!("{:>w$}: {}", key, lines.next().unwrap(), w = width);

                for line in lines {
                    println!("{:>w$}  {}", "", line, w = width);
                }
            } else {
                println!("{key:>width$}: {value}");
            }
        }
        println!(); // Blank line after section
    }
}
