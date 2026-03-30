use colored::Colorize;

use crate::section::{DisplaySection, DisplaySectionItem};

impl DisplaySectionItem for api::Host {
    fn as_section_item(&self) -> (String, String) {
        let str = self.to_string();
        let (l, r) = str.split_once(":").unwrap();

        (l.to_string(), r.trim().to_owned())
    }
}

impl DisplaySection for api::Host {
    fn as_section(&self) -> crate::section::Section {
        let mut items = Vec::new();

        let up_to_date = if self.version == self.latest_update {
            "Yes".green().bold()
        } else {
            "No".red().bold()
        };
        items.push(("Up to date".to_owned(), up_to_date.to_string()));

        items.push(("Mode".to_owned(), self.state.to_string().bold().to_string()));

        if let Some(version) = &self.version {
            items.push(("Current version".to_owned(), version.clone()));
        }

        if let Some(update) = &self.latest_update
            && self.version != self.latest_update
        {
            items.push(("Next version".to_owned(), update.clone()));
        }

        {
            let last_seen = api::time_diff(
                self.last_ping,
                jiff::Unit::Second,
                30_f64,
                jiff::Unit::Second,
            );
            items.push(("Last seen".to_owned(), last_seen.clone()));
        };

        (self.hostname.underline().to_string(), items)
    }
}

// TODO: config to extract wanted fields
impl DisplaySection for api::Node {
    fn as_section(&self) -> crate::section::Section {
        let details = {
            let mut details = self.host_details.os_version.iter().collect::<Vec<_>>();
            details.extend(self.host_details.osquery_info.iter());
            details.extend(self.host_details.platform_info.iter());
            details.extend(self.host_details.system_info.iter());
            details
                .into_iter()
                .map(|detail| (detail.0.clone(), detail.1.clone()))
                .collect()
        };

        (self.host_identifier.underline().to_string(), details)
    }
}

impl DisplaySectionItem for api::User {
    fn as_section_item(&self) -> (String, String) {
        let str = self.to_string();
        let (l, r) = str.split_once(":").unwrap();

        (l.to_string(), r.trim().to_owned())
    }
}
