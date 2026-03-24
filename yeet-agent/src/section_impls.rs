use console::{StyledObject, style};
use yeet::display;

use crate::section::{ColoredDisplay, DisplaySection, DisplaySectionItem};

impl ColoredDisplay<&str> for api::ProvisionState {
    fn colored_display(&self) -> StyledObject<&'static str> {
        match self {
            api::ProvisionState::NotSet => style("Not set").blue(),
            api::ProvisionState::Detached => style("Detached").yellow(),
            api::ProvisionState::Provisioned => style("Provisioned").green(),
        }
    }
}

impl DisplaySectionItem for api::Host {
    fn as_section_item(&self) -> (String, String) {
        let commit_ver = match &self.version {
            Some(version) => {
                let pos = version.rfind('.').map_or(0, |i| i.saturating_add(1));
                #[expect(clippy::string_slice)]
                version[pos..].to_owned()
            }
            None => style("Not Set").blue().to_string(),
        };

        let up_to_date = if self.version == self.latest_update {
            style("Up to date ").green()
        } else {
            style("Outdated   ").red()
        };

        (
            self.hostname.clone(),
            format!(
                "{} ({}) {up_to_date}{}",
                self.state.colored_display(),
                commit_ver,
                display::time_diff(
                    self.last_ping,
                    jiff::Unit::Second,
                    30_f64,
                    jiff::Unit::Second
                ),
            ),
        )
    }
}

impl DisplaySection for api::Host {
    fn as_section(&self) -> crate::section::Section {
        let mut items = Vec::new();

        let up_to_date = if self.version == self.latest_update {
            style("Yes").green().bold()
        } else {
            style("No").red().bold()
        };
        items.push(("Up to date".to_owned(), up_to_date.to_string()));

        items.push((
            "Mode".to_owned(),
            self.state.colored_display().bold().to_string(),
        ));

        if let Some(version) = &self.version {
            items.push(("Current version".to_owned(), version.clone()));
        }

        if let Some(update) = &self.latest_update
            && self.version != self.latest_update
        {
            items.push(("Next version".to_owned(), update.clone()));
        }

        {
            let last_seen = display::time_diff(
                self.last_ping,
                jiff::Unit::Second,
                30_f64,
                jiff::Unit::Second,
            );
            items.push(("Last seen".to_owned(), last_seen.clone()));
        };

        (style(&self.hostname).underlined().to_string(), items)
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

        (
            style(&self.host_identifier).underlined().to_string(),
            details,
        )
    }
}
